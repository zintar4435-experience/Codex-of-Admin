"""
REST API: Clients.
Includes connection link/config generation for all protocols.
"""
import base64
import json
import urllib.parse
import uuid as uuid_mod
from datetime import datetime, timezone, timedelta

from flask import Blueprint, request, jsonify
from flask_login import login_required

from app.models import db, Client, Inbound, Setting
from app.core.audit import log_action
from app.core.input_validators import validate_uuid, validate_email

bp = Blueprint("clients", __name__)


# ---------------------------------------------------------------------------
# Link generators
# ---------------------------------------------------------------------------

def _server(inbound: Inbound) -> str:
    """Возвращает адрес сервера: домен inbound → panel_domain → server_ip."""
    return (inbound.domain
            or Setting.get("panel_domain", "")
            or Setting.get("server_ip", ""))


def _port(inbound: Inbound) -> str:
    """Возвращает порт как строку, или пустую строку если не задан."""
    return str(inbound.port) if inbound.port is not None else ""


def _transport_link_params(inbound: "Inbound", tcfg: dict) -> dict:
    """Параметры транспорта для share-ссылки (vless/trojan).

    Возвращает dict с ключом 'type' (каноническое имя сети, h2→http) и
    параметрами, нужными клиенту для подключения по данному транспорту.
    Значения берутся из transport_config и совпадают с тем, что кладётся
    в серверный конфиг (_build_stream_settings).
    """
    tr = inbound.transport or "tcp"
    p: dict = {"type": "http" if tr == "h2" else tr}
    if tr == "ws":
        p["path"] = tcfg.get("path", "/")
        if tcfg.get("host"):
            p["host"] = tcfg["host"]
    elif tr == "grpc":
        p["serviceName"] = tcfg.get("service_name", "")
        p["mode"] = "gun"
    elif tr == "kcp":
        if tcfg.get("seed"):
            p["seed"] = tcfg["seed"]
        p["headerType"] = tcfg.get("header_type", "none")
    elif tr in ("h2", "httpupgrade", "splithttp"):
        p["path"] = tcfg.get("path", "/")
        host = tcfg.get("host") or (tcfg.get("hosts") or [None])[0]
        if host:
            p["host"] = host
    return p


def _vmess_link(client: Client, inbound: Inbound) -> str:
    tcfg = inbound.get_transport_config()
    server = _server(inbound)
    net = inbound.transport or "tcp"
    is_grpc = net == "grpc"
    obj = {
        "v": "2",
        "ps": client.name,
        "add": server,
        "port": _port(inbound),
        "id": client.uuid,
        "aid": "0",
        "scy": "auto",
        "net": net,
        # Для gRPC vmess-формат кладёт serviceName в поле "path", а режим
        # ("gun"/"multi") — в поле "type". Для остальных транспортов "type"
        # это header type ("none"), а "path" — обычный путь.
        "type": "gun" if is_grpc else "none",
        "host": tcfg.get("host", ""),
        "path": tcfg.get("service_name", "") if is_grpc else tcfg.get("path", "/"),
        "tls": "tls" if inbound.tls_enabled else "",
        "sni": inbound.domain or Setting.get("panel_domain", ""),
        "alpn": "",
        "fp": "",
    }
    b64 = base64.b64encode(json.dumps(obj).encode()).decode()
    return f"vmess://{b64}"


def _vless_link(client: Client, inbound: Inbound) -> str:
    tcfg = inbound.get_transport_config()
    server = _server(inbound)
    params: dict = {
        "encryption": "none",
    }
    params.update(_transport_link_params(inbound, tcfg))
    if inbound.tls_enabled:
        params["security"] = "tls"
        params["sni"] = inbound.domain or Setting.get("panel_domain", "")
    elif tcfg.get("reality_public_key"):
        params["security"] = "reality"
        params["pbk"] = tcfg.get("reality_public_key", "")
        params["sni"] = (tcfg.get("reality_server_names") or [""])[0]
        params["sid"] = (tcfg.get("reality_short_ids") or [""])[0]
        params["fp"] = tcfg.get("fingerprint", "chrome")
    if client.flow:
        params["flow"] = client.flow

    qs = urllib.parse.urlencode(params)
    return f"vless://{client.uuid}@{server}:{_port(inbound)}?{qs}#{urllib.parse.quote(client.name)}"


def _trojan_link(client: Client, inbound: Inbound) -> str:
    tcfg = inbound.get_transport_config()
    server = _server(inbound)
    password = client.password or client.uuid
    params: dict = {"security": "tls"}
    params.update(_transport_link_params(inbound, tcfg))
    sni = inbound.domain or Setting.get("panel_domain", "")
    if sni:
        params["sni"] = sni
    qs = urllib.parse.urlencode(params)
    return f"trojan://{urllib.parse.quote(password)}@{server}:{_port(inbound)}?{qs}#{urllib.parse.quote(client.name)}"


def _shadowsocks_link(client: Client, inbound: Inbound) -> str:
    extra = inbound.get_extra_config()
    method = extra.get("method", "aes-256-gcm")
    password = client.password or ""
    server = _server(inbound)
    # SIP002: userinfo MUST be URL-safe base64 без padding
    userinfo = base64.urlsafe_b64encode(
        f"{method}:{password}".encode()
    ).decode().rstrip("=")
    return f"ss://{userinfo}@{server}:{_port(inbound)}#{urllib.parse.quote(client.name)}"


def _naive_link(client: Client, inbound: Inbound) -> str:
    username = client.username or client.name
    password = client.password or ""
    domain = _server(inbound)
    return f"naive+https://{urllib.parse.quote(username)}:{urllib.parse.quote(password)}@{domain}:443#{urllib.parse.quote(client.name)}"


def _socks_link(client: Client, inbound: Inbound) -> str:
    server = _server(inbound)
    username = client.username or client.name
    password = client.password or ""
    userinfo = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"socks5://{userinfo}@{server}:{_port(inbound)}#{urllib.parse.quote(client.name)}"


LINK_GENERATORS = {
    "vmess": _vmess_link,
    "vless": _vless_link,
    "trojan": _trojan_link,
    "shadowsocks": _shadowsocks_link,
    "naive": _naive_link,
    "socks": _socks_link,
}


def generate_link(client: Client, inbound: Inbound) -> str | None:
    gen = LINK_GENERATORS.get(inbound.protocol)
    if gen:
        try:
            return gen(client, inbound)
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------

@bp.get("/inbound/<int:ib_id>")
@login_required
def list_clients(ib_id):
    inbound = Inbound.query.get_or_404(ib_id)
    result = []
    for c in inbound.clients:
        d = c.to_dict()
        d["link"] = generate_link(c, inbound)
        result.append(d)
    return jsonify(result)


@bp.post("/inbound/<int:ib_id>")
@login_required
def create_client(ib_id):
    inbound = Inbound.query.get_or_404(ib_id)
    data = request.get_json(force=True)

    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Поле name обязательно"}), 400

    # UUID: пользовательский — только проверка формата; если не прислал —
    # генератор в Client(uuid=...) ниже подставит свежий uuid4().
    if data.get("uuid"):
        ok, err = validate_uuid(data["uuid"])
        if not ok:
            return jsonify({"error": err}), 400

    # Email используется как stats-ключ Xray. Жёсткий формат не нужен
    # (xray примет любой непустой текст), но запрещены символы,
    # ломающие сам формат stats-query (`user>>>email>>>traffic`).
    email = (data.get("email") or f"{name}@panel").strip()
    if data.get("email"):
        ok, err = validate_email(data["email"], strict=False)
        if not ok:
            return jsonify({"error": err}), 400

    # Защита от дубликатов email и username в рамках одного инбаунда.
    # Xray не допускает двух клиентов с одинаковым email — xray run -test
    # упадёт с "User already exists". Ловим это здесь до commit.
    existing_email = Client.query.filter_by(inbound_id=ib_id, email=email).first()
    if existing_email:
        return jsonify({"error": f"Клиент с email \'{email}\' уже существует в этом inbound'е"}), 409

    username = (data.get("username") or name).strip()
    existing_username = Client.query.filter_by(inbound_id=ib_id, username=username).first()
    if existing_username:
        return jsonify({"error": f"Клиент с username \'{username}\' уже существует в этом inbound'е"}), 409

    expire_at = None
    try:
        if data.get("expire_days"):
            expire_at = datetime.now(timezone.utc) + timedelta(days=int(data["expire_days"]))
        elif data.get("expire_at"):
            expire_at = datetime.fromisoformat(data["expire_at"])
    except (ValueError, TypeError):
        return jsonify({"error": "Неверный формат expire_days/expire_at"}), 400

    client = Client(
        inbound_id=ib_id,
        name=name,
        uuid=data.get("uuid") or str(uuid_mod.uuid4()),
        password=data.get("password"),
        username=username,
        email=email,
        flow=data.get("flow"),
        expire_at=expire_at,
        traffic_limit_up=_parse_bytes(data.get("traffic_limit_up", 0)),
        traffic_limit_down=_parse_bytes(data.get("traffic_limit_down", 0)),
        # share_token: если передан явно (например, чтобы привязать клиента к
        # существующей "группе подписки" этого же человека) — используем его.
        # Иначе оставляем default из модели (UUID), который сгенерится в БД.
        share_token=data.get("share_token") or str(uuid_mod.uuid4()),
        enabled=data.get("enabled", True),
    )
    db.session.add(client)
    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(inbound.engine)
    log_action("client.create", target_type="client",
               target_id=client.id, target_name=client.name,
               details={"inbound_tag": inbound.tag})
    d = client.to_dict()
    d["link"] = generate_link(client, inbound)
    d["apply_id"] = apply_id
    return jsonify(d), 201


@bp.get("/<int:client_id>")
@login_required
def get_client(client_id):
    c = Client.query.get_or_404(client_id)
    d = c.to_dict()
    d["link"] = generate_link(c, c.inbound)
    return jsonify(d)


@bp.put("/<int:client_id>")
@login_required
def update_client(client_id):
    c = Client.query.get_or_404(client_id)
    data = request.get_json(force=True)

    # Email валидируем ТОЛЬКО если юзер реально его прислал в этом
    # запросе. На клиентах, созданных до появления этого валидатора,
    # email мог попасть с нестандартным форматом — не хотим блокировать
    # PUT, который email не трогает (смена name / enabled / лимитов).
    if "email" in data and data["email"]:
        ok, err = validate_email(data["email"], strict=False)
        if not ok:
            return jsonify({"error": err}), 400

    for field in ["name", "username", "email", "flow", "enabled"]:
        if field in data:
            setattr(c, field, data[field])
    # Only update password if non-empty string provided
    if data.get("password"):
        c.password = data["password"]

    try:
        if data.get("expire_days"):          # None, 0, "" all skip
            c.expire_at = datetime.now(timezone.utc) + timedelta(days=int(data["expire_days"]))
        elif "expire_at" in data:
            c.expire_at = datetime.fromisoformat(data["expire_at"]) if data["expire_at"] else None
    except (ValueError, TypeError):
        return jsonify({"error": "Неверный формат expire_days/expire_at"}), 400

    if "traffic_limit_up" in data:
        c.traffic_limit_up = _parse_bytes(data["traffic_limit_up"])
    if "traffic_limit_down" in data:
        c.traffic_limit_down = _parse_bytes(data["traffic_limit_down"])

    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(c.inbound.engine)
    log_action("client.update", target_type="client",
               target_id=c.id, target_name=c.name,
               details={"fields": list(data.keys())})
    d = c.to_dict()
    d["link"] = generate_link(c, c.inbound)
    d["apply_id"] = apply_id
    return jsonify(d)


@bp.delete("/<int:client_id>")
@login_required
def delete_client(client_id):
    c = Client.query.get_or_404(client_id)
    inbound = c.inbound
    snapshot = {"id": c.id, "name": c.name, "inbound_tag": inbound.tag}
    db.session.delete(c)
    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(inbound.engine)
    log_action("client.delete", target_type="client",
               target_id=snapshot["id"], target_name=snapshot["name"],
               details={"inbound_tag": snapshot["inbound_tag"]})
    return jsonify({"ok": True, "apply_id": apply_id})


@bp.post("/<int:client_id>/reset-traffic")
@login_required
def reset_traffic(client_id):
    c = Client.query.get_or_404(client_id)
    # Запомним сколько было сброшено — это часто бывает важно в аудите
    prev = {"up": c.traffic_used_up, "down": c.traffic_used_down}
    c.reset_traffic()
    db.session.commit()
    log_action("client.reset_traffic", target_type="client",
               target_id=c.id, target_name=c.name,
               details={"reset_up": prev["up"], "reset_down": prev["down"]})
    return jsonify({"ok": True, "client": c.to_dict()})


@bp.post("/<int:client_id>/toggle")
@login_required
def toggle_client(client_id):
    c = Client.query.get_or_404(client_id)
    c.enabled = not c.enabled
    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(c.inbound.engine)
    log_action("client.toggle", target_type="client",
               target_id=c.id, target_name=c.name,
               details={"enabled": c.enabled})
    return jsonify({"enabled": c.enabled, "apply_id": apply_id})


@bp.post("/<int:client_id>/rotate-token")
@login_required
def rotate_token(client_id):
    """Сгенерировать новый share_token. Старый URL подписки сразу инвалидируется.
    Используется, когда клиент потерял ссылку или нужно отозвать доступ.
    """
    c = Client.query.get_or_404(client_id)
    c.share_token = str(uuid_mod.uuid4())
    db.session.commit()
    log_action("client.rotate_token", target_type="client",
               target_id=c.id, target_name=c.name)
    return jsonify({"share_token": c.share_token})


# ---------------------------------------------------------------------------
# Top clients (для дашборда)
# ---------------------------------------------------------------------------

@bp.get("/top")
@login_required
def top_clients():
    """Возвращает топ N клиентов по суммарному трафику (up + down).

    Только клиентов с traffic > 0, чтобы не засорять список нулями.
    Сортировка по total desc.
    """
    try:
        limit = max(1, min(int(request.args.get("limit", 5)), 50))
    except (ValueError, TypeError):
        limit = 5

    # Берём с запасом и фильтруем нули в Python — порядок в БД сохраняется.
    # Альтернатива через ORDER BY (up+down) DESC даёт корректный результат
    # и работает на любых драйверах SQLAlchemy без diff'ов синтаксиса.
    candidates = (
        Client.query
        .order_by((Client.traffic_used_up + Client.traffic_used_down).desc())
        .limit(limit * 2)
        .all()
    )

    result = []
    for c in candidates:
        total = (c.traffic_used_up or 0) + (c.traffic_used_down or 0)
        if total <= 0:
            continue
        result.append({
            "id": c.id,
            "name": c.name,
            "inbound_id": c.inbound_id,
            "inbound_tag": c.inbound.tag,
            "up":    c.traffic_used_up or 0,
            "down":  c.traffic_used_down or 0,
            "total": total,
        })
        if len(result) >= limit:
            break

    return jsonify(result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_engine(inbound: Inbound):
    from app.core.xray import apply_xray_config
    from app.core.caddy import apply_caddy_config
    if inbound.engine == "xray":
        ok, msg = apply_xray_config()
        return ok, msg
    else:
        apply_caddy_config()
        return True, None


def _parse_bytes(value) -> int:
    """Accept bytes as int, float GB, or string with GB suffix. 0 = unlimited."""
    if not value:
        return 0
    if isinstance(value, str):
        v = value.strip()
        if not v or v == "0":
            return 0
        if v.upper().endswith("GB"):
            return int(float(v[:-2]) * 1024 ** 3)
        try:
            return int(float(v))
        except ValueError:
            return 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
