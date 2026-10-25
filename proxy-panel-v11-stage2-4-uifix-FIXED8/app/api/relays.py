"""REST API: промежуточные серверы («У меня блокировки»). Логика и формат —
app/core/relays.py.

Два набора эндпоинтов:
  • /api/relays — управление из панели (только после входа);
  • /relay-agent/<token>/… — для агента на промежуточном сервере: скрипт
    установки и настройки пересылки. Защищены секретным токеном в адресе
    (как подписка), без входа: агенту нечем логиниться.
"""
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, jsonify, request
from flask_login import login_required

from app import limiter
from app.core import relays as relays_core
from app.core.audit import log_action
from app.models import Relay, Setting, db

bp = Blueprint("relays", __name__)
agent_bp = Blueprint("relay_agent", __name__)

_NAME_MAX = 128


def _panel_url() -> str:
    domain = (Setting.get("panel_domain", "") or "").strip()
    if domain:
        return f"https://{domain}"
    return request.host_url.rstrip("/")


def _view(r: Relay) -> dict:
    d = r.to_dict()
    # Без домена с HTTPS скрипт установки не отдаётся (install.sh → 400) —
    # команду тогда не показываем, чтобы её не запускали впустую.
    has_https = bool((Setting.get("panel_domain", "") or "").strip())
    d["install_command"] = (
        relays_core.install_command(_panel_url(), r.token) if has_https else None)
    return d


@bp.get("/")
@login_required
def overview():
    return jsonify({
        "relays": [_view(r) for r in Relay.query.order_by(Relay.id).all()],
        "target": relays_core.target_ip(),
        "ports": relays_core.forward_ports(),
        "panel_https": bool((Setting.get("panel_domain", "") or "").strip()),
        "agent_version": relays_core.AGENT_VERSION,
        "variants": relays_core.variants_enabled(),
    })


@bp.put("/settings")
@login_required
def update_relay_settings():
    data = request.get_json(force=True) or {}
    if "variants" in data:
        Setting.set(relays_core.VARIANTS_SETTING, "1" if data.get("variants") else "0")
        db.session.commit()
        log_action("relay.settings", target_type="relay", target_id=0,
                   target_name=f"variants={'on' if data.get('variants') else 'off'}")
    return jsonify({"variants": relays_core.variants_enabled()})


def _clean_host(value) -> tuple[str | None, str | None]:
    host = (value if isinstance(value, str) else "").strip()
    if not host:
        return None, None
    if not relays_core.is_valid_host(host):
        return None, "Адрес — публичный IPv4, например 203.0.113.5"
    return host, None


@bp.post("/")
@login_required
def create_relay():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()[:_NAME_MAX] or "Промежуточный сервер"
    host, err = _clean_host(data.get("host"))
    if err:
        return jsonify({"error": err}), 400
    r = Relay(name=name, host=host, token=relays_core.new_token(), enabled=True)
    db.session.add(r)
    db.session.commit()
    log_action("relay.create", target_type="relay", target_id=r.id, target_name=r.name)
    return jsonify(_view(r)), 201


@bp.put("/<int:relay_id>")
@login_required
def update_relay(relay_id: int):
    r = db.session.get(Relay, relay_id) or abort(404)
    data = request.get_json(force=True) or {}
    if "name" in data:
        r.name = (data.get("name") or "").strip()[:_NAME_MAX] or r.name
    if "host" in data:
        host, err = _clean_host(data.get("host"))
        if err:
            return jsonify({"error": err}), 400
        r.host = host
    if "enabled" in data:
        r.enabled = bool(data.get("enabled"))
    db.session.commit()
    log_action("relay.update", target_type="relay", target_id=r.id, target_name=r.name)
    return jsonify(_view(r))


@bp.post("/<int:relay_id>/reset-traffic")
@login_required
def reset_relay_traffic(relay_id: int):
    r = db.session.get(Relay, relay_id) or abort(404)
    relays_core.reset_traffic(r, datetime.now(timezone.utc))
    db.session.commit()
    log_action("relay.reset_traffic", target_type="relay", target_id=r.id, target_name=r.name)
    return jsonify(_view(r))


@bp.delete("/<int:relay_id>")
@login_required
def delete_relay(relay_id: int):
    r = db.session.get(Relay, relay_id) or abort(404)
    name = r.name
    db.session.delete(r)
    db.session.commit()
    log_action("relay.delete", target_type="relay", target_id=relay_id, target_name=name)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Агент на промежуточном сервере
# ---------------------------------------------------------------------------

def _relay_by_token(token: str) -> Relay:
    """410 Gone — такого промежуточного сервера в панели нет (удалён): агент
    по этому коду снимает пересылку. Любой другой сбой агент считает
    временным и правила не трогает."""
    if not token or not (16 <= len(token) <= 64):
        abort(410)
    r = Relay.query.filter_by(token=token).first()
    if r is None:
        abort(410)
    return r


@agent_bp.get("/<token>/install.sh")
@limiter.limit("20 per hour")
def agent_install(token: str):
    r = _relay_by_token(token)
    try:
        script = relays_core.install_script(_panel_url(), r.token)
    except ValueError:
        abort(400)
    return Response(script, mimetype="text/x-shellscript",
                    headers={"Cache-Control": "no-store"})


@agent_bp.get("/<token>/config")
@limiter.limit("120 per hour")
def agent_config(token: str):
    r = _relay_by_token(token)
    # Отметка «на связи» и адрес, с которого пришёл агент (его и получит
    # приложение, если адрес не задан вручную).
    r.last_seen = datetime.now(timezone.utc)
    ip = (request.remote_addr or "").strip()
    if relays_core.is_valid_host(ip):
        r.detected_ip = ip
    version = (request.args.get("v") or "").strip()[:32]
    if version:
        r.agent_version = version
    # Счётчик трафика (агент версии 2+; старый агент его не шлёт).
    if "ep" in request.args:
        relays_core.add_traffic_report(
            r, request.args.get("ep"), request.args.get("up"),
            request.args.get("down"), r.last_seen)
    db.session.commit()
    # Адрес этого сервера не определился надёжно — 503: агент оставит
    # прежнюю пересылку как есть (а не «выключит» её или не перешлёт в 10.x).
    if r.enabled and not relays_core.target_ip():
        return Response("target unknown\n", status=503, mimetype="text/plain",
                        headers={"Cache-Control": "no-store"})
    return Response(relays_core.config_text(r), mimetype="text/plain",
                    headers={"Cache-Control": "no-store"})
