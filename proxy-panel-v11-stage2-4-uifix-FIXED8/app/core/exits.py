"""
Выход в интернет через другой сервер (каскад) и группы выходов.

Зачем. Пользователь подключается к ЭТОМУ серверу, а в интернет его трафик
выходит через ДРУГОЙ. Типовой случай: этот сервер в России (к нему легко
подключиться даже при ограничениях мобильной связи), выход — за границей
(там открываются заблокированные сайты). Каждое подключение (инбаунд)
выбирает свой выход, поэтому на одном сервере могут жить и «прямые»
подключения, и подключения через каскад.

Выход добавляется ОДНОЙ строкой — ключом подключения к другому серверу
(vless://…, trojan://…, socks5://…). Ключ можно взять в панели того
сервера, как для обычного клиента.

Группа выходов — несколько выходов под одним именем. Xray каждую минуту
проверяет их сам (observatory) и ведёт трафик через самый быстрый живой
(balancer, стратегия leastPing); если все недоступны — через первый.

Метка для приложения. Подключение через каскад получает в ссылках метку
расположения ВЫХОДА (coc_region), а не этого сервера: трафик выходит в
интернет именно там. Подробнее — app/core/server_region.py.
"""
import base64
import http.client
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass

from app.models import ExternalOutbound, OutboundGroup

log = logging.getLogger(__name__)

# Протоколы выходов, которые добавляются ключом (в дополнение к старым
# SOCKS/HTTP со страницы «Маршрутизация»).
KEY_PROTOCOLS = ("vless", "trojan")

# Транспорты, которые Xray 26 умеет как клиент. HTTP/2 («h2»/«http») и
# mKCP/QUIC в ключах почти не встречаются, а h2 из Xray убран — честно
# отказываем, а не собираем заведомо нерабочий выход.
_NETWORK_ALIASES = {
    "tcp": "tcp", "raw": "tcp", "": "tcp",
    "ws": "ws",
    "grpc": "grpc",
    "httpupgrade": "httpupgrade",
    "xhttp": "xhttp", "splithttp": "xhttp",
}

_VLESS_FLOWS = ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443")

# Российские сайты при «напрямую с этого сервера»: вся зона .ru/.рф/.su
# (не зависит от базы geosite) + российские IP + категория geosite, если
# она есть в установленной базе (проверяется при сборке конфига).
RU_DIRECT_DOMAINS = ["domain:ru", "domain:xn--p1ai", "domain:su"]
RU_DIRECT_GEOSITE = "geosite:category-ru"
RU_DIRECT_IPS = ["geoip:ru"]

# Проверка живости выходов в группе: адрес, который отвечает 204 без тела.
OBSERVATORY_PROBE_URL = "https://www.google.com/generate_204"
OBSERVATORY_INTERVAL = "1m"

EXIT_TAG_PREFIX = "exit-"
GROUP_TAG_PREFIX = "grp-"


class LinkError(ValueError):
    """Ключ не подходит как выход. Текст — для человека, показывается в UI."""


# ---------------------------------------------------------------------------
# Разбор ключа
# ---------------------------------------------------------------------------

def _first(qs: dict, key: str, default: str = "") -> str:
    v = qs.get(key)
    if not v:
        return default
    return (v[0] or "").strip()


def _split_host_port(parts: urllib.parse.SplitResult) -> tuple[str, int]:
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        raise LinkError("В ключе неправильный порт")
    if not host:
        raise LinkError("В ключе нет адреса сервера")
    if not port:
        raise LinkError("В ключе нет порта сервера")
    from app.core.input_validators import validate_hostname_or_ip
    ok, err = validate_hostname_or_ip(host)
    if not ok:
        raise LinkError(f"Адрес сервера в ключе не подходит: {err}")
    return host, int(port)


def _stream_from_query(qs: dict, *, default_security: str) -> dict:
    """Параметры транспорта и шифрования из query ключа (общие для VLESS и
    Trojan). Имена полей — как в общепринятом формате ссылок Xray."""
    raw_net = _first(qs, "type", "tcp").lower()
    if raw_net not in _NETWORK_ALIASES:
        if raw_net in ("h2", "http"):
            raise LinkError(
                "В ключе транспорт HTTP/2 — его больше нет в Xray. Попросите "
                "ключ с транспортом xhttp, ws, grpc или tcp."
            )
        raise LinkError(f"Транспорт «{raw_net}» как выход не поддерживается")
    net = _NETWORK_ALIASES[raw_net]

    security = _first(qs, "security", default_security).lower() or default_security
    if security not in ("none", "tls", "reality"):
        raise LinkError(f"Шифрование «{security}» не поддерживается (нужно tls, reality или none)")

    cfg: dict = {"network": net, "security": security}

    if security == "reality":
        pbk = _first(qs, "pbk")
        if not pbk:
            raise LinkError("В Reality-ключе нет публичного ключа (pbk)")
        sni = _first(qs, "sni")
        if not sni:
            raise LinkError("В Reality-ключе нет sni")
        cfg.update({
            "pbk": pbk,
            "sni": sni,
            "sid": _first(qs, "sid"),
            "spx": _first(qs, "spx"),
            "fp": _first(qs, "fp", "chrome") or "chrome",
        })
        pqv = _first(qs, "pqv")
        if pqv:
            cfg["pqv"] = pqv
    elif security == "tls":
        cfg["sni"] = _first(qs, "sni") or _first(qs, "peer")
        fp = _first(qs, "fp")
        if fp:
            cfg["fp"] = fp
        alpn = [a.strip() for a in _first(qs, "alpn").split(",") if a.strip()]
        if alpn:
            cfg["alpn"] = alpn

    if net in ("ws", "httpupgrade", "xhttp"):
        cfg["path"] = _first(qs, "path", "/") or "/"
        host = _first(qs, "host")
        if host:
            cfg["host"] = host
    if net == "xhttp":
        mode = _first(qs, "mode")
        if mode:
            cfg["mode"] = mode
        extra = _first(qs, "extra")
        if extra:
            try:
                extra_obj = json.loads(extra)
            except ValueError:
                raise LinkError("Параметр extra в ключе — не JSON")
            if isinstance(extra_obj, dict):
                cfg["extra"] = extra_obj
    if net == "grpc":
        cfg["service_name"] = _first(qs, "serviceName")
        cfg["grpc_multi"] = _first(qs, "mode").lower() == "multi"
    return cfg


def _parse_vless(link: str) -> dict:
    parts = urllib.parse.urlsplit(link)
    user_id = urllib.parse.unquote(parts.username or "").strip()
    if not user_id:
        raise LinkError("В ключе нет идентификатора пользователя (UUID)")
    if len(user_id) > 64 or not re.fullmatch(r"[A-Za-z0-9_\-]+", user_id):
        raise LinkError("Идентификатор пользователя в ключе не похож на UUID")
    host, port = _split_host_port(parts)
    qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    cfg = _stream_from_query(qs, default_security="none")
    cfg["uuid"] = user_id
    cfg["encryption"] = _first(qs, "encryption", "none") or "none"
    flow = _first(qs, "flow")
    if flow not in _VLESS_FLOWS:
        raise LinkError(f"Режим flow «{flow}» не поддерживается")
    if flow:
        if cfg["network"] != "tcp" or cfg["security"] == "none":
            # Vision работает только поверх TCP с TLS/Reality — Xray такой
            # выход не соберёт. Лучше сразу сказать, чем ловить отказ -test.
            raise LinkError("flow=xtls-rprx-vision в ключе требует tcp и tls/reality")
        cfg["flow"] = flow
    return {
        "protocol": "vless", "address": host, "port": port,
        "password": None, "username": None, "config": cfg,
        "name": urllib.parse.unquote(parts.fragment or "").strip(),
        "region": _region_from_query(qs),
    }


def _parse_trojan(link: str) -> dict:
    parts = urllib.parse.urlsplit(link)
    password = urllib.parse.unquote(parts.username or "")
    if not password:
        raise LinkError("В Trojan-ключе нет пароля")
    host, port = _split_host_port(parts)
    qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    cfg = _stream_from_query(qs, default_security="tls")
    return {
        "protocol": "trojan", "address": host, "port": port,
        "password": password, "username": None, "config": cfg,
        "name": urllib.parse.unquote(parts.fragment or "").strip(),
        "region": _region_from_query(qs),
    }


def _parse_socks(link: str) -> dict:
    parts = urllib.parse.urlsplit(link)
    host, port = _split_host_port(parts)
    user = urllib.parse.unquote(parts.username or "")
    pwd = urllib.parse.unquote(parts.password or "") if parts.password is not None else None
    if user and pwd is None:
        # Формат «socks5://base64(user:pass)@host:port» (так ключ выдаёт и
        # наша панель, см. app/api/clients.py:_socks_link).
        try:
            padded = user + "=" * (-len(user) % 4)
            decoded = base64.b64decode(padded, validate=False).decode()
            if ":" in decoded:
                user, pwd = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            pass
    qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    return {
        "protocol": "socks", "address": host, "port": port,
        "username": user or None, "password": pwd or None, "config": {},
        "name": urllib.parse.unquote(parts.fragment or "").strip(),
        "region": _region_from_query(qs),
    }


def _region_from_query(qs: dict) -> str | None:
    """Ключ из нашей же панели несёт метку расположения — тогда её и берём."""
    from app.core import server_region
    value = _first(qs, server_region.LINK_PARAM).lower()
    return value if value in server_region.REGIONS else None


def parse_link(link: str) -> dict:
    """Ключ → описание выхода: protocol, address, port, username, password,
    config (dict), name (из #фрагмента), region (из coc_region или None).
    Бросает LinkError с понятным текстом."""
    link = (link or "").strip()
    if not link:
        raise LinkError("Вставьте ключ сервера — строку, которая начинается с vless://")
    if len(link) > 8192:
        raise LinkError("Ключ слишком длинный")
    if any(ch in link for ch in ("\n", "\r", " ")):
        raise LinkError("Вставьте один ключ — одну строку без пробелов")
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme == "vless":
        return _parse_vless(link)
    if scheme == "trojan":
        return _parse_trojan(link)
    if scheme in ("socks", "socks5"):
        return _parse_socks(link)
    if scheme.startswith("naive"):
        raise LinkError(
            "NaiveProxy не может быть выходом для Xray. Попросите у того сервера "
            "VLESS-ключ (Reality) — его панель выдаёт так же, как клиенту."
        )
    if scheme in ("vmess", "ss", "hysteria2", "hy2", "tuic", "wireguard", "ssh"):
        raise LinkError(
            f"Ключи {scheme}:// как выход не поддерживаются. Нужен VLESS-ключ "
            f"(vless://…), подойдёт и Trojan или SOCKS5."
        )
    if scheme in ("http", "https"):
        raise LinkError(
            "Это похоже на ссылку-подписку или адрес сайта. Нужен ключ одного "
            "подключения — строка vless://… (в панели того сервера: клиент → ключ)."
        )
    raise LinkError("Не похоже на ключ. Нужна строка вида vless://…")


# ---------------------------------------------------------------------------
# Сборка outbound для Xray
# ---------------------------------------------------------------------------

def _stream_settings(cfg: dict) -> dict:
    net = cfg.get("network") or "tcp"
    sec = cfg.get("security") or "none"
    stream: dict = {"network": net, "security": sec}
    if sec == "reality":
        rs = {
            "serverName": cfg.get("sni", ""),
            "fingerprint": cfg.get("fp") or "chrome",
            "publicKey": cfg.get("pbk", ""),
            "shortId": cfg.get("sid", ""),
        }
        if cfg.get("spx"):
            rs["spiderX"] = cfg["spx"]
        if cfg.get("pqv"):
            rs["mldsa65Verify"] = cfg["pqv"]
        stream["realitySettings"] = rs
    elif sec == "tls":
        ts: dict = {}
        if cfg.get("sni"):
            ts["serverName"] = cfg["sni"]
        if cfg.get("fp"):
            ts["fingerprint"] = cfg["fp"]
        if cfg.get("alpn"):
            ts["alpn"] = list(cfg["alpn"])
        stream["tlsSettings"] = ts
    if net == "ws":
        ws: dict = {"path": cfg.get("path") or "/"}
        if cfg.get("host"):
            ws["host"] = cfg["host"]
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        hu: dict = {"path": cfg.get("path") or "/"}
        if cfg.get("host"):
            hu["host"] = cfg["host"]
        stream["httpupgradeSettings"] = hu
    elif net == "xhttp":
        xh: dict = {"path": cfg.get("path") or "/"}
        if cfg.get("host"):
            xh["host"] = cfg["host"]
        if cfg.get("mode"):
            xh["mode"] = cfg["mode"]
        if isinstance(cfg.get("extra"), dict):
            xh["extra"] = cfg["extra"]
        stream["xhttpSettings"] = xh
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": cfg.get("service_name", ""),
            "multiMode": bool(cfg.get("grpc_multi")),
        }
    return stream


def build_key_outbound(ext: ExternalOutbound) -> dict | None:
    """Outbound Xray для выхода VLESS/Trojan. None — если в БД битые
    параметры (выход тогда пропускается, подключения идут напрямую)."""
    cfg = ext.get_config()
    if ext.protocol == "vless":
        if not cfg.get("uuid"):
            return None
        user = {"id": cfg["uuid"], "encryption": cfg.get("encryption") or "none"}
        if cfg.get("flow"):
            user["flow"] = cfg["flow"]
        settings = {"vnext": [{"address": ext.address, "port": ext.port, "users": [user]}]}
    elif ext.protocol == "trojan":
        if not ext.password:
            return None
        settings = {"servers": [{"address": ext.address, "port": ext.port,
                                 "password": ext.password}]}
    else:
        return None
    return {
        "tag": ext.tag,
        "protocol": ext.protocol,
        "settings": settings,
        "streamSettings": _stream_settings(cfg),
    }


# ---------------------------------------------------------------------------
# Какой выход у подключения
# ---------------------------------------------------------------------------

def normalize_region(value) -> str:
    from app.core import server_region
    v = (value or "").strip().lower()
    return v if v in server_region.REGIONS else server_region.DEFAULT


@dataclass
class ResolvedExit:
    kind: str          # "outbound" | "balancer"
    tag: str
    region: str        # intl | ru
    members: list      # для группы — рабочие теги по порядку


def _usable_outbound(ext: ExternalOutbound | None) -> bool:
    if ext is None or not ext.enabled:
        return False
    if ext.protocol in KEY_PROTOCOLS:
        return build_key_outbound(ext) is not None
    return ext.protocol in ("socks", "http")


def resolve_exit(tag: str | None) -> ResolvedExit | None:
    """Во что на самом деле превратится выход подключения в конфиге Xray.
    None — выхода нет, он выключен или сломан: подключение идёт напрямую.
    Этим же ответом пользуются генератор конфига и метка в ссылках, поэтому
    они не могут разойтись."""
    if not tag:
        return None
    ext = ExternalOutbound.query.filter_by(tag=tag).first()
    if ext is not None:
        if not _usable_outbound(ext):
            return None
        return ResolvedExit("outbound", ext.tag, normalize_region(ext.region), [ext.tag])
    grp = OutboundGroup.query.filter_by(tag=tag).first()
    if grp is None or not grp.enabled:
        return None
    members = []
    first_region = None
    for mtag in grp.get_members():
        m = ExternalOutbound.query.filter_by(tag=mtag).first()
        if _usable_outbound(m):
            members.append(m.tag)
            if first_region is None:
                first_region = normalize_region(m.region)
    if not members:
        return None
    return ResolvedExit("balancer", grp.tag, first_region, members)


def exit_usages(tag: str) -> list[str]:
    """Кто пользуется выходом/группой: теги подключений и имена групп."""
    from app.models import Inbound
    used = [f"подключение {ib.tag}" for ib in Inbound.query.filter_by(exit_tag=tag).all()]
    for grp in OutboundGroup.query.all():
        if tag in grp.get_members():
            used.append(f"группа «{grp.name}»")
    return used


def new_tag(prefix: str) -> str:
    """Тег фиксированной длины: у двух таких тегов один не может быть
    началом другого — это важно для селектора балансировщика Xray, который
    сравнивает теги ПО ПРЕФИКСУ (селектор «out-1» захватил бы и «out-10»)."""
    from app.models import db
    for _ in range(20):
        tag = prefix + secrets.token_hex(4)
        if (db.session.query(ExternalOutbound.id).filter_by(tag=tag).first() is None
                and db.session.query(OutboundGroup.id).filter_by(tag=tag).first() is None):
            return tag
    raise RuntimeError("Не удалось подобрать свободный тег")


def prefix_conflicts(members: list[str], all_tags: list[str]) -> list[str]:
    """Теги, которые селектор балансировщика захватит по ошибке: чужой тег,
    начинающийся с тега участника группы."""
    member_set = set(members)
    bad = []
    for m in members:
        for t in all_tags:
            if t != m and t not in member_set and t.startswith(m):
                bad.append(f"{m} → {t}")
    return bad


# ---------------------------------------------------------------------------
# Куски конфига Xray
# ---------------------------------------------------------------------------

def build_balancers(groups: list[OutboundGroup], outbound_tags: list[str]) -> tuple[list, list]:
    """(routing.balancers, теги для observatory). Группа без рабочих
    участников не попадает в конфиг — её подключения идут напрямую
    (resolve_exit вернёт None по тем же правилам)."""
    balancers = []
    observed: list[str] = []
    present = set(outbound_tags)
    for grp in groups:
        resolved = resolve_exit(grp.tag)
        if resolved is None:
            continue
        members = [m for m in resolved.members if m in present]
        if not members:
            continue
        bad = prefix_conflicts(members, outbound_tags)
        if bad:
            log.warning("Группа %s: селектор захватит лишние выходы: %s", grp.tag, bad)
        balancers.append({
            "tag": grp.tag,
            "selector": members,
            "strategy": {"type": "leastPing"},
            "fallbackTag": members[0],
        })
        for m in members:
            if m not in observed:
                observed.append(m)
    return balancers, observed


def build_observatory(observed: list[str]) -> dict | None:
    if not observed:
        return None
    return {
        "subjectSelector": list(observed),
        "probeUrl": OBSERVATORY_PROBE_URL,
        "probeInterval": OBSERVATORY_INTERVAL,
        "enableConcurrency": True,
    }


def build_inbound_exit_rules(inbounds: list, balancer_tags: set) -> list[dict]:
    """Правила «весь трафик подключения — в его выход». Ставятся ПОСЛЕ
    ручных правил маршрутизации: явные правила владельца (блок рекламы,
    конкретный домен напрямую) важнее."""
    from app.core.geo_validator import validate_codes
    rules: list[dict] = []
    ru_domains = list(RU_DIRECT_DOMAINS)
    for ib in inbounds:
        if not getattr(ib, "exit_tag", None):
            continue
        resolved = resolve_exit(ib.exit_tag)
        if resolved is None:
            log.warning("Подключение %s: выход %s недоступен — трафик идёт напрямую",
                        ib.tag, ib.exit_tag)
            continue
        if resolved.kind == "balancer" and resolved.tag not in balancer_tags:
            continue
        if ib.exit_ru_direct:
            if RU_DIRECT_GEOSITE not in ru_domains and not validate_codes([RU_DIRECT_GEOSITE], []):
                ru_domains.append(RU_DIRECT_GEOSITE)
            rules.append({"type": "field", "inboundTag": [ib.tag],
                          "domain": ru_domains, "outboundTag": "direct"})
            rules.append({"type": "field", "inboundTag": [ib.tag],
                          "ip": list(RU_DIRECT_IPS), "outboundTag": "direct"})
        rule: dict = {"type": "field", "inboundTag": [ib.tag]}
        if resolved.kind == "balancer":
            rule["balancerTag"] = resolved.tag
        else:
            rule["outboundTag"] = resolved.tag
        rules.append(rule)
    return rules


# ---------------------------------------------------------------------------
# Проверка выхода: временный Xray + запрос через него
# ---------------------------------------------------------------------------

PROBE_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, deadline: float) -> bool:
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def probe_outbound(outbound: dict, timeout: float = 12.0) -> dict:
    """Проверяет выход по-настоящему: поднимает отдельный Xray с одним
    HTTP-входом на 127.0.0.1 и этим выходом и делает через него HTTPS-запрос.
    Рабочий Xray не трогается.

    Возвращает {"ok", "ms", "ip", "country", "error"}. ms — сколько занял
    запрос целиком (подключение к выходу + TLS до сайта), это и есть
    ощущаемая задержка.
    """
    from app.core.xray import XRAY_BINARY
    port = _free_loopback_port()
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "probe-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "http", "settings": {}}],
        "outbounds": [dict(outbound, tag="probe-out")],
    }
    # В конфиге секрет выхода (UUID/пароль): файл 0600 и удаляется сразу.
    fd, path = tempfile.mkstemp(prefix="coc-probe-", suffix=".json")
    proc = None
    result = {"ok": False, "ms": None, "ip": None, "country": None, "error": None}
    started = time.monotonic()
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)
        try:
            proc = subprocess.Popen(
                [XRAY_BINARY, "run", "-c", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            result["error"] = "Xray не установлен на сервере"
            return result
        if not _wait_port(port, started + 4.0):
            err = ""
            if proc.poll() is not None and proc.stderr:
                err = (proc.stderr.read() or b"").decode(errors="replace").strip()[-300:]
            result["error"] = "Xray не принял выход" + (f": {err}" if err else "")
            return result
        # Туннель через временный вход — явно (CONNECT), а не через
        # urllib.ProxyHandler: тот молча идёт в обход прокси для адресов из
        # no_proxy, и проверка «работала» бы даже с мёртвым выходом.
        target = urllib.parse.urlsplit(PROBE_URL)
        https = target.scheme == "https"
        left = max(3.0, timeout - (time.monotonic() - started))
        conn_cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
        conn = conn_cls("127.0.0.1", port, timeout=left)
        t0 = time.monotonic()
        try:
            conn.set_tunnel(target.hostname, target.port or (443 if https else 80))
            conn.request("GET", target.path or "/", headers={"User-Agent": "Mozilla/5.0"})
            resp = conn.getresponse()
            body = resp.read(4096).decode(errors="replace")
        except (OSError, http.client.HTTPException) as e:
            result["error"] = f"Через выход сайты не открываются ({e})"
            return result
        finally:
            conn.close()
        result["ms"] = int((time.monotonic() - t0) * 1000)
        for line in body.splitlines():
            k, _, v = line.partition("=")
            if k == "ip":
                result["ip"] = v.strip()
            elif k == "loc":
                result["country"] = v.strip().upper()
        result["ok"] = True
        return result
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            if proc.stderr:
                proc.stderr.close()
        try:
            os.unlink(path)
        except OSError:
            pass
