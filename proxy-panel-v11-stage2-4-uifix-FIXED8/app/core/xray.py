"""
Xray-core configuration generator.

Builds a complete config.json for xray-core from the database state.
Supports: VMess, VLESS, Trojan, Shadowsocks, SOCKS5, HTTP, Dokodemo-door.
Handles: TLS, transports (TCP/WS/gRPC/KCP/H2), routing, cascade, stats.
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

from app.models import (
    Inbound, Client, RoutingRule, ExternalOutbound, SplitTunnelList,
    Setting,
    ROUTING_ACTION_DIRECT, ROUTING_ACTION_BLOCK,
    ROUTING_ACTION_INBOUND, ROUTING_ACTION_OUTBOUND,
)

XRAY_BINARY = "/usr/local/bin/xray"
XRAY_CONFIG_PATH = "/etc/xray/config.json"


# ---------------------------------------------------------------------------
# Shared-443 (Reality + Caddy на одном порту) — helpers
# ---------------------------------------------------------------------------
#
# Reality на :443 принимает TCP, и для соединений с НЕ-Reality SNI
# (или без правильного auth) — TCP-проксирует на realitySettings.dest.
# В shared-443 режиме dest = наш локальный Caddy, который тогда
# слушает не на публичном :443, а на 127.0.0.1:8443. Caddy в этом
# режиме обрабатывает:
#   • TLS handshake для NaiveProxy-домена (своим LE-cert),
#   • TLS handshake для panel-домена (тоже своим cert),
#   • HTTP-01 ACME challenge на :80 (порт остаётся публичным).
#
# Reality-клиент (Karing/v2rayN с public_key) подключается с SNI =
# одного из serverNames. В shared-режиме serverNames = наши домены —
# Reality «стащит» настоящий LE-сертификат у Caddy и предъявит его
# клиенту, делая поток внешне неотличимым от обычного HTTPS-сайта.
#
# Если Reality-инбаунда на 443 нет — это НЕ shared-режим, Caddy
# слушает :443 как обычно, Reality (если есть на другом порту, типа
# 8443) работает с классическим dest (microsoft.com и т.п.).

SHARED_CADDY_LOOPBACK_ADDR = "127.0.0.1:8443"


def _is_reality_inbound(inbound: "Inbound") -> bool:
    """True если инбаунд использует Reality (есть reality_public_key)."""
    if inbound.protocol != "vless":
        return False
    tcfg = inbound.get_transport_config()
    return bool(tcfg.get("reality_public_key"))


def _is_reality_shared_443(inbound: "Inbound") -> bool:
    """True если этот Reality-инбаунд работает в shared-443 режиме."""
    return _is_reality_inbound(inbound) and inbound.port == 443


def find_reality_443_inbound() -> "Inbound | None":
    """
    Возвращает enabled Reality-инбаунд на порту 443, если он есть в БД.
    Используется и xray.py, и caddy.py для согласования listen-портов.
    """
    candidates = Inbound.query.filter_by(engine="xray", port=443, enabled=True).all()
    for ib in candidates:
        if _is_reality_inbound(ib):
            return ib
    return None


def _shared_443_server_names() -> list[str]:
    """
    Список доменов для realitySettings.serverNames в shared-режиме.
    Это домены, для которых Caddy уже имеет LE-сертификат: naive-инбаунды
    и panel_domain. Reality-клиент должен использовать SNI = один из них.

    Возвращает пустой список, если ни naive-домена, ни panel_domain ещё нет —
    тогда Reality стартанёт без serverNames, и любой клиент получит
    fallback на Caddy.
    """
    names: list[str] = []
    seen: set[str] = set()
    naive_ibs = Inbound.query.filter_by(engine="naive", enabled=True).all()
    for ib in naive_ibs:
        if ib.domain and ib.domain not in seen:
            seen.add(ib.domain)
            names.append(ib.domain)
    panel_domain = (Setting.get("panel_domain", "") or "").strip()
    if panel_domain and panel_domain not in seen:
        seen.add(panel_domain)
        names.append(panel_domain)
    return names


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_tls_settings(inbound: Inbound) -> dict | None:
    if not inbound.tls_enabled:
        return None
    # ВАЖНО: ветка с inbound.tls_acme была удалена.
    # Она строила путь /etc/ssl/caddy/{domain}/cert.pem, который не существует —
    # Caddy сохраняет сертификаты в /var/lib/caddy/.local/share/caddy/certificates/,
    # и export-механизма пока нет. На уровне API/UI tls_acme больше не доступен
    # для Xray-инбаундов; здесь дополнительная защита на случай старых записей.
    if inbound.tls_acme:
        log.warning(
            "Inbound %s имеет tls_acme=true, но ACME для Xray не реализован — "
            "используем manual cert_path/key_path. Установите пути вручную.",
            inbound.tag,
        )
    return {
        "certificates": [{
            "certificateFile": inbound.tls_cert_path,
            "keyFile": inbound.tls_key_path,
        }]
    }


def _build_stream_settings(inbound: Inbound) -> dict:
    transport = inbound.transport or "tcp"
    tcfg = inbound.get_transport_config()
    # Xray называет транспорт HTTP/2 "http"; в UI/БД он хранится как "h2".
    # Маппим только имя сети — ветки настроек ниже по-прежнему сверяются с "h2".
    network = "http" if transport == "h2" else transport
    stream: dict[str, Any] = {"network": network}

    if transport == "ws":
        stream["wsSettings"] = {
            "path": tcfg.get("path", "/"),
            "headers": {"Host": tcfg.get("host", "")},
        }
    elif transport == "grpc":
        stream["grpcSettings"] = {
            "serviceName": tcfg.get("service_name", ""),
            "multiMode": tcfg.get("multi_mode", False),
        }
    elif transport == "kcp":
        stream["kcpSettings"] = {
            "mtu": tcfg.get("mtu", 1350),
            "tti": tcfg.get("tti", 50),
            "uplinkCapacity": tcfg.get("uplink_capacity", 5),
            "downlinkCapacity": tcfg.get("downlink_capacity", 20),
            "congestion": tcfg.get("congestion", False),
            "readBufferSize": tcfg.get("read_buffer", 2),
            "writeBufferSize": tcfg.get("write_buffer", 2),
            "header": {"type": tcfg.get("header_type", "none")},
            "seed": tcfg.get("seed", ""),
        }
    elif transport == "h2":
        stream["httpSettings"] = {
            "host": tcfg.get("hosts", []),
            "path": tcfg.get("path", "/"),
        }
    elif transport == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": tcfg.get("path", "/"),
            "host": tcfg.get("host", ""),
        }
    elif transport == "splithttp":
        stream["splithttpSettings"] = {
            "path": tcfg.get("path", "/"),
            "host": tcfg.get("host", ""),
        }

    tls = _build_tls_settings(inbound)
    if tls:
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif tcfg.get("reality_public_key"):
        stream["security"] = "reality"
        # В shared-443 режиме (Reality на :443) принудительно подменяем
        # dest и serverNames на наш локальный Caddy и его обслуживаемые
        # домены. Пользовательские reality_dest / reality_server_names из
        # transport_config игнорируются — UI скрывает эти поля для shared.
        # См. развёрнутый комментарий вверху модуля и docstring
        # _is_reality_shared_443.
        if _is_reality_shared_443(inbound):
            dest = SHARED_CADDY_LOOPBACK_ADDR
            server_names = _shared_443_server_names()
            log.info(
                "Reality inbound %s в shared-443 режиме: dest=%s, "
                "serverNames=%s (panel/naive domains)",
                inbound.tag, dest, server_names,
            )
        else:
            dest = tcfg.get("reality_dest", "")
            server_names = tcfg.get("reality_server_names", [])
        stream["realitySettings"] = {
            "show": False,
            "dest": dest,
            # xver=1 в shared-443 режиме: Xray добавляет PROXY protocol v1 header
            # при проксировании TCP на Caddy (127.0.0.1:8443). Caddy читает его
            # через listener_wrapper proxy_protocol и видит реальный IP клиента
            # вместо 127.0.0.1. В не-shared режиме xver=0 — там нет Caddy-прослойки.
            "xver": 1 if _is_reality_shared_443(inbound) else 0,
            "serverNames": server_names,
            "privateKey": tcfg.get("reality_private_key", ""),
            "shortIds": tcfg.get("reality_short_ids", [""]),
        }

    return stream


# ---------------------------------------------------------------------------
# Inbound builders
# ---------------------------------------------------------------------------

def _build_vmess_inbound(inbound: Inbound) -> dict:
    active_clients = [c for c in inbound.clients if c.is_active]
    return {
        "tag": inbound.tag,
        "port": inbound.port,
        "protocol": "vmess",
        "settings": {
            "clients": [
                {
                    "id": c.uuid,
                    "alterId": 0,
                    "email": c.email or c.name,
                    "level": 0,
                }
                for c in active_clients
            ]
        },
        "streamSettings": _build_stream_settings(inbound),
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }


def _build_vless_inbound(inbound: Inbound) -> dict:
    active_clients = [c for c in inbound.clients if c.is_active]
    extra = inbound.get_extra_config()
    clients = []
    for c in active_clients:
        entry: dict[str, Any] = {
            "id": c.uuid,
            "email": c.email or c.name,
            "level": 0,
        }
        if c.flow:
            entry["flow"] = c.flow
        clients.append(entry)

    return {
        "tag": inbound.tag,
        "port": inbound.port,
        "protocol": "vless",
        "settings": {
            "clients": clients,
            "decryption": "none",
            "fallbacks": extra.get("fallbacks", []),
        },
        "streamSettings": _build_stream_settings(inbound),
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }


def _build_trojan_inbound(inbound: Inbound) -> dict:
    active_clients = [c for c in inbound.clients if c.is_active]
    extra = inbound.get_extra_config()
    return {
        "tag": inbound.tag,
        "port": inbound.port,
        "protocol": "trojan",
        "settings": {
            "clients": [
                {
                    "password": c.password or c.uuid,
                    "email": c.email or c.name,
                    "level": 0,
                }
                for c in active_clients
            ],
            "fallbacks": extra.get("fallbacks", []),
        },
        "streamSettings": _build_stream_settings(inbound),
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def _build_shadowsocks_inbound(inbound: Inbound) -> dict:
    extra = inbound.get_extra_config()
    method = extra.get("method", "aes-256-gcm")
    active_clients = [c for c in inbound.clients if c.is_active]

    # Shadowsocks 2022 uses a master password + per-user passwords
    if "2022" in method:
        return {
            "tag": inbound.tag,
            "port": inbound.port,
            "protocol": "shadowsocks",
            "settings": {
                "method": method,
                "password": extra.get("master_password", ""),
                "clients": [
                    {"password": c.password or c.uuid, "email": c.email or c.name}
                    for c in active_clients
                ],
                "network": "tcp,udp",
            },
        }

    # Classic multi-user via one port (shadowsocks plugin)
    return {
        "tag": inbound.tag,
        "port": inbound.port,
        "protocol": "shadowsocks",
        "settings": {
            "method": method,
            "password": extra.get("password", ""),
            "clients": [
                {"password": c.password, "email": c.email or c.name, "method": method}
                for c in active_clients
            ],
            "network": "tcp,udp",
        },
    }


def _build_socks_inbound(inbound: Inbound) -> dict:
    active_clients = [c for c in inbound.clients if c.is_active]
    extra = inbound.get_extra_config()
    return {
        "tag": inbound.tag,
        "port": inbound.port,
        "protocol": "socks",
        "settings": {
            "auth": "password" if active_clients else "noauth",
            "accounts": [
                {"user": c.username or c.name, "pass": c.password or c.uuid}
                for c in active_clients
            ],
            "udp": extra.get("udp", True),
            "ip": extra.get("bind_ip", "0.0.0.0"),
        },
    }


def _build_http_inbound(inbound: Inbound) -> dict:
    active_clients = [c for c in inbound.clients if c.is_active]
    return {
        "tag": inbound.tag,
        "port": inbound.port,
        "protocol": "http",
        "settings": {
            "accounts": [
                {"user": c.username or c.name, "pass": c.password or c.uuid}
                for c in active_clients
            ],
            "allowTransparent": False,
        },
    }


def _build_dokodemo_inbound(inbound: Inbound) -> dict:
    extra = inbound.get_extra_config()
    return {
        "tag": inbound.tag,
        "port": inbound.port,
        "protocol": "dokodemo-door",
        "settings": {
            "address": extra.get("dest_address", ""),
            "port": extra.get("dest_port", 0),
            "network": extra.get("network", "tcp,udp"),
            "followRedirect": extra.get("follow_redirect", False),
        },
    }


INBOUND_BUILDERS = {
    "vmess": _build_vmess_inbound,
    "vless": _build_vless_inbound,
    "trojan": _build_trojan_inbound,
    "shadowsocks": _build_shadowsocks_inbound,
    "socks": _build_socks_inbound,
    "http": _build_http_inbound,
    "dokodemo": _build_dokodemo_inbound,
}


# ---------------------------------------------------------------------------
# Outbound builders
# ---------------------------------------------------------------------------

def _build_direct_outbound() -> dict:
    return {"tag": "direct", "protocol": "freedom", "settings": {}}


def _build_block_outbound() -> dict:
    return {"tag": "block", "protocol": "blackhole", "settings": {}}


def _build_cascade_outbound(src_inbound: Inbound, dst_inbound: Inbound) -> dict:
    """
    Forward traffic from src_inbound through dst_inbound (cascade).
    We proxy locally to dst_inbound's port via loopback.

    Каскад поддерживается только если dst_inbound — SOCKS5 или HTTP inbound:
    у этих протоколов Xray знает, как построить outbound, идущий на 127.0.0.1:port,
    без знания клиентских credential'ов (мы используем noauth-режим). Для VLESS/
    VMess/Trojan такая схема не работает — нужен protocol-aware outbound с UUID/
    паролем зарегистрированного клиента, что отдельная фича.

    Валидация на уровне API (routing.py) не даёт создать rule с несовместимым
    dst_inbound — но защитный assert ниже остаётся на случай прямой записи в БД.
    """
    tag = f"cascade-{src_inbound.tag}->{dst_inbound.tag}"
    if dst_inbound.protocol == "http":
        return {
            "tag": tag,
            "protocol": "http",
            "settings": {
                "servers": [{"address": "127.0.0.1", "port": dst_inbound.port}]
            },
        }
    if dst_inbound.protocol == "socks":
        return {
            "tag": tag,
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": "127.0.0.1",
                    "port": dst_inbound.port,
                }]
            },
        }
    # Сюда попадаем только если БД содержит несовместимое правило (созданное
    # до введения валидации). Возвращаем blackhole, чтобы трафик хотя бы не
    # уходил в неправильный outbound и был виден в логах как "заблокированный".
    log.warning(
        "Каскад %s → %s невозможен (протокол %s не поддерживается); "
        "перенаправляем в blackhole. Пересоздайте rule через UI.",
        src_inbound.tag, dst_inbound.tag, dst_inbound.protocol,
    )
    return {"tag": tag, "protocol": "blackhole", "settings": {}}


def _build_external_outbound(ext: ExternalOutbound) -> dict:
    if ext.protocol == "socks":
        server: dict[str, Any] = {"address": ext.address, "port": ext.port}
        if ext.username:
            server["users"] = [{"user": ext.username, "pass": ext.password}]
        return {
            "tag": ext.tag,
            "protocol": "socks",
            "settings": {"servers": [server]},
        }
    else:  # http
        server = {"address": ext.address, "port": ext.port}
        if ext.username:
            server["users"] = [{"user": ext.username, "pass": ext.password}]
        return {
            "tag": ext.tag,
            "protocol": "http",
            "settings": {"servers": [server]},
        }


# ---------------------------------------------------------------------------
# Routing builder
# ---------------------------------------------------------------------------

def _build_routing_rules(
    db_rules: list[RoutingRule],
    split_lists: list[SplitTunnelList],
) -> list[dict]:
    """
    Convert DB routing rules + split-tunnel lists into Xray routing rules.
    """
    xray_rules = []

    # 1. Split-tunnel rules (higher priority = lower index)
    for lst in split_lists:
        if not lst.enabled:
            continue
        entries = lst.get_entries()
        if not entries:
            continue

        rule: dict[str, Any] = {"type": "field"}
        if lst.action == "direct":
            rule["outboundTag"] = "direct"
        elif lst.action == "block":
            rule["outboundTag"] = "block"
        else:
            continue  # "proxy": без явного правила трафик идёт в дефолтный outbound

        if lst.list_type == "domain":
            rule["domain"] = entries
        else:
            rule["ip"] = entries

        xray_rules.append(rule)

    # 2. Custom routing rules ordered by priority
    for r in sorted(db_rules, key=lambda x: x.priority):
        if not r.enabled:
            continue

        rule = {"type": "field"}

        domains = r.get_match_domains()
        ips = r.get_match_ips()
        protocols = r.get_match_protocols()

        # Пропускаем правила с битыми geosite:/geoip:-кодами — иначе
        # Xray не примет конфиг целиком, упадёт на старте и уйдёт в
        # crash loop (исторически именно так пропадал доступ к проксе
        # после клика по подсказке 'geosite:ru' в UI: v2fly/dlc такой
        # категории не содержит). Само правило остаётся в БД, в UI
        # помечено бейджем — юзер видит, что починить.
        from app.core.geo_validator import validate_codes
        bad = validate_codes(domains, ips)
        if bad:
            log.warning(
                "Routing rule id=%s (%r) пропущена при генерации конфига: "
                "битые коды %s. Поправьте правило в /routing.",
                r.id, r.name, bad,
            )
            continue

        if domains:
            rule["domain"] = domains
        if ips:
            rule["ip"] = ips
        if protocols:
            rule["protocol"] = protocols
        if r.match_ports:
            rule["port"] = r.match_ports
        if r.match_network:
            # NULL/пусто = оба, поле не эмитим (Xray по умолчанию принимает оба).
            # Иначе передаём как есть: "tcp" или "udp".
            rule["network"] = r.match_network
        if r.src_inbound_id:
            # filter by inboundTag (requires inbound tag)
            src = r.src_inbound
            if src:
                rule["inboundTag"] = [src.tag]

        if r.action == ROUTING_ACTION_DIRECT:
            rule["outboundTag"] = "direct"
        elif r.action == ROUTING_ACTION_BLOCK:
            rule["outboundTag"] = "block"
        elif r.action == ROUTING_ACTION_INBOUND and r.dst_inbound:
            if r.src_inbound is None:
                continue  # правило без источника некорректно, пропускаем
            rule["outboundTag"] = f"cascade-{r.src_inbound.tag}->{r.dst_inbound.tag}"
        elif r.action == ROUTING_ACTION_OUTBOUND and r.dst_outbound_tag:
            rule["outboundTag"] = r.dst_outbound_tag
        else:
            # Неизвестный или неполный action — пропускаем, не добавляем в конфиг
            log.warning("Routing rule id=%s пропущена: action=%r не обработан", r.id, r.action)
            continue

        xray_rules.append(rule)

    return xray_rules


# ---------------------------------------------------------------------------
# Stats API
# ---------------------------------------------------------------------------

def _build_stats_api() -> tuple[dict, dict]:
    """Returns (api, policy) sections for Xray."""
    api = {
        "tag": "api",
        "services": ["HandlerService", "LoggerService", "StatsService"],
    }
    policy = {
        "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
        "system": {
            "statsInboundUplink": True,
            "statsInboundDownlink": True,
            "statsOutboundUplink": True,
            "statsOutboundDownlink": True,
        },
    }
    return api, policy


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_xray_config() -> dict:
    """
    Build complete Xray config.json from current DB state.
    """
    from app.models import db

    xray_inbounds_db: list[Inbound] = (
        Inbound.query.filter_by(engine="xray", enabled=True).all()
    )
    routing_rules_db: list[RoutingRule] = RoutingRule.query.all()
    external_outbounds_db: list[ExternalOutbound] = (
        ExternalOutbound.query.filter_by(enabled=True).all()
    )
    split_lists: list[SplitTunnelList] = SplitTunnelList.query.all()

    # --- Inbounds ---
    inbounds = []
    for ib in xray_inbounds_db:
        builder = INBOUND_BUILDERS.get(ib.protocol)
        if builder:
            inbounds.append(builder(ib))

    # Stats API inbound (loopback only)
    stats_api_port = int(Setting.get("xray_api_port", "10085"))
    inbounds.append({
        "tag": "api",
        "port": stats_api_port,
        "listen": "127.0.0.1",
        "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    })

    # --- Outbounds ---
    outbounds = [_build_direct_outbound(), _build_block_outbound()]

    # Cascade outbounds: for each routing rule that chains two inbounds
    seen_cascade = set()
    for rule in routing_rules_db:
        if rule.action == ROUTING_ACTION_INBOUND and rule.src_inbound and rule.dst_inbound:
            key = (rule.src_inbound_id, rule.dst_inbound_id)
            if key not in seen_cascade:
                outbounds.append(_build_cascade_outbound(rule.src_inbound, rule.dst_inbound))
                seen_cascade.add(key)

    # External outbounds
    for ext in external_outbounds_db:
        outbounds.append(_build_external_outbound(ext))

    # --- Routing ---
    xray_routing_rules = _build_routing_rules(routing_rules_db, split_lists)

    # Always route Stats API to api outbound
    xray_routing_rules.insert(0, {
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api",
    })

    # --- Stats & API ---
    api_section, policy_section = _build_stats_api()

    log_level = Setting.get("xray_log_level", "warning")

    config = {
        "log": {
            "loglevel": log_level,
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log",
        },
        "api": api_section,
        "stats": {},
        "policy": policy_section,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": Setting.get("xray_domain_strategy", "AsIs"),
            "domainMatcher": "mph",
            "rules": xray_routing_rules,
        },
    }

    return config


def write_xray_config() -> str:
    """Write config to disk atomically and return path."""
    config = generate_xray_config()

    # Валидация ДО записи на диск: гоняем сгенерированный конфиг через
    # `xray run -test`. Если xray его не примет — рабочий
    # /etc/xray/config.json не трогается, ошибка летит наверх (в
    # apply_xray_config → API). Историческая причина: правило с битым
    # кодом 'geosite:ru' в БД роняло Xray на старте раз за разом,
    # потому что валидация делалась только post-factum через systemd.
    #
    # Важно: validate_config работает с DICT'ом, а не с уже записанным
    # файлом, потому что прогон делается из-под proxypanel-юзера, а
    # реальный Xray (с правами на /var/log/xray/) — из-под xray. Внутри
    # validate_config из тест-копии убирается секция log, чтобы тест не
    # ломался на permission denied при попытке открыть access.log.
    # Подробности — в docstring'е validate_config.
    #
    # Fail-open (если xray-бинарь недоступен): см. validate_config.
    from app.core.geo_validator import validate_config
    ok, msg = validate_config(config)
    if not ok:
        raise RuntimeError(
            f"xray run -test отклонил сгенерированный конфиг: {msg}. "
            f"Рабочий {XRAY_CONFIG_PATH} оставлен без изменений."
        )

    dest = Path(XRAY_CONFIG_PATH)
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Запись через tempfile в той же директории + os.replace — атомарная замена.
    # Защищает от полу-записанного конфига при kill -9 или сбое питания.
    fd, tmp_path = tempfile.mkstemp(
        dir=str(dest.parent), prefix=".config.", suffix=".json"
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        # mkstemp создаёт файл с правами 0600 — Xray (другой пользователь) не сможет прочитать.
        # Восстанавливаем стандартные 0644, как было при старом open(..., "w") через umask.
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, dest)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return XRAY_CONFIG_PATH


def reload_xray() -> tuple[bool, str]:
    """
    Применяет новый конфиг к Xray через `systemctl restart`.

    Почему restart, а НЕ reload-or-restart (как было раньше). Xray-core
    не умеет hot-reload по SIGHUP — у него нет signal-handler'а, и при
    получении HUP процесс молча умирает по дефолтному поведению ОС.
    Старая команда `systemctl reload-or-restart xray` через
    ExecReload=/bin/kill -HUP $MAINPID именно это и делала: systemd
    отправлял HUP, считал reload «успешным» (команда вернула 0,
    процесс кончился), но Xray был МЁРТВ. И поскольку systemd видел
    «clean exit by HUP», `Restart=on-failure` НЕ срабатывал, и Xray
    оставался выключенным до следующего ручного `systemctl start`.

    Чистый `restart` останавливает и заново стартует процесс — это
    единственный корректный способ перезагрузить Xray с новым конфигом.
    Кратковременный downtime ~1-2 сек неизбежен и предсказуем (раньше
    он был случайным — могло убить и оставить мёртвым на часы).

    install.sh / update.sh параллельно убирают ExecReload-строку из
    юнит-файла (см. ensure_xray_service_unit_safe в update.sh) — чтобы
    даже если кто-то снаружи руками сделает `systemctl reload xray`,
    systemd корректно упал бы на restart.
    """
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "restart", "xray"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, "Xray перезапущен"
        return False, (result.stderr or result.stdout or "").strip()
    except Exception as e:
        return False, str(e)


def apply_xray_config() -> tuple[bool, str]:
    """Write config + reload xray, с откатом к последнему рабочему конфигу.

    Правка #8. `write_xray_config()` проверяет конфиг через `xray run -test`,
    но это не гарантирует, что процесс реально стартует (занятый порт, плохой
    путь к сертификату, рантайм-условие). Если новый конфиг прошёл -test, но
    `systemctl restart xray` упал, мы бы оставили на диске нерабочий конфиг,
    и с Restart=always Xray ушёл бы в crash-loop.

    Поэтому: храним рядом config.json.last-good — копию конфига, который
    ТОЧНО успешно запускался. При неудачном рестарте восстанавливаем его и
    перезапускаем, чтобы вернуть Xray в рабочее состояние.
    """
    last_good = XRAY_CONFIG_PATH + ".last-good"
    try:
        write_xray_config()
    except Exception as e:
        return False, str(e)

    ok, msg = reload_xray()
    if ok:
        # Новый конфиг успешно запустился — фиксируем его как last-good.
        try:
            shutil.copy2(XRAY_CONFIG_PATH, last_good)
        except OSError:
            pass
        return True, msg

    # Рестарт не удался несмотря на пройденный -test. Пытаемся откатиться.
    if os.path.exists(last_good):
        try:
            shutil.copy2(last_good, XRAY_CONFIG_PATH)
            ok2, msg2 = reload_xray()
            if ok2:
                return False, (
                    f"{msg}. Откатано к последнему рабочему конфигу — "
                    f"Xray снова запущен со старой конфигурацией."
                )
            return False, f"{msg}. Откат также не удался: {msg2}"
        except OSError as e:
            return False, f"{msg}. Откат не удался (ошибка файла): {e}"
    return False, msg


def get_xray_stats(client_email: str) -> dict:
    """
    Query Xray Stats API for a client's traffic.
    Returns {"up": bytes, "down": bytes}
    """
    api_port = int(Setting.get("xray_api_port", "10085"))
    try:
        result = subprocess.run(
            [
                XRAY_BINARY, "api", "statsquery",
                f"--server=127.0.0.1:{api_port}",
                f"--pattern=user>>>{client_email}>>>traffic",
            ],
            capture_output=True, text=True, timeout=5
        )
        up = down = 0
        for line in result.stdout.splitlines():
            if "uplink" in line and "value" in line:
                try:
                    up = int(line.split("value:")[-1].strip().split()[0])
                except ValueError:
                    pass
            if "downlink" in line and "value" in line:
                try:
                    down = int(line.split("value:")[-1].strip().split()[0])
                except ValueError:
                    pass
        return {"up": up, "down": down}
    except Exception:
        return {"up": 0, "down": 0}
