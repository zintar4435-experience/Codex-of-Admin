"""REST API: Security presets — high-level toggles that map to RoutingRule's.

Each preset is a stable, named bundle of one or more RoutingRule entries.
Rules created by a preset are named with a "[security] " prefix so they
remain visible and editable on the Routing page — that's by design: a
preset is just a sugar shortcut, not a hidden mechanism.

Detection logic: a preset is considered "enabled" iff *every* rule name it
declares exists in the database. Partial states (some rules present, some
missing) are treated as enabled too — clicking enable will fill in the
gaps without touching existing rules (so user edits are preserved).
Clicking disable removes all rules whose name matches the preset's
declared names, regardless of whether they were edited.
"""
import json
from flask import Blueprint, jsonify
from flask_login import login_required
from app.models import db, RoutingRule, Inbound
from app.core.xray import apply_xray_config
from app.core.audit import log_action

bp = Blueprint("security", __name__)

# Имя-префикс, по которому отличаем правила, созданные пресетами.
# Меняется на свой страх и риск: если поменять, "старые" пресет-правила
# перестанут опознаваться как принадлежащие пресету.
SECURITY_RULE_PREFIX = "[security] "

# ─────────────────────────────────────────────────────────────────────
# Реестр пресетов.
#
# Каждый пресет — словарь с полями:
#   - title:       короткий заголовок для UI
#   - description: пояснение, ЧТО фактически делает пресет
#   - caveat:      опциональная заметка (например, "только для Xray")
#   - rules:       список правил, которые создаются при включении
#
# Каждое правило — словарь с теми же полями, что у RoutingRule (минус
# id/enabled — они дефолтные). Поле name ОБЯЗАТЕЛЬНО начинается с
# SECURITY_RULE_PREFIX — это то, как мы потом находим "свои" правила.
#
# Менять priority/match_*/action в существующих пресетах можно, но
# учитывайте: если у пользователя пресет уже включён, повторный enable
# НЕ перезатрёт его правила (мы только добавляем недостающие). Чтобы
# применить новые значения, пользователь должен сначала выключить
# пресет, потом включить заново.
# ─────────────────────────────────────────────────────────────────────
PRESETS: dict[str, dict] = {
    "block-bittorrent": {
        "title": "Блокировать BitTorrent трафик",
        "description": (
            "Sniffer Xray распознаёт BitTorrent-протокол по handshake'у и "
            "обрывает соединение до того, как клиент успеет найти пиров. "
            "Ловит ~95% реального торрент-трафика."
        ),
        "caveat": (
            "Работает только для Xray-инбаундов (VLESS/VMess/Trojan/Shadowsocks). "
            "Для NaiveProxy через Caddy нужны server-side меры (DNS-фильтрация, "
            "лимиты трафика)."
        ),
        "rules": [
            {
                "name": SECURITY_RULE_PREFIX + "block-bittorrent",
                "priority": 5,
                "match_domains": [],
                "match_ips": [],
                "match_protocols": ["bittorrent"],
                "match_ports": "",
                "action": "block",
            },
        ],
    },
    "block-ads-trackers": {
        "title": "Блокировать рекламу и трекеры",
        "description": (
            "Блокирует домены из категории geosite:category-ads-all "
            "(собранный v2fly список рекламных и tracking-сетей: DoubleClick, "
            "Google Analytics, Adsense, и сотни других)."
        ),
        "caveat": (
            "Применяется ко всем инбаундам, видящим DNS через Xray. Использует "
            "файл /usr/local/share/xray/geosite.dat — он обновляется только при "
            "переустановке/обновлении Xray."
        ),
        "rules": [
            {
                "name": SECURITY_RULE_PREFIX + "block-ads-trackers",
                "priority": 6,
                "match_domains": ["geosite:category-ads-all"],
                "match_ips": [],
                "match_protocols": [],
                "match_ports": "",
                "action": "block",
            },
        ],
    },
    "block-adult": {
        "title": "Блокировать adult-контент",
        "description": (
            "Блокирует домены из категории geosite:category-porn. "
            "Полезно если панель используется в семейной/корпоративной среде. "
            "По умолчанию выключено."
        ),
        "caveat": (
            "Геосайт-категория не покрывает каждый ресурс — это эвристика, "
            "не гарантированный фильтр."
        ),
        "rules": [
            {
                "name": SECURITY_RULE_PREFIX + "block-adult",
                "priority": 7,
                "match_domains": ["geosite:category-porn"],
                "match_ips": [],
                "match_protocols": [],
                "match_ports": "",
                "action": "block",
            },
        ],
    },
}


def _preset_or_404(preset_id: str):
    preset = PRESETS.get(preset_id)
    if preset is None:
        return None, (jsonify({"error": f"Unknown preset: {preset_id}"}), 404)
    return preset, None


def _find_existing_rules_by_name(names: list[str]) -> dict[str, RoutingRule]:
    """Возвращает {name: RoutingRule} для имён, реально присутствующих в БД."""
    if not names:
        return {}
    rows = RoutingRule.query.filter(RoutingRule.name.in_(names)).all()
    return {r.name: r for r in rows}


def _preset_state(preset_id: str, preset: dict) -> dict:
    """Считает текущее состояние пресета и собирает payload для фронта."""
    rule_names = [r["name"] for r in preset["rules"]]
    existing = _find_existing_rules_by_name(rule_names)
    enabled = len(existing) == len(rule_names)
    return {
        "id": preset_id,
        "title": preset["title"],
        "description": preset["description"],
        "caveat": preset.get("caveat"),
        "enabled": enabled,
        "affected_rule_ids": [r.id for r in existing.values()],
        "rules_summary": [
            {
                "name": r["name"],
                "action": r["action"],
                "match_protocols": r.get("match_protocols", []),
                "match_domains": r.get("match_domains", []),
            }
            for r in preset["rules"]
        ],
    }


@bp.get("/presets")
@login_required
def list_presets():
    """Возвращает все известные пресеты + контекст для UI.

    Контекст (has_xray_inbounds) нужен, чтобы фронт мог показать честный
    баннер «у вас сейчас нет Xray-инбаундов, пресеты ничего не сделают»
    — пресеты применяются только к Xray, не к NaiveProxy через Caddy."""
    presets = [_preset_state(pid, p) for pid, p in PRESETS.items()]
    has_xray = Inbound.query.filter_by(engine="xray").count() > 0
    return jsonify({
        "presets": presets,
        "has_xray_inbounds": has_xray,
    })


@bp.post("/presets/<preset_id>/enable")
@login_required
def enable_preset(preset_id: str):
    """Создаёт недостающие правила пресета. Не трогает уже существующие
    (даже если пользователь их вручную отредактировал)."""
    preset, err = _preset_or_404(preset_id)
    if err:
        return err

    rule_names = [r["name"] for r in preset["rules"]]
    existing = _find_existing_rules_by_name(rule_names)

    created_count = 0
    for rdef in preset["rules"]:
        if rdef["name"] in existing:
            continue
        rule = RoutingRule(
            name=rdef["name"],
            priority=rdef.get("priority", 100),
            src_inbound_id=None,
            match_domains=json.dumps(rdef.get("match_domains", [])),
            match_ips=json.dumps(rdef.get("match_ips", [])),
            match_protocols=json.dumps(rdef.get("match_protocols", [])),
            match_ports=rdef.get("match_ports", ""),
            action=rdef.get("action", "block"),
            dst_inbound_id=None,
            dst_outbound_tag=None,
            enabled=True,
        )
        db.session.add(rule)
        created_count += 1

    if created_count > 0:
        db.session.commit()
        apply_xray_config()
        log_action("security.preset_enable",
                   target_type="preset", target_name=preset_id,
                   details={"created_rules": created_count})

    return jsonify(_preset_state(preset_id, preset))


@bp.post("/presets/<preset_id>/disable")
@login_required
def disable_preset(preset_id: str):
    """Удаляет все правила, чьё имя совпадает с именами пресета.
    Если пользователь отредактировал правило — оно всё равно удаляется
    (имя осталось пресет-овским, поэтому считается принадлежащим пресету)."""
    preset, err = _preset_or_404(preset_id)
    if err:
        return err

    rule_names = [r["name"] for r in preset["rules"]]
    existing = _find_existing_rules_by_name(rule_names)

    deleted_count = 0
    for rule in existing.values():
        db.session.delete(rule)
        deleted_count += 1

    if deleted_count > 0:
        db.session.commit()
        apply_xray_config()
        log_action("security.preset_disable",
                   target_type="preset", target_name=preset_id,
                   details={"deleted_rules": deleted_count})

    return jsonify(_preset_state(preset_id, preset))
