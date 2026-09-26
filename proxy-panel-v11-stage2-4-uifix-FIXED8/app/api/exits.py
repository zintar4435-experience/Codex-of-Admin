"""REST API: выходы через другие серверы (каскад), группы выходов и выбор
выхода для каждого подключения. Логика — app/core/exits.py.

Все изменения конфигурации идут так же, как у инбаундов: сначала
сгенерированный конфиг проверяется `xray run -test` (до commit — битое не
попадает в БД), потом apply в фоне, ответ сразу с apply_id.
"""
import json

from flask import Blueprint, request, jsonify
from flask_login import login_required

from app.models import db, ExternalOutbound, OutboundGroup, Inbound
from app.core import exits as exits_core
from app.core import server_region
from app.core.audit import log_action

bp = Blueprint("exits", __name__)

_NAME_MAX = 128


def _clean_name(value, fallback: str) -> str:
    name = (value if isinstance(value, str) else "").strip()
    return (name or fallback)[:_NAME_MAX]


def _commit_and_apply():
    """Проверка конфига до commit → commit → apply в фоне.
    Возвращает (apply_id, None) или (None, текст ошибки) с откатом."""
    from app.api.inbounds import _pre_validate_xray
    db.session.flush()
    ok, err = _pre_validate_xray()
    if not ok:
        db.session.rollback()
        return None, err
    db.session.commit()
    from app.core.apply_runner import start_apply
    return start_apply("xray"), None


def _exit_view(ext: ExternalOutbound) -> dict:
    d = ext.to_dict()
    d["usable"] = exits_core.resolve_exit(ext.tag) is not None
    d["used_by"] = exits_core.exit_usages(ext.tag)
    return d


def _group_view(grp: OutboundGroup) -> dict:
    d = grp.to_dict()
    resolved = exits_core.resolve_exit(grp.tag)
    d["usable"] = resolved is not None
    d["region"] = resolved.region if resolved else None
    d["used_by"] = exits_core.exit_usages(grp.tag)
    return d


def _inbound_view(ib: Inbound) -> dict:
    resolved = exits_core.resolve_exit(ib.exit_tag) if ib.exit_tag else None
    return {
        "id": ib.id,
        "tag": ib.tag,
        "engine": ib.engine,
        "protocol": ib.protocol,
        "port": ib.port,
        "enabled": ib.enabled,
        # Каскад настраивается только у Xray-подключений: NaiveProxy живёт
        # в Caddy, SSH — в sshd, маршрутизация Xray их не касается.
        "can_exit": ib.engine == "xray",
        "exit_tag": ib.exit_tag,
        "exit_ru_direct": bool(ib.exit_ru_direct),
        # Выход выбран, но выключен/сломан → трафик идёт напрямую.
        "exit_broken": bool(ib.exit_tag) and resolved is None,
        "region": server_region.for_inbound(ib),
    }


@bp.get("/")
@login_required
def overview():
    return jsonify({
        "server_region": server_region.current(),
        "exits": [_exit_view(e) for e in ExternalOutbound.query.order_by(ExternalOutbound.id).all()],
        "groups": [_group_view(g) for g in OutboundGroup.query.order_by(OutboundGroup.id).all()],
        "inbounds": [_inbound_view(ib) for ib in Inbound.query.order_by(Inbound.id).all()],
    })


# ---------------------------------------------------------------------------
# Выходы
# ---------------------------------------------------------------------------

@bp.post("/parse")
@login_required
def parse_key():
    """Разобрать ключ без сохранения — чтобы показать, что получилось."""
    data = request.get_json(force=True) or {}
    try:
        parsed = exits_core.parse_link(data.get("link", ""))
    except exits_core.LinkError as e:
        return jsonify({"error": str(e)}), 400
    cfg = parsed["config"]
    return jsonify({
        "protocol": parsed["protocol"],
        "address": parsed["address"],
        "port": parsed["port"],
        "name": parsed["name"],
        "region": parsed["region"],
        "security": cfg.get("security"),
        "network": cfg.get("network"),
        "sni": cfg.get("sni"),
    })


def _apply_parsed(ext: ExternalOutbound, parsed: dict):
    ext.protocol = parsed["protocol"]
    ext.address = parsed["address"]
    ext.port = parsed["port"]
    ext.username = parsed.get("username")
    ext.password = parsed.get("password")
    ext.config = json.dumps(parsed["config"], ensure_ascii=False)


@bp.post("/")
@login_required
def create_exit():
    data = request.get_json(force=True) or {}
    try:
        parsed = exits_core.parse_link(data.get("link", ""))
    except exits_core.LinkError as e:
        return jsonify({"error": str(e)}), 400
    region = data.get("region") or parsed.get("region") or server_region.DEFAULT
    if region not in server_region.REGIONS:
        return jsonify({"error": "Расположение выхода: ru или intl"}), 400
    ext = ExternalOutbound(
        tag=exits_core.new_tag(exits_core.EXIT_TAG_PREFIX),
        name=_clean_name(data.get("name"), parsed.get("name") or parsed["address"]),
        region=region,
        enabled=True,
    )
    _apply_parsed(ext, parsed)
    db.session.add(ext)
    apply_id, err = _commit_and_apply()
    if err:
        return jsonify({"error": err}), 400
    log_action("exit.create", target_type="outbound", target_id=ext.id,
               target_name=ext.name,
               details={"protocol": ext.protocol, "address": ext.address,
                        "port": ext.port, "region": ext.region})
    return jsonify({**_exit_view(ext), "apply_id": apply_id}), 201


@bp.put("/<int:ext_id>")
@login_required
def update_exit(ext_id):
    ext = ExternalOutbound.query.get_or_404(ext_id)
    data = request.get_json(force=True) or {}
    if "link" in data and data["link"]:
        try:
            parsed = exits_core.parse_link(data["link"])
        except exits_core.LinkError as e:
            return jsonify({"error": str(e)}), 400
        _apply_parsed(ext, parsed)
    if "name" in data:
        ext.name = _clean_name(data["name"], ext.name or ext.tag)
    if "region" in data:
        if data["region"] not in server_region.REGIONS:
            return jsonify({"error": "Расположение выхода: ru или intl"}), 400
        ext.region = data["region"]
    if "enabled" in data:
        ext.enabled = bool(data["enabled"])
    apply_id, err = _commit_and_apply()
    if err:
        return jsonify({"error": err}), 400
    log_action("exit.update", target_type="outbound", target_id=ext.id,
               target_name=ext.name or ext.tag,
               details={"fields": sorted(k for k in data if k != "link" or data["link"])})
    return jsonify({**_exit_view(ext), "apply_id": apply_id})


@bp.delete("/<int:ext_id>")
@login_required
def delete_exit(ext_id):
    ext = ExternalOutbound.query.get_or_404(ext_id)
    used = exits_core.exit_usages(ext.tag)
    if used:
        return jsonify({"error": "Выход используется: " + ", ".join(used)
                        + ". Сначала выберите для них другой выход."}), 409
    snapshot = {"id": ext.id, "name": ext.name or ext.tag}
    db.session.delete(ext)
    apply_id, err = _commit_and_apply()
    if err:
        return jsonify({"error": err}), 400
    log_action("exit.delete", target_type="outbound", target_id=snapshot["id"],
               target_name=snapshot["name"])
    return jsonify({"ok": True, "apply_id": apply_id})


@bp.post("/<int:ext_id>/test")
@login_required
def test_exit(ext_id):
    """Проверка по-настоящему: через выход открывается сайт. Рабочий Xray
    не трогается — поднимается отдельный временный процесс."""
    ext = ExternalOutbound.query.get_or_404(ext_id)
    from app.core.xray import _build_external_outbound
    ob = _build_external_outbound(ext)
    if ob is None:
        return jsonify({"ok": False, "error": "Параметры выхода повреждены — добавьте ключ заново"})
    return jsonify(exits_core.probe_outbound(ob))


# ---------------------------------------------------------------------------
# Группы
# ---------------------------------------------------------------------------

def _validate_members(members) -> tuple[list | None, str | None]:
    if not isinstance(members, list) or not members:
        return None, "Выберите хотя бы один выход"
    clean = []
    for m in members:
        if not isinstance(m, str) or m in clean:
            continue
        if ExternalOutbound.query.filter_by(tag=m).first() is None:
            return None, f"Выхода {m} нет"
        clean.append(m)
    if not clean:
        return None, "Выберите хотя бы один выход"
    regions = {exits_core.normalize_region(
        ExternalOutbound.query.filter_by(tag=m).first().region) for m in clean}
    if len(regions) > 1:
        return None, ("В одной группе выходы должны быть в одной стране-зоне: "
                      "все в России или все не в России. Иначе приложение не "
                      "поймёт, какие сайты пускать напрямую.")
    # Селектор балансировщика Xray сравнивает теги по началу строки.
    all_tags = [t for (t,) in db.session.query(ExternalOutbound.tag).all()]
    all_tags += ["direct", "block", "api"]
    bad = exits_core.prefix_conflicts(clean, all_tags)
    if bad:
        return None, ("Теги выходов пересекаются по началу (" + ", ".join(bad)
                      + "). Переименуйте старый выход на странице «Маршрутизация».")
    return clean, None


@bp.post("/groups")
@login_required
def create_group():
    data = request.get_json(force=True) or {}
    members, err = _validate_members(data.get("members"))
    if err:
        return jsonify({"error": err}), 400
    grp = OutboundGroup(
        tag=exits_core.new_tag(exits_core.GROUP_TAG_PREFIX),
        name=_clean_name(data.get("name"), "Группа выходов"),
        members=json.dumps(members),
        enabled=True,
    )
    db.session.add(grp)
    apply_id, err = _commit_and_apply()
    if err:
        return jsonify({"error": err}), 400
    log_action("exit_group.create", target_type="outbound_group", target_id=grp.id,
               target_name=grp.name, details={"members": members})
    return jsonify({**_group_view(grp), "apply_id": apply_id}), 201


@bp.put("/groups/<int:grp_id>")
@login_required
def update_group(grp_id):
    grp = OutboundGroup.query.get_or_404(grp_id)
    data = request.get_json(force=True) or {}
    if "members" in data:
        members, err = _validate_members(data["members"])
        if err:
            return jsonify({"error": err}), 400
        grp.members = json.dumps(members)
    if "name" in data:
        grp.name = _clean_name(data["name"], grp.name)
    if "enabled" in data:
        grp.enabled = bool(data["enabled"])
    apply_id, err = _commit_and_apply()
    if err:
        return jsonify({"error": err}), 400
    log_action("exit_group.update", target_type="outbound_group", target_id=grp.id,
               target_name=grp.name, details={"fields": sorted(data.keys())})
    return jsonify({**_group_view(grp), "apply_id": apply_id})


@bp.delete("/groups/<int:grp_id>")
@login_required
def delete_group(grp_id):
    grp = OutboundGroup.query.get_or_404(grp_id)
    used = exits_core.exit_usages(grp.tag)
    if used:
        return jsonify({"error": "Группа используется: " + ", ".join(used)
                        + ". Сначала выберите для них другой выход."}), 409
    snapshot = {"id": grp.id, "name": grp.name}
    db.session.delete(grp)
    apply_id, err = _commit_and_apply()
    if err:
        return jsonify({"error": err}), 400
    log_action("exit_group.delete", target_type="outbound_group",
               target_id=snapshot["id"], target_name=snapshot["name"])
    return jsonify({"ok": True, "apply_id": apply_id})


# ---------------------------------------------------------------------------
# Выход конкретного подключения
# ---------------------------------------------------------------------------

@bp.put("/inbound/<int:ib_id>")
@login_required
def set_inbound_exit(ib_id):
    ib = Inbound.query.get_or_404(ib_id)
    if ib.engine != "xray":
        return jsonify({"error": "Каскад настраивается только у Xray-подключений "
                                 "(VLESS, Trojan и т.п.). NaiveProxy и SSH выходят "
                                 "в интернет прямо с этого сервера."}), 400
    data = request.get_json(force=True) or {}
    if "exit_tag" in data:
        tag = data["exit_tag"] or None
        if tag is not None:
            if not isinstance(tag, str):
                return jsonify({"error": "Неверный выход"}), 400
            known = (ExternalOutbound.query.filter_by(tag=tag).first() is not None
                     or OutboundGroup.query.filter_by(tag=tag).first() is not None)
            if not known:
                return jsonify({"error": "Такого выхода нет"}), 400
        ib.exit_tag = tag
    if "exit_ru_direct" in data:
        ib.exit_ru_direct = bool(data["exit_ru_direct"])
    apply_id, err = _commit_and_apply()
    if err:
        return jsonify({"error": err}), 400
    log_action("inbound.exit", target_type="inbound", target_id=ib.id,
               target_name=ib.tag,
               details={"exit_tag": ib.exit_tag, "ru_direct": bool(ib.exit_ru_direct)})
    return jsonify({**_inbound_view(ib), "apply_id": apply_id})
