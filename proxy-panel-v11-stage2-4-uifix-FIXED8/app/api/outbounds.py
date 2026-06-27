"""REST API: External outbounds (SOCKS5/HTTP cascade targets)."""
from flask import Blueprint, request, jsonify
from flask_login import login_required
from app.models import db, ExternalOutbound
from app.core.xray import apply_xray_config
from app.core.audit import log_action
from app.core.input_validators import (
    validate_tag, validate_port, validate_hostname_or_ip, validate_enum,
)

bp = Blueprint("outbounds", __name__)

# Xray умеет outbound в SOCKS5 и HTTP. Прочие протоколы (vmess/vless как
# outbound) требуют отдельной инфраструктуры (свой пользователь/UUID на
# удалённом сервере) — за пределами скоупа простого «каскад через прокси».
ALLOWED_PROTOCOLS = frozenset({"socks", "http"})


def _validate_outbound_data(data: dict, *, is_create: bool, current_id: int | None = None) -> tuple[bool, str | None, int | None]:
    """
    Возвращает (ok, error_message, normalized_port).
    На create требуем все поля; на update — только если они в data.

    Принцип «не блокировать уборку битых данных» (как в инбаундах):
    PUT, который не трогает address/port/protocol/tag, не пересчитывает
    их валидность, чтобы можно было выключить/удалить старый ломаный
    outbound через `{enabled: false}` без чистки полей.
    """
    if is_create or "protocol" in data:
        proto = data.get("protocol", "socks")
        ok, err = validate_enum(proto, ALLOWED_PROTOCOLS, label="protocol outbound'а")
        if not ok:
            return False, err, None

    if is_create or "address" in data:
        ok, err = validate_hostname_or_ip(data.get("address", ""))
        if not ok:
            return False, err, None

    normalized_port: int | None = None
    if is_create or "port" in data:
        # check_panel_conflicts=False: это порт УДАЛЁННОГО таргета,
        # никаких локальных биндов, 443/80 — норма.
        ok, err, normalized_port = validate_port(
            data.get("port"), check_panel_conflicts=False,
        )
        if not ok:
            return False, err, None

    return True, None, normalized_port


@bp.get("/")
@login_required
def list_outbounds():
    return jsonify([o.to_dict() for o in ExternalOutbound.query.all()])


@bp.post("/")
@login_required
def create_outbound():
    data = request.get_json(force=True)
    tag = data.get("tag", "").strip() if isinstance(data.get("tag"), str) else ""

    ok, err = validate_tag(tag)
    if not ok:
        return jsonify({"error": err}), 400
    if ExternalOutbound.query.filter_by(tag=tag).first():
        return jsonify({"error": f"Тег '{tag}' уже занят"}), 409

    ok, err, port = _validate_outbound_data(data, is_create=True)
    if not ok:
        return jsonify({"error": err}), 400

    out = ExternalOutbound(
        tag=tag,
        protocol=data.get("protocol", "socks"),
        address=data["address"],
        port=port,
        username=data.get("username"),
        password=data.get("password"),
        enabled=data.get("enabled", True),
    )
    db.session.add(out)
    db.session.commit()
    apply_xray_config()
    log_action("outbound.create", target_type="outbound",
               target_id=out.id, target_name=out.tag,
               details={"protocol": out.protocol, "address": out.address, "port": out.port})
    return jsonify(out.to_dict()), 201


@bp.put("/<int:out_id>")
@login_required
def update_outbound(out_id):
    out = ExternalOutbound.query.get_or_404(out_id)
    data = request.get_json(force=True)

    ok, err, normalized_port = _validate_outbound_data(
        data, is_create=False, current_id=out_id,
    )
    if not ok:
        return jsonify({"error": err}), 400
    if "port" in data and normalized_port is not None:
        data["port"] = normalized_port

    for field in ["protocol", "address", "port", "username", "password", "enabled"]:
        if field in data:
            setattr(out, field, data[field])
    db.session.commit()
    apply_xray_config()
    log_action("outbound.update", target_type="outbound",
               target_id=out.id, target_name=out.tag,
               details={"fields": list(data.keys())})
    return jsonify(out.to_dict())


@bp.delete("/<int:out_id>")
@login_required
def delete_outbound(out_id):
    out = ExternalOutbound.query.get_or_404(out_id)
    snapshot = {"id": out.id, "tag": out.tag, "protocol": out.protocol}
    db.session.delete(out)
    db.session.commit()
    apply_xray_config()
    log_action("outbound.delete", target_type="outbound",
               target_id=snapshot["id"], target_name=snapshot["tag"],
               details={"protocol": snapshot["protocol"]})
    return jsonify({"ok": True})

