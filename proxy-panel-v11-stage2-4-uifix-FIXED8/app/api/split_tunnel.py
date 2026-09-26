"""REST API: Split-tunnel lists."""
import urllib.request
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_login import login_required
from app.models import db, SplitTunnelList
from app.core.apply_runner import commit_and_start_xray
from app.core.audit import log_action
from app.core.url_guard import validate_public_url

bp = Blueprint("split_tunnel", __name__)


# Списки сплит-туннеля живут только в маршрутизации Xray. Раньше здесь
# вдобавок перезагружался Caddy — без всякой пользы, но в режиме «общий
# 443» это рвало соединение с самой панелью («Failed to fetch»).


@bp.get("/")
@login_required
def list_lists():
    return jsonify([lst.to_dict() for lst in SplitTunnelList.query.all()])


@bp.post("/")
@login_required
def create_list():
    data = request.get_json(force=True)
    lst = SplitTunnelList(
        name=data["name"],
        list_type=data.get("list_type", "domain"),
        action=data.get("action", "direct"),
        source_url=data.get("source_url"),
        content=data.get("content", ""),
        enabled=data.get("enabled", True),
    )
    db.session.add(lst)
    apply_id, err = commit_and_start_xray()
    if err:
        return jsonify({"error": err}), 400
    log_action("split.create", target_type="split", target_id=lst.id,
               target_name=lst.name,
               details={"type": lst.list_type, "action": lst.action})
    return jsonify({**lst.to_dict(), "apply_id": apply_id}), 201


@bp.put("/<int:lst_id>")
@login_required
def update_list(lst_id):
    lst = SplitTunnelList.query.get_or_404(lst_id)
    data = request.get_json(force=True)
    for field in ["name", "list_type", "action", "source_url", "content", "enabled"]:
        if field in data:
            setattr(lst, field, data[field])
    apply_id, err = commit_and_start_xray()
    if err:
        return jsonify({"error": err}), 400
    log_action("split.update", target_type="split", target_id=lst.id,
               target_name=lst.name, details={"fields": list(data.keys())})
    return jsonify({**lst.to_dict(), "apply_id": apply_id})


@bp.delete("/<int:lst_id>")
@login_required
def delete_list(lst_id):
    lst = SplitTunnelList.query.get_or_404(lst_id)
    snapshot = {"id": lst.id, "name": lst.name}
    db.session.delete(lst)
    apply_id, _ = commit_and_start_xray(validate=False)
    log_action("split.delete", target_type="split",
               target_id=snapshot["id"], target_name=snapshot["name"])
    return jsonify({"ok": True, "apply_id": apply_id})


@bp.post("/<int:lst_id>/refresh")
@login_required
def refresh_list(lst_id):
    lst = SplitTunnelList.query.get_or_404(lst_id)
    if not lst.source_url:
        return jsonify({"error": "URL не указан"}), 400
    # SSRF-защита: разрешаем только публичные http(s)-адреса. Блокирует
    # обращения к метаданным облака и внутренним сервисам (см. url_guard).
    ok, err = validate_public_url(lst.source_url)
    if not ok:
        return jsonify({"error": err}), 400
    try:
        with urllib.request.urlopen(lst.source_url, timeout=30) as resp:
            lst.content = resp.read().decode("utf-8", errors="replace")
        lst.last_updated = datetime.now(timezone.utc)
        apply_id, err = commit_and_start_xray()
        if err:
            return jsonify({"error": err}), 400
        log_action("split.refresh", target_type="split", target_id=lst.id,
                   target_name=lst.name,
                   details={"entries": len(lst.get_entries())})
        return jsonify({**lst.to_dict(), "apply_id": apply_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 502
