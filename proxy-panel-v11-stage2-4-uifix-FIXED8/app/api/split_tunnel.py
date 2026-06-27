"""REST API: Split-tunnel lists."""
import urllib.request
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_login import login_required
from app.models import db, SplitTunnelList
from app.core.xray import apply_xray_config
from app.core.caddy import apply_caddy_config
from app.core.audit import log_action

bp = Blueprint("split_tunnel", __name__)


def _apply_all():
    apply_xray_config()
    apply_caddy_config()


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
    db.session.commit()
    _apply_all()
    log_action("split.create", target_type="split", target_id=lst.id,
               target_name=lst.name,
               details={"type": lst.list_type, "action": lst.action})
    return jsonify(lst.to_dict()), 201


@bp.put("/<int:lst_id>")
@login_required
def update_list(lst_id):
    lst = SplitTunnelList.query.get_or_404(lst_id)
    data = request.get_json(force=True)
    for field in ["name", "list_type", "action", "source_url", "content", "enabled"]:
        if field in data:
            setattr(lst, field, data[field])
    db.session.commit()
    _apply_all()
    log_action("split.update", target_type="split", target_id=lst.id,
               target_name=lst.name, details={"fields": list(data.keys())})
    return jsonify(lst.to_dict())


@bp.delete("/<int:lst_id>")
@login_required
def delete_list(lst_id):
    lst = SplitTunnelList.query.get_or_404(lst_id)
    snapshot = {"id": lst.id, "name": lst.name}
    db.session.delete(lst)
    db.session.commit()
    _apply_all()
    log_action("split.delete", target_type="split",
               target_id=snapshot["id"], target_name=snapshot["name"])
    return jsonify({"ok": True})


@bp.post("/<int:lst_id>/refresh")
@login_required
def refresh_list(lst_id):
    lst = SplitTunnelList.query.get_or_404(lst_id)
    if not lst.source_url:
        return jsonify({"error": "URL не указан"}), 400
    if not lst.source_url.lower().startswith(("http://", "https://")):
        return jsonify({"error": "URL должен начинаться с http:// или https://"}), 400
    try:
        with urllib.request.urlopen(lst.source_url, timeout=30) as resp:
            lst.content = resp.read().decode("utf-8", errors="replace")
        lst.last_updated = datetime.now(timezone.utc)
        db.session.commit()
        _apply_all()
        log_action("split.refresh", target_type="split", target_id=lst.id,
                   target_name=lst.name,
                   details={"entries": len(lst.get_entries())})
        return jsonify(lst.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 502
