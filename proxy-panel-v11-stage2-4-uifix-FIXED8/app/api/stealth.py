"""REST API: «Заметность» — самопроверка сервера снаружи и подбор сайта
для маскировки Reality. Логика — app/core/stealth.py.

Все проверки синхронные, с жёстким бюджетом времени: gunicorn рвёт
запрос через 30 с (install.sh, --timeout 30).
"""
import time

from flask import Blueprint, request, jsonify
from flask_login import login_required

from app import limiter
from app.models import Setting
from app.core import stealth

bp = Blueprint("stealth", __name__)


def _server_ip() -> str | None:
    """Публичный IP: определённый (кэш /api/system/server-ip) → из настроек."""
    from app.api import system as sysapi
    cache = sysapi._server_ip_cache
    if not cache["ip"] or time.time() - cache["ts"] > 600:
        detected = sysapi._get_server_ip()
        if detected:
            cache["ip"], cache["ts"] = detected, time.time()
    return cache["ip"] or (Setting.get("server_ip", "") or "").strip() or None


@bp.post("/self-check")
@limiter.limit("10 per minute")
@login_required
def self_check():
    ip = _server_ip()
    t0 = time.monotonic()
    findings = stealth.self_check(ip)
    order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["level"], 9))
    return jsonify({"server_ip": ip, "findings": findings,
                    "took_ms": int((time.monotonic() - t0) * 1000)})


@bp.post("/target")
@limiter.limit("30 per minute")
@login_required
def check_target():
    data = request.get_json(force=True) or {}
    return jsonify(stealth.check_target(str(data.get("host", "")), 443, _server_ip()))


@bp.post("/popular")
@limiter.limit("6 per minute")
@login_required
def check_popular():
    return jsonify({"results": stealth.check_many(stealth.POPULAR_TARGETS, _server_ip())})


@bp.post("/neighbors")
@limiter.limit("4 per minute")
@login_required
def neighbors():
    ip = _server_ip()
    if not ip:
        return jsonify({"error": "Не удалось определить IP сервера"}), 400
    t0 = time.monotonic()
    res = stealth.scan_neighbors(ip)
    res["took_ms"] = int((time.monotonic() - t0) * 1000)
    res["server_ip"] = ip
    return jsonify(res)
