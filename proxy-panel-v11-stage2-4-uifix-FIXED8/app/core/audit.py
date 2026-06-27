"""
Audit log helper.

Используется так:

    from app.core.audit import log_action

    @bp.post("/")
    def create_something():
        # … основная работа …
        db.session.commit()
        log_action("thing.create", target_type="thing",
                   target_id=t.id, target_name=t.name,
                   details={"port": t.port})
        return jsonify(t.to_dict())

Принципы:
  • Вызывается ПОСЛЕ основного commit. Если основной commit упал — лога
    не будет, и это корректно (не было события).
  • Свой commit. Все ошибки внутри log_action глотаются с rollback,
    чтобы баг в логировании не ломал основной API.
  • current_user и request — берутся из Flask-контекста автоматически;
    в системных контекстах (scheduler) их нет, тогда username=None, ip=None.
"""
import json
import logging

from flask import has_request_context, request
from flask_login import current_user

from app.models import db, AuditLog

log = logging.getLogger(__name__)


def log_action(
    action: str,
    target_type: str | None = None,
    target_id: int | None = None,
    target_name: str | None = None,
    details: dict | None = None,
    username: str | None = None,   # явный override для системных записей
) -> None:
    """Записать действие в audit_logs. Никогда не бросает исключений наружу."""
    try:
        # Имя пользователя: явный override > current_user > None
        uname = username
        if uname is None and has_request_context():
            try:
                if current_user.is_authenticated:
                    uname = current_user.username
            except Exception:
                # Flask-Login может ругаться вне request lifecycle
                uname = None

        # IP-адрес — из request, если есть контекст
        ip = None
        if has_request_context():
            ip = request.remote_addr

        # target_name укорачиваем — длинные ссылки vless:// сюда лезть не должны,
        # но защитимся от случайностей.
        if target_name and len(target_name) > 256:
            target_name = target_name[:253] + "..."

        entry = AuditLog(
            action=action,
            username=uname,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            ip=ip,
            details=json.dumps(details, ensure_ascii=False) if details else None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        # Полностью глотаем — audit не должен валить ничего из основного flow.
        # Логируем хотя бы в обычный логгер, чтобы не потеряли совсем.
        log.warning("audit log failed: %s (action=%s)", e, action)
        try:
            db.session.rollback()
        except Exception:
            pass


def cleanup_old_logs(retention_days: int = 90) -> int:
    """Удалить записи старше N дней. Возвращает число удалённых.

    Вызывается scheduler'ом раз в сутки.
    """
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    try:
        deleted = AuditLog.query.filter(AuditLog.timestamp < cutoff).delete(
            synchronize_session=False
        )
        db.session.commit()
        return deleted
    except Exception as e:
        log.warning("audit cleanup failed: %s", e)
        db.session.rollback()
        return 0
