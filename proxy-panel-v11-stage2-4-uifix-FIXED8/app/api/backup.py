"""
REST API: резервная копия конфигурации (экспорт/импорт).

Назначение: выгрузить ВСЕ inbounds вместе с вложенными клиентами в один
JSON-файл и затем восстановить их на другом/обновлённом сервере, если
данные были потеряны.

Что входит в дамп:
  - inbounds: все поля, включая секреты (probe_resistance_secret,
    transport_config с reality-ключами, TLS-пути) — без них восстановленный
    inbound будет нерабочим.
  - clients: все поля, включая uuid/password/share_token и накопленный
    трафик (traffic_used_*), чтобы статистика и ссылки клиентов сохранялись.

Импорт:
  mode="skip" (по умолчанию): inbound с уже существующим tag пропускается.
  mode="replace": существующий inbound с тем же tag удаляется и создаётся заново.
  Каждый inbound импортируется в собственном savepoint — ошибка одного не
  срывает весь импорт. После импорта запускается apply конфигов.
"""
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, Response
from flask_login import login_required
from sqlalchemy.exc import SQLAlchemyError

from app.models import db, Inbound, Client
from app.core.audit import log_action

bp = Blueprint("backup", __name__)

BACKUP_FORMAT = "proxy-panel-backup"
BACKUP_VERSION = 1


# ---------------------------------------------------------------------------
# Сериализация (полная, с секретами — это резервная копия)
# ---------------------------------------------------------------------------

def _client_export(c: Client) -> dict:
    return {
        "name": c.name,
        "uuid": c.uuid,
        "password": c.password,
        "username": c.username,
        "email": c.email,
        "flow": c.flow,
        "expire_at": c.expire_at.isoformat() if c.expire_at else None,
        "traffic_limit_up": c.traffic_limit_up or 0,
        "traffic_limit_down": c.traffic_limit_down or 0,
        "traffic_used_up": c.traffic_used_up or 0,
        "traffic_used_down": c.traffic_used_down or 0,
        "share_token": c.share_token,
        "enabled": c.enabled,
    }


def _inbound_export(ib: Inbound) -> dict:
    return {
        "tag": ib.tag,
        "engine": ib.engine,
        "protocol": ib.protocol,
        "port": ib.port,
        "domain": ib.domain,
        "tls_enabled": ib.tls_enabled,
        "tls_cert_path": ib.tls_cert_path,
        "tls_key_path": ib.tls_key_path,
        "tls_acme": ib.tls_acme,
        "transport": ib.transport,
        "transport_config": ib.transport_config or "{}",
        "probe_resistance_secret": ib.probe_resistance_secret,
        "extra_config": ib.extra_config or "{}",
        "enabled": ib.enabled,
        "clients": [_client_export(c) for c in ib.clients],
    }


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@bp.get("/export")
@login_required
def export_all():
    inbounds = Inbound.query.order_by(Inbound.id).all()
    dump = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "inbound_count": len(inbounds),
        "client_count": sum(len(ib.clients) for ib in inbounds),
        "inbounds": [_inbound_export(ib) for ib in inbounds],
    }
    log_action("backup.export",
               details={"inbounds": dump["inbound_count"],
                        "clients": dump["client_count"]})
    import json
    body = json.dumps(dump, ensure_ascii=False, indent=2)
    fname = "proxy-panel-backup-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".json"
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _build_client(ib_id: int, c: dict) -> Client:
    used_up = int(c.get("traffic_used_up") or 0)
    used_down = int(c.get("traffic_used_down") or 0)
    return Client(
        inbound_id=ib_id,
        name=(c.get("name") or "imported").strip(),
        uuid=c.get("uuid"),
        password=c.get("password"),
        username=c.get("username"),
        email=c.get("email"),
        flow=c.get("flow"),
        expire_at=_parse_dt(c.get("expire_at")),
        traffic_limit_up=int(c.get("traffic_limit_up") or 0),
        traffic_limit_down=int(c.get("traffic_limit_down") or 0),
        traffic_used_up=used_up,
        traffic_used_down=used_down,
        # last_seen_* = used_*, чтобы первый тик после восстановления не
        # удвоил трафик (см. comment в models.Client / _ensure_schema).
        last_seen_up=used_up,
        last_seen_down=used_down,
        share_token=c.get("share_token"),
        enabled=bool(c.get("enabled", True)),
    )


def _build_inbound(d: dict) -> Inbound:
    return Inbound(
        tag=d["tag"],
        engine=d.get("engine", "xray"),
        protocol=d.get("protocol", ""),
        port=d.get("port"),
        domain=d.get("domain"),
        tls_enabled=bool(d.get("tls_enabled", False)),
        tls_cert_path=d.get("tls_cert_path"),
        tls_key_path=d.get("tls_key_path"),
        tls_acme=bool(d.get("tls_acme", False)),
        transport=d.get("transport"),
        transport_config=d.get("transport_config") or "{}",
        probe_resistance_secret=d.get("probe_resistance_secret"),
        extra_config=d.get("extra_config") or "{}",
        enabled=bool(d.get("enabled", True)),
    )


@bp.post("/import")
@login_required
def import_all():
    payload = request.get_json(force=True, silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Тело запроса должно быть JSON-объектом"}), 400

    # Принимаем как сам дамп, так и обёртку {"mode":..., "data": <дамп>}.
    mode = payload.get("mode", "skip")
    data = payload.get("data", payload)
    if mode not in ("skip", "replace"):
        return jsonify({"error": "mode должен быть 'skip' или 'replace'"}), 400

    if data.get("format") != BACKUP_FORMAT:
        return jsonify({"error": "Неверный формат файла резервной копии"}), 400
    inbounds = data.get("inbounds")
    if not isinstance(inbounds, list):
        return jsonify({"error": "В дампе нет списка inbounds"}), 400

    created_ib = skipped_ib = created_cl = skipped_cl = 0
    errors: list[str] = []
    engines_touched: set[str] = set()

    for d in inbounds:
        tag = (d.get("tag") or "").strip()
        if not tag:
            errors.append("inbound без tag пропущен")
            continue
        try:
            with db.session.begin_nested():
                existing = Inbound.query.filter_by(tag=tag).first()
                if existing:
                    if mode == "skip":
                        skipped_ib += 1
                        continue
                    db.session.delete(existing)
                    db.session.flush()

                ib = _build_inbound(d)
                db.session.add(ib)
                db.session.flush()  # получить ib.id
                engines_touched.add(ib.engine)

                for c in (d.get("clients") or []):
                    try:
                        with db.session.begin_nested():
                            db.session.add(_build_client(ib.id, c))
                            db.session.flush()
                            created_cl += 1
                    except SQLAlchemyError:
                        # дубликат email/username в рамках inbound и т.п.
                        skipped_cl += 1
                created_ib += 1
        except SQLAlchemyError as e:
            errors.append(f"inbound '{tag}': {type(e).__name__}")

    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": f"Не удалось сохранить импорт: {type(e).__name__}"}), 500

    # Применяем конфиги затронутых движков (async). Если xray недоступен —
    # данные всё равно восстановлены; apply вернёт ошибку отдельно.
    apply_ids = {}
    try:
        from app.core.apply_runner import start_apply
        for eng in engines_touched:
            apply_ids[eng] = start_apply(eng)
    except Exception as e:  # noqa: BLE001
        errors.append(f"apply не запущен: {e}")

    log_action("backup.import",
               details={"mode": mode, "created_inbounds": created_ib,
                        "skipped_inbounds": skipped_ib,
                        "created_clients": created_cl,
                        "skipped_clients": skipped_cl})

    return jsonify({
        "ok": True,
        "mode": mode,
        "created_inbounds": created_ib,
        "skipped_inbounds": skipped_ib,
        "created_clients": created_cl,
        "skipped_clients": skipped_cl,
        "errors": errors,
        "apply_ids": apply_ids,
    })
