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
import json
import re
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, Response
from flask_login import login_required
from sqlalchemy.exc import SQLAlchemyError

from app.models import db, Inbound, Client
from app.core.audit import log_action

bp = Blueprint("backup", __name__)

# share_token уходит в HTML-атрибуты списков и в публичный URL /sub/<token>.
# Формат — uuid4 (models.generate_uuid), поэтому принимаем только его.
_SHARE_TOKEN_RE = re.compile(r"[0-9a-fA-F-]{16,64}")


class _SkipInbound(Exception):
    """Внутренний сигнал: запись не прошла валидацию — откатить savepoint
    этого инбаунда и перейти к следующему, не срывая весь импорт."""

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


def _validate_imported_inbound(d: dict, *, replace_id: int | None) -> str | None:
    """БЕЗОПАСНОСТЬ (аудит 2026-07): импорт обязан проходить те же проверки,
    что и обычное создание инбаунда (POST /api/inbounds/).

    Раньше _build_inbound клал поля из файла в БД напрямую, и через «дамп»
    можно было создать то, что REST-путь запрещает: протокол вне белого
    списка (например dokodemo — произвольный port-forward на localhost-сервисы
    вроде admin API Caddy), занять служебный порт, подсунуть зарезервированный
    tag (direct/block/api), протащить любые символы в tag (XSS в списках).
    Файл бэкапа приходит извне (его могут прислать/подменить), поэтому
    доверять ему нельзя.

    Возвращает текст ошибки или None. Проверки намеренно ТЕ ЖЕ, что в
    inbounds.py, чтобы импорт не мог обойти ни одну из них.

    Файлы сертификатов на существование НЕ проверяем (в отличие от create):
    восстановление на чистый сервер — штатный сценарий, а cert-bridge
    синхронизирует их позже. Ограничиваемся защитой от traversal.
    """
    from app.api.inbounds import (
        ENABLED_XRAY_PROTOCOLS, NAIVE_PROTOCOLS, VALID_TRANSPORTS,
        _check_port_conflicts, _request_is_reality, _validate_naive_inbound_domain,
    )
    from app.core.input_validators import (
        validate_domain, validate_enum, validate_port, validate_tag,
    )

    ok, err = validate_tag(d.get("tag"))
    if not ok:
        return err

    engine = d.get("engine", "xray")
    ok, err = validate_enum(engine, ("xray", "naive"), label="engine")
    if not ok:
        return err

    protocol = d.get("protocol") or ""
    allowed = NAIVE_PROTOCOLS if engine == "naive" else ENABLED_XRAY_PROTOCOLS
    if protocol not in allowed:
        return (f"протокол '{protocol}' недоступен для engine={engine} "
                f"(разрешены: {', '.join(sorted(allowed))})")

    # transport_config / extra_config хранятся как JSON-текст: битая строка
    # уронила бы генератор конфига уже после записи в БД.
    tcfg = {}
    for field in ("transport_config", "extra_config"):
        raw = d.get(field) or "{}"
        if not isinstance(raw, str):
            return f"{field} должен быть JSON-строкой"
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return f"{field} не является валидным JSON"
        if not isinstance(parsed, dict):
            return f"{field} должен быть JSON-объектом"
        if field == "transport_config":
            tcfg = parsed

    if engine == "xray":
        transport = d.get("transport")
        if transport is not None and transport not in VALID_TRANSPORTS:
            return f"неверный транспорт: {transport}"
        # Reality определяем так же, как REST-путь — по ключу в transport_config.
        is_reality = _request_is_reality({"protocol": protocol, "transport_config": tcfg})
        ok, err, port = validate_port(d.get("port"), allow_reality_443=is_reality)
        if not ok:
            return err
        conflict = _check_port_conflicts(
            port, exclude_inbound_id=replace_id, is_reality=is_reality)
        if conflict:
            return conflict
    else:
        err = _validate_naive_inbound_domain(d.get("domain"))
        if err:
            return err

    domain = d.get("domain")
    if domain:
        ok, err = validate_domain(domain)
        if not ok:
            return err

    for field in ("tls_cert_path", "tls_key_path"):
        path = d.get(field)
        if path and (not str(path).startswith("/") or ".." in str(path)):
            return f"{field} должен быть абсолютным путём без '..'"

    return None


def _validate_imported_client(c: dict) -> str | None:
    """Те же проверки, что POST /api/clients/ — файл бэкапа недоверенный.
    Главное: name попадает в списки UI, uuid/email/share_token — в ссылки."""
    from app.core.input_validators import validate_email, validate_uuid

    name = (c.get("name") or "").strip()
    if not name:
        return "клиент без имени"
    if len(name) > 128:
        return "имя клиента длиннее 128 символов"

    if c.get("uuid"):
        ok, err = validate_uuid(c["uuid"])
        if not ok:
            return err
    if c.get("email"):
        ok, err = validate_email(c["email"])
        if not ok:
            return err
    token = c.get("share_token")
    if token is not None and not _SHARE_TOKEN_RE.fullmatch(str(token)):
        return "share_token имеет неверный формат"
    return None


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

                # БЕЗОПАСНОСТЬ: файл бэкапа недоверенный — валидируем теми же
                # правилами, что и REST-создание. exclude_inbound_id нужен для
                # mode=replace: собственный порт заменяемого инбаунда не должен
                # считаться конфликтом (запись уже удалена выше, но проверка
                # порта опирается на БД до commit).
                verr = _validate_imported_inbound(
                    d, replace_id=(existing.id if existing else None))
                if verr:
                    errors.append(f"inbound '{tag}' пропущен: {verr}")
                    skipped_ib += 1
                    raise _SkipInbound

                ib = _build_inbound(d)
                db.session.add(ib)
                db.session.flush()  # получить ib.id
                engines_touched.add(ib.engine)

                for c in (d.get("clients") or []):
                    cerr = _validate_imported_client(c)
                    if cerr:
                        errors.append(f"клиент в '{tag}' пропущен: {cerr}")
                        skipped_cl += 1
                        continue
                    try:
                        with db.session.begin_nested():
                            db.session.add(_build_client(ib.id, c))
                            db.session.flush()
                            created_cl += 1
                    except SQLAlchemyError:
                        # дубликат email/username в рамках inbound и т.п.
                        skipped_cl += 1
                created_ib += 1
        except _SkipInbound:
            # Инбаунд не прошёл валидацию: savepoint откатился, сообщение
            # уже в errors[]. Продолжаем импорт остальных.
            continue
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
