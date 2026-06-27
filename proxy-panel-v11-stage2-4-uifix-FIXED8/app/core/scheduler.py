"""
Background scheduler.

Runs in a SEPARATE systemd unit (proxy-panel-scheduler.service), NOT inside
gunicorn workers — иначе при --workers=N задачи запускались бы N раз
параллельно, конкурируя за SQLite и дублируя apply_*_config().

Job list:
  1. Poll Xray Stats API every minute → update client traffic counters.
  2. Poll Caddy access logs every 5 minutes → update NaiveProxy client traffic.
  3. Check client expiry / over-limit → disable + re-apply configs.
  4. Auto-update split-tunnel lists from remote URLs (daily).
"""
import logging
from datetime import datetime, timezone

from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def _accumulate_delta(client, new_up: int, new_down: int) -> tuple[int, int]:
    """Корректный учёт трафика для клиента с защитой от сброса внешнего счётчика.

    Внешний счётчик (Xray stats / сумма из Caddy access-log) ненадёжен:
    он обнуляется при рестарте Xray и падает при ротации логов Caddy.
    Поэтому мы храним «последнее увиденное» значение в client.last_seen_*
    и считаем дельту относительно него:

      * new >= last_seen — нормальный рост, дельта = new - last_seen
      * new <  last_seen — внешний счётчик упал (рестарт/ротация),
                           считаем всё, что есть сейчас, новой дельтой

    Возвращает (delta_up, delta_down). На стороне вызова — прибавить эти
    значения к client.traffic_used_* (это и есть accumulator).
    """
    last_up = client.last_seen_up or 0
    last_down = client.last_seen_down or 0

    if new_up >= last_up:
        delta_up = new_up - last_up
    else:
        # внешний счётчик упал — была новая эпоха (рестарт/ротация)
        log.info(
            "Клиент %s: счётчик up упал (%d → %d), начинаем новую эпоху",
            client.name, last_up, new_up,
        )
        delta_up = new_up

    if new_down >= last_down:
        delta_down = new_down - last_down
    else:
        log.info(
            "Клиент %s: счётчик down упал (%d → %d), начинаем новую эпоху",
            client.name, last_down, new_down,
        )
        delta_down = new_down

    client.last_seen_up = new_up
    client.last_seen_down = new_down
    return delta_up, delta_down


def _sync_xray_traffic():
    """Pull per-client stats from Xray Stats API and update DB."""
    from app.models import db, Client, TrafficStat
    from app.core.xray import get_xray_stats

    app = _get_app()
    with app.app_context():
        clients = Client.query.filter(
            Client.enabled == True,
            Client.inbound.has(engine="xray"),
        ).all()

        changed = False
        for client in clients:
            email = client.email or client.name
            stats = get_xray_stats(email)
            new_up = stats.get("up", 0) or 0
            new_down = stats.get("down", 0) or 0

            last_up = client.last_seen_up or 0
            last_down = client.last_seen_down or 0

            # Если ровно те же значения, что были — ничего не изменилось.
            if new_up == last_up and new_down == last_down:
                continue

            delta_up, delta_down = _accumulate_delta(client, new_up, new_down)
            # _accumulate_delta уже обновил last_seen_* в объекте клиента —
            # сессия SQLAlchemy теперь видит его dirty, commit нужен.
            changed = True

            if delta_up > 0 or delta_down > 0:
                client.traffic_used_up = (client.traffic_used_up or 0) + delta_up
                client.traffic_used_down = (client.traffic_used_down or 0) + delta_down
                db.session.add(TrafficStat(
                    client_id=client.id,
                    delta_up=delta_up,
                    delta_down=delta_down,
                ))

        if changed:
            db.session.commit()


def _sync_caddy_traffic():
    """Прибавить трафик NaiveProxy-клиентов по приросту из access-log Caddy.

    get_caddy_traffic_from_logs теперь возвращает ДЕЛЬТУ (новые байты с
    прошлого вызова) и сама хранит позицию чтения в state-файле, поэтому
    здесь дельту просто прибавляем к накопителю. last_seen_* для naive
    больше не используется (это была защита для накопительного счётчика,
    которым лог Caddy не является).
    """
    import os
    from app.models import db, Client, TrafficStat, Inbound
    from app.core.caddy import get_caddy_traffic_from_logs

    app = _get_app()
    with app.app_context():
        state_path = os.path.join(app.instance_path, "caddy_traffic.state")
        deltas = get_caddy_traffic_from_logs(state_path=state_path)
        if not deltas:
            return

        naive_clients = (
            Client.query
            .join(Inbound)
            .filter(Inbound.engine == "naive", Client.enabled == True)
            .all()
        )

        changed = False
        for client in naive_clients:
            username = client.username or client.name
            d = deltas.get(username)
            if not d:
                continue
            du = int(d.get("up", 0) or 0)
            dd = int(d.get("down", 0) or 0)
            if du <= 0 and dd <= 0:
                continue
            client.traffic_used_up = (client.traffic_used_up or 0) + du
            client.traffic_used_down = (client.traffic_used_down or 0) + dd
            db.session.add(TrafficStat(
                client_id=client.id,
                delta_up=du,
                delta_down=dd,
            ))
            changed = True

        if changed:
            db.session.commit()


def _enforce_limits():
    """
    Disable clients that have exceeded limits or expired.
    Re-apply Xray + Caddy configs if anything changed.
    """
    from app.models import db, Client
    from app.core.xray import apply_xray_config
    from app.core.caddy import apply_caddy_config

    app = _get_app()
    with app.app_context():
        active_clients = Client.query.filter_by(enabled=True).all()
        changed = False

        for client in active_clients:
            should_disable = client.is_expired or client.is_over_limit
            if should_disable:
                log.info(
                    "Disabling client %s (expired=%s, over_limit=%s)",
                    client.name, client.is_expired, client.is_over_limit
                )
                client.enabled = False
                changed = True

        if changed:
            db.session.commit()
            apply_xray_config()
            apply_caddy_config()


def _update_split_tunnel_lists():
    """Fetch updated IP/domain lists from configured URLs."""
    import urllib.request
    from app.models import db, SplitTunnelList

    app = _get_app()
    with app.app_context():
        lists = SplitTunnelList.query.filter(
            SplitTunnelList.source_url != None,
            SplitTunnelList.enabled == True,
        ).all()

        for lst in lists:
            if not (lst.source_url or "").lower().startswith(("http://", "https://")):
                log.warning("Пропущен split-tunnel список %r: URL не http(s)", lst.name)
                continue
            try:
                with urllib.request.urlopen(lst.source_url, timeout=30) as resp:
                    content = resp.read().decode("utf-8", errors="replace")
                lst.content = content
                lst.last_updated = datetime.now(timezone.utc)
                log.info("Updated split-tunnel list '%s' (%d bytes)", lst.name, len(content))
            except Exception as e:
                log.warning("Failed to update split-tunnel list '%s': %s", lst.name, e)

        db.session.commit()


# ---------------------------------------------------------------------------
# Audit log cleanup (этап 4)
# ---------------------------------------------------------------------------

def _cleanup_audit_logs():
    """Удалить записи audit-лога старше retention_days.

    Срок хранения берётся из Setting('audit_retention_days') или 90 по умолчанию.
    Запись о самой очистке в аудит НЕ пишется — иначе при каждом запуске
    cleanup будет порождать новую запись, которая через retention_days попадёт
    под следующий cleanup, и так далее. Логируем в обычный лог.
    """
    from app.core.audit import cleanup_old_logs
    from app.models import Setting

    app = _get_app()
    with app.app_context():
        days_raw = Setting.get("audit_retention_days", "90")
        try:
            days = max(1, int(days_raw))
        except (ValueError, TypeError):
            days = 90

        deleted = cleanup_old_logs(retention_days=days)
        if deleted:
            log.info("audit cleanup: удалено %d записей старше %d дней", deleted, days)


# ---------------------------------------------------------------------------
# App reference (set during init)
# ---------------------------------------------------------------------------

_app_ref = None


def _get_app():
    if _app_ref is None:
        raise RuntimeError("Scheduler not initialized with app")
    return _app_ref


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_blocking(app):
    """Запуск шедулера как блокирующего процесса.

    Используется systemd-юнитом proxy-panel-scheduler.service.
    Из веб-приложения НЕ вызывается — иначе каждый gunicorn-воркер
    создаёт свою копию задач, что ломает учёт трафика и
    дублирует apply_xray_config()/apply_caddy_config().
    """
    import signal
    from apscheduler.schedulers.blocking import BlockingScheduler

    # Логирование в stdout/stderr → systemd journal.
    # Без этого Python logging глотает INFO, и в journalctl ничего нет.
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

    global _app_ref
    _app_ref = app

    scheduler = BlockingScheduler(timezone="UTC")

    scheduler.add_job(
        _sync_xray_traffic,
        trigger=IntervalTrigger(seconds=60),
        id="sync_xray_traffic",
        replace_existing=True,
    )
    scheduler.add_job(
        _sync_caddy_traffic,
        trigger=IntervalTrigger(seconds=300),
        id="sync_caddy_traffic",
        replace_existing=True,
    )
    scheduler.add_job(
        _enforce_limits,
        trigger=IntervalTrigger(seconds=60),
        id="enforce_limits",
        replace_existing=True,
    )
    scheduler.add_job(
        _update_split_tunnel_lists,
        trigger=IntervalTrigger(hours=6),
        id="update_split_lists",
        replace_existing=True,
    )
    # Очистка старых записей audit-лога — раз в сутки.
    # Достаточно редкая операция; срок хранения настраивается через
    # Setting('audit_retention_days'), по умолчанию 90 дней.
    scheduler.add_job(
        _cleanup_audit_logs,
        trigger=IntervalTrigger(hours=24),
        id="cleanup_audit_logs",
        replace_existing=True,
    )

    def _shutdown(signum, frame):
        log.info("Получен сигнал %s, останавливаем шедулер", signum)
        scheduler.shutdown(wait=False)

    # systemd при stop шлёт SIGTERM — перехватываем для чистого выхода.
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info("Шедулер запущен (отдельный процесс)")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    log.info("Шедулер завершён")
