"""
apply_runner — асинхронный apply конфигов Xray/Caddy.

Зачем:
  В shared-443 режиме цепочка запроса пользователя проходит через Caddy.
  Когда backend вызывает apply_caddy_config() (POST /load к Caddy admin API)
  прямо внутри HTTP-обработчика — Caddy перевешивает listeners, текущий
  TCP-туннель рвётся, и браузер получает «Failed to fetch» даже если backend
  всё успешно сохранил.

Решение:
  1. Pre-validation (xray run -test) остаётся СИНХРОННОЙ — она защищает от
     ситуации «Caddy уехал на loopback, Xray не встал, :443 пустой».
  2. Сам apply (apply_caddy_config + apply_xray_config) запускается в
     daemon-треде. Handler сразу возвращает 200/201 с {apply_id: uuid}.
  3. Статус apply хранится в APPLY_STATUS (in-memory dict) с TTL.
  4. UI делает 1-3 polling GET /api/system/apply-status/<uuid>.

Mutex:
  Глобальный threading.Lock() предотвращает два параллельных apply.
  Если apply уже идёт — новый ставится в очередь через acquire() с
  timeout. При превышении timeout возвращается статус «busy».

  Примечание про multi-worker gunicorn: Lock работает только внутри одного
  процесса. При 2+ воркерах два apply могут идти параллельно из разных
  процессов — это допустимо (два reload Caddy подряд, оба idempotent).
  Критического race нет: последний apply победит, конфиг будет корректным.
"""
import threading
import time
import uuid as uuid_mod
from typing import Literal

# ── Статус-кеш ──────────────────────────────────────────────────────────────
# {uuid: {"status": "pending"|"ok"|"error", "msg": str|None, "exp": float}}
_STATUS: dict[str, dict] = {}
_STATUS_LOCK = threading.Lock()
_STATUS_TTL = 120  # секунды

# ── Apply mutex ──────────────────────────────────────────────────────────────
_APPLY_LOCK = threading.Lock()
_APPLY_TIMEOUT = 30  # сек — сколько ждём освобождения мутекса


def _set_status(apply_id: str, status: Literal["pending", "ok", "error"], msg: str | None = None):
    with _STATUS_LOCK:
        _STATUS[apply_id] = {
            "status": status,
            "msg": msg,
            "exp": time.monotonic() + _STATUS_TTL,
        }
        # Попутно чистим просроченные записи (раз в N вызовов это дёшево)
        expired = [k for k, v in _STATUS.items() if v["exp"] < time.monotonic()]
        for k in expired:
            del _STATUS[k]


def get_status(apply_id: str) -> dict | None:
    """Возвращает {status, msg} или None если uuid неизвестен/просрочен."""
    with _STATUS_LOCK:
        entry = _STATUS.get(apply_id)
        if entry is None:
            return None
        if entry["exp"] < time.monotonic():
            del _STATUS[apply_id]
            return None
        return {"status": entry["status"], "msg": entry["msg"]}


def _run_apply(apply_id: str, engine: str, app):
    """Выполняется в фоновом треде. Захватывает app context и мутекс, делает apply."""
    with app.app_context():
        acquired = _APPLY_LOCK.acquire(timeout=_APPLY_TIMEOUT)
        if not acquired:
            _set_status(apply_id, "error", "Apply занят — попробуйте через несколько секунд")
            return
        try:
            from app.api.inbounds import _apply_for_engine
            ok, msg = _apply_for_engine(engine)
            if ok:
                _set_status(apply_id, "ok")
            else:
                _set_status(apply_id, "error", msg)
        except Exception as e:
            _set_status(apply_id, "error", str(e))
        finally:
            _APPLY_LOCK.release()


def start_apply(engine: str) -> str:
    """
    Запускает apply в фоновом треде.
    Возвращает apply_id — UUID для последующего GET /api/system/apply-status/<id>.

    Вызывать ПОСЛЕ db.session.commit() и ПОСЛЕ синхронной pre-validation.
    """
    from flask import current_app
    app = current_app._get_current_object()
    apply_id = str(uuid_mod.uuid4())
    _set_status(apply_id, "pending")
    t = threading.Thread(target=_run_apply, args=(apply_id, engine, app), daemon=True)
    t.start()
    return apply_id
