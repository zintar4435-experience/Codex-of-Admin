"""
SSH-движок: узел «туннель поверх обычной SSH-сессии».

── ЗАЧЕМ ЭТО ЕСТЬ ──────────────────────────────────────────────────────────
SSH — единственный из наших протоколов, по которому НЕ бьёт объёмная заморозка
соединений (отчёт net4people #490: SSH и SFTP из-под неё исключены). Причина не
в маскировке, а в цене вопроса: на SSH живут хостинги и разработчики, и широко
резать его дороже, чем терпеть.

ЧЕСТНО О ЦЕНЕ. SSH не маскируется вовсе: соединение начинается с открытой
строки `SSH-2.0-...`, и DPI опознаёт его с первого байта. Это разрешение, а не
невидимость. Поэтому SSH — запасная нога, которая ломается по ДРУГИМ причинам,
чем TLS-протоколы, а не замена основному каналу.

── ПОЧЕМУ ПАНЕЛЬ НЕ ДЕЛАЕТ ЭТО САМА ────────────────────────────────────────
Учётки SSH — это учётки ОС. Их заведение требует root, как и правила учёта
трафика. Панель работает от непривилегированного `proxypanel`, и её белый
список sudoers сознательно узкий: даже файрволом она только ЧИТАЕТ статус
(см. core/firewall.py) — «автоматически управлять файрволом из веб-панели
плохая идея с точки зрения безопасности». Дать ей `useradd` и `nft` означало бы
превратить любую компрометацию процесса панели (баг в зависимости, увод сессии)
в root на хосте.

Поэтому здесь разделение:
  • ПАНЕЛЬ (этот модуль) только ОПИСЫВАЕТ желаемое состояние в JSON-файл
    STATE_PATH и только ЧИТАЕТ счётчики из TRAFFIC_PATH. Никакого sudo.
  • ROOT-скрипт `/usr/local/bin/coc-ssh-sync.py` (ставится install.sh, запуск
    по systemd-таймеру) приводит систему к этому состоянию и пишет счётчики
    обратно. Он заново проверяет ВСЁ, что читает: скомпрометированная панель
    может записать в state только то, что пройдёт его валидацию, и трогает он
    исключительно учётки со своим префиксом.

Цена разделения — задержка: изменения доезжают за один тик таймера (60 с), а не
мгновенно. Для отключения по лимиту это приемлемо (и явно описано в README).
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile

log = logging.getLogger(__name__)

# Каталог обмена между панелью и root-скриптом. Создаётся install.sh:
# владелец root:proxypanel, права 0770 — панель пишет state, root пишет traffic.
SPOOL_DIR = "/var/lib/proxy-panel/ssh"
STATE_PATH = os.path.join(SPOOL_DIR, "state.json")
TRAFFIC_PATH = os.path.join(SPOOL_DIR, "traffic.json")

# Префикс имён управляемых учёток. Root-скрипт трогает ТОЛЬКО их: без префикса
# ошибка в панели (или подстановка в БД) могла бы снести системного
# пользователя. Имя клиента в него не входит — оно берётся из client.id, чтобы
# переименование клиента не порождало новую учётку и не теряло трафик.
USER_PREFIX = "cocssh_"

# Группа, по которой sshd применяет запирающий Match-блок (см. install.sh).
USER_GROUP = "cocssh"

# Порт по умолчанию. Отдельный от системного 22 НЕ делаем: смысл SSH здесь
# именно в том, что он выглядит как обычный административный SSH, а нестандартный
# порт — сам по себе аномалия.
DEFAULT_PORT = 22

HOST_KEY_PATHS = (
    "/etc/ssh/ssh_host_ed25519_key.pub",
    "/etc/ssh/ssh_host_rsa_key.pub",
)

# Разрешённые типы клиентских ключей. ssh-rsa намеренно нет: OpenSSH ≥8.8
# по умолчанию не принимает подпись rsa-sha, и такой ключ дал бы клиенту
# «пароль верный, а войти нельзя» без внятной ошибки.
_KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384")
_PUBKEY_RE = re.compile(
    r"^(?:" + "|".join(_KEY_TYPES) + r") [A-Za-z0-9+/]{20,1000}={0,3}(?: \S{0,64})?$"
)


def os_username(client_id: int) -> str:
    """Имя системной учётки для клиента панели."""
    return f"{USER_PREFIX}{int(client_id)}"


# ---------------------------------------------------------------------------
# Ключевая пара клиента
# ---------------------------------------------------------------------------

def _ssh_keygen_path() -> str | None:
    """Путь к ssh-keygen. Сначала известные абсолютные, потом PATH.

    Абсолютные первыми намеренно: поиск по PATH в сервисе — способ подсунуть
    свой бинарник, если кто-то дотянулся до окружения процесса. PATH здесь
    только запасной вариант для нестандартных дистрибутивов.
    """
    import shutil

    for candidate in ("/usr/bin/ssh-keygen", "/bin/ssh-keygen"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("ssh-keygen")


def generate_keypair(comment: str = "") -> tuple[str, str] | None:
    """Генерирует ed25519-пару через ssh-keygen. Возвращает (private, public).

    ssh-keygen, а не библиотека: `cryptography` в зависимостях панели нет, а
    тащить её ради одной операции — лишняя поверхность. ssh-keygen есть на
    любом сервере, где вообще есть sshd.

    Ключ без парольной фразы: его вводить некому — приложение подключается
    само. Защита ключа — права на файл и то, что учётка заперта.
    """
    keygen = _ssh_keygen_path()
    if keygen is None:
        log.warning("ssh-keygen не найден — ключ не сгенерирован")
        return None

    safe_comment = re.sub(r"[^A-Za-z0-9._@-]", "", comment or "codex")[:48] or "codex"
    tmpdir = tempfile.mkdtemp(prefix="cocssh-")
    key_path = os.path.join(tmpdir, "id_ed25519")
    try:
        subprocess.run(
            [keygen, "-q", "-t", "ed25519", "-N", "",
             "-C", safe_comment, "-f", key_path],
            check=True, capture_output=True, timeout=20,
        )
        with open(key_path, "r", encoding="utf-8") as f:
            private = f.read()
        with open(key_path + ".pub", "r", encoding="utf-8") as f:
            public = f.read().strip()
        return private, public
    except (subprocess.SubprocessError, OSError) as e:
        log.warning("ssh-keygen не отработал: %s", e)
        return None
    finally:
        for p in (key_path, key_path + ".pub"):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def is_valid_public_key(line: str) -> bool:
    """Проверка строки публичного ключа (формат authorized_keys)."""
    return bool(_PUBKEY_RE.match((line or "").strip()))


def get_host_public_key() -> str | None:
    """Публичный ключ ЭТОГО сервера — уезжает клиенту в ссылке.

    Без него клиент принимает любой ключ сервера, и подмена на пути становится
    возможной. Предпочитаем ed25519: он короче и его понимают все клиенты.
    Комментарий (третье поле, обычно `root@hostname`) отрезаем — он раскрывает
    имя хоста и на проверку не влияет.
    """
    for path in HOST_KEY_PATHS:
        try:
            with open(path, "r", encoding="utf-8") as f:
                parts = f.read().strip().split()
        except OSError:
            continue
        if len(parts) >= 2:
            return f"{parts[0]} {parts[1]}"
    log.warning("Публичный ключ хоста не прочитан (%s)", ", ".join(HOST_KEY_PATHS))
    return None


# ---------------------------------------------------------------------------
# Желаемое состояние → файл
# ---------------------------------------------------------------------------

def build_ssh_state() -> dict:
    """Собирает желаемое состояние SSH-учёток из БД.

    Активность считаем по client.is_active — это уже учитывает и enabled, и
    срок, и превышение лимита. Неактивный клиент попадает в state с
    enabled=false, а НЕ исчезает из него: разница важна, потому что исчезнувшая
    запись означает «удалить учётку и потерять её трафик», а enabled=false —
    «запереть, сессии оборвать, счётчики сохранить».
    """
    from app.models import Client, Inbound

    inbounds = Inbound.query.filter_by(engine="ssh").all()
    users: list[dict] = []
    port = DEFAULT_PORT

    for ib in inbounds:
        if ib.port:
            port = int(ib.port)
        if not ib.enabled:
            # Инбаунд выключен — все его клиенты заперты, но не удалены.
            for c in ib.clients:
                users.append(_user_entry(c, enabled=False))
            continue
        for c in ib.clients:
            users.append(_user_entry(c, enabled=bool(c.is_active)))

    return {"version": 1, "port": port, "group": USER_GROUP, "users": users}


def _user_entry(client, enabled: bool) -> dict:
    key = (client.ssh_public_key or "").strip()
    return {
        "username": os_username(client.id),
        "client_id": client.id,
        "enabled": bool(enabled and is_valid_public_key(key)),
        "authorized_keys": [key] if is_valid_public_key(key) else [],
    }


def apply_ssh_config() -> tuple[bool, str | None]:
    """Записывает желаемое состояние. Реальное применение — за root-скриптом.

    Запись атомарная (tmp + rename в том же каталоге): root-скрипт читает файл
    по таймеру и обязан увидеть либо старое состояние целиком, либо новое
    целиком. Недописанный JSON он отбросит, но тогда тик пропадёт зря.
    """
    try:
        state = build_ssh_state()
    except Exception as e:
        log.exception("build_ssh_state failed")
        return False, f"SSH: ошибка построения состояния: {e}"

    try:
        os.makedirs(SPOOL_DIR, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=SPOOL_DIR, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o640)
            os.replace(tmp, STATE_PATH)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    except OSError as e:
        # Каталога нет или нет прав — значит install.sh/update.sh ещё не
        # раскатывали SSH-часть. Это не повод ронять apply остальных движков.
        log.warning("SSH state не записан (%s): %s", STATE_PATH, e)
        return False, (
            f"SSH: не удалось записать {STATE_PATH} ({e}). "
            f"Похоже, серверная часть SSH ещё не установлена — "
            f"выполните update.sh на сервере."
        )

    log.info("SSH state записан: %d учёток", len(state["users"]))
    return True, None


# ---------------------------------------------------------------------------
# Счётчики трафика
# ---------------------------------------------------------------------------

def read_ssh_traffic() -> dict[str, dict]:
    """Читает счётчики, записанные root-скриптом: {username: {up, down}}.

    Значения НАКОПИТЕЛЬНЫЕ с момента создания правил nftables, а не дельты.
    Они обнуляются при пересборке таблицы (перезагрузка сервера, рестарт
    сервиса) — ровно тот случай, который умеет ловить _accumulate_delta в
    шедулере, поэтому здесь ничего не сглаживаем.

    up   — байты ОТ клиента К серверу (его исходящий трафик);
    down — байты ОТ сервера К клиенту (его входящий).
    Считается только плечо «клиент↔сервер»: плечо «сервер↔цель» несёт те же
    самые байты второй раз, и учёт обоих удвоил бы счёт.
    """
    try:
        with open(TRAFFIC_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log.warning("Счётчики SSH не прочитаны (%s): %s", TRAFFIC_PATH, e)
        return {}

    users = data.get("users")
    if not isinstance(users, dict):
        return {}

    out: dict[str, dict] = {}
    for username, counters in users.items():
        if not isinstance(counters, dict):
            continue
        try:
            out[str(username)] = {
                "up": max(0, int(counters.get("up", 0) or 0)),
                "down": max(0, int(counters.get("down", 0) or 0)),
            }
        except (TypeError, ValueError):
            continue
    return out


def sync_status() -> dict:
    """Состояние связки панель↔root-скрипт — для индикатора в UI.

    Показываем ТРИ разных факта, потому что они ломаются независимо:
      • installed  — каталог обмена есть (серверная часть раскатана);
      • state_age  — сколько секунд назад панель писала желаемое состояние;
      • traffic_age — сколько секунд назад root-скрипт отчитывался.
    Если traffic_age растёт и переваливает за пару минут — таймер не работает,
    и учётки в системе разъехались с тем, что показывает панель.
    """
    import time

    now = time.time()

    def _age(path: str):
        try:
            return int(now - os.stat(path).st_mtime)
        except OSError:
            return None

    return {
        "installed": os.path.isdir(SPOOL_DIR),
        "state_age": _age(STATE_PATH),
        "traffic_age": _age(TRAFFIC_PATH),
    }
