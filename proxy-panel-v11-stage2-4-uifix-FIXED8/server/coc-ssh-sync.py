#!/usr/bin/env python3
"""
coc-ssh-sync — привилегированная половина SSH-движка панели.

Запускается ОТ ROOT по systemd-таймеру (coc-ssh-sync.timer, раз в минуту).
Панель работает от непривилегированного `proxypanel` и root-прав не получает:
она только описывает желаемое состояние в state.json, а этот скрипт приводит
к нему систему и кладёт обратно счётчики трафика. Почему именно так — см.
app/core/ssh.py: белый список sudoers панели сознательно узкий, и `useradd` с
`nft` в нём быть не должно, иначе любая компрометация процесса панели
превращается в root на хосте.

Соответственно, этот скрипт НЕ доверяет state.json. Всё, что он оттуда читает,
проверяется заново:
  • имя учётки обязано совпасть с ^cocssh_[0-9]{1,9}$ — трогаем только свои;
  • строка ключа обязана пройти регулярку формата authorized_keys;
  • ничего из файла не попадает в shell: subprocess вызывается списком
    аргументов, без shell=True.

Что делает за один проход:
  1. Заводит/удаляет системные учётки под клиентов панели (заперты: без шелла,
     без PTY, только проброс портов — запирающий Match-блок ставит install.sh).
  2. Раскладывает authorized_keys с опциями restrict,port-forwarding.
  3. Держит таблицу nftables со счётчиками трафика по каждой учётке.
  4. Пишет счётчики в traffic.json для шедулера панели.

УЧЁТ ТРАФИКА — как считается. Считаем ТОЛЬКО плечо «сервер↔цель», то есть
соединения, которые процесс учётки открывает наружу по просьбе клиента:
  up   — выход от процесса учётки к цели (meta skuid): то, что клиент отправил;
  down — ответы цели, помеченные ct mark этой учётки: то, что клиент получил.
Плечо «клиент↔сервер» (порт sshd) несёт те же самые байты второй раз, и учёт
обоих удвоил бы счёт.

ПОЧЕМУ ИМЕННО ЭТО ПЛЕЧО, А НЕ ПОРТ SSHD. Плечо «клиент↔сервер» к учётке
привязать нельзя в принципе: `meta skuid` смотрит на владельца СОКЕТА, а сокет
соединения создаёт root'овый sshd вызовом accept() ДО понижения прав. Понижение
прав владельца сокета уже не меняет (`sk_uid` проставляется при создании), и
правило `meta skuid <uid> tcp sport 22` не совпадает никогда — счётчики стоят
на нуле, а лимиты трафика не срабатывают вовсе.
Проверено замером на живом сервере 02.08.2026: при работающем туннеле правило
`tcp sport 22` и правило `meta skuid 0 tcp sport 22` дали ОДИНАКОВЫЕ показания,
а `meta skuid <uid учётки>` — ноль. Соединения же наружу процесс учётки
открывает сам, и там владелец сокета правильный.

Почему для входящих нужен ct mark: сопоставить пакет с владельцем сокета
(`meta skuid`) ядро умеет только на исходящем пути. Поэтому первый же
исходящий пакет соединения помечает conntrack-запись меткой учётки, и входящие
пакеты того же соединения считаются по этой метке.

Фильтра по порту в счётных правилах намеренно НЕТ: учётка заперта (nologin, без
шелла и PTY), никакой собственной сетевой активности, кроме проброшенных
соединений, у неё быть не может. Соединение «клиент↔сервер» под счёт не попадёт
— его сокет принадлежит root'у, а не учётке.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys
import tempfile

SPOOL_DIR = "/var/lib/proxy-panel/ssh"
STATE_PATH = os.path.join(SPOOL_DIR, "state.json")
TRAFFIC_PATH = os.path.join(SPOOL_DIR, "traffic.json")

HOME_ROOT = "/var/lib/coc-ssh"
USER_GROUP = "cocssh"
NFT_TABLE = "coc_ssh"

# Имя пустой цепочки-метки, обозначающей ФОРМУ счётных правил. Входит в
# отпечаток ruleset: пока имя совпадает, таблица считается актуальной.
# ПОДНИМАТЬ НОМЕР при любой правке формы правил (плечо, набор матчей,
# направления) — иначе на уже работающих серверах правила останутся старыми,
# потому что набор комментариев у них не меняется. Именно так и произошло
# 02.08.2026 при смене плеча учёта.
RULES_SCHEME_CHAIN = "scheme_v2"

# Пространство ct mark для наших меток: старший байт 0x0C выделен под этот
# скрипт, младшие — uid. Так метки не сталкиваются с чужими (ufw, docker,
# policy-routing), которые обычно живут в малых значениях.
MARK_BASE = 0x0C000000

USERNAME_RE = re.compile(r"^cocssh_[0-9]{1,9}$")
_KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384")
PUBKEY_RE = re.compile(
    r"^(?:" + "|".join(_KEY_TYPES) + r") [A-Za-z0-9+/]{20,1000}={0,3}(?: \S{0,64})?$"
)

# Опции authorized_keys. `restrict` выключает ВСЁ (pty, agent-forwarding,
# X11, user-rc, port-forwarding), после чего port-forwarding возвращается
# явно. Порядок важен: restrict обязан идти первым.
KEY_OPTIONS = "restrict,port-forwarding"

NFT = "/usr/sbin/nft"


def log(msg: str) -> None:
    print(f"coc-ssh-sync: {msg}", flush=True)


def run(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


# ---------------------------------------------------------------------------
# Чтение и проверка желаемого состояния
# ---------------------------------------------------------------------------

def load_state() -> dict | None:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        log(f"{STATE_PATH} нет — панель ещё не создавала SSH-инбаунд")
        return None
    except (OSError, ValueError) as e:
        log(f"ОШИБКА: {STATE_PATH} не прочитан: {e}")
        return None

    if not isinstance(state, dict):
        log("ОШИБКА: state.json не объект")
        return None

    try:
        port = int(state.get("port") or 22)
    except (TypeError, ValueError):
        port = 22
    if not (1 <= port <= 65535):
        log(f"ОШИБКА: недопустимый порт {port!r}, беру 22")
        port = 22

    users = []
    for entry in state.get("users") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("username") or "")
        if not USERNAME_RE.match(name):
            log(f"пропущена учётка с недопустимым именем: {name!r}")
            continue
        keys = [
            k.strip() for k in (entry.get("authorized_keys") or [])
            if isinstance(k, str) and PUBKEY_RE.match(k.strip())
        ]
        users.append({
            "username": name,
            "enabled": bool(entry.get("enabled")) and bool(keys),
            "keys": keys,
        })

    return {"port": port, "users": users}


# ---------------------------------------------------------------------------
# Системные учётки
# ---------------------------------------------------------------------------

def ensure_group() -> None:
    try:
        run(["/usr/bin/getent", "group", USER_GROUP])
    except subprocess.CalledProcessError:
        run(["/usr/sbin/groupadd", "--system", USER_GROUP])
        log(f"создана группа {USER_GROUP}")


def existing_managed_users() -> set[str]:
    return {u.pw_name for u in pwd.getpwall() if USERNAME_RE.match(u.pw_name)}


def ensure_user(username: str) -> None:
    try:
        pwd.getpwnam(username)
        return
    except KeyError:
        pass
    home = os.path.join(HOME_ROOT, username)
    run([
        "/usr/sbin/useradd",
        "--gid", USER_GROUP,
        "--home-dir", home,
        "--create-home",
        # nologin, а не оболочка: интерактивная сессия этой учётке не нужна.
        # Пробросу портов шелл не требуется — он идёт отдельными каналами.
        "--shell", "/usr/sbin/nologin",
        "--comment", "Codex of Connect tunnel user",
        username,
    ])
    # Пароля нет вовсе: вход только по ключу. `!` в поле пароля = вход по
    # паролю невозможен ни при каких настройках sshd.
    run(["/usr/bin/passwd", "--lock", username], check=False)
    log(f"создана учётка {username}")


def write_authorized_keys(username: str, keys: list[str]) -> None:
    info = pwd.getpwnam(username)
    ssh_dir = os.path.join(info.pw_dir, ".ssh")
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    os.chown(ssh_dir, info.pw_uid, info.pw_gid)
    os.chmod(ssh_dir, 0o700)

    path = os.path.join(ssh_dir, "authorized_keys")
    body = "".join(f"{KEY_OPTIONS} {k}\n" for k in keys)

    # Ничего не переписываем, если содержимое совпадает: лишняя запись меняет
    # mtime и мешает потом понять, когда учётку правда трогали.
    try:
        with open(path, "r", encoding="utf-8") as f:
            if f.read() == body:
                return
    except OSError:
        pass

    fd, tmp = tempfile.mkstemp(dir=ssh_dir, prefix=".ak-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(body)
    os.chown(tmp, info.pw_uid, info.pw_gid)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    log(f"{username}: authorized_keys обновлён ({len(keys)} ключ(ей))")


def lock_user(username: str) -> None:
    """Запереть учётку: ключи убрать, срок истечь, живые сессии оборвать.

    Одного пустого authorized_keys мало — уже установленная сессия от него не
    рвётся и продолжает возить трафик, а отключение по лимиту в таком случае
    ничего бы не отключило до тех пор, пока пользователь сам не отвалится.
    """
    try:
        pwd.getpwnam(username)
    except KeyError:
        return
    write_authorized_keys(username, [])
    # expiredate=1 — 1970-01-02, гарантированно в прошлом: sshd отказывает
    # такой учётке до проверки ключа.
    run(["/usr/sbin/usermod", "--expiredate", "1", username], check=False)
    run(["/usr/bin/pkill", "-KILL", "-u", username], check=False)


def unlock_user(username: str) -> None:
    run(["/usr/sbin/usermod", "--expiredate", "", username], check=False)


def delete_user(username: str) -> None:
    if not USERNAME_RE.match(username):
        return
    run(["/usr/bin/pkill", "-KILL", "-u", username], check=False)
    run(["/usr/sbin/userdel", "--remove", username], check=False)
    log(f"удалена учётка {username}")


def reconcile_users(users: list[dict]) -> dict[str, int]:
    """Приводит учётки к состоянию из state. Возвращает {username: uid} живых."""
    ensure_group()
    wanted = {u["username"] for u in users}

    for username in existing_managed_users() - wanted:
        # Учётки нет в желаемом состоянии — клиент удалён в панели.
        delete_user(username)

    uids: dict[str, int] = {}
    for u in users:
        name = u["username"]
        try:
            ensure_user(name)
        except subprocess.CalledProcessError as e:
            log(f"ОШИБКА: не создана учётка {name}: {e.stderr.strip()}")
            continue
        if u["enabled"]:
            write_authorized_keys(name, u["keys"])
            unlock_user(name)
        else:
            lock_user(name)
        try:
            # Счётчики держим и для запертых: их последний трафик должен
            # доехать в панель, а не пропасть вместе с правилом.
            uids[name] = pwd.getpwnam(name).pw_uid
        except KeyError:
            pass
    return uids


# ---------------------------------------------------------------------------
# nftables: счётчики трафика
# ---------------------------------------------------------------------------

def nft_available() -> bool:
    return os.path.exists(NFT)


def read_counters() -> dict[str, dict[str, int]]:
    """Текущие значения счётчиков из таблицы: {username: {up, down}}."""
    try:
        res = run([NFT, "-j", "list", "table", "inet", NFT_TABLE])
    except (subprocess.CalledProcessError, subprocess.SubprocessError, OSError):
        return {}
    try:
        data = json.loads(res.stdout)
    except ValueError:
        return {}

    out: dict[str, dict[str, int]] = {}
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        comment = rule.get("comment") or ""
        if not comment.startswith("cocssh:"):
            continue
        parts = comment.split(":")
        if len(parts) != 3:
            continue
        _, username, direction = parts
        for expr in rule.get("expr", []):
            counter = expr.get("counter")
            if isinstance(counter, dict) and "bytes" in counter:
                out.setdefault(username, {"up": 0, "down": 0})
                out[username][direction] = int(counter["bytes"])
    return out


def build_ruleset(uids: dict[str, int], port: int,
                  preserve: dict[str, dict[str, int]]) -> str:
    """Собирает полный ruleset. Счётчики выживших учёток переносятся.

    Перенос обязателен: без него каждая пересборка (добавили клиента) обнуляла
    бы счётчики всем, панель видела бы падение значения и начинала новую эпоху
    — трафик между двумя тиками терялся бы при каждом изменении списка.

    `port` в самих правилах больше не используется (см. шапку файла) — параметр
    оставлен, потому что порт по-прежнему пишется в лог пересборки.
    """
    mark_rules = []
    out_rules = []
    in_rules = []
    for username, uid in sorted(uids.items()):
        mark = MARK_BASE | (uid & 0xFFFFFF)
        kept = preserve.get(username, {})
        up_bytes = int(kept.get("up", 0))
        down_bytes = int(kept.get("down", 0))
        mark_rules.append(
            f"        meta skuid {uid} ct mark set {mark}"
        )
        # Плечо «сервер↔цель». Исходящее от процесса учётки — это то, что
        # клиент ОТПРАВИЛ (up); ответы цели по ct mark — то, что он ПОЛУЧИЛ
        # (down). Порт в правилах не фигурирует намеренно — см. шапку файла:
        # фильтр по порту sshd пришпиливал учёт к плечу «клиент↔сервер», где
        # сокет принадлежит root'у и совпадения не будет никогда.
        out_rules.append(
            f'        meta skuid {uid} '
            f'counter packets 0 bytes {up_bytes} comment "cocssh:{username}:up"'
        )
        in_rules.append(
            f'        ct mark {mark} '
            f'counter packets 0 bytes {down_bytes} comment "cocssh:{username}:down"'
        )

    return "\n".join([
        # Идиома «создать-и-удалить»: `delete table` на несуществующей таблице
        # — ошибка, а `table` её создаёт, если её нет. Вместе получается
        # идемпотентный сброс, после которого таблица собирается заново.
        f"table inet {NFT_TABLE}",
        f"delete table inet {NFT_TABLE}",
        f"table inet {NFT_TABLE} {{",
        # Пометка идёт РАНЬШЕ подсчёта (priority -150), чтобы соединение уже
        # было помечено к моменту, когда его увидит счётная цепочка.
        # Имя цепочки НЕ 'mark': это зарезервированное слово грамматики nft,
        # и такой ruleset не парсится.
        "    chain mark_flows {",
        "        type filter hook output priority -150; policy accept;",
        *mark_rules,
        "    }",
        "    chain count_out {",
        "        type filter hook output priority 0; policy accept;",
        *out_rules,
        "    }",
        "    chain count_in {",
        "        type filter hook input priority 0; policy accept;",
        *in_rules,
        "    }",
        # Метка ФОРМЫ правил. Пустая обычная цепочка (без hook) — к ней ничто
        # не обращается, на трафик она не влияет и стоит ноль.
        #
        # Зачем. Отпечаток ниже сравнивает набор комментариев вида
        # «cocssh:<учётка>:<направление>». Когда 02.08.2026 у правил сменилось
        # ПЛЕЧО (убран фильтр по порту sshd), комментарии остались прежними —
        # отпечаток совпал, и скрипт на живом сервере решил, что пересобирать
        # нечего. Правила остались старыми, починка не доехала.
        # Теперь любая правка формы правил = новый номер здесь, и пересборка
        # происходит принудительно.
        f"    chain {RULES_SCHEME_CHAIN} {{ }}",
        "}",
        "",
    ])


def current_signature() -> str | None:
    """Отпечаток действующего ruleset: набор учёток И форма правил.

    Нужен, чтобы НЕ пересобирать таблицу на каждом тике: пересборка — это
    короткое окно, когда счётчиков нет, а трафик идёт.

    Форма правил учитывается через имя цепочки-метки: одного набора учёток
    мало, потому что смена ПЛЕЧА учёта комментарии не меняет (см. build_ruleset).
    """
    try:
        res = run([NFT, "-j", "list", "table", "inet", NFT_TABLE])
        data = json.loads(res.stdout)
    except (subprocess.SubprocessError, OSError, ValueError):
        return None
    marks = []
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if rule and (rule.get("comment") or "").startswith("cocssh:"):
            marks.append(rule["comment"])
        chain = item.get("chain")
        if chain and str(chain.get("name", "")).startswith("scheme_v"):
            marks.append(f"scheme:{chain['name']}")
    return "|".join(sorted(marks))


def wanted_signature(uids: dict[str, int]) -> str:
    marks = [f"scheme:{RULES_SCHEME_CHAIN}"]
    for username in uids:
        marks.append(f"cocssh:{username}:down")
        marks.append(f"cocssh:{username}:up")
    return "|".join(sorted(marks))


def sync_counters(uids: dict[str, int], port: int) -> dict[str, dict[str, int]]:
    if not nft_available():
        log("nft не найден — учёт трафика SSH отключён")
        return {}

    existing = read_counters()
    if current_signature() != wanted_signature(uids) or not uids:
        ruleset = build_ruleset(uids, port, existing)
        try:
            subprocess.run([NFT, "-f", "-"], input=ruleset, text=True,
                           check=True, capture_output=True, timeout=30)
            log(f"правила учёта пересобраны ({len(uids)} учёток, порт {port})")
        except subprocess.CalledProcessError as e:
            # Учёт трафика — не повод ломать доступ: учётки уже приведены в
            # порядок выше, и туннель работает даже без счётчиков.
            log(f"ОШИБКА nft (учёт трафика пропущен): {e.stderr.strip()}")
            return existing
        except (subprocess.SubprocessError, OSError) as e:
            log(f"ОШИБКА nft (учёт трафика пропущен): {e}")
            return existing

    return read_counters() or existing


def write_traffic(counters: dict[str, dict[str, int]]) -> None:
    payload = {"version": 1, "users": counters}
    os.makedirs(SPOOL_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=SPOOL_DIR, prefix=".traffic-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        # Панель файл только читает: 0640 root:proxypanel.
        os.chmod(tmp, 0o640)
        try:
            import grp
            os.chown(tmp, 0, grp.getgrnam("proxypanel").gr_gid)
        except (KeyError, OSError):
            pass
        os.replace(tmp, TRAFFIC_PATH)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def main() -> int:
    if os.geteuid() != 0:
        log("скрипт обязан запускаться от root")
        return 1

    state = load_state()
    if state is None:
        return 0

    try:
        uids = reconcile_users(state["users"])
    except Exception as e:
        log(f"ОШИБКА при синхронизации учёток: {e}")
        return 1

    counters = sync_counters(uids, state["port"])

    try:
        write_traffic(counters)
    except OSError as e:
        log(f"ОШИБКА: счётчики не записаны: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
