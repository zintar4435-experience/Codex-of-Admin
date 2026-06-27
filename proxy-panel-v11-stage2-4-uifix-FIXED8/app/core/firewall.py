"""
UFW status reader для UI-индикатора «открыт ли порт в файрволе».

Контекст. Панель работает от пользователя proxypanel; `ufw status` без
sudo ничего не отдаёт. В sudoers (см. install.sh и
ensure_panel_ufw_sudoers в update.sh) добавлен read-only allow на
`sudo /usr/sbin/ufw status` и `sudo /usr/sbin/ufw status verbose`.
Никаких write-команд панели не дано — менять файрвол должен админ
руками. Это сознательное решение: UFW работает поверх iptables/nftables,
attack surface большой, и автоматическое управление правилами файрвола
из веб-панели — плохая идея с точки зрения безопасности.

Этот модуль:
  - Запускает `sudo ufw status verbose`, парсит вывод;
  - Кэширует результат в памяти процесса на TTL_SECONDS секунд
    (UFW-состояние редко меняется — кэш не даёт fork'аться на каждый
    запрос на странице инбаундов);
  - Fail-open: если UFW не установлен, sudo не работает, или вывод не
    разобрался — возвращает {"available": False}. UI в таком случае
    показывает «не удалось проверить» — это лучше чем зелёный
    false-positive.
"""
from __future__ import annotations

import logging
import re
import subprocess
import threading
import time

log = logging.getLogger(__name__)

UFW_BINARY = "/usr/sbin/ufw"
SUDO_BINARY = "/usr/bin/sudo"

# TTL для in-process кэша. UFW-состояние не меняется само — только когда
# админ дёргает руками. 10 сек достаточно чтобы UI чувствовал «живой
# отклик» после `ufw allow ...`, и не на каждый клик в форме делать
# subprocess.
TTL_SECONDS = 10

_lock = threading.Lock()
_cache: dict = {"ts": 0.0, "data": None}


# ─────────────────────────────────────────────────────────────────────
# Парсер вывода `ufw status verbose`
# ─────────────────────────────────────────────────────────────────────
#
# Пример (из Ubuntu 24.04):
#   Status: active
#   Logging: on (low)
#   Default: deny (incoming), allow (outgoing), disabled (routed)
#   New profiles: skip
#
#   To                         Action      From
#   --                         ------      ----
#   22/tcp                     ALLOW IN    Anywhere
#   80/tcp                     ALLOW IN    Anywhere
#   443                        ALLOW IN    Anywhere
#   8000:9000/tcp              ALLOW IN    Anywhere
#   OpenSSH                    ALLOW IN    Anywhere
#   22/tcp (v6)                ALLOW IN    Anywhere (v6)

_STATUS_RE = re.compile(r"^Status:\s*(\w+)", re.MULTILINE)
_DEFAULT_RE = re.compile(r"^Default:\s*(\w+)\s*\(incoming\)", re.MULTILINE)

# Match строк правил. Захватываем target (поле "To"), действие, источник.
# - target может быть: "22/tcp", "443", "8000:9000/tcp", "OpenSSH" и т.п.
# - action: "ALLOW IN", "DENY IN", "REJECT IN", "ALLOW OUT" (исходящие
#   нам не интересны для UI-индикатора входящего порта, но всё равно
#   парсим — пусть будет полная картина).
# Не учитываем `(v6)`-варианты как отдельные правила — IPv4/IPv6
# обычно дублируются, юзера интересует, открыт ли порт вообще.
_RULE_RE = re.compile(
    r"^"
    r"(?P<target>\S+(?:\s+\([^)]+\))?)"   # target (м.б. с "(v6)")
    r"\s{2,}"
    r"(?P<action>ALLOW|DENY|REJECT|LIMIT)\s+(?P<direction>IN|OUT|FWD)"
    r"\s{2,}"
    r"(?P<source>.+?)"
    r"\s*$",
    re.MULTILINE,
)


def _parse_target(target: str) -> tuple[str | None, str | None]:
    """
    "22/tcp"        → ("22", "tcp")
    "443"           → ("443", None)        # без proto — оба
    "8000:9000/tcp" → ("8000:9000", "tcp")
    "OpenSSH"       → (None, None)         # app-profile, не разбираем
    "22/tcp (v6)"   → ("22", "tcp")
    """
    s = re.sub(r"\s*\([^)]+\)$", "", target).strip()  # убираем "(v6)" и подобное
    if "/" in s:
        port_part, proto = s.rsplit("/", 1)
        proto = proto.lower()
        if proto not in ("tcp", "udp"):
            return None, None
    else:
        port_part, proto = s, None
    # Это число, диапазон, или app-profile?
    if re.match(r"^\d+(:\d+)?$", port_part):
        return port_part, proto
    # App-profile (OpenSSH, "Apache Full" и т.п.) — не разворачиваем.
    # Для UI достаточно знать про конкретные номера.
    return None, None


def _parse_ufw_output(text: str) -> dict:
    """Превращает текст `ufw status verbose` в структуру для API."""
    status_match = _STATUS_RE.search(text)
    if not status_match:
        return {
            "available": True,
            "active": False,
            "default_in": "unknown",
            "allowed_ports": [],
            "raw": text,
        }
    active = status_match.group(1).lower() == "active"
    default_match = _DEFAULT_RE.search(text)
    default_in = default_match.group(1).lower() if default_match else "unknown"

    rules: list[dict] = []
    seen: set[tuple] = set()  # дедуп IPv4/IPv6 близнецов
    for m in _RULE_RE.finditer(text):
        # Интересуют только INPUT'ы (на которые юзер заходит из сети).
        if m.group("direction") != "IN":
            continue
        port_part, proto = _parse_target(m.group("target"))
        if port_part is None:
            continue
        # Нормализуем source — убираем суффикс "(v6)", чтобы IPv4-/IPv6-
        # близнецы свернулись в одно правило (юзеру в UI всё равно).
        source = re.sub(r"\s*\(v6\)\s*$", "", m.group("source").strip())
        key = (port_part, proto, m.group("action"), source)
        if key in seen:
            continue
        seen.add(key)
        rules.append({
            "port": port_part,
            "proto": proto,                              # "tcp" / "udp" / None (оба)
            "action": m.group("action"),                 # ALLOW / DENY / REJECT / LIMIT
            "source": source,
        })

    return {
        "available": True,
        "active": active,
        "default_in": default_in,        # "deny" / "allow" / "reject" / "unknown"
        "allowed_ports": rules,
        "raw": text,
    }


def _run_ufw_status() -> dict:
    """
    Один shot: запускает `sudo ufw status verbose` и парсит вывод.
    Не кэширует — это делает обёртка get_ufw_status().
    """
    try:
        result = subprocess.run(
            [SUDO_BINARY, "-n", UFW_BINARY, "status", "verbose"],
            capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError as e:
        # sudo или ufw отсутствуют
        log.info("UFW status недоступен (binary не найден): %s", e)
        return {"available": False, "reason": "binary_not_found"}
    except subprocess.TimeoutExpired:
        log.warning("ufw status timeout — возможно sudo требует пароль.")
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        log.warning("Неожиданная ошибка при запросе ufw status: %s", e)
        return {"available": False, "reason": "error"}

    if result.returncode != 0:
        # Наиболее частый кейс — sudo не настроен (sudoers-запись не
        # подложена). Отдаём явно — UI покажет инструкцию.
        msg = (result.stderr or result.stdout or "").strip().splitlines()
        first_line = msg[0] if msg else f"RC={result.returncode}"
        log.info("ufw status RC=%d: %s", result.returncode, first_line)
        return {
            "available": False,
            "reason": "sudo_failed",
            "detail": first_line,
        }

    return _parse_ufw_output(result.stdout or "")


def get_ufw_status(*, force_refresh: bool = False) -> dict:
    """
    Возвращает кэшированное состояние UFW. TTL 10 сек.

    Структура:
      {"available": False, "reason": "binary_not_found"|"sudo_failed"|...}
        — UFW не доступен (не установлен / нет sudo).
      {"available": True, "active": bool, "default_in": "deny"|"allow"|"reject"|"unknown",
       "allowed_ports": [{"port": "8443", "proto": "tcp", "action": "ALLOW", "source": "Anywhere"}, ...]}
        — норма.
    """
    now = time.monotonic()
    with _lock:
        if not force_refresh and _cache["data"] is not None:
            if now - _cache["ts"] < TTL_SECONDS:
                return _cache["data"]
    data = _run_ufw_status()
    with _lock:
        _cache["ts"] = time.monotonic()
        _cache["data"] = data
    return data


def is_port_allowed(port: int, *, proto: str = "tcp") -> dict:
    """
    Проверяет, открыт ли указанный порт в UFW (с учётом default-policy
    и диапазонных правил). Удобно для UI-индикатора.

    Возвращает dict:
      {"status": "open"|"closed"|"unknown",
       "message": str,            # человекочитаемая строка для UI
       "hint": str | None}        # готовая команда для админа, если closed

    "unknown" — когда UFW недоступен или статус не определился.
    """
    status = get_ufw_status()
    proto_norm = proto.lower()
    if not status.get("available"):
        reason = status.get("reason", "unknown")
        if reason == "sudo_failed":
            msg = ("Не удалось проверить UFW (нужна миграция sudoers). "
                   "Перезапустите `bash update.sh panel`.")
        elif reason == "binary_not_found":
            msg = "UFW не установлен на сервере."
        else:
            msg = "Не удалось получить состояние UFW."
        return {"status": "unknown", "message": msg, "hint": None}

    if not status.get("active"):
        # UFW выключен — система пускает любые подключения. Внешний
        # cloud-firewall провайдера, если есть, мы из панели не видим.
        return {
            "status": "open",
            "message": ("UFW неактивен — все порты открыты на уровне "
                        "сервера. Проверьте облачный firewall провайдера, "
                        "если он есть."),
            "hint": None,
        }

    default_allow = status.get("default_in") == "allow"
    for rule in status.get("allowed_ports", []):
        # proto: если в правиле None — значит оба (tcp+udp).
        rp = rule.get("proto")
        if rp is not None and rp != proto_norm:
            continue
        port_part = rule.get("port", "")
        # Диапазон 8000:9000 ?
        if ":" in port_part:
            try:
                lo, hi = port_part.split(":", 1)
                if int(lo) <= port <= int(hi):
                    if rule["action"] == "ALLOW":
                        return {
                            "status": "open",
                            "message": (f"Порт {port}/{proto_norm} открыт в UFW "
                                        f"(правило {port_part}/{rp or 'any'} "
                                        f"{rule['action']} from {rule['source']})."),
                            "hint": None,
                        }
            except ValueError:
                continue
        else:
            try:
                if int(port_part) == port:
                    if rule["action"] == "ALLOW":
                        return {
                            "status": "open",
                            "message": (f"Порт {port}/{proto_norm} открыт в UFW "
                                        f"({rule['action']} from {rule['source']})."),
                            "hint": None,
                        }
            except ValueError:
                continue

    # Явного allow-правила нет.
    if default_allow:
        return {
            "status": "open",
            "message": (f"Явного правила для {port}/{proto_norm} нет, но "
                        f"default-policy UFW = allow incoming. Порт доступен."),
            "hint": None,
        }
    return {
        "status": "closed",
        "message": (f"Порт {port}/{proto_norm} НЕ открыт в UFW. "
                    f"Подключения извне будут получать timeout."),
        "hint": f"sudo ufw allow {port}/{proto_norm}",
    }
