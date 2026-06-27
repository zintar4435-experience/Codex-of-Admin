"""
Валидатор geosite:/geoip:-кодов, используемых в правилах роутинга.

Зачем нужен. В правиле RoutingRule поля match_domains / match_ips —
произвольные строки, которые попадают в Xray-конфиг как есть. Если там
оказывается, например, "geosite:ru" — а в установленной у пользователя
geosite.dat (v2fly/domain-list-community → dlc.dat) такой категории нет
— Xray на старте падает с "code not found in geosite.dat: RU" и уходит
в crash loop через systemd. Это уже произошло (см. историю v11-stage1-5).

Подход. Авторитетный источник истины — сам бинарь xray, режим
`xray run -test -c <probe>`. Мы строим минимальный пробный конфиг,
содержащий проверяемые коды как routing-правило, и просим xray его
распарсить (без запуска инбаундов). По exit code и тексту ошибки
определяем, какие коды битые.

Альтернативы, которые рассматривали и отвергли:
  - `xray geosite list` — такой подкоманды в xray-core НЕТ.
  - Парсить .dat-файл вручную через protobuf — оверкилл, схема может
    меняться между версиями, добавляет зависимость.
  - Хардкод "известных" категорий — устаревает на следующий день.

Кэш. Проверка через subprocess — недёшево (десятки-сотни мс на вызов),
поэтому валидные коды кладём в module-level set. Кэш инвалидируется
при изменении mtime файлов /usr/local/share/xray/geosite.dat и geoip.dat
— это покрывает обновления .dat через cron/ручной wget.

Fail-open. Если xray-бинарь отсутствует, упал по таймауту или вернул
ошибку, которую мы не распознали как missing-код — считаем переданные
коды валидными. Логика: лучше пропустить плохое правило на этапе
валидации (и поймать его позже на apply через validate_config),
чем заблокировать пользователю работу с панелью.
"""
import json
import logging
import os
import re
import subprocess
import tempfile
import threading

log = logging.getLogger(__name__)

XRAY_BINARY = "/usr/local/bin/xray"
GEOSITE_PATH = "/usr/local/share/xray/geosite.dat"
GEOIP_PATH = "/usr/local/share/xray/geoip.dat"

GEOSITE_PREFIX = "geosite:"
GEOIP_PREFIX = "geoip:"

# Лимит итераций цикла "ищем все битые коды по одному". xray -test
# останавливается на первой ошибке, поэтому, если в правиле N битых
# кодов, нужно N+1 вызовов чтобы их все собрать. 25 — потолок, после
# которого что-то с правилом сильно не так.
_MAX_ITERATIONS = 25

# Парсеры сообщений xray. Видели две формулировки в разных версиях:
#   "code not found in geosite.dat: XYZ"
#   "failed to load geosite: XYZ"
# Имя кода в выводе xray всегда UPPER-CASE.
_RE_NOT_FOUND = re.compile(
    r"code not found in (?:geosite|geoip)\.dat:\s*([A-Z0-9_\-!@]+)",
    re.IGNORECASE,
)
_RE_FAILED_LOAD = re.compile(
    r"failed to load (?:geosite|geoip):\s*([A-Z0-9_\-!@]+)",
    re.IGNORECASE,
)

# Module-level кэш. Структура:
#   {"key": (geosite_mtime, geoip_mtime), "valid": set("geosite:cn", ...)}
# key == None означает "ещё не инициализирован".
_cache_lock = threading.Lock()
_cache: dict = {"key": None, "valid": set()}


# ---------------------------------------------------------------------------
# Внутренние helpers
# ---------------------------------------------------------------------------

def _strip_code(raw: str) -> str | None:
    """
    Из 'geosite:!geolocation-ru@cn' извлекаем 'geolocation-ru' — то имя,
    которое xray будет искать в .dat (без префикса, без leading !, без
    @attr). Возвращает None если строка не начинается с geosite:/geoip:.
    """
    if not isinstance(raw, str):
        return None
    if raw.startswith(GEOSITE_PREFIX):
        body = raw[len(GEOSITE_PREFIX):]
    elif raw.startswith(GEOIP_PREFIX):
        body = raw[len(GEOIP_PREFIX):]
    else:
        return None
    # Отрезаем leading ! (negation в xray-синтаксисе)
    body = body.lstrip("!")
    # Отрезаем trailing @attribute (geosite:google@ads → google)
    body = body.split("@", 1)[0]
    body = body.strip()
    return body or None


def _files_key() -> tuple:
    """Идентификатор актуальной версии .dat-файлов для cache invalidation."""
    def _mtime(p: str) -> float:
        try:
            return os.stat(p).st_mtime
        except OSError:
            return 0.0
    return (_mtime(GEOSITE_PATH), _mtime(GEOIP_PATH))


def _ensure_cache_fresh() -> None:
    """Сбрасывает кэш если .dat-файлы изменились с прошлой проверки."""
    key = _files_key()
    with _cache_lock:
        if _cache["key"] != key:
            _cache["key"] = key
            _cache["valid"] = set()


def _is_cached_valid(raw: str) -> bool:
    with _cache_lock:
        return raw in _cache["valid"]


def _mark_cached_valid(items: list[str]) -> None:
    with _cache_lock:
        _cache["valid"].update(items)


def _build_probe_config(domains: list[str], ips: list[str]) -> dict:
    """
    Минимальный валидный конфиг xray с одним routing-правилом, в которое
    кладём проверяемые коды. Никаких реальных портов: dokodemo-door на
    127.0.0.1:1 (не открывается при -test), outbound — freedom (direct).
    """
    rule: dict = {"type": "field", "outboundTag": "direct"}
    if domains:
        rule["domain"] = list(domains)
    if ips:
        rule["ip"] = list(ips)
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "tag": "probe",
            "port": 1,
            "listen": "127.0.0.1",
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [rule]},
    }


def _run_xray_test_inline(config: dict) -> tuple[int, str]:
    """
    Записывает config во временный файл и запускает `xray run -test -c <file>`.
    Возвращает (returncode, output) где output — конкатенация stdout+stderr.
    Кидает исключения только при serious-проблемах (FileNotFoundError,
    TimeoutExpired) — их ловит вызывающий и обрабатывает как fail-open.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        path = f.name
    try:
        result = subprocess.run(
            [XRAY_BINARY, "run", "-test", "-c", path],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode, (result.stdout or "") + (result.stderr or "")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _parse_missing_code(xray_output: str) -> str | None:
    """Из вывода xray вытаскиваем имя ненайденного кода (UPPER-CASE)."""
    for pattern in (_RE_NOT_FOUND, _RE_FAILED_LOAD):
        m = pattern.search(xray_output)
        if m:
            return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# Публичное API
# ---------------------------------------------------------------------------

def validate_codes(domains: list, ips: list) -> list[str]:
    """
    Возвращает список ИСХОДНЫХ строк из domains/ips, которые xray не
    смог распарсить как существующие коды (geosite:XXX где XXX нет в
    geosite.dat, или geoip:XXX где XXX нет в geoip.dat).

    Пустой результат — всё ок (или валидатор недоступен, fail-open).

    Что игнорируем (считаем валидным заведомо):
      - Строки, не начинающиеся на 'geosite:' / 'geoip:' — это
        domain:foo.com, full:bar, regexp:^baz$, plain CIDR и т.п.
        Их синтаксис xray проверит уже на этапе apply через
        validate_config().
      - Не-строки (None и т.п. — могут попасть из кривых данных).
    """
    _ensure_cache_fresh()

    # Отбираем только geosite:/geoip:-коды, которых ещё нет в кэше.
    pending_domains: list[str] = []
    pending_ips: list[str] = []
    # Mapping для обратного маппинга при разборе ошибки xray:
    # UPPER(stripped_name) → исходная строка как её ввёл юзер.
    by_stripped_upper: dict[str, str] = {}

    for raw in (domains or []):
        stripped = _strip_code(raw)
        if stripped is None:
            continue
        if _is_cached_valid(raw):
            continue
        pending_domains.append(raw)
        by_stripped_upper[stripped.upper()] = raw

    for raw in (ips or []):
        stripped = _strip_code(raw)
        if stripped is None:
            continue
        if _is_cached_valid(raw):
            continue
        pending_ips.append(raw)
        by_stripped_upper[stripped.upper()] = raw

    if not pending_domains and not pending_ips:
        return []

    invalid: list[str] = []
    # Цикл: пока xray -test не вернёт RC=0, по одному выбрасываем
    # битые коды и пробуем снова. Закладываемся, что нормальный кейс —
    # ноль или один битый код, цикл срабатывает один-два раза.
    for _ in range(_MAX_ITERATIONS):
        if not pending_domains and not pending_ips:
            break
        try:
            rc, output = _run_xray_test_inline(
                _build_probe_config(pending_domains, pending_ips)
            )
        except FileNotFoundError:
            log.warning(
                "Xray-бинарь %s не найден; валидация geo-кодов пропущена (fail-open).",
                XRAY_BINARY,
            )
            return []
        except subprocess.TimeoutExpired:
            log.warning("xray -test превысил таймаут; fail-open.")
            return []
        except Exception as e:
            log.warning("Неожиданная ошибка запуска xray -test (%s); fail-open.", e)
            return []

        if rc == 0:
            # Все pending-коды валидны. Кэшируем и выходим.
            _mark_cached_valid(pending_domains + pending_ips)
            break

        missing = _parse_missing_code(output)
        if missing is None:
            # xray ругается на что-то, но это не missing-код — значит
            # ошибка где-то ещё (синтаксис правила, например). Не наша
            # зона: пусть apply-проверка ловит. Fail-open.
            log.warning(
                "xray -test вернул RC=%d, но missing-код не распознан. "
                "Первые 500 символов вывода:\n%s",
                rc, output.strip()[:500],
            )
            return invalid

        # Сопоставляем missing (UPPER-CASE) обратно с pending-строкой.
        original = by_stripped_upper.get(missing.upper())
        if original is None:
            # На всякий случай — линейный поиск (вдруг xray иначе
            # нормализовал имя).
            for cand in pending_domains + pending_ips:
                stripped = _strip_code(cand) or ""
                if stripped.upper() == missing.upper():
                    original = cand
                    break
        if original is None:
            # Совсем странный случай — отдаём что есть.
            log.warning(
                "Не смогли сопоставить missing-код %r с входом %r/%r.",
                missing, pending_domains, pending_ips,
            )
            return invalid

        invalid.append(original)
        pending_domains = [x for x in pending_domains if x != original]
        pending_ips = [x for x in pending_ips if x != original]

    return invalid


def validate_config(config: dict) -> tuple[bool, str]:
    """
    Прогоняет dict-конфиг через `xray run -test`. Возвращает (ok, message).
    Используется как страховка перед атомарной заменой /etc/xray/config.json
    в apply_xray_config(): даже если статическая валидация (validate_codes)
    что-то пропустила, сюда не пройдёт ничего, что Xray не смог распарсить.

    Зачем dict, а не путь. Панель работает от пользователя `proxypanel`,
    а Xray в проде — от пользователя `xray`. Лог-файлы в /var/log/xray/
    принадлежат xray:xray и proxypanel к ним писать не может. Если
    запустить `xray run -test` на конфиге с реальными путями access.log
    и error.log из-под proxypanel, xray попытается открыть их на запись
    и получит permission denied — даже если конфиг сам по себе валидный.
    Поэтому здесь мы:
      1. Делаем shallow-копию конфига.
      2. Полностью убираем секцию log (тогда xray дефолтит на stdout/
         stderr — никаких файлов).
      3. Пишем эту тест-версию во временный файл и гоняем xray -test.
      4. Возвращаем результат; рабочий конфиг (с реальными путями)
         пишет на диск уже вызывающий код.

    Это значит: log-секция конфига этой проверкой НЕ покрывается. Так
    и должно быть — log-пути и log_level статически валидируются на
    уровне settings-API (validate_setting в system.py), а реальные
    проблемы с правами на /var/log/xray/ Xray сам диагностирует при
    запуске сервиса, не в режиме -test.

    Fail-open. Если xray-бинарь недоступен — возвращаем (True, "")
    и пишем warning в лог. Иначе любая проблема с самим валидатором
    могла бы заблокировать всю работу с конфигом.
    """
    # 1. Готовим тест-копию: убираем секцию log целиком.
    test_config = dict(config)  # shallow copy верхнего уровня — нам этого хватит
    test_config.pop("log", None)
    # Тестировать в полностью изолированном виде: оставляем настройки,
    # инбаунды, outbound'ы, routing — всё что определяет «правильность»
    # бизнес-логики Xray. Log не определяет — это I/O.

    # 2. Пишем во временный файл и запускаем xray -test.
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(test_config, f)
        path = f.name
    try:
        try:
            result = subprocess.run(
                [XRAY_BINARY, "run", "-test", "-c", path],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            log.warning(
                "Xray-бинарь %s не найден; валидация конфига пропущена (fail-open).",
                XRAY_BINARY,
            )
            return True, ""
        except subprocess.TimeoutExpired:
            log.warning("xray -test превысил таймаут на валидации конфига; fail-open.")
            return True, ""
        except Exception as e:
            log.warning("Неожиданная ошибка валидации конфига (%s); fail-open.", e)
            return True, ""
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    if result.returncode == 0:
        return True, ""
    msg = (result.stdout or "") + (result.stderr or "")
    # Возвращаем первую содержательную строку — она обычно описывает суть.
    return False, msg.strip().splitlines()[-1] if msg.strip() else f"RC={result.returncode}"
