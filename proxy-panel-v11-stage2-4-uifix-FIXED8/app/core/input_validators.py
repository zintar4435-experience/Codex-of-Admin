"""
Лёгкие input-валидаторы для REST API эндпоинтов.

Это чистые функции — без I/O, без subprocess, без БД. Используются как
fail-early фильтр для входных данных, прежде чем оно попадёт в БД и
затем в apply_xray_config(). Когда сабсистема может крякнуться от
битого входа (Xray не примет конфиг → systemd зацикливает рестарты),
лучше дублировать проверку на двух уровнях:
  - input layer: эти функции, отдают 400 пользователю с понятным
    текстом, БД не трогается;
  - apply layer: write_xray_config через xray run -test —
    последняя линия обороны от багов в самих валидаторах.

Возвращаемое значение унифицировано:
    (ok: bool, error_msg: str | None [, normalized_value])

Если ok=True — error_msg is None. Если ok=False — error_msg описывает
проблему на русском, готовое к показу юзеру.

Стиль: каждая функция отвечает за ОДНУ концепцию (port, tag, ports-list,
regexp в match_domains, TLS-пути). Никаких сетевых проверок и обращений
к БД — БД-зависимые проверки (уникальность tag, конфликт port с другими
инбаундами) делаются в вызывающем коде, потому что им нужен доступ к
db.session.
"""
import re
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────
# Tag (inbound.tag)
# ─────────────────────────────────────────────────────────────────────

# Tag живёт в JSON-ключе xray-конфига, попадает в имена outbound для
# каскадов (cascade-{src}->{dst}), используется как имя caddy-сайта.
# Никаких пробелов, кавычек, точек, слешей, чтобы ничего не цеплять
# в любом из этих контекстов.
TAG_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

# Имена, занятые ядром (xray.py билдит outbound'ы с этими тегами,
# и api-инбаунд с tag='api'). Если юзер создаст inbound с одним из этих
# имён — будут коллизии в routing rules.
RESERVED_TAGS = frozenset({"direct", "block", "api"})


def validate_tag(tag) -> tuple[bool, str | None]:
    if not isinstance(tag, str):
        return False, "Tag должен быть строкой"
    if not TAG_RE.match(tag):
        return False, (
            "Tag должен состоять из латинских букв, цифр, '_' и '-' "
            f"(1-64 символа). Получено: {tag!r}"
        )
    if tag.lower() in RESERVED_TAGS:
        return False, (
            f"Tag '{tag}' зарезервирован ядром "
            f"({', '.join(sorted(RESERVED_TAGS))})"
        )
    return True, None


# ─────────────────────────────────────────────────────────────────────
# Port (inbound.port)
# ─────────────────────────────────────────────────────────────────────

# Порты, на которых уже сидит инфраструктура панели на VPS:
#   80   — Caddy ACME HTTP-01 challenge
#   443  — Caddy HTTPS (NaiveProxy + reverse-proxy панели)
#   2019 — Caddy admin API
#   5000 — gunicorn (захардкожено в proxy-panel.service, см. HANDOVER 4.1)
# Если юзер выберет один из этих портов для Xray inbound, бинд не
# удастся, Xray уйдёт в crash loop.
# Порт SSH (22) и xray-api-порт (Setting xray_api_port) проверяются
# вызывающим кодом отдельно — они контекст-зависимые.
PANEL_INFRA_PORTS = frozenset({80, 443, 2019, 5000})


def validate_port(
    value,
    *,
    check_panel_conflicts: bool = True,
    allow_reality_443: bool = False,
) -> tuple[bool, str | None, int | None]:
    """
    Возвращает (ok, error, normalized_port_int).
    Принимает int или str с числом. Отвергает порты вне 1..65535 и
    (если check_panel_conflicts=True) порты, занятые инфраструктурой
    панели.

    check_panel_conflicts=True — для портов локального бинда (Xray
    inbound, xray_api_port). Эти порты Xray будет открывать на
    этой машине, и пересечение с Caddy/gunicorn = гарантированный
    crash.

    check_panel_conflicts=False — для удалённых портов (external
    outbound address:port). Удалённый таргет на 443 это норма, не
    конфликт.

    allow_reality_443=True — особый случай для Reality-инбаунда в
    shared-443 режиме. Reality на :443 — это ФРОНТ для трафика, и он
    сам делегирует не-Reality TCP на локальный Caddy (127.0.0.1:8443
    через realitySettings.dest). Поэтому Reality МОЖЕТ занимать 443
    без коллизии с Caddy — Caddy в этом режиме переезжает на loopback.
    Дополнительная проверка «только один Reality-инбаунд на 443»
    делается на API-уровне в _check_port_conflicts (нужен доступ к БД).
    """
    if value is None:
        return False, "Порт обязателен для Xray-инбаунда", None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False, f"Порт должен быть целым числом, получено: {value!r}", None
    if not (1 <= port <= 65535):
        return False, f"Порт должен быть в диапазоне 1..65535, получено: {port}", None
    if check_panel_conflicts and port in PANEL_INFRA_PORTS:
        # Reality-исключение для 443: Caddy в shared-режиме сам уходит на 127.0.0.1:8443.
        if allow_reality_443 and port == 443:
            return True, None, port
        return False, (
            f"Порт {port} занят инфраструктурой панели "
            f"(80/443 — Caddy, 2019 — Caddy admin, 5000 — gunicorn). "
            f"Выберите другой свободный порт."
        ), None
    return True, None, port


# ─────────────────────────────────────────────────────────────────────
# UUID (Client.uuid для VLESS/VMess)
# ─────────────────────────────────────────────────────────────────────

# Стандартная форма RFC 4122: 8-4-4-4-12 hex-цифр через дефис.
# Регистр случается смешанный — Xray принимает любой, мы тоже.
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def validate_uuid(value) -> tuple[bool, str | None]:
    """Для пустого/None — ок (вызывающий код сам подставит сгенерированный)."""
    if value is None or value == "":
        return True, None
    if not isinstance(value, str):
        return False, "UUID должен быть строкой"
    if not UUID_RE.match(value):
        return False, (
            f"UUID должен быть в формате 8-4-4-4-12 hex (например "
            f"'1f3c4a5e-2b6d-4d8e-9c1a-7f5b3e2d4c6a'). Получено: {value!r}"
        )
    return True, None


# ─────────────────────────────────────────────────────────────────────
# Email (Client.email — stats label; настройка acme_email — для LE)
# ─────────────────────────────────────────────────────────────────────

# Лютая «полная» email-regex по RFC 5322 имеет сотни строк и всё равно
# проходит по edge-кейсам. Делаем простую проверку: одна @, обе стороны
# непустые, в правой есть точка. Этого достаточно для LE (он сам
# отказывается выпускать сертификат на кривой email) и для общего
# user input.
_EMAIL_STRICT_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# Символы, которые ломают xray stats-query (формат `user>>>email>>>traffic`).
# Это узкая чёрная нумерация — не пытаемся валидировать email полноценно,
# просто отсекаем то, что точно сломает наблюдаемость.
_EMAIL_STATS_BAD_CHARS = frozenset({">", "<", "\n", "\r", "\t"})


def validate_email(value, *, allow_empty: bool = True, strict: bool = False) -> tuple[bool, str | None]:
    """
    strict=False (для client.email): только запрет на символы,
        ломающие xray stats. Точку и @ не требуем — клиент может
        иметь email-метку вида 'John Doe@panel' (дефолт из POST), и
        это валидно для Xray.
    strict=True (для acme_email): требуем полноценный формат, потому
        что Let's Encrypt не выпустит сертификат на мусор.
    """
    if value is None or value == "":
        if allow_empty:
            return True, None
        return False, "Email обязателен"
    if not isinstance(value, str):
        return False, "Email должен быть строкой"
    found = sorted(_EMAIL_STATS_BAD_CHARS & set(value))
    if found:
        return False, (
            f"Email содержит символы, ломающие Xray stats: "
            f"{''.join(repr(c) for c in found)}"
        )
    if strict and not _EMAIL_STRICT_RE.match(value):
        return False, f"Невалидный формат email: {value!r}"
    return True, None


# ─────────────────────────────────────────────────────────────────────
# Domain name (settings.panel_domain — для ACME / Caddy)
# ─────────────────────────────────────────────────────────────────────

# RFC 1035 + 1123: метки 1..63 символов, [a-zA-Z0-9-], не начинаются и
# не заканчиваются дефисом. Полный hostname 1..253 символа. Поддомены
# через '.'. IDN (xn--…) тоже укладывается в этот же ASCII-набор.
# Мы ОЧЕНЬ строго: только lowercase, потому что для ACME регистр не
# имеет значения, а несоответствие регистра между Setting и сертификатом
# может стать неочевидным источником багов.
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
)


def validate_domain(value) -> tuple[bool, str | None]:
    """Для пустого/None — ошибка (домен обязателен где это вызывается)."""
    if not isinstance(value, str) or not value:
        return False, "Домен обязателен"
    v = value.strip().lower()
    if len(v) > 253:
        return False, f"Длина домена > 253 символов: {len(v)}"
    if not _DOMAIN_RE.match(v):
        return False, (
            f"Домен должен быть валидным hostname-ом ([a-z0-9-], "
            f"минимум один уровень, без подчёркиваний и пробелов). "
            f"Получено: {value!r}"
        )
    return True, None


# ─────────────────────────────────────────────────────────────────────
# Hostname or IP (ExternalOutbound.address)
# ─────────────────────────────────────────────────────────────────────

# IPv4: четыре октета 0-255. Без leading zeros не паримся — Xray примет.
_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
# Очень грубый IPv6 чек — допускаем что-либо с двоеточиями и hex.
# Полный IPv6 regex монструозен и для нашей задачи не нужен.
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def validate_hostname_or_ip(value) -> tuple[bool, str | None]:
    """
    Адрес удалённого таргета (для outbound). Принимаем:
      - IPv4 в каноническом формате
      - IPv6 (грубо: hex и двоеточия)
      - hostname (как validate_domain — но допускаем single-label на
        случай локальных адресов вроде "myproxy")
    Отказ: пустое, пробелы внутри, и явные опечатки типа "http://...".

    Особый кейс: если строка выглядит как IPv4 (4 числовые группы через
    точку), мы валидируем её ТОЛЬКО как IP. Технически "256.0.0.1" —
    валидный hostname по RFC 1123 (allow-all-numeric-labels), но
    пользователь, набирая такое, явно имел в виду IP-адрес и ошибся.
    Лучше ругнуться сразу, чем дальше xray попытается резолвить «IP»
    через DNS и упадёт с непонятной ошибкой.
    """
    if not isinstance(value, str) or not value.strip():
        return False, "Адрес обязателен"
    v = value.strip()
    if any(c.isspace() for c in v):
        return False, f"Адрес не может содержать пробелы: {value!r}"
    if "://" in v:
        return False, (
            f"Адрес — только хост или IP, без схемы (http://, socks://). "
            f"Получено: {value!r}"
        )
    # IPv4-shape: 4 численные группы через точку. Если так — валидируем
    # как IPv4 строго, hostname-fallback не применяем.
    if re.match(r"^\d+(\.\d+){3}$", v):
        if _IPV4_RE.match(v):
            return True, None
        return False, (
            f"Невалидный IPv4: октеты должны быть в диапазоне 0..255. "
            f"Получено: {value!r}"
        )
    # IPv6-shape: содержит ':', все символы — hex/двоеточие. Грубо, но
    # достаточно для отсечения мусора. Реальную валидность проверит xray.
    if ":" in v:
        if _IPV6_RE.match(v):
            return True, None
        return False, f"Невалидный IPv6: {value!r}"
    # Иначе считаем hostname'ом. Допускаем single-label (для локальных
    # таргетов типа "myproxy") и многоуровневые (example.com).
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
                r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$", v):
        return True, None
    return False, f"Невалидный hostname или IP: {value!r}"


# ─────────────────────────────────────────────────────────────────────
# Enum validator (для xray_log_level, xray_domain_strategy, протоколов)
# ─────────────────────────────────────────────────────────────────────

def validate_enum(value, allowed, *, label: str = "значение") -> tuple[bool, str | None]:
    """
    Допустимые значения — через множество (case-sensitive). Удобно для
    Xray-настроек, где регистр имеет значение (AsIs != asis).
    """
    if value in allowed:
        return True, None
    return False, (
        f"Недопустимое {label}: {value!r}. "
        f"Допустимо: {', '.join(sorted(repr(x) for x in allowed))}"
    )


# ─────────────────────────────────────────────────────────────────────
# match_ports (RoutingRule.match_ports)
# ─────────────────────────────────────────────────────────────────────

# Грубый pre-filter: только цифры, запятые, тире и пробелы. Если строка
# содержит что-то ещё — это точно мусор, дальше парсить не имеет смысла.
_PORTS_GROSS_RE = re.compile(r"^[\d\s,\-]+$")


def validate_match_ports(value) -> tuple[bool, str | None]:
    """
    Формат Xray: '53,80,443,8000-9000' — список через запятую,
    каждый элемент — либо число, либо range a-b. Пробелы вокруг чисел
    игнорируются. None и пустая строка означают 'без фильтра по портам'
    и считаются валидными.
    """
    if value is None or value == "":
        return True, None
    if not isinstance(value, str):
        return False, (
            f"match_ports должно быть строкой, получено: "
            f"{type(value).__name__}"
        )
    s = value.strip()
    if not s:
        return True, None
    if not _PORTS_GROSS_RE.match(s):
        return False, (
            "match_ports должно состоять из чисел, запятых и тире "
            f"(пример: '80,443,8000-9000'). Получено: {value!r}"
        )
    for piece in s.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            parts = piece.split("-")
            if len(parts) != 2:
                return False, f"Неверный диапазон портов: {piece!r}"
            try:
                a, b = int(parts[0].strip()), int(parts[1].strip())
            except ValueError:
                return False, f"Неверный диапазон портов: {piece!r}"
            if not (1 <= a <= 65535 and 1 <= b <= 65535):
                return False, f"Порты в диапазоне {piece!r} должны быть 1..65535"
            if a > b:
                return False, f"В диапазоне {piece!r} начало больше конца"
        else:
            try:
                p = int(piece)
            except ValueError:
                return False, f"Неверный порт: {piece!r}"
            if not (1 <= p <= 65535):
                return False, f"Порт {p} вне диапазона 1..65535"
    return True, None


# ─────────────────────────────────────────────────────────────────────
# regexp:... записи в match_domains
# ─────────────────────────────────────────────────────────────────────

def validate_regexp_entries(entries) -> tuple[bool, str | None]:
    """
    Из всех элементов entries (match_domains), начинающихся на 'regexp:',
    проверяем компилируется ли тело как regex. Используем python re —
    Xray на бэкенде использует Go-stdlib regex, но базовый синтаксис
    совпадает, и самые частые user-ошибки (незакрытые скобки, битые
    escape-последовательности) ловит обе библиотеки одинаково.
    """
    if not entries:
        return True, None
    if not isinstance(entries, list):
        return True, None  # тип проверит другой валидатор
    for raw in entries:
        if not isinstance(raw, str):
            continue
        if not raw.startswith("regexp:"):
            continue
        body = raw[len("regexp:"):]
        try:
            re.compile(body)
        except re.error as e:
            return False, f"Невалидная регулярка в {raw!r}: {e}"
    return True, None


# ─────────────────────────────────────────────────────────────────────
# TLS cert / key paths (inbound.tls_cert_path, inbound.tls_key_path)
# ─────────────────────────────────────────────────────────────────────

def validate_tls_paths(
    cert_path: str | None,
    key_path: str | None,
) -> tuple[bool, str | None]:
    """
    Проверяет, что cert и key путь:
      - не пустой;
      - указывает на существующий файл;
      - размер > 0 байт.

    Что НЕ проверяем здесь:
      - читаемость самим xray-юзером — у панели (proxypanel) и Xray
        (xray) могут быть разные права; проверять os.access мы можем
        только относительно текущего процесса, что не показательно;
      - валидность PEM или срок действия — это потребовало бы
        openssl-вызова или python-cryptography (которые могут не
        прочитать файл по правам), и в итоге сюда не попадёт ничего,
        чего бы не поймал xray run -test после write_xray_config.

    То есть смысл функции — ловить наиболее частые user-ошибки
    (опечатка в пути, пустой файл после неудачного scp). Конечная
    защита — xray run -test через write_xray_config.
    """
    for label, path in (("cert", cert_path), ("key", key_path)):
        if not path:
            return False, f"TLS {label}_path пустой"
        p = Path(path)
        if not p.is_file():
            return False, f"TLS {label} файл не существует: {path}"
        try:
            size = p.stat().st_size
        except OSError as e:
            return False, f"Не удалось прочитать TLS {label} файл {path}: {e}"
        if size == 0:
            return False, f"TLS {label} файл {path} пустой (0 байт)"
    return True, None
