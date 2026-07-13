"""REST API: System — status, logs, restart, settings, xray update."""
import subprocess
import platform
import os
import re
import json
import socket
import secrets
import threading
import time
import urllib.request
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app.models import db, Setting, AuditLog
from app import limiter
from app.core.xray import apply_xray_config, XRAY_CONFIG_PATH, XRAY_BINARY
from app.core.caddy import apply_caddy_config, get_caddy_status
from app.core.audit import log_action
from app.core.input_validators import (
    validate_port, validate_domain, validate_email, validate_enum,
    validate_dns_server,
)

bp = Blueprint("system", __name__)

# ---------------------------------------------------------------------------
# .env helpers
# ---------------------------------------------------------------------------

ENV_PATH = "/opt/proxy-panel/instance/.env"


def _write_env(key: str, value: str) -> None:
    """Update or append a KEY=value line in the .env file."""
    lines = []
    found = False
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            lines = f.readlines()
    new_lines = []
    for line in lines:
        if line.startswith(f"{key}="):
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"{key}={value}\n")
    with open(ENV_PATH, "w") as f:
        f.writelines(new_lines)


# ---------------------------------------------------------------------------
# DNS check helper
# ---------------------------------------------------------------------------

def _get_server_ip() -> str:
    """Возвращает публичный IP сервера.

    Порядок попыток:
    1. Внешний сервис api.ipify.org — единственный надёжный способ для серверов
       за NAT/с Floating IP/Elastic IP (исходящий сокет в таком случае вернёт
       приватный адрес интерфейса, не публичный).
    2. Fallback: исходящий UDP-сокет (полезно при отсутствии интернета —
       хотя бы вернёт что-то осмысленное в логи).
    3. Последняя надежда — gethostbyname.
    """
    # 1) Внешний сервис — самый надёжный для NAT/Floating IP
    try:
        req = urllib.request.Request(
            "https://api.ipify.org",
            headers={"User-Agent": "proxy-panel/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            ip = resp.read().decode().strip()
            # минимальная валидация формата IPv4
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return ip
    except Exception:
        pass

    # 2) Fallback: исходящий сокет (вернёт приватный IP за NAT, но это лучше чем ничего)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass

    # 3) Последняя надежда
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.error:
        return ""


def _check_dns(domain: str) -> bool:
    """Return True if the domain resolves to this server's IP."""
    try:
        resolved = socket.gethostbyname(domain)
        return resolved == _get_server_ip()
    except socket.error:
        return False


# ---------------------------------------------------------------------------
# Onboarding handoff — короткоживущие одноразовые токены, чтобы перенести
# админ-сессию с http://IP:5000/setup-progress на https://panel_domain/dashboard
# после выпуска сертификата.
#
# Зачем: куки сессии привязаны к хосту, на котором их выставили (89.169.5.77).
# При редиректе на myvpstest2.duckdns.org браузер их не отправит, и юзера
# выкинет на форму логина. Handoff-токен — это короткоживущий one-shot пароль,
# который setup-progress (от имени залогиненного админа) запрашивает на HTTP
# origin'е и подставляет в URL редиректа; принимающий эндпоинт /auth/onboarding-
# handoff на HTTPS origin'е логинит юзера и редиректит на /dashboard.
#
# Хранилище — таблица settings (она и так универсальный k/v стор для панели),
# чтобы токены переживали рестарт gunicorn и были одинаковы для всех воркеров.
# ---------------------------------------------------------------------------

_HANDOFF_PREFIX = "handoff:"
_HANDOFF_TTL = 60  # секунд


def _cleanup_expired_handoff_tokens() -> None:
    """Удаляет просроченные / битые handoff-записи. Вызывается при выписке нового."""
    now = int(time.time())
    expired_keys = []
    for s in Setting.query.filter(Setting.key.like(f"{_HANDOFF_PREFIX}%")).all():
        try:
            data = json.loads(s.value)
            if int(data.get("exp", 0)) < now:
                expired_keys.append(s.key)
        except Exception:
            expired_keys.append(s.key)
    if expired_keys:
        for k in expired_keys:
            row = db.session.get(Setting, k)
            if row is not None:
                db.session.delete(row)
        db.session.commit()


def make_handoff_token(user_id: int) -> str:
    """Создаёт одноразовый handoff-токен с TTL _HANDOFF_TTL секунд."""
    _cleanup_expired_handoff_tokens()
    token = secrets.token_urlsafe(32)
    Setting.set(
        f"{_HANDOFF_PREFIX}{token}",
        json.dumps({"uid": int(user_id), "exp": int(time.time()) + _HANDOFF_TTL}),
    )
    db.session.commit()
    return token


def consume_handoff_token(token: str) -> int | None:
    """Валидирует и одноразово гасит handoff-токен. Возвращает user_id или None."""
    if not token or not isinstance(token, str) or len(token) > 100:
        return None
    row = db.session.get(Setting, f"{_HANDOFF_PREFIX}{token}")
    if row is None:
        return None
    # Атомарно удаляем — токен одноразовый.
    raw_value = row.value
    db.session.delete(row)
    db.session.commit()
    try:
        data = json.loads(raw_value)
        if int(data.get("exp", 0)) < int(time.time()):
            return None
        return int(data["uid"])
    except Exception:
        return None


def schedule_panel_restart(delay_seconds: int = 3) -> bool:
    """Планирует асинхронный рестарт сервиса proxy-panel через systemctl.
    Возвращает False, если рестарт не нужен (HTTPS_ENABLED уже включён в env)."""
    if os.environ.get("HTTPS_ENABLED", "false").lower() == "true":
        return False
    subprocess.Popen(
        ["sh", "-c", f"sleep {int(delay_seconds)}; sudo /usr/bin/systemctl restart proxy-panel"],
        start_new_session=True,
    )
    return True


# ---------------------------------------------------------------------------
# HTTPS enablement — shared logic + endpoint
# ---------------------------------------------------------------------------

# Зарезервированные домены, которые Let's Encrypt отклоняет для ACME-аккаунтов
_FORBIDDEN_EMAIL_DOMAINS = {
    "example.com", "example.net", "example.org",
    "test.com", "test.net", "test.org",
    "localhost", "invalid", "local",
}


def _validate_email(email: str) -> str | None:
    """Возвращает None если email валиден, иначе строку с описанием ошибки."""
    if not email:
        return "Email обязателен для получения TLS-сертификата"
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return f"Некорректный формат email: {email}"
    domain_part = email.split("@", 1)[1].lower()
    if domain_part in _FORBIDDEN_EMAIL_DOMAINS:
        return (
            f"Email с доменом @{domain_part} не принимается Let's Encrypt. "
            "Укажите настоящий email-адрес."
        )
    return None


def _do_https_setup(domain: str, email: str, force: bool = False) -> tuple[bool, str]:
    """
    Единственное место, где живёт логика перехода на HTTPS:
      - сохранение домена/email в БД
      - применение конфига Caddy
      - запись GUNICORN_BIND=127.0.0.1:5000 в .env
      - закрытие порта 5000 в ufw
      - перезапуск сервиса

    Возвращает (ok: bool, message: str).
    При force=False и несовпадении DNS возвращает (False, "dns_warning").
    """
    email_error = _validate_email(email)
    if email_error:
        return False, email_error

    if not force and not _check_dns(domain):
        return False, "dns_warning"

    Setting.set("panel_domain", domain)
    if email:
        Setting.set("acme_email", email)
    db.session.commit()

    ok, msg = apply_caddy_config()
    if not ok:
        return False, f"Ошибка Caddy: {msg}"

    _write_env("HTTPS_ENABLED", "true")
    _write_env("GUNICORN_BIND", "127.0.0.1:5000")

    # ВАЖНО: сам рестарт панели здесь НЕ запускаем.
    # Раньше тут был subprocess.Popen([..., "sleep 3 && systemctl restart proxy-panel"])
    # — задержка хрупкая: при медленной сети ответ мог не успеть дойти до браузера.
    # Теперь страница /setup-progress сама вызовет POST /api/system/restart-self
    # сразу после загрузки — синхронизация через клиента, без таймера.

    return True, "/setup-progress"


@bp.get("/https-status")
@limiter.limit("30 per minute")
def https_status():
    """Проверяет, выпущен ли TLS-сертификат для panel_domain.

    Намеренно БЕЗ @login_required: страница setup_progress поллит этот
    эндпоинт во время онбординга через HTTP origin (89.169.5.77:5000), и
    у нас нет надёжной гарантии, что куки доедут (Secure-флаг, рестарт
    сервиса и т.п.). Эндпоинт ничего не пишет в БД и только удаляет
    временное правило ufw на 5000 — то есть «помогает закрыться», что
    мы и так хотим. Никакого ущерба от анонимных вызовов нет."""
    import ssl
    domain = Setting.get("panel_domain", "")
    if not domain:
        return jsonify({"ready": False, "status": "Домен не настроен"})

    # Подключаемся к 127.0.0.1:443 с SNI домена — это обходит hairpin NAT
    # и не требует доступа к файлам Caddy (которые принадлежат caddy:caddy).
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                if not cert:
                    raise ValueError("пустой сертификат")
        # Сертификат готов — закрываем прямой доступ на порт 5000.
        # ufw разрешён в sudoers строго для этой одной команды.
        #
        # Гейт по HTTPS_ENABLED: этот эндпоинт намеренно анонимный (его
        # поллит страница онбординга через HTTP origin). Чтобы аноним не
        # мог дёргать sudo-команду после завершения онбординга, выполняем
        # закрытие порта ТОЛЬКО пока процесс ещё в HTTP-режиме (онбординг
        # не завершён). После рестарта с HTTPS_ENABLED=true ufw уже не
        # трогается — порт 5000 к этому моменту и так закрыт.
        if os.environ.get("HTTPS_ENABLED", "false").lower() != "true":
            subprocess.run(
                ["sudo", "/usr/sbin/ufw", "delete", "allow", "5000/tcp"],
                capture_output=True
            )
        return jsonify({"ready": True, "url": f"https://{domain}/dashboard"})
    except Exception:
        return jsonify({"ready": False, "status": "Получаем сертификат от Let's Encrypt…"})


@bp.post("/onboarding-handoff")
@login_required
def onboarding_handoff():
    """Выдаёт одноразовый токен для перехода админа с http://IP:5000 на
    https://panel_domain/. Используется страницей /setup-progress сразу
    после того, как /https-status вернул ready=true.

    Без этого механизма редирект на новый домен высадит юзера на форму
    логина (кросс-хост куки)."""
    token = make_handoff_token(current_user.id)
    return jsonify({"token": token})

@bp.post("/enable-https")
@login_required
def enable_https():
    """Switch the panel from HTTP to HTTPS via Caddy + Let's Encrypt."""
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    email = data.get("email", "").strip()
    force = bool(data.get("force", False))

    if not domain or not email:
        return jsonify({"error": "Домен и email обязательны"}), 400

    ok, msg = _do_https_setup(domain, email, force=force)

    if not ok and msg == "dns_warning":
        return jsonify({
            "warning": (
                "Домен пока не указывает на этот сервер. "
                "Сертификат может не выпуститься. Продолжить?"
            )
        }), 200

    if not ok:
        return jsonify({"error": msg}), 500

    return jsonify({"ok": True, "redirect": msg})


@bp.post("/restart-self")
@login_required
def restart_self():
    """Одноразовый рестарт панели — используется страницей /setup-progress
    сразу после смены HTTP→HTTPS, чтобы новый процесс gunicorn подхватил
    HTTPS_ENABLED=true из .env и включил ProxyFix middleware.

    Защита от злоупотребления: работает только пока ТЕКУЩИЙ процесс
    стартовал без HTTPS_ENABLED. После рестарта новая инстанция уже
    имеет HTTPS_ENABLED=true в os.environ, и эндпоинт становится no-op.
    То есть кнопкой нельзя дёргать рестарт после онбординга.
    """
    if os.environ.get("HTTPS_ENABLED", "false").lower() == "true":
        return jsonify({"ok": False, "skipped": "already_https"}), 200

    if not Setting.get("panel_domain"):
        # _do_https_setup ещё не вызывался — рестартить нечего.
        return jsonify({"error": "panel_domain not configured"}), 400

    # start_new_session=True — детачим от gunicorn-воркера, чтобы при его
    # завершении дочерний процесс не получил SIGHUP и спокойно дождался,
    # пока ответ долетит до клиента, прежде чем рестартить сервис.
    # Маленькая задержка 1с — достаточно, чтобы flush ответа.
    subprocess.Popen(
        ["sh", "-c", "sleep 1; sudo /usr/bin/systemctl restart proxy-panel"],
        start_new_session=True,
    )
    return jsonify({"ok": True})


@bp.get("/health")
def health():
    """Healthcheck — без авторизации, для systemd и мониторинга."""
    return jsonify({"status": "ok"}), 200


# Кеш определённого IP (ipify дёргать на каждый запрос незачем).
_server_ip_cache = {"ip": "", "ts": 0.0}

@bp.get("/server-ip")
@limiter.limit("30 per minute")
@login_required
def server_ip():
    """Определённый публичный IP сервера (для показа в настройках).

    Кешируем на 10 минут: внешний вызов к ipify не нужен на каждый клик.
    Отдаём также сохранённую настройку server_ip — UI решит, что показать.
    """
    now = time.time()
    if not _server_ip_cache["ip"] or now - _server_ip_cache["ts"] > 600:
        detected = _get_server_ip()
        if detected:
            _server_ip_cache["ip"] = detected
            _server_ip_cache["ts"] = now
    return jsonify({
        "detected": _server_ip_cache["ip"],
        "configured": Setting.get("server_ip", ""),
    })


# ---------------------------------------------------------------------------
# Двухфакторная аутентификация (TOTP)
# ---------------------------------------------------------------------------

@bp.get("/2fa/status")
@login_required
def twofa_status():
    return jsonify({
        "enabled": bool(current_user.totp_enabled),
        "recovery_left": current_user.recovery_codes_left(),
    })


@bp.post("/2fa/setup")
@login_required
@limiter.limit("10 per minute")
def twofa_setup():
    """Сгенерировать новый секрет (ожидающий подтверждения) и вернуть QR-данные.

    Пока пользователь не подтвердит код — totp_enabled остаётся False,
    вход вторым фактором не требуется.
    """
    from app.core import totp
    if current_user.totp_enabled:
        return jsonify({"error": "2FA уже включена. Сначала отключите её."}), 400
    secret = totp.generate_secret()
    current_user.totp_secret = secret
    db.session.commit()
    uri = totp.provisioning_uri(secret, account=current_user.username)
    return jsonify({"secret": secret, "uri": uri})


@bp.post("/2fa/enable")
@login_required
@limiter.limit("10 per minute")
def twofa_enable():
    """Подтвердить код от authenticator и включить 2FA. Возвращает резервные коды."""
    from app.core import totp
    data = request.get_json(silent=True) or {}
    code = (data.get("code", "") or "").strip()
    if current_user.totp_enabled:
        return jsonify({"error": "2FA уже включена"}), 400
    if not current_user.totp_secret:
        return jsonify({"error": "Сначала выполните setup"}), 400
    if not totp.verify(current_user.totp_secret, code):
        return jsonify({"error": "Неверный код. Проверьте время на устройстве."}), 400
    recovery = totp.generate_recovery_codes()
    current_user.set_recovery_codes(recovery)
    current_user.totp_enabled = True
    db.session.commit()
    log_action("auth.2fa_enabled", username=current_user.username)
    return jsonify({"ok": True, "recovery_codes": recovery})


@bp.post("/2fa/disable")
@login_required
@limiter.limit("10 per minute")
def twofa_disable():
    """Отключить 2FA. Требует текущий пароль ИЛИ действующий код 2FA."""
    from app.core import totp
    data = request.get_json(silent=True) or {}
    password = data.get("password", "") or ""
    code = (data.get("code", "") or "").strip()
    if not current_user.totp_enabled:
        return jsonify({"error": "2FA не включена"}), 400
    ok = (password and current_user.check_password(password)) \
        or totp.verify(current_user.totp_secret, code) \
        or current_user.use_recovery_code(code)
    if not ok:
        return jsonify({"error": "Нужен текущий пароль или действующий код 2FA"}), 400
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.recovery_codes = None
    db.session.commit()
    log_action("auth.2fa_disabled", username=current_user.username)
    return jsonify({"ok": True})


@bp.get("/apply-status/<apply_id>")
@login_required
def apply_status(apply_id):
    """Возвращает статус фонового apply конфига.

    Используется UI после save/delete: вместо ожидания синхронного apply
    (который мог бы оборвать соединение в shared-443 режиме) UI сразу
    получает 200/201, затем поллит этот endpoint.

    Ответ:
      {"status": "pending"}              — apply ещё выполняется
      {"status": "ok"}                   — apply завершился успешно
      {"status": "error", "msg": "..."}  — apply завершился с ошибкой
      {"status": "unknown"}              — uuid не найден (истёк TTL или неверный)
    """
    from app.core.apply_runner import get_status
    result = get_status(apply_id)
    if result is None:
        return jsonify({"status": "unknown"})
    return jsonify(result)


@bp.get("/firewall")
@login_required
def firewall_status():
    """
    Возвращает состояние UFW для UI-индикатора в форме создания/
    редактирования инбаунда. Только read-only — менять файрвол панель
    не умеет (сознательное решение, см. app/core/firewall.py).

    Формат ответа:
      {"available": False, "reason": "..."}  — UFW недоступен;
      {"available": True, "active": bool, "default_in": "deny"|...,
       "allowed_ports": [{"port": str, "proto": str|None, "action": str,
                          "source": str}, ...]}
    """
    from app.core.firewall import get_ufw_status
    data = get_ufw_status()
    # Не отдаём raw-вывод фронту: бесполезный шум, плюс может содержать
    # системную инфу. Используется только для отладки в логе на стороне
    # сервера (см. _parse_ufw_output).
    return jsonify({k: v for k, v in data.items() if k != "raw"})


def _service_status(name: str) -> dict:
    try:
        r = subprocess.run(["systemctl", "is-active", name],
                           capture_output=True, text=True, timeout=5)
        active = r.stdout.strip() == "active"
    except Exception:
        active = False
    return {"name": name, "active": active}


# Кэш версии установленного Xray: она меняется только при обновлении бинарника,
# а subprocess-вызов на каждый запрос — лишний форк на слабом VPS.
# Сбрасывается явно после xray_update (см. _reset_xray_version_cache).
_xray_ver_cache = {"ver": "", "ts": 0.0}
_XRAY_VER_TTL = 300.0


def _reset_xray_version_cache():
    _xray_ver_cache["ver"] = ""
    _xray_ver_cache["ts"] = 0.0


def _xray_version() -> str:
    now = time.time()
    if _xray_ver_cache["ver"] and now - _xray_ver_cache["ts"] < _XRAY_VER_TTL:
        return _xray_ver_cache["ver"]
    try:
        r = subprocess.run([XRAY_BINARY, "version"], capture_output=True, text=True, timeout=5)
        m = re.search(r"Xray (\S+)", r.stdout)
        ver = m.group(1) if m else "unknown"
    except Exception:
        ver = "unknown"
    if ver != "unknown":
        _xray_ver_cache["ver"] = ver
        _xray_ver_cache["ts"] = now
    return ver


# Кэш последней версии Xray с GitHub: запрос к api.github.com медленный
# (до 10с) и незачем дёргать его на каждый заход на страницу «Сервер».
# Версия на GitHub меняется раз в недели — часа кэша более чем достаточно.
_xray_latest_cache = {"ver": "", "ts": 0.0}
_XRAY_LATEST_TTL = 3600  # секунд


def _xray_latest_version() -> str:
    now = time.time()
    if _xray_latest_cache["ver"] and now - _xray_latest_cache["ts"] < _XRAY_LATEST_TTL:
        return _xray_latest_cache["ver"]
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
            headers={"User-Agent": "proxy-panel/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            ver = data.get("tag_name", "").lstrip("v")
        if ver:
            _xray_latest_cache["ver"] = ver
            _xray_latest_cache["ts"] = now
        return ver
    except Exception:
        # При сетевой ошибке отдаём прошлое известное значение (если было),
        # чтобы UI не «прыгал» — лучше слегка устаревшее, чем пусто.
        return _xray_latest_cache["ver"]


# Версия кода панели: файл VERSION лежит в корне установки (рядом с run.py),
# приезжает из репозитория при установке/обновлении; его же печатает
# update.sh («Версия до/после»). Путь считаем от app/api/ → корень панели.
_PANEL_VERSION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "VERSION",
)


def _panel_version() -> str:
    try:
        with open(_PANEL_VERSION_PATH) as f:
            return f.read().strip() or "unknown"
    except OSError:
        return "unknown"


# Кэш ответа /status: его поллит статус-бар на КАЖДОЙ открытой странице,
# а внутри — несколько subprocess-вызовов (systemctl is-active xray/caddy)
# + HTTP к Caddy admin. Схема stale-while-revalidate: запрос ВСЕГДА получает
# ответ мгновенно из кэша, а если кэш устарел (> TTL) — обновление уходит в
# фоновый поток (один на воркер, под замком). Раньше TTL (4с) был меньше
# периода поллинга (15с), и КАЖДЫЙ опрос промахивался и блокировался на
# subprocess-вызовах — это и были периодические «затупы». Синхронный сбор
# остался только у самого первого запроса после старта воркера.
_status_cache = {"ts": 0.0, "data": None}
_STATUS_TTL = 10.0
_status_lock = threading.Lock()
_status_refreshing = False


def _collect_status() -> dict:
    """Реальный сбор статуса (subprocess + HTTP к Caddy). Небыстрый — зовём
    его либо на самом первом запросе, либо из фонового потока."""
    xray = _service_status("xray")
    caddy_svc = _service_status("caddy")
    caddy_api = get_caddy_status()
    try:
        load = os.getloadavg()
    except AttributeError:
        load = (0, 0, 0)
    try:
        st = os.statvfs("/")
        disk_total = st.f_blocks * st.f_frsize
        disk_free  = st.f_bfree  * st.f_frsize
        disk_used  = disk_total - disk_free
    except Exception:
        disk_total = disk_used = 0

    return {
        "panel":  {"version": _panel_version()},
        "xray":   {**xray, "version": _xray_version()},
        "caddy":  {**caddy_svc, "api_reachable": caddy_api["running"]},
        "system": {
            "platform": platform.system(),
            "load_avg": list(load),
            "disk_total": disk_total,
            "disk_used":  disk_used,
        },
    }


def _refresh_status_async():
    """Фоновое обновление кэша. Замок гарантирует один поток на воркер;
    _collect_status не трогает БД/контекст приложения — потоку ничего не нужно."""
    global _status_refreshing
    with _status_lock:
        if _status_refreshing:
            return
        _status_refreshing = True

    def _work():
        global _status_refreshing
        try:
            data = _collect_status()
            _status_cache["data"] = data
            _status_cache["ts"] = time.time()
        except Exception:
            pass  # следующий запрос попробует снова
        finally:
            with _status_lock:
                _status_refreshing = False

    threading.Thread(target=_work, name="status-refresh", daemon=True).start()


@bp.get("/status")
@login_required
def status():
    now = time.time()
    if _status_cache["data"] is not None:
        if now - _status_cache["ts"] >= _STATUS_TTL:
            _refresh_status_async()
        return jsonify(_status_cache["data"])
    # Первый запрос после старта воркера — собираем синхронно.
    data = _collect_status()
    _status_cache["data"] = data
    _status_cache["ts"] = now
    return jsonify(data)


@bp.get("/xray/versions")
@login_required
def xray_versions():
    current = _xray_version()
    latest  = _xray_latest_version()
    return jsonify({
        "current": current,
        "latest":  latest,
        "update_available": bool(latest and latest != current),
    })


XRAY_UPDATER_SCRIPT = "/usr/local/bin/xray-update.sh"


@bp.post("/xray/update")
@login_required
def xray_update():
    """Trigger xray update via root-owned updater script (via sudo)."""
    data    = request.get_json(silent=True) or {}
    version = (data.get("version") or _xray_latest_version()).lstrip("v")
    if not version:
        return jsonify({"error": "Не удалось получить последнюю версию с GitHub"}), 502
    # Жёсткая валидация формата версии: только N.N.N (опц. -suffix).
    # version уходит в URL внутри xray-update.sh (wget на github);
    # хоть инъекции и нет (argv-форма), отсекаем мусор заранее.
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", version):
        return jsonify({"error": f"Неверный формат версии: {version!r}. Ожидается N.N.N"}), 400

    if not os.path.exists(XRAY_UPDATER_SCRIPT):
        return jsonify({"error": (
            "Updater не установлен. Переустановите панель командой: sudo bash install.sh"
        )}), 500

    try:
        result = subprocess.run(
            ["sudo", XRAY_UPDATER_SCRIPT, version],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            # Бинарник сменился — закэшированная версия больше не актуальна.
            _reset_xray_version_cache()
            log_action("xray.update", target_type="service", target_name="xray",
                       details={"version": version, "ok": True})
            return jsonify({"ok": True, "version": version,
                            "message": f"Xray обновлён до v{version}"})
        log_action("xray.update", target_type="service", target_name="xray",
                   details={"version": version, "ok": False,
                            "stderr": (result.stderr or result.stdout or "")[:200]})
        return jsonify({"error": result.stderr or result.stdout or "Unknown error"}), 500
    except subprocess.TimeoutExpired:
        log_action("xray.update", target_type="service", target_name="xray",
                   details={"version": version, "ok": False, "reason": "timeout"})
        return jsonify({"error": "Таймаут загрузки (120с)"}), 504
    except Exception as e:
        log_action("xray.update", target_type="service", target_name="xray",
                   details={"version": version, "ok": False, "error": str(e)[:200]})
        return jsonify({"error": str(e)}), 500


@bp.get("/logs/xray")
@login_required
def xray_logs():
    try:
        lines = max(1, min(int(request.args.get("lines", 100)), 5000))
    except (ValueError, TypeError):
        lines = 100
    log_type = request.args.get("type", "error")
    # log_type подставляется в путь к файлу, поэтому строго whitelist.
    # Без него ?type=../../caddy/access (и подобное) позволял бы прочитать
    # произвольный *.log на сервере, доступный пользователю panel.
    if log_type not in ("error", "access"):
        return jsonify({"error": "Параметр type должен быть 'error' или 'access'"}), 400
    log_file = f"/var/log/xray/{log_type}.log"
    try:
        result = subprocess.run(["tail", "-n", str(lines), log_file],
                                capture_output=True, text=True, timeout=5)
        return jsonify({"log": result.stdout, "file": log_file})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.get("/logs/caddy")
@login_required
def caddy_logs():
    try:
        lines = max(1, min(int(request.args.get("lines", 100)), 5000))
    except (ValueError, TypeError):
        lines = 100
    try:
        result = subprocess.run(
            ["journalctl", "-u", "caddy", "-n", str(lines), "--no-pager", "--output=short"],
            capture_output=True, text=True, timeout=5)
        return jsonify({"log": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.post("/restart/xray")
@login_required
def restart_xray():
    ok, msg = apply_xray_config()
    log_action("service.restart", target_type="service", target_name="xray",
               details={"ok": ok, "message": msg})
    return jsonify({"ok": ok, "message": msg})


@bp.post("/restart/caddy")
@login_required
def restart_caddy():
    ok, msg = apply_caddy_config()
    log_action("service.restart", target_type="service", target_name="caddy",
               details={"ok": ok, "message": msg})
    return jsonify({"ok": ok, "message": msg})


ALLOWED_SETTINGS = {
    "panel_domain", "acme_email", "xray_log_level",
    "xray_domain_strategy", "xray_api_port", "server_ip",
    "xray_dns", "xray_dns_query_strategy",
}

XRAY_SETTINGS = {
    "xray_log_level", "xray_domain_strategy", "xray_api_port",
    "xray_dns", "xray_dns_query_strategy",
}

# Допустимые значения queryStrategy в секции dns Xray.
XRAY_DNS_STRATEGIES = frozenset({"UseIP", "UseIPv4", "UseIPv6"})

# Допустимые значения log-level в Xray (`log.loglevel`).
XRAY_LOG_LEVELS = frozenset({"debug", "info", "warning", "error", "none"})

# Допустимые значения `routing.domainStrategy` в Xray.
XRAY_DOMAIN_STRATEGIES = frozenset({"AsIs", "IPIfNonMatch", "IPOnDemand"})


def _validate_setting(key: str, value) -> tuple[bool, str | None, object]:
    """
    Валидирует одно key/value перед сохранением. Возвращает
    (ok, error, normalized_value). Если ok=False — настройку не пишем.

    Принцип: валидация СТРОГАЯ на input. В отличие от inbound/routing,
    settings — это глобальное состояние, ошибиться один раз тут — это
    положить целый Xray (некорректный log level → xray test FAIL →
    write_xray_config не заменит файл, но юзер увидит ошибку «Xray не
    перезапустился» без понимания причины).
    """
    if key == "panel_domain":
        # Пустое допустимо: бывает что юзер хочет сбросить домен и
        # вернуться на HTTP-онбординг. Но если непустое — должно быть
        # валидным.
        if not value:
            return True, None, ""
        ok, err = validate_domain(value)
        if not ok:
            return False, err, None
        return True, None, str(value).strip().lower()
    if key == "acme_email":
        if not value:
            return True, None, ""
        ok, err = validate_email(value, allow_empty=False, strict=True)
        if not ok:
            return False, err, None
        return True, None, str(value).strip()
    if key == "xray_log_level":
        ok, err = validate_enum(value, XRAY_LOG_LEVELS, label="xray_log_level")
        if not ok:
            return False, err, None
        return True, None, value
    if key == "xray_domain_strategy":
        ok, err = validate_enum(value, XRAY_DOMAIN_STRATEGIES, label="xray_domain_strategy")
        if not ok:
            return False, err, None
        return True, None, value
    if key == "xray_api_port":
        # Это локальный bind-порт самого Xray (для stats API). Поэтому
        # check_panel_conflicts=True: ставить его на 80/443 категорически
        # нельзя.
        ok, err, port = validate_port(value, check_panel_conflicts=True)
        if not ok:
            return False, err, None
        # Дополнительно: не должен пересекаться с уже существующими
        # Xray-инбаундами.
        from app.models import Inbound
        conflict = Inbound.query.filter(
            Inbound.engine == "xray",
            Inbound.port == port,
        ).first()
        if conflict:
            return False, (
                f"Порт {port} уже занят инбаундом '{conflict.tag}'. "
                f"Выберите другой порт для xray_api_port."
            ), None
        return True, None, str(port)
    if key == "xray_dns":
        # DoH-URL или обычный DNS IP/hostname; пусто — DNS не задан.
        if not value:
            return True, None, ""
        ok, err = validate_dns_server(value)
        if not ok:
            return False, err, None
        return True, None, str(value).strip()
    if key == "xray_dns_query_strategy":
        if not value:
            return True, None, "UseIP"
        ok, err = validate_enum(value, XRAY_DNS_STRATEGIES, label="xray_dns_query_strategy")
        if not ok:
            return False, err, None
        return True, None, value
    if key == "server_ip":
        # Этот ключ — display-only (показывается в подписке/UI). Если
        # юзер хочет руками задать «логичный» IP отличный от detected —
        # позволяем что угодно непустое. Реальную работу проксы это не
        # ломает.
        if value is None:
            return True, None, ""
        return True, None, str(value).strip()
    # Неизвестный ключ сюда вообще не должен дойти (фильтр ALLOWED_SETTINGS
    # выше), но защитимся.
    return True, None, str(value)


@bp.get("/settings")
@login_required
def get_settings():
    rows = Setting.query.all()
    # Не отдаём внутренние ключи: одноразовые handoff-токены (auth-bypass)
    # и миграционные маркеры не должны попадать в API-ответ.
    _hidden = ("handoff:", "migration_")
    return jsonify({r.key: r.value for r in rows
                    if not r.key.startswith(_hidden)})


@bp.put("/settings")
@login_required
def update_settings():
    data = request.get_json(force=True)
    changed_keys = set()
    for key, value in data.items():
        if key not in ALLOWED_SETTINGS:
            continue
        ok, err, normalized = _validate_setting(key, value)
        if not ok:
            # Жёстко 400 на первой же кривой настройке. Никаких частичных
            # сохранений — иначе UI получит подтверждение «всё ок», а на
            # самом деле часть данных не дошла.
            return jsonify({"error": f"{key}: {err}"}), 400
        Setting.set(key, str(normalized))
        changed_keys.add(key)
    db.session.commit()

    if changed_keys & XRAY_SETTINGS:
        ok, msg = apply_xray_config()
        if not ok:
            log_action("settings.update", target_type="settings",
                       details={"keys": sorted(changed_keys), "xray_restart_failed": msg})
            return jsonify({"ok": True, "warning": f"Настройки сохранены, но Xray не перезапустился: {msg}"}), 200

    if changed_keys:
        log_action("settings.update", target_type="settings",
                   details={"keys": sorted(changed_keys)})
    return jsonify({"ok": True})


@bp.post("/change-password")
@login_required
def change_password():
    data         = request.get_json(force=True)
    current_pwd  = data.get("current_password", "")
    new_password = data.get("password", "").strip()
    if not current_user.check_password(current_pwd):
        log_action("password.change", target_type="user",
                   target_name=current_user.username,
                   details={"ok": False, "reason": "bad_current"})
        return jsonify({"error": "Неверный текущий пароль"}), 401
    if not new_password or len(new_password) < 10:
        return jsonify({"error": "Новый пароль должен быть не менее 10 символов"}), 400
    if new_password == current_pwd:
        return jsonify({"error": "Новый пароль должен отличаться от текущего"}), 400
    current_user.set_password(new_password)
    db.session.commit()
    log_action("password.change", target_type="user",
               target_name=current_user.username,
               details={"ok": True})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Dashboard endpoints: traffic history + alerts
# ---------------------------------------------------------------------------

@bp.get("/traffic-history")
@login_required
def traffic_history():
    """Агрегирует TrafficStat по часовым бакетам за последние N часов.

    Возвращает: [{"ts": "2025-01-15T14:00:00+00:00", "up": 12345, "down": 67890}, ...]

    Бакеты с нулевым трафиком включаются в ответ, чтобы фронт мог рисовать
    непрерывный график без дыр. Если за весь период не было записей,
    возвращается пустой массив — фронт показывает заглушку.

    Реализация в Python (без SQLite-specific strftime) ради переносимости
    на случай миграции на Postgres. Запрос идёт по recorded_at; на больших
    объёмах TrafficStat имеет смысл добавить индекс на recorded_at
    (сейчас его нет — table scan терпим, потому что период не более 7 дней).
    """
    from datetime import datetime, timedelta, timezone
    from app.models import TrafficStat

    try:
        hours = max(1, min(int(request.args.get("hours", 24)), 168))  # max 7 дней
    except (ValueError, TypeError):
        hours = 24

    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    # Округляем начало до часа — чтобы первый бакет был полным интервалом,
    # а не "обрубком".
    bucket_start = start.replace(minute=0, second=0, microsecond=0)

    # Инициализируем все бакеты нулями
    buckets: dict[str, list[int]] = {}
    cursor = bucket_start
    while cursor <= now:
        buckets[cursor.isoformat()] = [0, 0]
        cursor += timedelta(hours=1)

    rows = TrafficStat.query.filter(TrafficStat.recorded_at >= bucket_start).all()
    for r in rows:
        rec = r.recorded_at
        if rec.tzinfo is None:
            rec = rec.replace(tzinfo=timezone.utc)
        key = rec.replace(minute=0, second=0, microsecond=0).isoformat()
        if key in buckets:
            buckets[key][0] += int(r.delta_up or 0)
            buckets[key][1] += int(r.delta_down or 0)

    return jsonify([
        {"ts": ts, "up": v[0], "down": v[1]}
        for ts, v in sorted(buckets.items())
    ])


@bp.get("/alerts")
@login_required
def alerts():
    """Возвращает клиентов, требующих внимания админа:
      - срок жизни истекает в ближайшие 7 дней
      - использовано ≥ 90% любого лимита трафика (up или down)

    Уже истёкшие/превышенные не возвращаем — они и так помечены в таблице
    клиентов своим красным badge'ом, дублировать в "алёрты" не нужно.
    """
    from datetime import datetime, timedelta, timezone
    from app.models import Client

    now      = datetime.now(timezone.utc)
    cutoff   = now + timedelta(days=7)

    expiring = []
    near_lim = []

    for c in Client.query.filter_by(enabled=True).all():
        # ── Скоро истечёт ──
        if c.expire_at:
            ea = c.expire_at if c.expire_at.tzinfo else c.expire_at.replace(tzinfo=timezone.utc)
            if now < ea <= cutoff:
                hours_left = int((ea - now).total_seconds() // 3600)
                expiring.append({
                    "id": c.id,
                    "name": c.name,
                    "inbound_id": c.inbound_id,
                    "inbound_tag": c.inbound.tag,
                    "hours_left": hours_left,
                })

        # ── У лимита трафика ──
        # Берём максимум из uplink/downlink-загрузок, чтобы триггериться
        # даже когда один из лимитов 0 (= безлимитен), а другой — у предела.
        pct_up   = (c.traffic_used_up   / c.traffic_limit_up   * 100) if c.traffic_limit_up   else 0
        pct_down = (c.traffic_used_down / c.traffic_limit_down * 100) if c.traffic_limit_down else 0
        pct = max(pct_up, pct_down)
        if 90 <= pct < 100:   # 100%+ это уже is_over_limit, отдельная категория
            near_lim.append({
                "id": c.id,
                "name": c.name,
                "inbound_id": c.inbound_id,
                "inbound_tag": c.inbound.tag,
                "pct": round(pct, 1),
            })

    # Сортировка: что больше горит — выше
    expiring.sort(key=lambda x: x["hours_left"])
    near_lim.sort(key=lambda x: -x["pct"])

    return jsonify({
        "expiring_soon": expiring,
        "near_limit":    near_lim,
    })


# ---------------------------------------------------------------------------
# Audit log endpoint (этап 4)
# ---------------------------------------------------------------------------

@bp.get("/audit-logs")
@login_required
def audit_logs():
    """Список записей audit-лога с фильтрами и пагинацией.

    Параметры запроса:
      - limit:  макс. записей на страницу (1–500, default 100)
      - offset: смещение (default 0)
      - action: фильтр по префиксу действия (например, "client." вернёт
                все client.create / client.update / client.delete и т.д.)
      - user:   точный фильтр по имени пользователя
    """
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
    except (ValueError, TypeError):
        limit = 100
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except (ValueError, TypeError):
        offset = 0

    action_filter = (request.args.get("action") or "").strip()
    user_filter   = (request.args.get("user") or "").strip()

    q = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if action_filter:
        # Префиксный фильтр через LIKE — позволяет искать "client.%" или "auth.%"
        q = q.filter(AuditLog.action.like(f"{action_filter}%"))
    if user_filter:
        q = q.filter(AuditLog.username == user_filter)

    total = q.count()
    rows  = q.offset(offset).limit(limit).all()

    return jsonify({
        "total":   total,
        "offset":  offset,
        "limit":   limit,
        "entries": [e.to_dict() for e in rows],
    })
