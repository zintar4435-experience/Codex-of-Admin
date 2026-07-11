"""
Flask application factory.
"""
import os
import hmac
import secrets
from datetime import timedelta
from flask import Flask, request, jsonify, session
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3

from app.models import db, User

limiter = Limiter(get_remote_address, default_limits=[])


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        # busy_timeout: при конкурентной записи (2+ процесса/треда) ждём до 5с
        # освобождения блокировки вместо мгновенного "database is locked".
        cursor.execute("PRAGMA busy_timeout=5000")
        # synchronous=NORMAL — безопасный и быстрый режим для WAL.
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


def create_app(config_overrides: dict = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    # --- Persistent SECRET_KEY ---
    # Приоритет: переменная окружения → файл .secret_key → генерация при первом запуске.
    # Это гарантирует сохранение сессий между перезапусками сервиса.
    _key_path = os.path.join(app.instance_path, ".secret_key")
    if os.path.exists(_key_path):
        _secret = open(_key_path).read().strip()
    else:
        os.makedirs(app.instance_path, exist_ok=True)
        _secret = os.urandom(32).hex()
        open(_key_path, "w").write(_secret)
        os.chmod(_key_path, 0o600)

    # --- Base config ---
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", _secret),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL",
            f"sqlite:///{os.path.join(app.instance_path, 'panel.db')}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # Кэширование статики (шрифты/иконки/логотип/css) браузером на 30 дней.
        # Без этого Flask отдаёт Cache-Control: no-cache, и браузер на КАЖДОЙ
        # странице перепроверяет все статические файлы отдельными запросами к
        # серверу. На сети с заметным RTT это давало 1-2 секунды задержки на
        # каждую загрузку. С max-age статика берётся из кэша без обращения к
        # серверу. Имена файлов стабильны; при обновлении ассетов нужен
        # hard-refresh (или поднять версию в ссылке).
        SEND_FILE_MAX_AGE_DEFAULT=timedelta(days=30),
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false") == "true",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Idle-таймаут сессии (правка #5): без этого авторизация жила, пока
        # открыта вкладка, и не истекала никогда. Делаем сессию permanent
        # со скользящим сроком — Flask продлевает его при каждом запросе
        # (SESSION_REFRESH_EACH_REQUEST=True по умолчанию), так что после
        # N часов бездействия требуется повторный вход.
        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=int(os.environ.get("SESSION_LIFETIME_HOURS", "12"))
        ),
        REMEMBER_COOKIE_DURATION=timedelta(days=7),
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false") == "true",
    )

    if config_overrides:
        app.config.update(config_overrides)

    os.makedirs(app.instance_path, exist_ok=True)

    # --- Extensions ---
    db.init_app(app)
    limiter.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Требуется авторизация"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # --- CSRF protection (правка #7) ---
    # Токен на сессию. Шаблоны вставляют его в <meta name="csrf-token">,
    # JS-хелпер api() шлёт его в заголовке X-CSRF-Token на мутирующих
    # запросах. Проверяем на сервере. SameSite=Lax остаётся как второй
    # эшелон. GET/HEAD не проверяются.
    #
    # Исключения — эндпоинты первичного онбординга, которые вызываются
    # со standalone-страниц (setup/setup_progress, не наследующих base.html,
    # т.е. без csrf-meta). Они защищены SameSite=Lax + логином.
    # Исключения — эндпоинты, вызываемые со standalone-страниц, не
    # наследующих base.html (нет csrf-meta): форма входа и страницы
    # первичного онбординга (setup / setup_progress). Они защищены
    # SameSite=Lax + (где применимо) логином.
    _CSRF_EXEMPT = {
        "/auth/login",
        "/setup",
        "/api/system/enable-https",
        "/api/system/onboarding-handoff",
        "/api/system/restart-self",
    }
    _CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    @app.context_processor
    def _inject_csrf():
        def csrf_token():
            tok = session.get("_csrf")
            if not tok:
                tok = secrets.token_urlsafe(32)
                session["_csrf"] = tok
            return tok
        return {"csrf_token": csrf_token}

    @app.before_request
    def _csrf_and_session():
        # Скользящий idle-таймаут: помечаем сессию permanent, но только
        # когда в ней уже что-то есть (не плодим cookie на публичном /sub).
        if session:
            session.permanent = True
        # CSRF-проверка покрывает ВСЕ мутирующие запросы, а не только /api/.
        # Раньше формы вне /api/ (например, /auth/logout) проходили без
        # проверки токена — теперь нет. Токен принимается из заголовка
        # X-CSRF-Token (JS-хелпер api()) или из поля формы _csrf (logout).
        if request.method in _CSRF_METHODS:
            if request.path in _CSRF_EXEMPT:
                return
            sent = (request.headers.get("X-CSRF-Token", "")
                    or request.form.get("_csrf", ""))
            token = session.get("_csrf", "")
            if not (token and sent and hmac.compare_digest(sent, token)):
                return jsonify({"error": "CSRF-токен отсутствует или неверен"}), 403

    # --- Blueprints ---
    from app.api.auth import bp as auth_bp
    from app.api.inbounds import bp as inbounds_bp
    from app.api.clients import bp as clients_bp
    from app.api.routing import bp as routing_bp
    from app.api.split_tunnel import bp as split_bp
    from app.api.system import bp as system_bp
    from app.api.outbounds import bp as outbounds_bp
    from app.api.security import bp as security_bp
    from app.api.subscription import bp as subscription_bp
    from app.api.backup import bp as backup_bp
    from app.views import bp as views_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(inbounds_bp, url_prefix="/api/inbounds")
    app.register_blueprint(clients_bp, url_prefix="/api/clients")
    app.register_blueprint(routing_bp, url_prefix="/api/routing")
    app.register_blueprint(split_bp, url_prefix="/api/split-tunnel")
    app.register_blueprint(system_bp, url_prefix="/api/system")
    app.register_blueprint(outbounds_bp, url_prefix="/api/outbounds")
    app.register_blueprint(security_bp, url_prefix="/api/security")
    app.register_blueprint(backup_bp, url_prefix="/api/backup")
    # Subscription URL — публичный (без авторизации), доступ только по токену.
    app.register_blueprint(subscription_bp, url_prefix="/sub")
    app.register_blueprint(views_bp)

    # --- DB init ---
    with app.app_context():
        db.create_all()
        _ensure_schema()      # добавление недостающих колонок без Alembic
        _seed_defaults()

    # Шедулер запускается отдельным systemd-юнитом proxy-panel-scheduler.service.
    # См. app/core/scheduler.py:run_blocking — внутри веб-приложения он не нужен.

    # --- Error handlers: always return JSON for API routes ---
    from flask import request, jsonify
    from sqlalchemy.exc import OperationalError, SQLAlchemyError

    @app.errorhandler(OperationalError)
    def handle_db_error(e):
        app.logger.error("DB OperationalError: %s", e)
        if request.path.startswith("/api/"):
            return jsonify({"error": "Ошибка базы данных. Проверьте права на /instance/panel.db"}), 500
        return str(e), 500

    @app.errorhandler(SQLAlchemyError)
    def handle_sqlalchemy_error(e):
        app.logger.error("SQLAlchemyError: %s", e)
        if request.path.startswith("/api/"):
            return jsonify({"error": f"Ошибка БД: {type(e).__name__}"}), 500
        return str(e), 500

    @app.errorhandler(500)
    def handle_500(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Внутренняя ошибка сервера"}), 500
        return e

    if os.environ.get("HTTPS_ENABLED", "false").lower() == "true":
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

    # --- Caddy config push на старте панели ---
    # Caddy запускается с минимальным /etc/caddy/Caddyfile (только admin
    # endpoint на localhost:2019). Полная конфигурация HTTPS-серверов
    # генерируется панелью и пушится в Caddy через admin API. Эта
    # конфигурация живёт только в памяти Caddy.
    #
    # Если по любой причине Caddy потеряет runtime-конфиг (reload через
    # systemctl, ручной рестарт, OOM-kill и т.п.), HTTPS-серверы исчезнут
    # и панель станет недоступна по домену. Раньше это случалось каждую
    # ночь из-за logrotate с postrotate-reload — починено через
    # copytruncate в /etc/logrotate.d/caddy.
    #
    # Этот фоновый поток — defense in depth: даже если Caddy потеряет
    # конфиг ПО ЛЮБОЙ ДРУГОЙ причине, рестарт панели (systemctl restart
    # proxy-panel) её восстановит. С учётом gunicorn'a с двумя воркерами
    # вызов происходит дважды (по разу на воркер); apply_caddy_config —
    # идемпотентен, повторный пуш просто заменяет конфиг тем же самым.
    _start_caddy_config_pusher(app)

    return app


def _start_caddy_config_pusher(app):
    """Фоновый поток, который через 5 секунд после старта панели пушит
    актуальный конфиг в Caddy admin API.

    Делается в отдельном потоке, чтобы НЕ блокировать старт gunicorn'a,
    если Caddy в этот момент недоступен (его таймаут на /load может
    висеть десятки секунд). При любой ошибке — пишем warning, дальше
    панель работает как обычно.
    """
    import threading
    import time

    def _worker():
        # Небольшая задержка — на случай, если систему только что
        # подняли и Caddy ещё не успел начать слушать localhost:2019.
        time.sleep(5)
        try:
            # Импорт внутри потока — чтобы любые проблемы с импортом
            # не падали в момент старта приложения.
            from app.core.caddy import apply_caddy_config
            with app.app_context():
                apply_caddy_config()
            app.logger.info("Caddy config (re)applied on panel startup")
        except Exception as e:
            # Намеренно широкий except — что бы ни пошло не так, это не
            # должно ронять панель. Если Caddy лёг, можно повторить
            # вручную: see app.core.caddy.apply_caddy_config()
            app.logger.warning(
                "Could not apply Caddy config on panel startup: %s. "
                "Panel will work, but Caddy may need manual config push.",
                e,
            )

    # daemon=True — поток умрёт вместе с воркером, не блокируя shutdown.
    t = threading.Thread(target=_worker, name="caddy-config-pusher", daemon=True)
    t.start()


def _ensure_schema():
    """Идемпотентная миграция схемы для случаев, когда Alembic не используется.

    Добавляет недостающие колонки в существующие таблицы через ALTER TABLE.
    SQLAlchemy db.create_all() умеет только создавать новые таблицы — для
    эволюции существующей схемы (новое поле в Client и т.п.) этот метод
    бесполезен, поэтому делаем вручную.

    Каждый блок должен быть проверкой "если колонки нет — добавить":
    повторный запуск на уже мигрированной БД ничего не делает.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)

    # --- clients: last_seen_up / last_seen_down (правка #4: учёт трафика после рестарта) ---
    if "clients" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("clients")}
        with db.engine.begin() as conn:
            if "last_seen_up" not in existing:
                conn.execute(text(
                    "ALTER TABLE clients ADD COLUMN last_seen_up BIGINT DEFAULT 0"
                ))
                # Инициализация: считаем, что в прошлом тике мы видели в Xray
                # ровно то, что уже накоплено в traffic_used_up. Без этого на
                # первом же тике после апгрейда дельта = весь Xray cumulative,
                # и трафик удвоится. Безопасно даже если Xray был перезапущен:
                # _accumulate_delta поймает "new < last_seen" и сам обработает.
                conn.execute(text(
                    "UPDATE clients SET last_seen_up = COALESCE(traffic_used_up, 0)"
                ))
            if "last_seen_down" not in existing:
                conn.execute(text(
                    "ALTER TABLE clients ADD COLUMN last_seen_down BIGINT DEFAULT 0"
                ))
                conn.execute(text(
                    "UPDATE clients SET last_seen_down = COALESCE(traffic_used_down, 0)"
                ))

            # --- clients: share_token для subscription URL (этап 2) ---
            # У существующих клиентов токена нет — раздаём уникальные UUID.
            # default=generate_uuid сработает только на INSERT, поэтому на
            # старых строках нужен явный UPDATE.
            if "share_token" not in existing:
                import uuid as _uuid
                conn.execute(text(
                    "ALTER TABLE clients ADD COLUMN share_token VARCHAR(36)"
                ))
                rows = conn.execute(text("SELECT id FROM clients")).fetchall()
                for (cid,) in rows:
                    conn.execute(
                        text("UPDATE clients SET share_token = :tok WHERE id = :id"),
                        {"tok": str(_uuid.uuid4()), "id": cid},
                    )

    # --- inbounds: одноразовый сброс tls_acme для Xray (правка #3) ---
    # Опция Auto-ACME для Xray-инбаундов никогда не работала (путь
    # /etc/ssl/caddy/{domain}/cert.pem не существует). Старые записи могли
    # иметь tls_acme=1; сбрасываем их в 0, чтобы убрать шум из логов.
    # Маркер в settings защищает от случайного повторного сброса, если
    # пользователь вручную выставит флаг для будущей реализации экспорта.
    if "inbounds" in inspector.get_table_names() and "settings" in inspector.get_table_names():
        with db.engine.begin() as conn:
            marker = conn.execute(text(
                "SELECT value FROM settings WHERE key = 'migration_xray_tls_acme_reset'"
            )).fetchone()
            if marker is None:
                conn.execute(text(
                    "UPDATE inbounds SET tls_acme = 0 WHERE tls_acme = 1 AND engine = 'xray'"
                ))
                conn.execute(text(
                    "INSERT INTO settings (key, value) VALUES ('migration_xray_tls_acme_reset', '1')"
                ))

    # --- routing_rules: match_network (TCP / UDP / оба) ---
    # NULL по умолчанию (= оба, без фильтрации). Включается в Xray-конфиг
    # только если значение не NULL — обратная совместимость для всех
    # существующих правил.
    if "routing_rules" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("routing_rules")}
        if "match_network" not in existing:
            with db.engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE routing_rules ADD COLUMN match_network VARCHAR(8)"
                ))

    # --- users: поля двухфакторной аутентификации (TOTP) ---
    # Старые БД не имеют этих колонок; добавляем с безопасными значениями
    # по умолчанию (2FA выключена, секрета нет) — на вход это не влияет.
    if "users" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("users")}
        with db.engine.begin() as conn:
            if "totp_secret" not in existing:
                conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)"))
            if "totp_enabled" not in existing:
                conn.execute(text("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0 NOT NULL"))
            if "recovery_codes" not in existing:
                conn.execute(text("ALTER TABLE users ADD COLUMN recovery_codes TEXT"))

    # --- clients: unique constraints на (inbound_id, email) и (inbound_id, username) ---
    # SQLite не поддерживает ADD CONSTRAINT после создания таблицы. Единственный
    # способ добавить unique index — CREATE UNIQUE INDEX IF NOT EXISTS.
    # Перед созданием индекса дедуплицируем существующие строки (если есть):
    # из каждой группы дубликатов оставляем запись с наименьшим id, остальные удаляем.
    if "clients" in inspector.get_table_names():
        with db.engine.begin() as conn:
            # Проверяем, созданы ли уже индексы (idempotent)
            existing_idx = {row[0] for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='clients'")
            ).fetchall()}

            if "uq_client_inbound_email" not in existing_idx:
                # Дедуп по email: удаляем дубликаты, оставляем наименьший id
                conn.execute(text("""
                    DELETE FROM clients WHERE id NOT IN (
                        SELECT MIN(id) FROM clients GROUP BY inbound_id, email
                    )
                """))
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_client_inbound_email "
                    "ON clients (inbound_id, email)"
                ))

            if "uq_client_inbound_username" not in existing_idx:
                # Дедуп по username
                conn.execute(text("""
                    DELETE FROM clients WHERE id NOT IN (
                        SELECT MIN(id) FROM clients GROUP BY inbound_id, username
                    )
                """))
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_client_inbound_username "
                    "ON clients (inbound_id, username)"
                ))


def _seed_defaults():
    """Create default settings if they don't exist."""
    from app.models import Setting
    defaults = {
        "xray_api_port": "10085",
        "xray_log_level": "warning",
        "xray_domain_strategy": "IPIfNonMatch",
        "panel_domain": "",
        "acme_email": "",
        "xray_dns": "",                       # DoH-URL/IP; пусто = системный DNS
        "xray_dns_query_strategy": "UseIP",
    }
    for key, value in defaults.items():
        if db.session.get(Setting, key) is None:
            db.session.add(Setting(key=key, value=value))
    db.session.commit()
