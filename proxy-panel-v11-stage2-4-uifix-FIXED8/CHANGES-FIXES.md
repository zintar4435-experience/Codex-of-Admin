# Правки безопасности/стабильности + экспорт/импорт (поверх v11-stage2-4-uifix)

Все изменения внесены поверх исходного архива и проверены автотестами
(Flask test client 31/31 + unit-тест отката Xray 6/6).

## Безопасность
- CSRF-защита. Токен на сессию: шаблоны кладут его в
  <meta name="csrf-token">, JS-хелпер api() шлёт X-CSRF-Token на
  POST/PUT/PATCH/DELETE; сервер проверяет на всех мутирующих /api/.
  Исключения — эндпоинты онбординга (enable-https, onboarding-handoff,
  restart-self) со standalone-страниц; защищены SameSite=Lax + логином.
  Файлы: app/__init__.py, base.html, split_tunnel.html, security.html.
- Таймаут сессии. Раньше авторизация не истекала никогда (жила, пока
  открыта вкладка). Теперь сессия permanent со скользящим сроком
  PERMANENT_SESSION_LIFETIME (env SESSION_LIFETIME_HOURS, по умолчанию 12ч).
- GET /api/system/settings — фильтр служебных ключей (handoff:*, migration_*).
- split-tunnel URL — только http/https (закрыт file:///SSRF).
- GET /api/system/https-status — rate-limit 30/мин.
- Валидация версии Xray в /api/system/xray/update (только N.N.N).

## Стабильность
- Откат конфига Xray. apply_xray_config хранит config.json.last-good;
  если новый конфиг прошёл -test, но restart не поднялся — старый
  восстанавливается и Xray перезапускается (убирает crash-loop).
- SQLite: busy_timeout=5000 + synchronous=NORMAL.
- gunicorn: --workers 1 --threads 4 (было 2 воркера).
- Зависимости с верхними границами (<NEXTMAJOR).
- bind gunicorn из окружения GUNICORN_BIND (дефолт 0.0.0.0:5000), install.sh.

## Мелочи
- 400 вместо 500 на кривом expire_days/expire_at (clients.py).
- db.session.get вместо легаси User.query.get (auth.py).

## Новая фича: экспорт/импорт (app/api/backup.py, кнопки в inbounds)
- GET  /api/backup/export — все inbounds с клиентами в JSON (включая
  секреты, share_token, накопленный трафик).
- POST /api/backup/import — восстановление. mode=skip (по умолч.)
  пропускает существующие по tag, mode=replace пересоздаёт. Каждый inbound
  в своём savepoint; дубли клиентов пропускаются; после импорта — apply.
  last_seen_* = traffic_used_*, чтобы первый тик не удвоил трафик.

## Применение на сервере
1. Код: update.sh panel из корня архива (или скопировать файлы), затем
   sudo systemctl restart proxy-panel proxy-panel-scheduler
2. bind-фикс (только если заходишь по https://домен): заменить ExecStart в
   /etc/systemd/system/proxy-panel.service строкой из install.sh /
   приложенного proxy-panel.service, затем daemon-reload + restart.

## Догоняющая правка (UI-аудит)
- Кнопка «Редактировать» у inbound теперь подтягивает probe-resistance
  секрет NaiveProxy отдельным запросом (GET /api/inbounds/<id>/secret) и
  подставляет его в форму. Раньше поле открывалось пустым и сохранение
  затирало секрет. inbounds.html.
- Удалены два неиспользуемых эндпоинта: GET /api/clients/<id>/link
  (ссылка и так есть в списке клиентов) и GET /api/system/services-status
  (дубль /api/system/status). clients.py, system.py.

## Аудит матрицы транспортов + учёт трафика (итерации 1–4)
Проверено тест-стендом «протокол×транспорт»: было 11/21, стало 21/21.
- HTTP/2: в конфиге транспорт назывался "h2"; Xray ждёт "http". Исправлено
  маппингом при генерации (значение в БД не мигрируется). xray.py.
- Ссылки подключения для kcp/h2/httpupgrade/splithttp были неполными
  (не хватало seed/headerType и path/host) → клиент не подключался. Добавлен
  общий помощник транспортных параметров для vless/trojan. VMess+gRPC:
  serviceName теперь передаётся в поле path, режим — в type. clients.py.
- Учёт трафика NaiveProxy переписан на инкрементальное чтение access-log
  Caddy (offset+inode в state-файле instance/caddy_traffic.state, обработка
  ротации и обрезания). Раньше суммировалось «окно» из 100k строк и
  трактовалось как накопительный счётчик — трафик врал. caddy.py, scheduler.py.
- Убран двойной db.session.commit() в обновлении split-tunnel. scheduler.py.

## Визуал + переработка страницы Inbounds (Claude Design → панель)
- Тема Glass (Liquid Glass): добавлена как [data-theme="glass"], сделана
  темой по умолчанию; выбирается в «Сервер → Внешний вид» (slate/frosted/glass).
  Стекло (backdrop-filter) — только на верхнеуровневых панелях; карточкам
  даётся полупрозрачный фон без блюра (защита от артефактов Chrome).
- Страница Inbounds переработана: две колонки (Xray слева, NaiveProxy справа)
  вместо одной таблицы с фильтром. Каждый inbound — раскрывающаяся карточка.
- Клиенты теперь видны ИНЛАЙН: клик по inbound подгружает его клиентов
  (GET /api/clients/inbound/<id>) прямо в карточку, с действиями: ссылка+QR,
  Subscription URL (+смена токена), сброс трафика, вкл/выкл, удалить,
  создать/редактировать. Все действия через существующие API (+CSRF).
- Отдельная страница /clients оставлена рабочей как запасной путь; ссылка-
  переход из строки inbound убрана (её заменяет раскрытие). Backend не менялся.

## Темы из дизайна + фикс уезда страницы (FIXED7)
- Frosted убрана, вместо неё тема Codex — «красивая» тёмно-изумрудная тема
  из дизайна (градиентный фон, мятный акцент). base.html, server.html.
- Glass переписана точно по архиву: глубокий фон + анимированные цветные
  пятна (body::before, @keyframes glassDrift), матовые панели и карточки
  (backdrop-filter), у вложенных карточек блюр снят (.card .card) — иначе
  Chrome рисует чёрное. base.html.
- Переключатель тем: slate / codex / glass (по умолчанию glass).
- ФИКС: при раскрытии обеих колонок Inbounds страница уезжала за экран.
  Причина — flex-ребёнок .main без min-width:0 + grid-колонки без min-width:0.
  Добавлено min-width:0 на .main/.content/колонки; таблица клиентов скроллится
  внутри своей области. base.html, inbounds.html.

## IP сервера + уплотнение таблицы + 2FA (FIXED8)
- IP сервера: новый GET /api/system/server-ip (определяет публичный IP через
  ipify, кеш 10 мин). На странице «Сервер» поле IP автозаполняется и показано
  заблюренным; иконка-глаз раскрывает на 8 сек (или при фокусе на поле).
- Таблица клиентов: два столбца трафика сведены в один (↑/↓), кнопки поджаты —
  без горизонтального скролла на обычной ширине (скролл остаётся как страховка).
- Двухфакторная аутентификация (TOTP, без внешних зависимостей):
  • app/core/totp.py — RFC 6238 на стандартной библиотеке (SHA1, 6 цифр, 30с).
  • User: totp_secret/totp_enabled/recovery_codes (+ идемпотентная миграция).
  • /api/system/2fa/{status,setup,enable,disable} (login_required, CSRF).
  • Вход (/auth/login): при включённой 2FA требует код (или одноразовый
    резервный код). Логин по-прежнему работает без 2FA.
  • UI: карточка на «Сервер → Настройки» с QR-подключением и резервными
    кодами; на странице входа поле кода появляется при необходимости.

## Совместимость с приложением Codex-Connect
Аудит стыка «панель → подписка → приложение Codex-Connect». Приложение
парсит ровно два формата ссылок: VLESS+Reality и NaiveProxy. Найдено и
исправлено три расхождения (все — на стороне генерации ссылок, app/api/clients.py):
- ФИКС: NaiveProxy — пароль в share-ссылке. Раньше `client.password or ""`
  давал пустой пароль у клиента без явного пароля, тогда как Caddy авторизует
  по `client.password or client.uuid` — Basic-auth не сходился, подключения не
  было. Теперь ссылка тоже несёт uuid (`_naive_link`).
- ФИКС: VLESS+Reality в shared-443 — SNI в ссылке. Сервер в shared-режиме
  игнорирует reality_server_names из формы и подставляет свои panel/naive-домены
  (xray.py:_build_stream_settings), а ссылка брала SNI из пустого поля формы →
  `sni=""` → Reality-handshake у клиента не сходился. Теперь `_vless_link` в
  shared-443 берёт SNI из того же `_shared_443_server_names()`, что и сервер.
  Классический Reality (port≠443) не затронут — SNI по-прежнему из формы.
- Метка совместимости в UI списка inbounds: бейдж «Connect ✓/✗» показывает,
  прочитает ли приложение этот inbound из подписки (VLESS+Reality или Naive —
  да; vmess/trojan/ss/socks/http и vless с обычным TLS — нет, ссылка молча
  отбрасывается). inbounds.html, функция ccCompatible (зеркалит _vless_link).
