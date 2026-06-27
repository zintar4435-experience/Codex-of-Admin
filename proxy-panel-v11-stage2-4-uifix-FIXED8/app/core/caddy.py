"""
Caddy + NaiveProxy configuration manager.

Uses the Caddy JSON Admin API (http://localhost:2019) to apply config.
NaiveProxy runs as a Caddy forwardproxy plugin.

Panel itself is also reverse-proxied through Caddy on port 443.
"""
import base64
import json
import os
import collections
import logging
import requests
from typing import Any

from app.models import Inbound, Client, Setting

log = logging.getLogger(__name__)

CADDY_API = "http://127.0.0.1:2019"
MAX_LINES = 100_000
PANEL_BACKEND_ADDR = "http://127.0.0.1:5000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _panel_domain() -> str:
    return Setting.get("panel_domain", "")


def _naive_inbounds() -> list[Inbound]:
    return Inbound.query.filter_by(engine="naive", enabled=True).all()


def _caddy_post(path: str, data: Any) -> tuple[bool, str]:
    try:
        r = requests.post(
            f"{CADDY_API}{path}",
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code in (200, 201, 204):
            return True, "OK"
        return False, f"Caddy API {r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)


def _caddy_load(config: dict) -> tuple[bool, str]:
    return _caddy_post("/load", config)


# ---------------------------------------------------------------------------
# Route builders
# ---------------------------------------------------------------------------

def _encode_naive_credential(user: str, password: str) -> str:
    """
    Double-base64-кодирует "user:pass" для поля auth_credentials плагина
    klzgrad/forwardproxy.

    Почему double-encoding. Структура в JSON для forward_proxy — массив
    строк. Каждая строка — это base64 от []byte. А внутри тех []byte
    лежит base64-encoded "user:pass" (формат HTTP Basic auth challenge).
    То есть формула: encode_outer(encode_inner("user:pass")).

    Внутренний слой — то, что плагин использует как Basic-auth ключ.
    Внешний слой — артефакт Go: маршаллер JSON стандартно сериализует
    []byte как base64-string. В Caddyfile-форме (`basic_auth user pass`)
    адаптер сам делает оба шага; в JSON-форме мы обязаны их повторить.

    Проверено через `caddy adapt`: 'basic_auth alice secret123' даёт
    "WVd4cFkyVTZjMlZqY21WME1USXo=" = base64 от "YWxpY2U6c2VjcmV0MTIz"
    = base64 от "alice:secret123".
    """
    inner = base64.b64encode(f"{user}:{password}".encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    return outer


def _build_naive_catchall_route(inbounds: list[Inbound]) -> dict | None:
    """
    Build ОДИН NaiveProxy route для всех активных naive-инбаундов.
    auth_credentials объединяется по всем клиентам всех инбаундов.

    ── MATCHER (stage1-17) ──
    Route матчится OR-условием:
        [{"host": [naive_domain, ...]}, {"method": ["CONNECT"]}]
    В JSON-формате Caddy массив `match` = OR между объектами. То есть
    запрос попадает в этот route если выполнено любое из:
      • host-header равен одному из naive-доменов (probe/auth-check
        GET/HEAD), ИЛИ
      • метод == CONNECT (туннель — там host = target:port, не наш
        домен; чистый host-match их не ловит).

    ── ПОЧЕМУ НЕ ПРОСТО CATCH-ALL БЕЗ MATCH (как в stage1-16) ──
    Caddy `auto_https` решает какие сертификаты выпускать/обновлять
    через ACME, СКАНИРУЯ host-matchers всех routes. Catch-all route
    без match не даёт ему ни одного домена → cert для naive-домена
    не управляется и не подгружается в in-memory cache. Symptом —
    `tls.handshake "no matching certificates and no custom selection
    logic"` + `internal error` на TLS handshake.

    Добавление `{"host": [...]}` в match[0] возвращает auto_https
    нужную информацию (Caddy видит host-matcher и активирует ACME
    для этого домена). А `{"method": ["CONNECT"]}` в match[1]
    обеспечивает что CONNECT-запросы тоже попадают в route, даже
    когда их HTTP-Host = target:port.

    ── ПОЧЕМУ НЕ ОБЫЧНЫЙ HOST-MATCH (как в stage1-13/14/15) ──
    Без method-альтернативы CONNECT-запросы не матчились, плагин
    не получал их, Caddy отвечал дефолтным `NOP, status:0`, туннель
    не открывался. Это была главная причина "wrong version number"
    в curl/Karing до stage1-16. Подробности — см. README stage1-16.

    ── MULTI-INBOUND ──
    Если у пользователя несколько naive-инбаундов на разных
    субдоменах, все домены идут в один `host`-массив, а
    auth_credentials объединяются. SNI-фильтр на TLS-уровне
    (`tls_connection_policies.match.sni`) выбирает корректный cert
    для каждого SNI.
    """
    if not inbounds:
        return None

    naive_domains = [ib.domain for ib in inbounds if ib.domain]
    if not naive_domains:
        return None

    active_clients = []
    probe_resistance = None
    for ib in inbounds:
        for c in ib.clients:
            if c.is_active:
                active_clients.append(c)
        if probe_resistance is None and ib.probe_resistance_secret:
            probe_resistance = ib.probe_resistance_secret

    forward_proxy: dict[str, Any] = {
        "handler": "forward_proxy",
        "hide_ip": True,
        "hide_via": True,
    }
    if active_clients:
        forward_proxy["auth_credentials"] = [
            _encode_naive_credential(c.username or c.name, c.password or c.uuid)
            for c in active_clients
        ]
    if probe_resistance:
        forward_proxy["probe_resistance"] = {"domain": probe_resistance}

    # subroute-обёртка обязательна — без неё forward_proxy не делает
    # connection hijack для CONNECT-запросов. Подробности были раньше
    # в комментарии _build_naive_route (stage1-13). Сохраняем.
    subroute_wrapper = {
        "handler": "subroute",
        "routes": [{"handle": [forward_proxy]}],
    }

    return {
        # OR-matcher: см. docstring.
        "match": [
            {"host": naive_domains},
            {"method": ["CONNECT"]},
        ],
        "handle": [subroute_wrapper],
        "terminal": True,
    }


# ВАЖНО: _build_naive_route (per-inbound с host-match) удалён намеренно.
# Stage1-13/14/15: создавал route с "match":[{"host":[inbound.domain]}],
# что ломало CONNECT — см. docstring _build_naive_catchall_route.
# Заменён на единый catch-all route без host-match (stage1-16).


# ВАЖНО: _build_combined_route был удалён намеренно.
#
# Раньше существовала «фича»: если inbound.domain совпадал с panel_domain
# (или был пустым), Caddy получал route с двумя handler'ами подряд —
# forward_proxy и reverse_proxy. Идея была: forward_proxy интерцептит
# CONNECT-запросы, остальное падает в reverse_proxy на панель.
#
# Это не работает. forward_proxy для GET-запросов без proxy-семантики
# возвращает 301 с Location на ту же URL — браузер уходит в бесконечный
# редирект. ERR_TOO_MANY_REDIRECTS на панели как только naive-инбаунд
# создан на её домене.
#
# Правильное решение: NaiveProxy ВСЕГДА на отдельном (суб)домене,
# никаких пересечений с panel_domain. Это валидируется в API
# (app/api/inbounds.py: _validate_naive_inbound_domain).


def _panel_handler() -> dict:
    """Caddy reverse_proxy handler pointing to the panel's gunicorn."""
    return {
        "handler": "reverse_proxy",
        "upstreams": [{"dial": "127.0.0.1:5000"}],
        "headers": {
            "request": {
                "set": {
                    "X-Forwarded-Proto": ["https"],
                }
            }
        },
    }


def _build_panel_route(panel_domain: str) -> dict:
    """Reverse proxy route for the panel UI itself."""
    return {
        "match": [{"host": [panel_domain]}],
        "handle": [_panel_handler()],
        "terminal": True,
    }


def _build_tls_automation(domains: list[str], *, shared_mode: bool = False) -> dict:
    """ACME automation for all managed domains.

    В shared-443 режиме Caddy слушает 127.0.0.1:8443, и публичный :443
    занят Xray Reality. TLS-ALPN-01 в этом режиме НЕ работает — challenge
    приходит на публичный :443 (где сидит Reality, не Caddy). HTTP-01 на
    :80 продолжает работать как обычно (порт остаётся за Caddy).
    Поэтому при shared_mode явно отключаем tls-alpn challenge через
    вложенный объект challenges в ACME issuer'е (Caddy 2.x JSON API
    использует именно такой формат: challenges.tls-alpn.disabled=true;
    глобальная опция `disable_tls_alpn_challenge` существует только в
    Caddyfile-уровне, не в JSON).
    """
    issuer: dict[str, Any] = {
        "module": "acme",
        "email": Setting.get("acme_email", ""),
    }
    if shared_mode:
        # Явно указываем оба challenge'а:
        #   http: {} — оставляем включённым с дефолтами (на :80, через Caddy)
        #   tls-alpn: {disabled: true} — отключаем, т.к. :443 не у нас
        # Если не указать http явно, Caddy остаётся при дефолтах и всё
        # равно умеет http-01 — но явность лучше для отладки.
        issuer["challenges"] = {
            "http": {},
            "tls-alpn": {"disabled": True},
        }
    return {
        "policies": [
            {
                "subjects": domains,
                "issuers": [issuer],
            }
        ]
    }


# ---------------------------------------------------------------------------
# Main config builder
# ---------------------------------------------------------------------------

def generate_caddy_config() -> dict:
    """
    Build complete Caddy JSON config.
    Structure:
      - HTTPS server on :443 ИЛИ 127.0.0.1:8443 (shared-443 режим)
        - NaiveProxy routes (per inbound, matched by SNI on inbound.domain)
        - Panel reverse-proxy route on panel_domain
      - HTTP server on :80 (redirect to HTTPS + ACME http-01)

    ── SHARED-443 РЕЖИМ ──
    Если в БД есть enabled Reality-инбаунд с port=443 — Caddy УХОДИТ
    с публичного :443 на 127.0.0.1:8443. Reality занимает :443 как фронт
    и проксирует НЕ-Reality трафик (NaiveProxy, панель, обычные браузеры)
    на наш loopback. Снаружи весь трафик идёт на :443 и неотличим от
    обычного HTTPS-сайта — лучше для DPI-устойчивости.

    Когда Reality-инбаунд на 443 удаляется/отключается — Caddy при следующем
    apply вернётся на публичный :443 (fallback). См. find_reality_443_inbound
    в xray.py.

    Принцип per-naive-домен: каждый NaiveProxy-инбаунд требует СВОЕГО (суб)домена,
    отдельного от panel_domain. На входе в API это валидируется
    (см. app/api/inbounds.py); здесь — defensive skip с warning'ом
    если в БД оказался инбаунд с пустым domain или domain==panel_domain
    (например, после миграции из старой версии, где такое допускалось).
    """
    from app.models import db
    from app.core.xray import find_reality_443_inbound
    db.session.expire_all()          # гарантируем свежие данные из БД для всех Settings и Inbound
    panel_domain = _panel_domain()
    naive_ibs = _naive_inbounds()

    # ── Shared-443 detection ──
    # Один источник истины — БД. Если есть Reality на 443, мы уходим на loopback.
    # Логика дублируется в xray.py (_is_reality_shared_443 на per-inbound уровне)
    # — для согласованности используем общий helper find_reality_443_inbound.
    reality_443 = find_reality_443_inbound()
    shared_mode = reality_443 is not None
    https_listen = "127.0.0.1:8443" if shared_mode else ":443"
    if shared_mode:
        log.info(
            "Caddy: shared-443 режим (Reality inbound '%s' занимает :443). "
            "Caddy слушает на %s.",
            reality_443.tag, https_listen,
        )

    routes = []
    # Ordered unique domains for TLS automation
    seen_domains: set[str] = set()
    all_domains: list[str] = []

    def _add_domain(d: str) -> None:
        if d and d not in seen_domains:
            seen_domains.add(d)
            all_domains.append(d)

    if panel_domain:
        _add_domain(panel_domain)

    # Фильтруем naive-инбаунды + добавляем их domains в SNI-список.
    # routes для них собираем НИЖЕ — после panel-route (см. порядок).
    valid_naive_ibs: list[Inbound] = []
    for ib in naive_ibs:
        # NaiveProxy ОБЯЗАН иметь свой домен, отличный от panel_domain.
        # Если нет — пропускаем с warning'ом (защита от исторических данных
        # или прямой записи в БД). API не даст создать такой инбаунд.
        if not ib.domain:
            log.warning(
                "NaiveProxy inbound id=%s (tag=%r) пропущен: пустой domain. "
                "Откройте /inbounds и задайте отдельный субдомен.",
                ib.id, ib.tag,
            )
            continue
        if panel_domain and ib.domain == panel_domain:
            log.warning(
                "NaiveProxy inbound id=%s (tag=%r) пропущен: domain совпадает "
                "с panel_domain=%r. NaiveProxy должен жить на отдельном "
                "субдомене, иначе панель уходит в редирект-петлю.",
                ib.id, ib.tag, panel_domain,
            )
            continue
        _add_domain(ib.domain)
        valid_naive_ibs.append(ib)

    # ── ПОРЯДОК ROUTES (критичен) ──────────────────────────────────
    # 1) Panel route ПЕРВЫМ. У него match=panel_domain + terminal,
    #    так что запросы на саму панель уходят сюда и дальше не идут.
    # 2) NaiveProxy catch-all route ВТОРЫМ. У него нет host-match
    #    (иначе CONNECT не ловится — см. _build_naive_catchall_route).
    #    Сюда попадает всё, что не было поймано panel-route'ом.
    # Обратный порядок ломает панель: catch-all naive перехватил бы и
    # запросы на panel_domain.
    if panel_domain:
        routes.append(_build_panel_route(panel_domain))

    if valid_naive_ibs:
        naive_route = _build_naive_catchall_route(valid_naive_ibs)
        if naive_route is not None:
            routes.append(naive_route)

    https_server: dict[str, Any] = {
        "listen": [https_listen],
        "automatic_https": {"disable_redirects": True},  # cert-менеджмент оставляем, убираем только лишние редиректы
        "routes": routes,
        "logs": {"default_logger_name": "naive_access"},
    }

    if shared_mode:
        # В shared-443 режиме Xray пробрасывает TCP на 127.0.0.1:8443 с
        # PROXY protocol v1 header (xver=1 в realitySettings). Caddy должен
        # распаковать этот header ПЕРЕД TLS-handshake'ом, чтобы видеть реальный
        # IP клиента в access.log вместо 127.0.0.1.
        #
        # listener_wrappers — порядок важен: сначала proxy_protocol (читает
        # первые байты TCP и извлекает реальный IP), потом tls (handshake).
        # trusted_proxies обязателен — без него Caddy игнорирует header в целях
        # безопасности (чтобы внешний клиент не мог подделать IP).
        https_server["listener_wrappers"] = [
            {
                "wrapper": "proxy_protocol",
                "allow": ["127.0.0.1/32"],
            },
            {"wrapper": "tls"},
        ]

    if all_domains:
        https_server["tls_connection_policies"] = [
            {"match": {"sni": all_domains}}
        ]

    http_server = {
        "listen": [":80"],
        # automatic_https НЕ отключаем целиком: Caddy сам подмешает
        # /.well-known/acme-challenge/* route перед нашими routes.
        # Disable_redirects=True (на https_server) уже снял автоматический 301,
        # поэтому наш кастомный редирект ниже не конфликтует.
        "routes": [
            {
                "handle": [
                    {
                        "handler": "static_response",
                        "headers": {"Location": ["https://{http.request.host}{http.request.uri}"]},
                        "status_code": 301,
                    }
                ]
            }
        ],
    }

    config: dict[str, Any] = {
        "admin": {
            "listen": "localhost:2019",
            "enforce_origin": False,
        },
        "logging": {
            "logs": {
                "naive_access": {
                    "writer": {
                        "output": "file",
                        "filename": "/var/log/caddy/access.log",
                    },
                    "encoder": {"format": "json"},
                    "level": "INFO",
                    "include": ["http.log.access.naive_access"],
                }
            }
        },
        "apps": {
            "http": {
                "servers": {
                    "https": https_server,
                    "http": http_server,
                }
            },
            "tls": {
                "automation": (
                    _build_tls_automation(all_domains, shared_mode=shared_mode)
                    if all_domains else {}
                ),
            },
        },
    }

    return config


def _redact_for_log(config: dict) -> dict:
    """Возвращает копию конфига с замаскированными чувствительными полями.
    Используется только для логирования."""
    import copy
    redacted = copy.deepcopy(config)

    def walk(node):
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if k in ("pass", "password", "secret", "privateKey"):
                    node[k] = "***"
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(redacted)
    return redacted


def apply_caddy_config() -> tuple[bool, str]:
    """Push new config to running Caddy via Admin API."""
    import logging, json as _json
    log = logging.getLogger(__name__)
    try:
        config = generate_caddy_config()
        log.info("Caddy config: %s", _json.dumps(_redact_for_log(config), ensure_ascii=False))
        return _caddy_load(config)
    except Exception as e:
        log.exception("generate_caddy_config failed")
        return False, str(e)


def get_caddy_traffic_from_logs(
    log_path: str = "/var/log/caddy/access.log",
    state_path: str | None = None,
) -> dict:
    """Инкрементально читает access-log Caddy и возвращает ДЕЛЬТУ трафика
    по каждому пользователю с прошлого вызова: {username: {"up": d, "down": d}}.

    Раньше функция суммировала размеры по последним 100k строкам (скользящее
    окно) и отдавала это как «накопительный счётчик» — что было неверно:
    окно не монотонно (старые строки выпадают, при ротации файл обнуляется),
    из-за чего трафик NaiveProxy то недосчитывался, то давал ложные скачки.

    Теперь читаем только НОВЫЕ байты: позиция (offset) и inode файла хранятся
    в state_path. На каждом вызове:
      * inode тот же и size >= offset → читаем offset→EOF (нормальный прирост);
      * inode сменился (ротация) или size < offset (обрезание/copytruncate) →
        читаем файл с начала.

    Ограничение: при ротации хвост старого файла между последним чтением и
    ротацией теряется (новое имя ротированного файла мы не отслеживаем). Это
    ограничено окном между опросами; чтобы потери были малы, опрашиваем часто
    (раз в 5 минут) относительно размера ротации.
    """
    if state_path is None:
        state_path = log_path + ".pp-traffic-state"

    stats: dict[str, dict] = {}

    try:
        st = os.stat(log_path)
    except FileNotFoundError:
        return stats
    inode = st.st_ino
    size = st.st_size

    # Прошлая позиция чтения.
    offset = 0
    prev_inode = None
    try:
        with open(state_path) as sf:
            state = json.load(sf)
        prev_inode = state.get("inode")
        offset = int(state.get("offset", 0))
    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError):
        offset, prev_inode = 0, None

    # Ротация (сменился inode) или обрезание (файл стал короче offset) → с нуля.
    if prev_inode != inode or offset > size:
        offset = 0

    new_offset = offset
    try:
        with open(log_path, "r", errors="replace") as f:
            f.seek(offset)
            for line in f:
                try:
                    entry = json.loads(line)
                    user = entry.get("request", {}).get("user", "")
                    if not user:
                        continue
                    req_size = entry.get("request", {}).get("body_size", 0) or 0
                    resp_size = entry.get("size", 0) or 0
                    if user not in stats:
                        stats[user] = {"up": 0, "down": 0}
                    stats[user]["up"] += req_size
                    stats[user]["down"] += resp_size
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
            new_offset = f.tell()
    except OSError:
        return stats

    # Сохраняем новую позицию.
    try:
        d = os.path.dirname(state_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(state_path, "w") as sf:
            json.dump({"inode": inode, "offset": new_offset}, sf)
    except OSError:
        pass

    return stats


def get_caddy_status() -> dict:
    """Get Caddy server status via Admin API."""
    try:
        r = requests.get(f"{CADDY_API}/config/", timeout=5)
        return {"running": r.status_code == 200, "config": r.json() if r.status_code == 200 else None}
    except Exception:
        return {"running": False, "config": None}
