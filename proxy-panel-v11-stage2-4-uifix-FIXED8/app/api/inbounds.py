"""
REST API: Inbounds (Xray + NaiveProxy).
"""
import json
import subprocess
from flask import Blueprint, request, jsonify
from flask_login import login_required

from app.models import db, Inbound, Setting
from app.core.xray import apply_xray_config
from app.core.caddy import apply_caddy_config
from app.core.audit import log_action
from app.core.input_validators import (
    validate_tag, validate_port, validate_tls_paths, validate_domain,
)

bp = Blueprint("inbounds", __name__)

XRAY_PROTOCOLS = {"vmess", "vless", "trojan", "shadowsocks", "socks", "http", "dokodemo"}
NAIVE_PROTOCOLS = {"naive"}
SSH_PROTOCOLS = {"ssh"}

# Движки, которые вообще можно создать. Отдельный список, потому что engine
# приходит из запроса и раньше любая опечатка молча создавала инбаунд, который
# ни один apply не обслуживает.
VALID_ENGINES = {"xray", "naive", "ssh"}

# Протоколы, доступные для СОЗДАНИЯ новых инбаундов. Пока в проде проверены
# только VLESS (вкл. Reality) и NaiveProxy — остальные временно скрыты в UI и
# заблокированы на создание здесь (вторая линия для прямых вызовов API).
# Чтобы вернуть протокол, когда он заработает, добавьте его сюда (одна строка).
# Существующих инбаундов это НЕ касается — редактирование/применение работают.
ENABLED_XRAY_PROTOCOLS = {"vless", "trojan"}
# «h2» убран: Xray ≥24.12 удалил транспорт HTTP/2 (миграция на XHTTP =
# splithttp), конфиг с ним не проходит `xray run -test`. Существующие
# h2-инбаунды в БД применить нельзя — их нужно пересоздать на другом
# транспорте (splithttp/ws/grpc).
VALID_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "httpupgrade", "splithttp"}

XRAY_BIN = "/usr/local/bin/xray"


def _validate_reality_compat(protocol: str, transport: str) -> str | None:
    """Возвращает текст ошибки, если Reality несовместим с протоколом/транспортом.

    Reality применяется ядром Xray только к VLESS и требует транспорт TCP.
    На другом сочетании Reality либо игнорируется (инбаунд без шифрования),
    либо конфиг не проходит проверку.
    """
    if protocol != "vless":
        return (
            f"Reality поддерживается только VLESS, а выбран протокол "
            f"'{protocol}'. Выберите VLESS или отключите Reality."
        )
    if (transport or "tcp") != "tcp":
        return (
            f"Reality требует транспорт TCP, а выбран '{transport}'. "
            f"Reality работает только с TCP."
        )
    return None


def _validate_reality_ready(port: int, tcfg: dict) -> str | None:
    """Проверяет, что Reality-инбаунд заведётся, ДО применения конфига.

    Полевой провал (отчёт 30.08): пользователь создавал VLESS+Reality на 443
    на свежей панели — и либо Xray отвергал конфиг сырым дампом «empty
    serverNames» (изменения не сохранялись), либо, что хуже, панель по домену
    падала наглухо. Причина у обоих одна: у Reality на 443 (shared-режим)
    serverNames сервер берёт из panel_domain + доменов naive-инбаундов
    (_shared_443_server_names). Пока домен панели не задан и нет naive —
    список ПУСТ, и Reality не запускается / рвёт маршрут до панели.

    Ловим это заранее человеческим сообщением, вместо дампа Xray или мёртвой
    панели. Ключи проверяем defensively: UI их генерирует, но прямой
    API-клиент может прислать пустые.
    """
    if not (tcfg.get("reality_public_key") or "").strip():
        return "Reality: не заданы ключи. Нажмите «Перегенерировать» в форме."
    if not (tcfg.get("reality_private_key") or "").strip():
        return "Reality: не задан приватный ключ. Нажмите «Перегенерировать»."

    if port == 443:
        # shared-443: serverNames подставляет сервер из panel_domain + naive.
        from app.core.xray import _shared_443_server_names
        if not _shared_443_server_names():
            return (
                "Reality на 443 использует домен панели как «прикрытие», но он "
                "ещё не задан. Сначала укажите домен панели в Настройках "
                "(или создайте инбаунд NaiveProxy с доменом) — и повторите."
            )
    else:
        # Классический Reality: serverNames обязателен (UI ставит decoy-домен,
        # но прямой API-клиент или ручная правка могли оставить пусто).
        names = tcfg.get("reality_server_names") or []
        if not [n for n in names if (n or "").strip()]:
            return (
                "Reality: не задан serverNames (домен-прикрытие, напр. "
                "www.cloudflare.com). Заполните его в разделе Advanced."
            )
    return None


def _shared_443_healthcheck_sni() -> str | None:
    """Домен для SNI пост-проверки :443 после перехода в shared-443.

    Предпочитаем ПАНЕЛЬНЫЙ домен: именно он «падал наглухо» в поле, и по
    нему Caddy отвечает осмысленным маршрутом (панель), а не forward_proxy.
    Иначе — первый naive-домен (для него Caddy тоже держит сертификат, а
    Reality — serverNames). Если ни того, ни другого нет, возвращаем None —
    проверять нечем (но до shared-443 в таком состоянии вообще не доходят:
    см. _validate_reality_ready).
    """
    from app.core.xray import _shared_443_server_names
    panel = (Setting.get("panel_domain", "") or "").strip()
    if panel:
        return panel
    names = _shared_443_server_names()
    return names[0] if names else None


def _classify_443_failure(exc: BaseException) -> str:
    """Что означает провал пробы :443: «мёртв» или «жив, но не готов».

    Граница — протокольная, а не «любая ошибка = откат»:

      dead  — на :443 никто TLS-способный не ответил: connection refused
              (порт пуст), таймаут (Reality принял TCP, а Caddy так и не
              прислал ServerHello — relay повис), reset, EOF без TLS-алерта
              (пир оборвал рукопожатие молча = relay уронил). Это и есть
              полевое «панель легла наглухо» — откатывать НАДО.

      alive — пришёл TLS-алерт (SSLError с причиной: internal_error,
              handshake_failure, unrecognized_name…). Значит пакет ПРОШЁЛ
              через Reality до Caddy и Caddy ОТВЕТИЛ — фронт живой, просто
              у него ещё нет сертификата для этого SNI (ACME только пошёл)
              или иная TLS-деталь. Откатывать НЕЛЬЗЯ: это потушило бы
              правильно настроенный инбаунд во время прогрева.

    Важно про порядок проверок: ssl.SSLError — подкласс OSError, поэтому
    сначала различаем SSL-ветки, и только потом общий OSError.
    """
    import ssl
    # Пир закрыл соединение молча, без алерта — relay оборвался.
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return "dead"
    # Любой другой SSLError = TLS-пир существует и что-то ответил.
    if isinstance(exc, ssl.SSLError):
        return "alive"
    # refused / timeout / reset и прочее на уровне сокета.
    return "dead"


def _healthcheck_public_443(sni: str, *, attempts: int = 3,
                            timeout: float = 4.0) -> tuple[str, str]:
    """Проверяет, что публичный :443 РЕАЛЬНО обслуживает трафик после
    перехода в shared-443 (Reality на :443 → relay → Caddy на 127.0.0.1:8443).

    Полевой провал: systemctl вернул 0 по обоим сервисам, но связка
    Reality→Caddy трафик не несла — панель по домену «падала наглухо», а
    VLESS «за настоящим сайтом» показывал «подключено» и молча ничего не
    грузил. `xray run -test` этого не ловит: он валидирует конфиг, а не
    живой путь. Поэтому проверяем фронт end-to-end.

    Как: подключаемся к 127.0.0.1:443 (там Reality) обычным НЕ-Reality
    клиентом с SNI=sni — ровно как браузер. Reality обязан сфолбечить и
    прорелеить на Caddy, Caddy — стерминировать TLS и ответить HTTP.

    Возвращает (вердикт, детали), вердикт ∈ {"ok", "alive", "dead"}:
      ok    — рукопожатие прошло и пришла строка «HTTP/1.x» (всё работает);
      alive — фронт отвечает на TLS-уровне, но пока не полноценно (нет
              сертификата / пустой ответ после рукопожатия) — НЕ откатывать,
              см. _classify_443_failure;
      dead  — на :443 никто не отвечает — откатывать.

    Валидность сертификата тут НЕ проверяем (CERT_NONE): за неё отвечает
    ACME, а цель проверки — «отвечает ли фронт вообще». Ретраи с паузой:
    Reality и Caddy только что рестартовали, даём фронту подняться, чтобы
    не словить ложный «dead» на не успевшем забиндиться :443.
    """
    import socket
    import ssl
    import time as _t

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False      # SNI != адрес сокета (127.0.0.1)
    ctx.verify_mode = ssl.CERT_NONE  # валидность cert — забота ACME, не этой проверки
    verdict, last = "dead", ""
    for i in range(attempts):
        try:
            raw = socket.create_connection(("127.0.0.1", 443), timeout=timeout)
            try:
                with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                    tls.settimeout(timeout)
                    req = (
                        f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
                        f"User-Agent: pp-healthcheck\r\nConnection: close\r\n\r\n"
                    ).encode()
                    tls.sendall(req)
                    head = tls.recv(128)
                if head.startswith(b"HTTP/"):
                    return "ok", head.split(b"\r\n", 1)[0].decode("latin1", "replace")
                # Рукопожатие ПРОШЛО (сертификат есть, relay работает), а HTTP
                # не пришёл — фронт жив, странность на уровне ответа. Не откат.
                verdict, last = "alive", f"рукопожатие ок, но ответ не HTTP: {head[:48]!r}"
            finally:
                try:
                    raw.close()
                except OSError:
                    pass
        except (OSError, ssl.SSLError) as e:
            verdict = _classify_443_failure(e)
            last = f"{type(e).__name__}: {e}"
            if verdict == "alive":
                # TLS-пир ответил — дальше ждать нечего, фронт живой.
                return verdict, last
        if i + 1 < attempts:
            _t.sleep(2)
    return verdict, last or "нет ответа"


def _rollback_shared_443(sni: str, detail: str) -> tuple[bool, str]:
    """Авто-откат неудавшегося перехода в shared-443.

    Публичный :443 после перехода не обслуживает трафик. Возвращаем сервер
    в заведомо рабочее состояние: отключаем Reality-инбаунд на :443 (это
    снимает shared-режим), затем применяем конфиги в НЕ-shared порядке —
    сначала Xray (освобождает :443), потом Caddy (возвращается на публичный
    :443). Причину пишем в extra_config инбаунда, чтобы владелец видел в UI,
    почему инбаунд выключен, и мог починить (домен/сертификат/PROXY-protocol)
    и включить заново.
    """
    from app.core.xray import find_reality_443_inbound

    reality_ib = find_reality_443_inbound()
    if reality_ib is None:
        # Некого откатывать (гонка / ручное вмешательство в БД). Пытаемся хотя
        # бы вернуть Caddy на публичный :443 напрямую.
        apply_caddy_config()
        return False, (
            "Публичный :443 не отвечает после перехода в shared-443, а "
            "Reality-инбаунд на :443 для авто-отката не найден. Проверьте "
            f"конфигурацию вручную (SNI={sni}: {detail})."
        )

    reason = (
        "Автоотключён: после перехода в shared-443 публичный :443 перестал "
        f"отвечать (проверка SNI={sni}: {detail}). Сервер возвращён на прямой "
        "Caddy :443. Проверьте домен/сертификат/PROXY-protocol и включите заново."
    )
    reality_ib.enabled = False
    extra = reality_ib.get_extra_config()
    extra["auto_disabled_reason"] = reason
    reality_ib.extra_config = json.dumps(extra, ensure_ascii=False)
    db.session.commit()

    # shared-режим снят (Reality-443 disabled) → НЕ-shared порядок apply.
    ok_x, msg_x = apply_xray_config()
    ok_c, msg_c = apply_caddy_config()
    tail = ""
    if not ok_x:
        tail += f" Xray при откате: {msg_x}."
    if not ok_c:
        tail += f" Caddy при откате: {msg_c}."
    return False, (
        f"Переход в shared-443 отменён: публичный :443 не отвечал ({detail}). "
        f"Reality-инбаунд '{reality_ib.tag}' отключён, Caddy возвращён на :443.{tail} "
        f"Исправьте причину и включите инбаунд заново."
    )


def _apply_for_engine(engine: str) -> tuple[bool, str]:
    """Применяет конфиг только нужного движка.

    ── ПОРЯДОК APPLY и shared-443 РЕЖИМ ──
    При переходе Reality-инбаунда между port=443 и другим портом нужен
    правильный порядок, иначе будет коллизия за :443:

      Целевое состояние: Reality на :443 (shared).
        Сначала apply_caddy — Caddy уходит на 127.0.0.1:8443, :443
        свободен. Затем apply_xray — Reality занимает :443.

      Целевое состояние: Reality не на :443 (или его нет).
        Сначала apply_xray — Reality уходит с :443 (если был). Затем
        apply_caddy — Caddy приходит на :443.

    ── PRE-VALIDATION Xray ──
    Перед любым apply (особенно в shared-режиме, где Caddy переезжает
    первым) мы прогоняем сгенерированный Xray-конфиг через
    `xray run -test`. Если xray не примет конфиг — НЕ начинаем переход
    Caddy, чтобы не оставить систему в зависшем состоянии
    "Caddy на loopback, Xray не стартанул, :443 пустой → ERR_TIMED_OUT".
    Без pre-validation любая ошибка в xray-конфиге (битый Reality, конфликт
    с другим инбаундом, неподдерживаемая комбинация транспорта+security и т.п.)
    могла бы вырубить публичный :443 полностью.

    Naive-операции на shared-state не влияют (NaiveProxy всегда внутри
    Caddy), для них порядок не имеет значения — apply только Caddy.
    """
    from app.core.xray import find_reality_443_inbound, generate_xray_config
    from app.core.geo_validator import validate_config

    if engine == "naive":
        ok, msg = apply_caddy_config()
        return ok, msg if not ok else None

    # SSH ни Caddy, ни Xray не касается: панель только записывает желаемое
    # состояние учёток, а приводит систему к нему root-скрипт по таймеру
    # (см. core/ssh.py — почему именно так). Значит apply здесь мгновенный, а
    # реальное изменение доезжает в течение одного тика таймера.
    if engine == "ssh":
        from app.core.ssh import apply_ssh_config
        ok, msg = apply_ssh_config()
        return ok, msg

    # engine == "xray" — сначала pre-validate, потом apply в нужном порядке.

    # PRE-VALIDATION: гоняем будущий xray-конфиг через `xray run -test`
    # ПРЕЖДЕ чем что-то применять. Это даёт нам fail-fast: если xray не
    # примет — выходим до apply_caddy (особенно критично в shared-режиме,
    # где apply_caddy уже бы переселил Caddy на loopback).
    try:
        proposed_xray = generate_xray_config()
    except Exception as e:
        return False, f"Xray: ошибка построения конфига: {e}"
    ok_v, msg_v = validate_config(proposed_xray)
    if not ok_v:
        return False, (
            f"Xray валидация отклонила конфиг (`xray run -test`): {msg_v}. "
            f"Caddy не трогался — текущее состояние сохранено."
        )

    target_shared = find_reality_443_inbound() is not None

    if target_shared:
        # Reality будет/остаётся на :443 → Caddy первым уезжает.
        # Безопасно: xray-конфиг прошёл pre-validate, так что после apply_caddy
        # apply_xray почти наверняка примет тот же конфиг.
        ok_c, msg_c = apply_caddy_config()
        if not ok_c:
            return False, f"Caddy: {msg_c}"
        ok_x, msg_x = apply_xray_config()
        if not ok_x:
            # Pre-validate прошёл, но реальный systemctl restart xray
            # упал. Caddy уже переехал на loopback, а рабочий Xray не
            # поднят → публичный :443 пустой. Авто-откат вернёт Caddy на
            # :443 (снимет shared, отключив Reality-443).
            return _rollback_shared_443(
                _shared_443_healthcheck_sni() or "",
                f"Xray apply не удался: {msg_x}",
            )

        # ── ПОСТ-ПРОВЕРКА ПУБЛИЧНОГО :443 (shared-443) ──
        # Оба сервиса рестартовали «успешно» (systemctl вернул 0), но это НЕ
        # доказывает, что связка Reality(:443)→relay→Caddy(:8443) реально несёт
        # трафик. Полевой случай: панель по домену «падала наглухо», а VLESS «за
        # настоящим сайтом» показывал «подключено» и молча ничего не грузил —
        # именно этот тихий провал. Проверяем фронт end-to-end; при провале
        # откатываемся, чтобы сервер не остался мёртвым (владелец сам решит,
        # чинить домен/сертификат/PROXY-protocol или отказаться от shared-443).
        sni = _shared_443_healthcheck_sni()
        if sni:
            verdict, detail = _healthcheck_public_443(sni)
            if verdict == "dead":
                return _rollback_shared_443(sni, detail)
            if verdict == "alive":
                # Фронт отвечает на TLS-уровне, но ещё не полноценно — чаще
                # всего сертификат для домена только выпускается (ACME).
                # Откат тут навредил бы; отдаём владельцу честный статус.
                import logging
                logging.getLogger(__name__).warning(
                    "shared-443: :443 жив, но не готов (SNI=%s): %s", sni, detail)
                return True, (
                    f"Применено. Публичный :443 отвечает, но пока не полноценно "
                    f"({detail}). Обычно это выпуск сертификата — подождите "
                    f"минуту и обновите страницу панели по домену."
                )
        return True, None

    # Reality не на :443 → Xray первым (если был на :443, освободит),
    # потом Caddy (займёт :443).
    ok_x, msg_x = apply_xray_config()
    if not ok_x:
        return False, msg_x
    ok_c, msg_c = apply_caddy_config()
    if not ok_c:
        return False, f"Caddy: {msg_c}"
    return True, None


def _validate_behind_caddy(
    protocol: str,
    transport: str,
    domain: str | None,
    tcfg: dict,
) -> str | None:
    """
    Проверка режима «за настоящим сайтом» (transport_config.behind_caddy).
    Возвращает текст ошибки или None.

    Требования продиктованы тем, как этот режим устроен: Caddy на 443
    отдаёт обычный сайт и заворачивает в Xray ровно один путь по loopback.

    1. **Транспорт только ws/httpupgrade.** Caddy умеет проксировать
       именно HTTP-апгрейд. У tcp/kcp/grpc проксирование через reverse_proxy
       по пути не работает. splithttp (он же XHTTP) намеренно не разрешён:
       его не поддерживает наш клиент — sing-box такого транспорта не знает
       вовсе (в 1.13.14 есть http/ws/quic/grpc/httpupgrade).
    2. **Домен обязателен и отличается от панельного** — иначе туннельный
       путь и панель делят один хост.
    3. **Reality несовместим** — это два взаимоисключающих способа
       обращаться с TLS: тут его терминирует Caddy своим сертификатом.
    4. **Путь обязателен и не должен угадываться.** Короткий или словарный
       путь (/ws, /vpn, /api) находится активным зондированием, и тогда
       весь смысл маскировки под сайт теряется.
    """
    if protocol != "vless":
        return (
            "Режим «за настоящим сайтом» поддержан только для VLESS — "
            "клиент умеет именно его."
        )
    if transport not in {"ws", "httpupgrade"}:
        return (
            "Режим «за настоящим сайтом» требует транспорт ws или httpupgrade: "
            "Caddy проксирует по пути только HTTP-апгрейд."
        )
    if tcfg.get("reality_public_key"):
        return (
            "Reality и режим «за настоящим сайтом» несовместимы: TLS здесь "
            "терминирует Caddy сертификатом вашего домена. Выберите одно."
        )
    if not isinstance(domain, str) or not domain.strip():
        return (
            "Режим «за настоящим сайтом» требует домен — Caddy матчит route "
            "по хосту и по пути."
        )
    panel_domain = Setting.get("panel_domain", "").strip()
    if panel_domain and domain.strip().lower() == panel_domain.lower():
        return (
            f"Домен не может совпадать с панельным ({panel_domain}): "
            f"туннельный путь и панель окажутся на одном хосте."
        )
    path = (tcfg.get("path") or "").strip()
    if not path.startswith("/") or len(path.strip("/")) < 8:
        return (
            "Задайте неочевидный путь длиной от 8 символов, начиная с «/» "
            "(например, /a7f3c1b9e2). Короткий или словарный путь находится "
            "перебором, и маскировка под сайт перестаёт работать."
        )
    return None


def _validate_naive_inbound_domain(domain: str | None) -> str | None:
    """
    Возвращает текст ошибки или None.

    NaiveProxy в этой панели работает через Caddy + плагин klzgrad/
    forwardproxy. Caddy матчит входящий TLS по SNI на route. Поэтому
    NaiveProxy ОБЯЗАН иметь свой домен:

    1. **Не пустой.** Без SNI-совпадения Caddy не знает, какому route
       отдать соединение, и панель уйдёт в неопределённое состояние.

    2. **Отличный от panel_domain.** Раньше была «фича» — naive и
       панель на одном домене через цепочку handler'ов
       forward_proxy → reverse_proxy. Не работает: forward_proxy
       для не-CONNECT GET-запросов возвращает 301 с Location на ту
       же URL → бесконечный редирект → ERR_TOO_MANY_REDIRECTS в
       браузере на панели. Решение — отдельный субдомен. См. также
       app/core/caddy.py, удалённую функцию _build_combined_route.
    """
    if not isinstance(domain, str) or not domain.strip():
        return (
            "NaiveProxy требует доменное имя — Caddy матчит трафик "
            "по SNI на конкретный домен. Создайте отдельный субдомен "
            "(например, naive.example.com) и укажите его."
        )
    domain = domain.strip()
    panel_domain = Setting.get("panel_domain", "").strip()
    if panel_domain and domain.lower() == panel_domain.lower():
        return (
            f"NaiveProxy не может быть на том же домене что и панель "
            f"({panel_domain}). Используйте отдельный субдомен — иначе "
            f"панель уйдёт в редирект-петлю (исторический баг combined-"
            f"route, fixed in stage1-12 by enforcement)."
        )
    return None


def _request_is_reality(data: dict) -> bool:
    """True если в payload запрос на создание/обновление Reality-инбаунда.

    Reality определяется по наличию reality_public_key в transport_config.
    Это согласовано с xray.py:_is_reality_inbound (которое проверяет БД).
    """
    if data.get("protocol") and data["protocol"] != "vless":
        return False
    tcfg = data.get("transport_config") or {}
    return bool(tcfg.get("reality_public_key"))


def _check_port_conflicts(
    port: int,
    *,
    exclude_inbound_id: int | None = None,
    is_reality: bool = False,
) -> str | None:
    """
    Проверяет, не конфликтует ли port с уже существующими Xray-инбаундами
    и с настройкой xray_api_port. Возвращает текст ошибки или None.

    exclude_inbound_id: id текущего инбаунда при PUT, чтобы исключить
    "конфликт с самим собой".

    is_reality: True если создаваемый/обновляемый инбаунд — Reality.
    Это определяет можно ли занимать port=443 (shared-режим) и блокирует
    8443 для не-Caddy сущностей если shared активен.

    Замечание про enabled: проверяем ВСЕ Xray-инбаунды независимо от
    enabled. Disabled-инбаунд тоже занимает порт-номер по смыслу UI
    (юзер не сможет понять, почему 8443 «уже занят», если не видит
    отключенного инбаунда). Это даёт более очевидное поведение —
    "номера портов уникальны на уровне сущностей", а не "на уровне
    запущенных слушателей". Если юзеру действительно нужно "тот же
    порт, но через другой инбаунд" — пусть удалит старый.
    """
    # ── Особый случай 443: только Reality (shared-443 режим) ──
    if port == 443:
        if not is_reality:
            return (
                "Порт 443 зарезервирован под Caddy (панель, NaiveProxy, ACME). "
                "Использовать 443 разрешено только для Reality-инбаунда — "
                "в этом режиме Caddy автоматически уходит на 127.0.0.1:8443, "
                "а Reality становится фронтом и проксирует non-Reality трафик "
                "обратно на него (shared-443)."
            )
        # Только один Reality-инбаунд на :443 одновременно
        q443 = Inbound.query.filter(
            Inbound.engine == "xray",
            Inbound.port == 443,
        )
        if exclude_inbound_id is not None:
            q443 = q443.filter(Inbound.id != exclude_inbound_id)
        existing_443 = q443.first()
        if existing_443:
            return (
                f"На порту 443 уже есть Xray-инбаунд '{existing_443.tag}' "
                f"(id={existing_443.id}). Только один Reality может занимать "
                f"443 одновременно (shared-режим эксклюзивный)."
            )

    # ── Особый случай 8443: зарезервирован под Caddy в shared-режиме ──
    # Если уже есть Reality на 443, никакой Xray-инбаунд не может биндить 8443
    # (там сидит Caddy на 127.0.0.1:8443).
    if port == 8443:
        q_rt443 = Inbound.query.filter(
            Inbound.engine == "xray",
            Inbound.port == 443,
            Inbound.enabled == True,  # noqa: E712 — SQLAlchemy idiom
        )
        if exclude_inbound_id is not None:
            q_rt443 = q_rt443.filter(Inbound.id != exclude_inbound_id)
        for ib in q_rt443.all():
            tcfg = ib.get_transport_config()
            if tcfg.get("reality_public_key"):
                return (
                    f"Порт 8443 зарезервирован под Caddy (loopback) в shared-443 "
                    f"режиме — Reality-инбаунд '{ib.tag}' уже занимает 443 и "
                    f"проксирует non-Reality трафик на 127.0.0.1:8443. "
                    f"Выберите другой порт для этого инбаунда или удалите Reality."
                )

    # Conflict с другим инбаундом (общий случай)
    q = Inbound.query.filter(
        Inbound.engine == "xray",
        Inbound.port == port,
    )
    if exclude_inbound_id is not None:
        q = q.filter(Inbound.id != exclude_inbound_id)
    other = q.first()
    if other:
        return (
            f"Порт {port} уже занят инбаундом '{other.tag}' (id={other.id}). "
            f"Выберите свободный порт или удалите старый инбаунд."
        )
    # Conflict с xray_api_port (см. xray.py generate_xray_config — там
    # создаётся внутренний api-inbound на этом порту)
    try:
        api_port = int(Setting.get("xray_api_port", "10085"))
    except (TypeError, ValueError):
        api_port = 10085
    if port == api_port:
        return (
            f"Порт {port} зарезервирован под Xray stats API "
            f"(настройка xray_api_port). Поменяйте настройку или "
            f"выберите другой порт для инбаунда."
        )
    return None


def _pre_validate_xray() -> tuple[bool, str | None]:
    """Синхронная pre-validation: прогоняет ТЕКУЩИЙ (до commit) конфиг через
    xray run -test. Используется перед db.session.commit() в create/update,
    чтобы поймать ошибки Xray до того как данные попадут в БД.

    Для delete/toggle не используется — там конфиг гарантированно упрощается
    (один инбаунд/клиент убывает), что не может сломать Xray.

    Возвращает (True, None) если ok, (False, message) если нет.
    """
    from app.core.xray import generate_xray_config
    from app.core.geo_validator import validate_config
    try:
        proposed = generate_xray_config()
    except Exception as e:
        return False, f"Ошибка построения xray-конфига: {e}"
    ok, msg = validate_config(proposed)
    if not ok:
        return False, (
            f"Xray отклонил конфиг (`xray run -test`): {msg}. "
            f"Изменения не сохранены."
        )
    return True, None


@bp.get("/")
@login_required
def list_inbounds():
    engine = request.args.get("engine")
    q = Inbound.query
    if engine:
        q = q.filter_by(engine=engine)
    return jsonify([ib.to_dict() for ib in q.order_by(Inbound.id).all()])


@bp.post("/reality-keys")
@login_required
def generate_reality_keys():
    """Генерирует новую пару X25519-ключей для VLESS Reality.

    Внутри просто вызывает `xray x25519` — это родной механизм Xray для
    генерации пары. Возвращает {"private_key": "...", "public_key": "..."}.

    Серверу нужен private_key (попадёт в realitySettings.privateKey),
    клиенту — public_key (попадёт в vless://...?pbk=).

    Парсер устойчив к разным форматам вывода Xray:
      - старый:  "Private key: ..." / "Public key: ..."
      - новый:   "PrivateKey: ..." / "Password: ..."
      - другие:  любая строка вида "<label>: <base64-url-safe-43chars>"
    Fallback: если ничего не нашлось по меткам — берём первые две
    base64-url-safe строки в выводе (исторически private идёт первой).
    """
    import re

    try:
        result = subprocess.run(
            [XRAY_BIN, "x25519"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return jsonify({"error": f"Xray не найден по пути {XRAY_BIN}"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "xray x25519 не ответил за 10с"}), 500

    if result.returncode != 0:
        return jsonify({
            "error": f"xray x25519 завершился с кодом {result.returncode}: {result.stderr.strip()}"
        }), 500

    # X25519-ключ Xray — это 32 байта в base64-url-safe без padding, ровно 43 символа.
    # Используем как фильтр чтобы отделить ключи от всего прочего шума.
    KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}=?$")

    private_key, public_key = None, None

    # Проход 1: по меткам. Принимаем любые лейблы, содержащие "private"
    # или "public"/"password" (case-insensitive, пробелы и регистр игнорим).
    for line in result.stdout.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        value = value.strip()
        if not KEY_RE.match(value):
            continue
        label_norm = label.lower().replace(" ", "")
        if "private" in label_norm and private_key is None:
            private_key = value
        elif ("public" in label_norm or "password" in label_norm) and public_key is None:
            public_key = value

    # Проход 2 (fallback): если по меткам не нашли — берём первые две
    # отдельные base64-url-safe строки. Учитываем что строка может быть
    # просто ключ без префикса (некоторые версии Xray так и пишут).
    if not (private_key and public_key):
        candidates = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            # вариант 1: вся строка — ключ
            if KEY_RE.match(stripped):
                candidates.append(stripped)
                continue
            # вариант 2: "что-то: ключ" — берём только значение
            if ":" in stripped:
                _, _, value = stripped.partition(":")
                value = value.strip()
                if KEY_RE.match(value):
                    candidates.append(value)
        if len(candidates) >= 2:
            private_key = private_key or candidates[0]
            public_key = public_key or candidates[1]

    if not (private_key and public_key):
        # Совсем не вышло — отдаём raw_output, чтобы можно было увидеть
        # что именно Xray вывел и поправить парсер при необходимости.
        return jsonify({
            "error": f"Не удалось распарсить вывод xray x25519. Raw: {result.stdout[:300]!r}",
        }), 500

    return jsonify({"private_key": private_key, "public_key": public_key})


@bp.post("/")
@login_required
def create_inbound():
    data = request.get_json(force=True)

    engine = data.get("engine", "xray")
    protocol = data.get("protocol", "")
    tag = data.get("tag", "").strip() if isinstance(data.get("tag"), str) else ""

    # Tag: формат + уникальность.
    ok, err = validate_tag(tag)
    if not ok:
        return jsonify({"error": err}), 400
    if Inbound.query.filter_by(tag=tag).first():
        return jsonify({"error": f"Тег '{tag}' уже существует"}), 409

    if engine not in VALID_ENGINES:
        return jsonify({"error": (
            f"Неизвестный движок: {engine}. Допустимы: "
            f"{', '.join(sorted(VALID_ENGINES))}"
        )}), 400

    if engine == "xray" and protocol not in XRAY_PROTOCOLS:
        return jsonify({"error": f"Неверный протокол для Xray: {protocol}"}), 400
    if engine == "xray" and protocol not in ENABLED_XRAY_PROTOCOLS:
        return jsonify({"error": (
            "Этот протокол временно недоступен. Сейчас поддерживаются "
            "VLESS (включая Reality) и NaiveProxy."
        )}), 400
    if engine == "naive" and protocol not in NAIVE_PROTOCOLS:
        return jsonify({"error": "Для NaiveProxy протокол должен быть 'naive'"}), 400
    if engine == "ssh" and protocol not in SSH_PROTOCOLS:
        return jsonify({"error": "Для SSH протокол должен быть 'ssh'"}), 400

    # SSH-инбаунд может быть только ОДИН: за ним стоит системный sshd, а не
    # процесс, который панель поднимает на выбранном порту. Второй инбаунд
    # означал бы два разных желаемых состояния для одних и тех же учёток ОС —
    # они бы затирали друг друга на каждом apply.
    if engine == "ssh":
        existing_ssh = Inbound.query.filter_by(engine="ssh").first()
        if existing_ssh:
            return jsonify({"error": (
                f"SSH-инбаунд уже существует (тег '{existing_ssh.tag}'). "
                f"За SSH стоит системный sshd — он один на сервер; "
                f"добавляйте клиентов в существующий инбаунд."
            )}), 409

    # NaiveProxy: domain обязателен и должен отличаться от panel_domain
    # (см. _validate_naive_inbound_domain).
    if engine == "naive":
        err = _validate_naive_inbound_domain(data.get("domain"))
        if err:
            return jsonify({"error": err}), 400

    transport = data.get("transport", "tcp")
    if engine == "xray" and transport not in VALID_TRANSPORTS:
        return jsonify({"error": f"Неверный транспорт: {transport}"}), 400

    # Port: только для xray. Naive всегда сидит на 443 через Caddy.
    port_normalized: int | None = None
    if engine == "xray":
        # Reality-инбаунды имеют право на shared-443 (port=443).
        # _request_is_reality смотрит на наличие reality_public_key в data.
        is_reality = _request_is_reality(data)
        ok, err, port_normalized = validate_port(
            data.get("port"), allow_reality_443=is_reality,
        )
        if not ok:
            return jsonify({"error": err}), 400
        conflict = _check_port_conflicts(port_normalized, is_reality=is_reality)
        if conflict:
            return jsonify({"error": conflict}), 409
    elif engine == "ssh":
        # Порт СУЩЕСТВУЮЩЕГО sshd. Панель его не занимает и не меняет — только
        # записывает, чтобы правила учёта трафика считали нужное плечо, а
        # ссылка вела на верный порт. Проверки на конфликт нет намеренно:
        # порт уже занят sshd, и это норма, а не коллизия.
        raw_port = data.get("port")
        if raw_port in (None, "", 0):
            from app.core.ssh import DEFAULT_PORT as _SSH_DEFAULT_PORT
            port_normalized = _SSH_DEFAULT_PORT
        else:
            try:
                port_normalized = int(raw_port)
            except (TypeError, ValueError):
                return jsonify({"error": "Порт SSH — число от 1 до 65535"}), 400
            if not (1 <= port_normalized <= 65535):
                return jsonify({"error": "Порт SSH — число от 1 до 65535"}), 400

    # TLS-пути: только если tls_enabled=true (Reality использует другой
    # security и не требует cert/key файлов — поля tls_cert_path/key_path
    # просто игнорируются генератором конфига в _build_tls_settings).
    tls_enabled = bool(data.get("tls_enabled", False))
    cert_path = data.get("tls_cert_path")
    key_path = data.get("tls_key_path")
    if engine == "xray" and tls_enabled:
        # Cert-bridge: если пути не заданы вручную, но есть домен — берём
        # сертификат, который Caddy уже выпустил для этого домена (копируется
        # в /etc/xray/certs/<domain>/ через xray-cert-sync). Иначе — ручные пути.
        domain = (data.get("domain") or "").strip()
        if not (cert_path or key_path) and domain:
            # Домен идёт в путь /etc/xray/certs/<domain>/ и в SNI конфига —
            # валидируем формат, чтобы отсечь traversal (../) и мусор.
            ok, err = validate_domain(domain)
            if not ok:
                return jsonify({"error": err}), 400
            from app.core.certs import trigger_cert_sync, xray_cert_paths
            trigger_cert_sync()
            cert_path, key_path = xray_cert_paths(domain)
        ok, err = validate_tls_paths(cert_path, key_path)
        if not ok:
            return jsonify({"error": (
                f"{err}. Для TLS нужен сертификат: укажите домен, для которого "
                f"Caddy уже выпустил сертификат (панельный/naive), либо задайте "
                f"пути к cert/key вручную."
            )}), 400

    # Нормализация transport_config для Reality:
    # UI скрывает поле reality_dest в shared-443 (порт 443) — там backend
    # подставляет 127.0.0.1:8443 автоматически при генерации xray-конфига.
    # Но xray run -test читает dest из БД и падает если он пустой.
    # Подставляем корректный дефолт в зависимости от порта:
    #   порт 443  → 127.0.0.1:8443  (shared-443, Caddy loopback)
    #   другой    → microsoft.com:443  (стандартный Reality fallback-dest)
    tcfg = dict(data.get("transport_config") or {})
    if engine == "xray" and tcfg.get("reality_public_key"):
        # Reality применяется ядром только к VLESS и требует raw TCP. На
        # другом протоколе/транспорте сервер тихо проигнорировал бы Reality
        # (инбаунд остался бы БЕЗ шифрования) или не принял конфиг.
        err = _validate_reality_compat(protocol, transport)
        if err:
            return jsonify({"error": err}), 400
        # Заведётся ли Reality (ключи + источник serverNames) — до применения,
        # чтобы не ловить сырой дамп xray и не ронять панель (см. helper).
        err = _validate_reality_ready(port_normalized, tcfg)
        if err:
            return jsonify({"error": err}), 400
        if not tcfg.get("reality_dest"):
            if port_normalized == 443:
                tcfg["reality_dest"] = "127.0.0.1:8443"
            else:
                tcfg["reality_dest"] = "microsoft.com:443"

    # Режим «за настоящим сайтом» (Caddy на 443 → Xray на loopback).
    if engine == "xray" and tcfg.get("behind_caddy"):
        err = _validate_behind_caddy(
            protocol, transport, data.get("domain"), tcfg,
        )
        if err:
            return jsonify({"error": err}), 400
        # Свой TLS у Xray в этом режиме не нужен и вреден: сертификатом
        # владеет Caddy, он же терминирует соединение.
        data["tls_enabled"] = False

    # PRE-VALIDATION (синхронная): добавляем объект в сессию, делаем flush
    # (SQL INSERT без commit — данные видны внутри транзакции, но не снаружи),
    # генерируем конфиг с новым инбаундом и прогоняем xray run -test.
    # При ошибке — rollback, ничего в БД не остаётся.
    ib = Inbound(
        tag=tag,
        engine=engine,
        protocol=protocol,
        port=port_normalized,
        domain=data.get("domain"),
        tls_enabled=tls_enabled,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        # tls_acme: пока не реализован экспорт сертификатов Caddy в путь,
        # на который смотрит Xray (/etc/ssl/caddy/...). Поле в схеме остаётся
        # для будущей реализации через Caddy events; на запись принудительно
        # ставим False, чтобы UI/API-клиенты не могли создать сломанный inbound.
        tls_acme=False,
        transport=transport if engine == "xray" else None,
        transport_config=json.dumps(tcfg),
        probe_resistance_secret=data.get("probe_resistance_secret"),
        extra_config=json.dumps(data.get("extra_config", {})),
        enabled=data.get("enabled", True),
    )
    db.session.add(ib)

    if engine == "xray":
        db.session.flush()
        ok_v, msg_v = _pre_validate_xray()
        if not ok_v:
            db.session.rollback()
            return jsonify({"error": msg_v}), 400

    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(engine)
    log_action("inbound.create", target_type="inbound",
               target_id=ib.id, target_name=ib.tag,
               details={"engine": engine, "protocol": protocol, "port": ib.port})
    result = ib.to_dict()
    result["apply_id"] = apply_id
    return jsonify(result), 201


@bp.get("/<int:ib_id>")
@login_required
def get_inbound(ib_id):
    ib = Inbound.query.get_or_404(ib_id)
    return jsonify(ib.to_dict())


@bp.put("/<int:ib_id>")
@login_required
def update_inbound(ib_id):
    ib = Inbound.query.get_or_404(ib_id)
    data = request.get_json(force=True)

    updatable = [
        "port", "domain", "tls_enabled", "tls_cert_path", "tls_key_path",
        "transport", "probe_resistance_secret", "enabled",
        # tls_acme намеренно исключён — см. POST-обработчик выше.
    ]

    # Валидация ДО setattr/commit. Используем merged-значения
    # (новое из data, иначе текущее из БД) — чтобы PUT'ы, не
    # затрагивающие port/tls, не падали из-за чужих несвежих данных.

    # NaiveProxy: если юзер меняет domain — валидируем его (не пустой,
    # не == panel_domain). PUT, не трогающий domain, не перепроверяет
    # — на случай если в БД давно лежит «исторический» инбаунд с
    # некорректным доменом, юзер должен иметь возможность
    # отключить/удалить его не починив domain сначала.
    if ib.engine == "naive" and "domain" in data:
        err = _validate_naive_inbound_domain(data["domain"])
        if err:
            return jsonify({"error": err}), 400

    if ib.engine == "xray":
        # Port: валидируем только если изменился (или передан вообще).
        if "port" in data:
            # is_reality по merged-снимку: если data меняет transport_config,
            # смотрим на новое; иначе смотрим на текущее состояние БД.
            # См. _request_is_reality (data) и xray._is_reality_inbound (db).
            if "transport_config" in data:
                is_reality = _request_is_reality({
                    "protocol": data.get("protocol", ib.protocol),
                    "transport_config": data["transport_config"],
                })
            else:
                # Импорт здесь — чтобы избежать циклов на верхнем уровне.
                from app.core.xray import _is_reality_inbound
                is_reality = _is_reality_inbound(ib)
            ok, err, port_normalized = validate_port(
                data["port"], allow_reality_443=is_reality,
            )
            if not ok:
                return jsonify({"error": err}), 400
            conflict = _check_port_conflicts(
                port_normalized,
                exclude_inbound_id=ib_id,
                is_reality=is_reality,
            )
            if conflict:
                return jsonify({"error": conflict}), 409
            # подменяем на нормализованный int — на случай если юзер прислал "443"
            data["port"] = port_normalized

        # TLS-пути: проверяем ТОЛЬКО если юзер реально трогает TLS-поля
        # в этом запросе. Это намеренно: на работающем инбаунде с
        # tls_enabled=true путь к сертификату мог "испортиться" после
        # его создания (cron renew переехал, файл удалили, etc.). PUT,
        # который не касается TLS вообще (например, "enabled=false" или
        # смена probe_resistance), не должен падать из-за стороннего
        # состояния. Если же юзер сам включает TLS или меняет путь —
        # тогда валидируем по полной.
        touches_tls = (
            "tls_enabled" in data
            or "tls_cert_path" in data
            or "tls_key_path" in data
        )
        if touches_tls:
            merged_tls_enabled = bool(data.get("tls_enabled", ib.tls_enabled))
            if merged_tls_enabled:
                merged_cert = data.get("tls_cert_path", ib.tls_cert_path)
                merged_key = data.get("tls_key_path", ib.tls_key_path)
                # Cert-bridge (как в create): если путей нет, но есть домен —
                # берём сертификат Caddy для этого домена.
                merged_domain = (data.get("domain", ib.domain) or "").strip()
                if not (merged_cert or merged_key) and merged_domain:
                    ok, err = validate_domain(merged_domain)
                    if not ok:
                        return jsonify({"error": err}), 400
                    from app.core.certs import trigger_cert_sync, xray_cert_paths
                    trigger_cert_sync()
                    merged_cert, merged_key = xray_cert_paths(merged_domain)
                    data["tls_cert_path"] = merged_cert
                    data["tls_key_path"] = merged_key
                ok, err = validate_tls_paths(merged_cert, merged_key)
                if not ok:
                    return jsonify({"error": (
                        f"{err}. Укажите домен с сертификатом Caddy либо пути вручную."
                    )}), 400

    for field in updatable:
        if field in data:
            setattr(ib, field, data[field])

    # Включение через форму (PUT enabled=true) — тот же смысл, что toggle:
    # снимаем пометку авто-отключения, иначе она «зависнет» на рабочем
    # инбаунде и всплывёт ложным бейджем при следующем ручном выключении.
    if "enabled" in data and ib.enabled:
        extra = ib.get_extra_config()
        if extra.pop("auto_disabled_reason", None) is not None:
            ib.extra_config = json.dumps(extra, ensure_ascii=False)

    if "transport_config" in data:
        ib.transport_config = json.dumps(data["transport_config"])
    if "extra_config" in data:
        ib.extra_config = json.dumps(data["extra_config"])

    # Reality-совместимость: если после изменений инбаунд использует Reality,
    # protocol (immutable в PUT) и transport должны быть VLESS+TCP.
    if ib.engine == "xray" and ib.get_transport_config().get("reality_public_key"):
        err = _validate_reality_compat(ib.protocol, ib.transport or "tcp")
        if err:
            return jsonify({"error": err}), 400
        # Тот же замок, что и на create: не дать сохранить Reality без
        # источника serverNames/ключей (напр. правка порта на 443, когда
        # домен панели ещё не задан) — иначе панель по домену может упасть.
        err = _validate_reality_ready(ib.port, ib.get_transport_config())
        if err:
            return jsonify({"error": err}), 400

    # PRE-VALIDATION (синхронная): flush изменений в сессию (без commit),
    # генерируем конфиг и гоняем xray run -test. Только для xray.
    if ib.engine == "xray":
        db.session.flush()
        ok_v, msg_v = _pre_validate_xray()
        if not ok_v:
            db.session.rollback()
            return jsonify({"error": msg_v}), 400

    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(ib.engine)
    # details: что именно поменялось — пишем ключи из payload, но без значений
    # (там могут быть длинные конфиги).
    log_action("inbound.update", target_type="inbound",
               target_id=ib.id, target_name=ib.tag,
               details={"fields": list(data.keys())})
    result = ib.to_dict()
    result["apply_id"] = apply_id
    return jsonify(result)


@bp.delete("/<int:ib_id>")
@login_required
def delete_inbound(ib_id):
    ib = Inbound.query.get_or_404(ib_id)
    # Запоминаем до удаления — после db.delete() атрибуты могут быть недоступны.
    ib_snapshot = {"id": ib.id, "tag": ib.tag, "engine": ib.engine,
                   "protocol": ib.protocol, "clients_lost": len(ib.clients)}
    db.session.delete(ib)
    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(ib_snapshot["engine"])
    log_action("inbound.delete", target_type="inbound",
               target_id=ib_snapshot["id"], target_name=ib_snapshot["tag"],
               details=ib_snapshot)
    return jsonify({"ok": True, "apply_id": apply_id})


@bp.post("/<int:ib_id>/toggle")
@login_required
def toggle_inbound(ib_id):
    ib = Inbound.query.get_or_404(ib_id)
    ib.enabled = not ib.enabled
    # Включаем заново — снимаем пометку авто-отключения: если apply снова
    # упадёт по :443, _rollback_shared_443 поставит свежую причину; если
    # поднимется — старая пометка не должна «висеть» на рабочем инбаунде.
    if ib.enabled:
        extra = ib.get_extra_config()
        if extra.pop("auto_disabled_reason", None) is not None:
            ib.extra_config = json.dumps(extra, ensure_ascii=False)
    db.session.commit()

    from app.core.apply_runner import start_apply
    apply_id = start_apply(ib.engine)
    log_action("inbound.toggle", target_type="inbound",
               target_id=ib.id, target_name=ib.tag,
               details={"enabled": ib.enabled})
    return jsonify({"enabled": ib.enabled, "apply_id": apply_id})


@bp.get("/<int:ib_id>/secret")
@login_required
def get_inbound_secret(ib_id):
    """
    Возвращает probe_resistance_secret конкретного inbound'а.
    Намеренно вынесен в отдельный эндпоинт — секрет не включается
    в обычный список GET /api/inbounds (Inbound.to_dict()).
    """
    ib = Inbound.query.get_or_404(ib_id)
    return jsonify({"id": ib.id, "probe_resistance_secret": ib.probe_resistance_secret})
