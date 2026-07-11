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
    validate_tag, validate_port, validate_tls_paths,
)

bp = Blueprint("inbounds", __name__)

XRAY_PROTOCOLS = {"vmess", "vless", "trojan", "shadowsocks", "socks", "http", "dokodemo"}
NAIVE_PROTOCOLS = {"naive"}

# Протоколы, доступные для СОЗДАНИЯ новых инбаундов. Пока в проде проверены
# только VLESS (вкл. Reality) и NaiveProxy — остальные временно скрыты в UI и
# заблокированы на создание здесь (вторая линия для прямых вызовов API).
# Чтобы вернуть протокол, когда он заработает, добавьте его сюда (одна строка).
# Существующих инбаундов это НЕ касается — редактирование/применение работают.
ENABLED_XRAY_PROTOCOLS = {"vless", "trojan"}
VALID_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "h2", "httpupgrade", "splithttp"}

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
            # упал. Это редкое состояние (например, права на /etc/xray/
            # или systemd сбойнул). Caddy уже переехал, но рабочий xray
            # не поднят. Лучше что мы можем — сообщить и оставить разруливать
            # вручную (через UI: вернуть Reality на 8443 → apply вернёт всё назад).
            return False, (
                f"Xray apply: {msg_x}. ВНИМАНИЕ: Caddy уже переехал на "
                f"127.0.0.1:8443, а Xray не стартанул — публичный :443 пустой. "
                f"Откатите вручную: в UI поменяйте port у Reality с 443 на "
                f"другой, сохраните; Caddy вернётся на :443."
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

    if engine == "xray" and protocol not in XRAY_PROTOCOLS:
        return jsonify({"error": f"Неверный протокол для Xray: {protocol}"}), 400
    if engine == "xray" and protocol not in ENABLED_XRAY_PROTOCOLS:
        return jsonify({"error": (
            "Этот протокол временно недоступен. Сейчас поддерживаются "
            "VLESS (включая Reality) и NaiveProxy."
        )}), 400
    if engine == "naive" and protocol not in NAIVE_PROTOCOLS:
        return jsonify({"error": "Для NaiveProxy протокол должен быть 'naive'"}), 400

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
        if not tcfg.get("reality_dest"):
            if port_normalized == 443:
                tcfg["reality_dest"] = "127.0.0.1:8443"
            else:
                tcfg["reality_dest"] = "microsoft.com:443"

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
