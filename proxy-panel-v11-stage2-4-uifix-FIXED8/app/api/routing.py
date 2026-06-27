"""REST API: Routing rules."""
import json
from flask import Blueprint, request, jsonify
from flask_login import login_required
from app.models import db, RoutingRule, Inbound, ExternalOutbound
from app.models import (
    ROUTING_ACTION_DIRECT, ROUTING_ACTION_BLOCK,
    ROUTING_ACTION_INBOUND, ROUTING_ACTION_OUTBOUND,
)
from app.core.xray import apply_xray_config
from app.core.geo_validator import validate_codes
from app.core.input_validators import validate_match_ports, validate_regexp_entries
from app.core.audit import log_action

bp = Blueprint("routing", __name__)

VALID_ACTIONS = {
    ROUTING_ACTION_DIRECT,
    ROUTING_ACTION_BLOCK,
    ROUTING_ACTION_INBOUND,
    ROUTING_ACTION_OUTBOUND,
}

# match_network = NULL/None означает "оба" (без фильтра). Допустимые
# значения иначе — только "tcp" или "udp". "tcp,udp" эквивалентно NULL,
# мы его нормализуем в NULL чтобы не плодить пустых-смысловых значений.
VALID_NETWORK_VALUES = {None, "", "tcp", "udp"}


def _normalize_network(value):
    """Принимает то, что прислал фронт, возвращает то, что положим в БД."""
    if value is None or value == "":
        return None
    v = str(value).strip().lower()
    if v in ("both", "tcp,udp", "udp,tcp"):
        return None
    if v in ("tcp", "udp"):
        return v
    return _INVALID_NETWORK  # сигнал валидатору


_INVALID_NETWORK = object()

# Каскад между inbound'ами реализован через локальный outbound на 127.0.0.1:dst_port.
# Это работает только если dst_inbound говорит на этом порту по протоколу,
# который Xray умеет проксировать как outbound с auto-detection: SOCKS5 и HTTP.
# Для VLESS/VMess/Trojan каскад потребовал бы настоящий протокол-aware outbound
# с уже зарегистрированным клиентом в dst — это отдельная фича.
CASCADE_COMPATIBLE_PROTOCOLS = {"socks", "http"}


def _validate_rule_data(data: dict) -> str | None:
    """Возвращает текст ошибки или None если всё в порядке."""
    action = data.get("action")
    if action not in VALID_ACTIONS:
        return "Недопустимое значение action"
    # match_network: принимаем только tcp / udp / null/пусто.
    if "match_network" in data:
        normalized = _normalize_network(data["match_network"])
        if normalized is _INVALID_NETWORK:
            return "Недопустимое значение match_network (только tcp / udp / пусто)"
    # Валидация geosite:/geoip:-кодов: прогоняем через xray run -test.
    # Это ловит самую больную проблему (правило с несуществующим кодом
    # роняло Xray в crash loop, см. v11-stage1-5). Прочие записи в
    # match_domains / match_ips (domain:foo, full:..., regexp:..., CIDR)
    # валидатор пропускает — их синтаксис проверится на apply.
    bad_codes = validate_codes(
        data.get("match_domains", []),
        data.get("match_ips", []),
    )
    if bad_codes:
        return (
            f"Неизвестные geo-коды: {', '.join(bad_codes)}. "
            f"Установленная geosite.dat (v2fly/dlc) не содержит таких категорий. "
            f"Для России в этой базе используйте 'geosite:geolocation-ru' "
            f"вместо 'geosite:ru'. См. имена файлов в "
            f"https://github.com/v2fly/domain-list-community/tree/master/data"
        )
    # match_ports: формат "80,443,8000-9000" или пусто. Если кривой —
    # xray-test всё равно бы поймал на apply, но юзеру дать понятную
    # ошибку прямо из API быстрее и приятнее, чем расшифровывать вывод
    # xray.
    if "match_ports" in data:
        ok, err = validate_match_ports(data["match_ports"])
        if not ok:
            return err
    # regexp:... записи в match_domains. Битая regex роняла бы apply
    # через xray-test (defense layer 2), но точный текст ошибки от Go-
    # regex для юзера непонятен. Pre-compile через python re даёт более
    # человекочитаемое сообщение.
    ok, err = validate_regexp_entries(data.get("match_domains", []))
    if not ok:
        return err
    if action == ROUTING_ACTION_INBOUND:
        dst_id = data.get("dst_inbound_id")
        if not dst_id:
            return "dst_inbound_id обязателен для action=inbound"
        # Проверяем что dst-инбаунд существует и имеет совместимый протокол.
        dst = db.session.get(Inbound, int(dst_id))
        if not dst:
            return f"Inbound {dst_id} не существует"
        if dst.protocol not in CASCADE_COMPATIBLE_PROTOCOLS:
            return (
                f"Каскад на {dst.protocol}-inbound не поддерживается. "
                f"Используйте SOCKS5 или HTTP inbound в качестве промежуточного звена, "
                f"либо настройте внешний прокси (action=outbound)."
            )
    if action == ROUTING_ACTION_OUTBOUND:
        tag = data.get("dst_outbound_tag")
        if not tag:
            return "dst_outbound_tag обязателен для action=outbound"
        # Проверяем, что outbound с таким тегом реально существует.
        # Иначе apply_xray_config сгенерирует routing-правило, ссылающееся
        # на несуществующий outbound, и xray run -test упадёт с
        # "tag not found" — а юзер увидит generic-ошибку. Лучше дать
        # понятное сообщение на входе.
        if not ExternalOutbound.query.filter_by(tag=tag).first():
            return (
                f"Outbound с тегом '{tag}' не существует. "
                f"Создайте его в разделе 'Внешние outbound', или измените "
                f"dst_outbound_tag."
            )
    return None


@bp.get("/")
@login_required
def list_rules():
    rules = RoutingRule.query.order_by(RoutingRule.priority).all()
    return jsonify([r.to_dict() for r in rules])


@bp.post("/")
@login_required
def create_rule():
    data = request.get_json(force=True)
    err = _validate_rule_data(data)
    if err:
        return jsonify({"error": err}), 400
    rule = RoutingRule(
        name=data.get("name", "Rule"),
        priority=data.get("priority", 100),
        src_inbound_id=data.get("src_inbound_id"),
        match_domains=json.dumps(data.get("match_domains", [])),
        match_ips=json.dumps(data.get("match_ips", [])),
        match_protocols=json.dumps(data.get("match_protocols", [])),
        match_ports=data.get("match_ports"),
        match_network=_normalize_network(data.get("match_network")),
        action=data.get("action", "direct"),
        dst_inbound_id=data.get("dst_inbound_id"),
        dst_outbound_tag=data.get("dst_outbound_tag"),
        enabled=data.get("enabled", True),
    )
    db.session.add(rule)
    db.session.commit()
    apply_xray_config()
    log_action("rule.create", target_type="rule",
               target_id=rule.id, target_name=rule.name,
               details={"action": rule.action, "priority": rule.priority})
    return jsonify(rule.to_dict()), 201


@bp.put("/<int:rule_id>")
@login_required
def update_rule(rule_id):
    rule = RoutingRule.query.get_or_404(rule_id)
    data = request.get_json(force=True)
    # При частичном обновлении подставляем текущие значения из БД для
    # action и dst-полей (валидация каскада зависит от них всех вместе).
    #
    # А вот match_domains/match_ips/match_ports включаем в merged ТОЛЬКО
    # если юзер реально их прислал в этом PUT. Иначе на правиле, у
    # которого в БД лежит давно-битый код (например geosite:ru до
    # обновления панели), нельзя было бы поменять ни приоритет, ни
    # тумблер enabled, ни имя — каждый PUT валился бы на «неизвестный
    # geo-код». Юзер сначала хочет починить как минимум выключить
    # такое правило, а уже потом редактировать домены. Если же юзер
    # трогает match_* — валидируем по полной (UI всегда так делает на
    # save из модалки).
    merged = {
        "action": data.get("action", rule.action),
        "dst_inbound_id": data.get("dst_inbound_id", rule.dst_inbound_id),
        "dst_outbound_tag": data.get("dst_outbound_tag", rule.dst_outbound_tag),
    }
    if "match_domains" in data:
        merged["match_domains"] = data["match_domains"]
    if "match_ips" in data:
        merged["match_ips"] = data["match_ips"]
    if "match_ports" in data:
        merged["match_ports"] = data["match_ports"]
    err = _validate_rule_data(merged)
    if err:
        return jsonify({"error": err}), 400
    for field in ["name", "priority", "src_inbound_id", "match_ports",
                  "action", "dst_inbound_id", "dst_outbound_tag", "enabled"]:
        if field in data:
            setattr(rule, field, data[field])
    for field in ["match_domains", "match_ips", "match_protocols"]:
        if field in data:
            setattr(rule, field, json.dumps(data[field]))
    # match_network отдельно — нужна нормализация (пусто → NULL)
    if "match_network" in data:
        rule.match_network = _normalize_network(data["match_network"])
    db.session.commit()
    apply_xray_config()
    log_action("rule.update", target_type="rule",
               target_id=rule.id, target_name=rule.name,
               details={"fields": list(data.keys())})
    return jsonify(rule.to_dict())


@bp.delete("/<int:rule_id>")
@login_required
def delete_rule(rule_id):
    rule = RoutingRule.query.get_or_404(rule_id)
    snapshot = {"id": rule.id, "name": rule.name, "action": rule.action}
    db.session.delete(rule)
    db.session.commit()
    apply_xray_config()
    log_action("rule.delete", target_type="rule",
               target_id=snapshot["id"], target_name=snapshot["name"],
               details={"action": snapshot["action"]})
    return jsonify({"ok": True})
