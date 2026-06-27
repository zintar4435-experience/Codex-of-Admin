"""
Subscription URL — публичный endpoint для клиентских приложений
(v2rayN, v2box, NekoBox, Streisand, sing-box, Clash и т.д.).

Один URL `/sub/<share_token>` возвращает base64-объединение всех
ссылок клиентов, у которых задан этот же share_token. Это позволяет:
  - дать одному пользователю один URL вместо набора ссылок vless://…
  - автоматически обновлять список при добавлении/удалении inbound'а
    на стороне сервера (клиент перечитывает подписку периодически).

Защита: токен — UUID4 (122 бита энтропии). Никаких других проверок:
ни Referer, ни IP — это убьёт мобильные клиенты в роуминге.
Если нужно отозвать URL — админ генерирует клиенту новый share_token
через панель (POST /api/clients/<id>/rotate-token).
"""
import base64
from datetime import timezone
from flask import Blueprint, abort, Response

from app.models import Client
from app.api.clients import generate_link

bp = Blueprint("subscription", __name__)


@bp.get("/<token>")
def subscription(token: str):
    # Базовая защита от мусорных запросов: токен — это UUID, длина 36.
    # Чуть более широкие границы (32-64) на случай, если позже добавим
    # сокращённые токены или другой формат.
    if not token or not (16 <= len(token) <= 64):
        abort(404)

    clients = Client.query.filter_by(share_token=token).all()
    if not clients:
        abort(404)

    # Собираем ссылки только от активных клиентов (учитывая enabled / expire / limit).
    # Это важно: если у клиента закончился срок или лимит, его строка не должна
    # уходить в подписку — иначе клиент-приложение продолжит подключаться
    # до следующего обновления, забирая впустую соединения.
    links: list[str] = []
    total_used_up   = 0
    total_used_down = 0
    total_limit_up   = 0
    total_limit_down = 0
    soonest_expire  = None

    for c in clients:
        # Накапливаем статистику ДЛЯ ВСЕХ клиентов с этим токеном —
        # включая отключённых: пользователь должен видеть, сколько уже потрачено,
        # а не сколько потрачено "активной частью".
        total_used_up   += c.traffic_used_up   or 0
        total_used_down += c.traffic_used_down or 0
        if c.traffic_limit_up:   total_limit_up   += c.traffic_limit_up
        if c.traffic_limit_down: total_limit_down += c.traffic_limit_down
        if c.expire_at:
            ea = c.expire_at
            if ea.tzinfo is None:
                ea = ea.replace(tzinfo=timezone.utc)
            if soonest_expire is None or ea < soonest_expire:
                soonest_expire = ea

        if not c.is_active:
            continue
        link = generate_link(c, c.inbound)
        if link:
            links.append(link)

    body = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")

    # Subscription-Userinfo: стандартный заголовок, понимаемый большинством
    # клиентских приложений. Формат: "upload=N; download=N; total=N; expire=UNIX_TS".
    # Все четыре поля опциональны; пропускаем то, что неизвестно.
    info_parts = [f"upload={total_used_up}", f"download={total_used_down}"]
    total_limit = total_limit_up + total_limit_down
    if total_limit > 0:
        info_parts.append(f"total={total_limit}")
    if soonest_expire:
        info_parts.append(f"expire={int(soonest_expire.timestamp())}")

    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        # Сколько часов клиент должен ждать перед очередным запросом подписки.
        # 12 — разумный компромисс между «не дёргать сервер каждые 5 минут»
        # и «увидеть новый inbound сегодня же».
        "Profile-Update-Interval": "12",
        "Subscription-Userinfo": "; ".join(info_parts),
        # Cache-Control: подписка содержит секреты — клиентам и прокси
        # запрещено её кэшировать.
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }

    return Response(body, status=200, headers=headers)
