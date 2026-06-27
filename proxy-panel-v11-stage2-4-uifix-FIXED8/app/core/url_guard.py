"""
Защита от SSRF для пользовательских URL, по которым панель сама ходит
(split-tunnel source_url: ручной refresh и авто-обновление в шедулере).

Проблема. refresh скачивает содержимое по URL, который задал админ.
Без проверки туда можно подставить:
  - http://169.254.169.254/...  — endpoint метаданных облака (AWS/GCP/
    Hetzner и т.п.), отдаёт токены/ключи доступа к самому хостингу;
  - http://127.0.0.1:2019/...   — локальный admin API Caddy (без пароля);
  - http://10.x / 192.168.x      — внутренняя сеть.

Решение. Резолвим хост и проверяем КАЖДЫЙ полученный IP: запрещаем
loopback / private / link-local / multicast / reserved / unspecified.
Разрешаем только публичные адреса.

Оговорка (TOCTOU). Между нашей проверкой и реальным запросом DNS-запись
теоретически может «перепривязаться» на приватный IP (DNS rebinding).
Полная защита потребовала бы коннекта строго к проверенному IP с
сохранением SNI/Host — это усложнение несоразмерно модели угроз
(эндпоинт доступен только залогиненному админу). Проверка ниже
закрывает основной и наиболее опасный вектор — обращение к метаданным
облака и локальным служебным сервисам по прямому имени/IP.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def validate_public_url(url: str) -> tuple[bool, str | None]:
    """
    Возвращает (ok, error). ok=True если URL — http(s) и его хост
    резолвится исключительно в публичные адреса.
    """
    if not isinstance(url, str) or not url.strip():
        return False, "URL пустой"
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Не удалось разобрать URL"

    if parsed.scheme not in ("http", "https"):
        return False, "URL должен начинаться с http:// или https://"

    host = parsed.hostname
    if not host:
        return False, "В URL отсутствует хост"

    # Хост может быть задан сразу как IP-литерал — проверим до резолва.
    literal_ip = _as_ip(host)
    if literal_ip is not None:
        if _is_blocked(literal_ip):
            return False, _blocked_msg(host, str(literal_ip))
        return True, None

    # Иначе резолвим имя и проверяем все полученные адреса.
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"Не удалось разрешить хост {host}: {e}"

    for info in infos:
        ip = _as_ip(info[4][0])
        if ip is None:
            return False, f"Некорректный адрес для {host}: {info[4][0]!r}"
        if _is_blocked(ip):
            return False, _blocked_msg(host, str(ip))

    return True, None


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_blocked(addr) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _blocked_msg(host: str, ip: str) -> str:
    return (
        f"Хост {host} резолвится в адрес {ip} из внутренней/служебной сети. "
        f"Для защиты от SSRF разрешены только публичные адреса — "
        f"укажите URL на внешний ресурс."
    )
