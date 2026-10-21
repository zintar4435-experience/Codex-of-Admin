"""
Промежуточные серверы («У меня блокировки», решение владельца 2026-10-21).

Зачем. 20–21.10.2026 мобильные операторы (Билайн, Т2) в одном городе
отрезали соединения с зарубежными серверами — у всех VPN разом, протокол
значения не имел. Против такого помогает только одно: телефон подключается
к адресу в России, а тот уже передаёт поток на основной сервер.

Как устроено.
  • Промежуточный сервер — «немой» пересыльщик портов (nftables DNAT на
    ЭТОТ сервер). Ключей не знает, ничего не расшифровывает: шифрование
    идёт от телефона до основного сервера, у пользователя тот же ключ и тот
    же IP на выходе в интернет.
  • Ставится одной командой (install_script): агент сам забирает из этой
    панели, на какой адрес и какие порты пересылать (config_text), и раз в
    пару минут сверяется. Управление — только отсюда.
  • Приложение узнаёт адреса промежуточных серверов из подписки (заголовок
    subscription_header) и ходит через них, ТОЛЬКО когда пользователь сам
    включил «У меня блокировки». Автоматически ничего не переключается.
  • Кто зайдёт на адрес промежуточного сервера браузером или сканером,
    увидит ровно то же, что на основном: соединение пересылается целиком,
    сертификаты на промежуточном сервере не нужны.

Порт 22 не пересылается никогда: на нём живёт ssh самого промежуточного
сервера (иначе владелец потерял бы к нему доступ). SSH-подключения на 22-м
порту через промежуточный сервер поэтому не ходят — приложение это знает
по списку портов в заголовке.
"""
import ipaddress
import re
import secrets

from app.models import Inbound, Relay, Setting

# Версия формата заголовка подписки и ответа агенту.
FORMAT_VERSION = 1

# Заголовок подписки с адресами промежуточных серверов. Чужие клиенты
# неизвестный заголовок игнорируют.
SUBSCRIPTION_HEADER = "Coc-Relays"

# Порт ssh самого промежуточного сервера — не пересылается никогда.
RESERVED_PORTS = frozenset({22})

AGENT_VERSION = "1"


def new_token() -> str:
    return secrets.token_urlsafe(24)


def _client_port(ib: Inbound) -> int | None:
    """Порт, на который подключается приложение (как в ссылке клиента)."""
    if ib.protocol == "naive":
        return 443
    if ib.protocol == "ssh":
        from app.core import ssh as ssh_core
        return ib.port or ssh_core.DEFAULT_PORT
    if ib.engine == "xray":
        from app.core.caddy import is_behind_caddy
        if is_behind_caddy(ib):
            return 443
    return ib.port


def forward_ports() -> list[int]:
    """TCP-порты включённых подключений, которые пересылает промежуточный
    сервер. Без 22 (ssh самого промежуточного сервера)."""
    ports: set[int] = set()
    for ib in Inbound.query.filter_by(enabled=True).all():
        try:
            port = _client_port(ib)
        except Exception:
            port = None
        if isinstance(port, int) and 1 <= port <= 65535 and port not in RESERVED_PORTS:
            ports.add(port)
    return sorted(ports)


def target_ip() -> str:
    """IPv4 этого (основного) сервера — куда пересылать."""
    ip = (Setting.get("server_ip", "") or "").strip()
    if not _is_ipv4(ip):
        from app.api.system import _get_server_ip
        ip = (_get_server_ip() or "").strip()
    return ip if _is_ipv4(ip) else ""


def _is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_host(value: str) -> bool:
    """Адрес промежуточного сервера для приложения: публичный IPv4."""
    if not _is_ipv4(value):
        return False
    ip = ipaddress.ip_address(value)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def subscription_header() -> str | None:
    """Значение заголовка Coc-Relays или None, если промежуточных серверов
    нет. Формат (одна строка, без секретов):
        v=1; hosts=1.2.3.4,5.6.7.8; ports=443,8443
    hosts — в порядке, в котором приложение их пробует (живые свежее —
    раньше); ports — какие порты они пересылают."""
    relays = Relay.query.filter_by(enabled=True).all()
    hosts: list[str] = []

    def freshness(r: Relay):
        return r.last_seen.timestamp() if r.last_seen else 0.0

    for r in sorted(relays, key=freshness, reverse=True):
        h = r.public_host
        if is_valid_host(h) and h not in hosts:
            hosts.append(h)
    ports = forward_ports()
    if not hosts or not ports:
        return None
    return (f"v={FORMAT_VERSION}; hosts={','.join(hosts)}; "
            f"ports={','.join(str(p) for p in ports)}")


def config_text(relay: Relay) -> str:
    """Ответ агенту промежуточного сервера (простой текст — агенту не нужен
    jq). enabled=0 — пересылку снять."""
    target = target_ip()
    enabled = relay.enabled and bool(target)
    lines = [
        f"format={FORMAT_VERSION}",
        f"enabled={1 if enabled else 0}",
        f"target={target if enabled else ''}",
        f"ports={','.join(str(p) for p in forward_ports()) if enabled else ''}",
    ]
    return "\n".join(lines) + "\n"


_SAFE_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def install_command(panel_url: str, token: str) -> str:
    return (f"curl -fsSL {panel_url}/relay-agent/{token}/install.sh "
            f"| sudo bash")


def install_script(panel_url: str, token: str) -> str:
    """Скрипт установки агента. panel_url и token проверяются строго —
    они подставляются в shell-скрипт."""
    if not _SAFE_URL.match(panel_url) or not _SAFE_TOKEN.match(token):
        raise ValueError("unsafe panel url or token")
    return (_INSTALL_TEMPLATE
            .replace("__PANEL_URL__", panel_url)
            .replace("__TOKEN__", token)
            .replace("__AGENT_VERSION__", AGENT_VERSION))


# Агент: nftables DNAT «все пересылаемые порты → основной сервер» +
# masquerade обратно. Таблица своя (ip coc_relay), чужие правила не
# трогает. Синхронизация — systemd-таймер раз в 2 минуты; панель
# недоступна — правила не меняются (пересылка продолжает работать).
_INSTALL_TEMPLATE = r"""#!/usr/bin/env bash
# Codex of Connect — промежуточный сервер (пересыльщик портов).
# Ставит агента, который забирает настройки из панели основного сервера
# и пересылает порты на него. Ключей и трафика в открытом виде здесь нет.
set -euo pipefail

PANEL_URL='__PANEL_URL__'
TOKEN='__TOKEN__'

if [ "$(id -u)" != 0 ]; then
  echo "Запустите от root: curl ... | sudo bash" >&2
  exit 1
fi

echo "== Codex of Connect: установка промежуточного сервера =="

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nftables curl ca-certificates >/dev/null
elif ! command -v nft >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "Нужны nft (nftables) и curl. Установите их и запустите снова." >&2
  exit 1
fi

install -d -m 700 /etc/coc-relay
umask 077
printf 'PANEL_URL=%s\nTOKEN=%s\n' "$PANEL_URL" "$TOKEN" > /etc/coc-relay/env

cat > /usr/local/bin/coc-relay-sync <<'SYNC'
#!/usr/bin/env bash
# Сверка с панелью: на какой адрес и какие порты пересылать.
set -euo pipefail
. /etc/coc-relay/env
STATE=/etc/coc-relay/rules.nft

remove_rules() {
  if nft list table ip coc_relay >/dev/null 2>&1; then
    nft delete table ip coc_relay
    echo "coc-relay: пересылка снята"
  fi
  rm -f "$STATE"
}

body=$(mktemp)
trap 'rm -f "$body" "$body.nft"' EXIT
code=$(curl -sS --max-time 20 -o "$body" -w '%{http_code}' \
  "$PANEL_URL/relay-agent/$TOKEN/config?v=__AGENT_VERSION__" || true)
code=${code:-000}

if [ "$code" = 404 ]; then
  echo "coc-relay: панель не знает этот сервер (удалён) — снимаю пересылку"
  remove_rules
  exit 0
fi
if [ "$code" != 200 ]; then
  echo "coc-relay: панель недоступна (HTTP $code) — правила не меняю"
  exit 0
fi

val() { sed -n "s/^$1=//p" "$body" | head -n 1 | tr -d '\r'; }
enabled=$(val enabled)
target=$(val target)
ports=$(val ports)

if [ "$enabled" != 1 ] || [ -z "$ports" ]; then
  remove_rules
  exit 0
fi
if ! [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "coc-relay: некорректный адрес из панели — правила не меняю" >&2
  exit 0
fi
if ! [[ "$ports" =~ ^[0-9]{1,5}(,[0-9]{1,5})*$ ]]; then
  echo "coc-relay: некорректные порты из панели — правила не меняю" >&2
  exit 0
fi
for p in ${ports//,/ }; do
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ] || [ "$p" = 22 ]; then
    echo "coc-relay: недопустимый порт $p — правила не меняю" >&2
    exit 0
  fi
done
set_ports=${ports//,/, }

cat > "$body.nft" <<NFT
table ip coc_relay {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    fib daddr type local tcp dport { $set_ports } dnat to $target
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip daddr $target tcp dport { $set_ports } masquerade
  }
}
NFT

if [ -f "$STATE" ] && cmp -s "$body.nft" "$STATE" \
    && nft list table ip coc_relay >/dev/null 2>&1; then
  exit 0
fi

{ echo "table ip coc_relay"; echo "delete table ip coc_relay"; cat "$body.nft"; } | nft -f -
install -m 600 "$body.nft" "$STATE"
echo "coc-relay: пересылка на $target, порты $ports"
SYNC
chmod 755 /usr/local/bin/coc-relay-sync

cat > /etc/sysctl.d/99-coc-relay.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
SYSCTL
sysctl -q -w net.ipv4.ip_forward=1

cat > /etc/systemd/system/coc-relay.service <<'UNIT'
[Unit]
Description=Codex of Connect relay: sync forwarding rules with the panel
Wants=network-online.target
After=network-online.target nftables.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/coc-relay-sync
UNIT

cat > /etc/systemd/system/coc-relay.timer <<'UNIT'
[Unit]
Description=Codex of Connect relay: periodic sync

[Timer]
OnBootSec=20s
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now coc-relay.timer >/dev/null
systemctl start coc-relay.service || true

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo
  echo "ВНИМАНИЕ: включён ufw. Он может не пропускать пересылаемый трафик."
  echo "Разрешите его сами (например: ufw default allow routed) — скрипт"
  echo "настройки файрвола не меняет."
fi

echo
echo "Готово. Состояние: journalctl -u coc-relay.service -n 20"
echo "В панели основного сервера этот сервер появится как «на связи» в течение пары минут."
"""
