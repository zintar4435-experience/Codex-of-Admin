"""
Заметность сервера: что видит тот, кто проверяет его снаружи, и подбор
сайта для маскировки Reality.

Зачем. Блокировки всё чаще строятся не на «узнать протокол», а на
«этот адрес ведёт себя не как обычный сайт»: сканер приходит на IP, смотрит
открытые порты, какой сертификат отдаётся, совпадает ли имя сайта (SNI) с
тем, кому принадлежит адрес. Панель проверяет то же самое у себя и
объясняет простыми словами, что поправить.

Сайт для маскировки Reality (dest/serverNames). Reality выдаёт себя за
чужой сайт: для постороннего сервер отвечает его настоящим сертификатом.
Хороший сайт-«донор»:
  • TLS 1.3 и HTTP/2, обмен ключами X25519 — иначе Reality не заработает
    или будет отличаться от настоящего браузерного соединения;
  • действующий сертификат на это имя;
  • рядом с сервером (малая задержка, лучше всего — «сосед» в той же
    подсети хостинга): когда SNI — www.microsoft.com, а адрес — дешёвый
    VPS, это несовпадение видно без всякого декодирования;
  • не заблокирован и не замедлен в России — иначе соединение режется
    просто по имени.
Поиск «соседей» повторяет идею RealiTLScanner (XTLS): перебрать адреса
подсети сервера на :443 и найти те, что отвечают TLS 1.3 + h2 с
действующим сертификатом.

Поправка по полю (26.09.2026): у части российских провайдеров соединения,
где в SNI малоизвестный домен, «замерзают» после первых килобайт — текст
проходит, картинки и страницы нет. Так вёл себя Reality на 443 под
собственным доменом владельца, а тот же сервер под www.samsung.com (3x-ui)
работал стабильно. Сосед по подсети — тоже малоизвестный домен, поэтому
главный совет — крупный известный сайт, соседи — для опытных.
"""
import concurrent.futures
import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse

# Популярные «доноры» — основной совет для России (см. поправку в docstring).
POPULAR_TARGETS = [
    "www.microsoft.com", "www.apple.com", "dl.google.com", "www.samsung.com",
    "www.nvidia.com", "www.amd.com", "www.intel.com", "www.sony.com",
    "aws.amazon.com", "www.oracle.com", "www.asus.com", "www.logitech.com",
]

# Заблокированы или замедлены в России — соединение с таким SNI режется
# по имени, какой бы хорошей ни была остальная маскировка.
RU_BLOCKED_SUFFIXES = (
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
    "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net",
    "twitter.com", "x.com", "twimg.com", "linkedin.com", "licdn.com",
    "discord.com", "discord.gg", "discordapp.com", "signal.org",
    "torproject.org", "rutracker.org", "medium.com", "soundcloud.com",
    "patreon.com", "viber.com", "whatsapp.com", "whatsapp.net",
)

_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


def _now_ms() -> float:
    return time.monotonic() * 1000


def is_ru_blocked(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in RU_BLOCKED_SUFFIXES)


def _name_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base) and host.count(".") == base.count(".") + 1
    return pattern == host


def resolve_v4(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def tls_probe(ip: str, port: int = 443, sni: str | None = None,
              timeout: float = 4.0) -> dict:
    """Одно TLS-рукопожатие «как браузер»: TLS 1.3, ALPN h2. Цепочка
    сертификата проверяется по системным корням, имя — вручную (для
    соседей имя заранее неизвестно).

    {"ok", "tls13", "h2", "chain_valid", "names", "name_ok", "tcp_ms",
     "tls_ms", "error"}"""
    res = {"ok": False, "tls13": False, "h2": False, "chain_valid": False,
           "names": [], "name_ok": None, "tcp_ms": None, "tls_ms": None, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    t0 = _now_ms()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as e:
        res["error"] = f"порт закрыт или не отвечает ({e.__class__.__name__})"
        return res
    res["tcp_ms"] = int(_now_ms() - t0)
    t1 = _now_ms()
    try:
        with ctx.wrap_socket(sock, server_hostname=sni) as ss:
            res["tls_ms"] = int(_now_ms() - t1)
            res["tls13"] = ss.version() == "TLSv1.3"
            res["h2"] = ss.selected_alpn_protocol() == "h2"
            cert = ss.getpeercert() or {}
            res["chain_valid"] = True
            res["names"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    except ssl.SSLCertVerificationError as e:
        res["error"] = f"сертификат недействителен ({e.verify_message})"
        sock.close()
        return res
    except ssl.SSLError as e:
        reason = getattr(e, "reason", None) or str(e)
        if "VERSION" in str(reason).upper() or "PROTOCOL" in str(reason).upper():
            res["error"] = "нет TLS 1.3"
        else:
            res["error"] = f"TLS не установился ({reason})"
        sock.close()
        return res
    except OSError as e:
        res["error"] = f"соединение оборвалось ({e.__class__.__name__})"
        sock.close()
        return res
    if sni:
        res["name_ok"] = any(_name_matches(n, sni) for n in res["names"])
    res["ok"] = True
    return res


def x25519_supported(ip: str, port: int, sni: str | None, timeout: float = 5.0) -> bool | None:
    """Поддерживает ли сайт обмен ключами X25519 (его всегда шлёт клиент
    Reality). Python до 3.13 не умеет ограничить группы — спрашиваем
    openssl. None — openssl нет, проверить не смогли."""
    exe = shutil.which("openssl")
    if not exe:
        return None
    cmd = [exe, "s_client", "-connect", f"{ip}:{port}", "-tls1_3",
           "-groups", "X25519", "-brief"]
    if sni:
        cmd += ["-servername", sni]
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode == 0 and "CONNECTION ESTABLISHED" in out


def _proximity(server_ip: str | None, ip: str) -> str | None:
    """«сосед»: та же /24; «рядом»: та же /16."""
    if not server_ip:
        return None
    try:
        a, b = ipaddress.ip_address(server_ip), ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4 or b.version != 4:
        return None
    if ipaddress.ip_network(f"{server_ip}/24", strict=False) == ipaddress.ip_network(f"{ip}/24", strict=False):
        return "сосед по подсети"
    if ipaddress.ip_network(f"{server_ip}/16", strict=False) == ipaddress.ip_network(f"{ip}/16", strict=False):
        return "рядом (та же /16)"
    return None


def _verdict(host: str, probe: dict, x25519, proximity: str | None) -> tuple[bool, list[str], list[str]]:
    """(подходит, проблемы, плюсы). Проблемы — блокирующие для Reality."""
    bad, good = [], []
    if not probe.get("ok"):
        bad.append(probe.get("error") or "не отвечает")
        return False, bad, good
    if not probe["tls13"]:
        bad.append("нет TLS 1.3")
    if not probe["h2"]:
        bad.append("нет HTTP/2")
    if probe.get("name_ok") is False:
        bad.append("сертификат выдан на другое имя")
    if x25519 is False:
        bad.append("не поддерживает X25519")
    if is_ru_blocked(host):
        bad.append("сайт заблокирован или замедлен в России — соединение режется по имени")
    ms = probe.get("tcp_ms")
    if proximity:
        good.append(proximity)
    if ms is not None:
        if ms <= 30:
            good.append(f"быстро отвечает ({ms} мс)")
        elif ms > 120:
            bad.append(f"далеко от сервера ({ms} мс) — рукопожатие заметно медленнее обычного")
    return not bad, bad, good


def check_target(host: str, port: int = 443, server_ip: str | None = None) -> dict:
    """Проверка одного сайта как цели Reality (по имени)."""
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith(("http://", "https://")):
        host = urllib.parse.urlsplit(host).hostname or ""
    if ":" in host:
        host, _, p = host.partition(":")
        if p.isdigit():
            port = int(p)
    if not _HOST_RE.match(host or ""):
        return {"host": host, "ok": False, "problems": ["это не имя сайта (нужно вида www.example.com)"],
                "pluses": [], "ip": None}
    ips = resolve_v4(host)
    if not ips:
        return {"host": host, "ok": False, "problems": ["имя не находится в DNS"], "pluses": [], "ip": None}
    ip = ips[0]
    probe = tls_probe(ip, port, sni=host)
    x = x25519_supported(ip, port, host) if probe.get("ok") else None
    prox = _proximity(server_ip, ip)
    ok, bad, good = _verdict(host, probe, x, prox)
    return {
        "host": host, "port": port, "ip": ip, "ok": ok, "problems": bad, "pluses": good,
        "tls13": probe["tls13"], "h2": probe["h2"], "x25519": x,
        "ms": probe.get("tcp_ms"),
        "dest": f"{host}:{port}",
    }


def check_many(hosts: list[str], server_ip: str | None, workers: int = 8) -> list[dict]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda h: check_target(h, 443, server_ip), hosts))
    return sorted(results, key=lambda r: (not r["ok"], r.get("ms") or 10**6))


def scan_neighbors(server_ip: str, budget_s: float = 18.0, workers: int = 64) -> dict:
    """Перебор /24 сервера на :443: кто отвечает TLS 1.3 + h2 с действующим
    сертификатом. Имя берём из сертификата соседа и проверяем, что
    сертификат на это имя отдаётся именно по этому адресу.

    Укладываемся в budget_s (панель отвечает не дольше 30 с): что не
    успели — не проверяем, в ответе partial=True."""
    try:
        net = ipaddress.ip_network(f"{server_ip}/24", strict=False)
    except ValueError:
        return {"error": "Не удалось определить IP сервера", "candidates": [], "scanned": 0}
    if net.version != 4 or not ipaddress.ip_address(server_ip).is_global:
        return {"error": "У сервера нет публичного IPv4 — соседей не найти", "candidates": [], "scanned": 0}
    deadline = time.monotonic() + budget_s
    hosts = [str(h) for h in net.hosts() if str(h) != server_ip]

    skipped = object()   # не успели проверить — не считается «проверенным»

    def probe_one(ip):
        if time.monotonic() > deadline - 2:
            return skipped
        base = tls_probe(ip, 443, sni=None, timeout=1.5)
        if not base.get("ok") or not base["tls13"] or not base["h2"]:
            return None
        names = [n for n in base["names"] if not n.startswith("*.") and _HOST_RE.match(n)]
        if not names:
            return None
        name = names[0].lower()
        if is_ru_blocked(name) or time.monotonic() > deadline - 1:
            return None
        again = tls_probe(ip, 443, sni=name, timeout=2.0)
        if not again.get("ok") or not again["tls13"] or not again["h2"] or not again["name_ok"]:
            return None
        # Совпадает ли DNS имени с этим адресом: тогда dest можно писать
        # именем, иначе — адресом (имя может вести на CDN в другом месте).
        dns_match = ip in resolve_v4(name)
        return {"host": name, "ip": ip, "ms": again["tcp_ms"], "dns_match": dns_match,
                "dest": f"{name}:443" if dns_match else f"{ip}:443"}

    scanned = 0
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe_one, ip) for ip in hosts]
        for f in futs:
            left = deadline - time.monotonic()
            try:
                r = f.result(timeout=max(0.05, left))
            except concurrent.futures.TimeoutError:
                continue
            if r is skipped:
                continue
            scanned += 1
            if r:
                found.append(r)
        for f in futs:
            f.cancel()
    found.sort(key=lambda r: (not r["dns_match"], r["ms"] or 10**6))
    return {"candidates": found, "scanned": scanned, "total": len(hosts),
            "partial": scanned < len(hosts), "subnet": str(net)}


# ---------------------------------------------------------------------------
# Самопроверка сервера
# ---------------------------------------------------------------------------

_KNOWN_PORTS = {
    22: "SSH",
    80: "Caddy (выпуск сертификатов, переадресация на HTTPS)",
    443: "HTTPS (Caddy / Reality)",
    5000: "панель по HTTP",
}


def _listening_public_tcp() -> list[int] | None:
    """Порты TCP, которые слушаются НЕ только на loopback. None — ss нет."""
    exe = shutil.which("ss")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-ltnH"], capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return None
    ports = set()
    for line in (r.stdout or "").splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        local = cols[3]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if not port.isdigit():
            continue
        if addr in ("127.0.0.1", "::1") or addr.startswith("127."):
            continue
        ports.add(int(port))
    return sorted(ports)


def _f(level: str, title: str, detail: str = "") -> dict:
    return {"level": level, "title": title, "detail": detail}


def self_check(server_ip: str | None) -> list[dict]:
    """Что видно снаружи. Уровни: ok / info / warn / bad."""
    from app.models import Inbound, Setting
    from app.core.firewall import get_ufw_status
    from app.core.xray import _is_reality_inbound, find_reality_443_inbound

    findings: list[dict] = []
    panel_domain = (Setting.get("panel_domain", "") or "").strip().lower()
    https_on = bool(panel_domain)
    inbounds = Inbound.query.filter_by(enabled=True).all()
    xray_ports = {ib.port: ib for ib in inbounds if ib.engine == "xray" and ib.port}

    # --- 1. Открытые порты ---
    ufw = get_ufw_status(force_refresh=True)
    if ufw.get("available") and not ufw.get("active"):
        findings.append(_f("warn", "Файрвол (UFW) выключен",
                           "Снаружи доступен любой порт, который что-то слушает. "
                           "Включите: sudo ufw enable (порты SSH, 80, 443 и ваших подключений панель уже открывала)."))
    ports = _listening_public_tcp()
    if ports is None:
        findings.append(_f("info", "Список открытых портов получить не удалось",
                           "Нет утилиты ss (пакет iproute2)."))
    else:
        allowed = {str(r.get("port")) for r in ufw.get("allowed_ports", [])} if ufw.get("available") else set()
        blocked_by_fw = ufw.get("available") and ufw.get("active") and ufw.get("default_in") != "allow"

        def visible(p: int) -> bool:
            return not blocked_by_fw or str(p) in allowed

        vis = [p for p in ports if visible(p)]
        labels = []
        for p in vis:
            if p in xray_ports:
                labels.append(f"{p} — подключение {xray_ports[p].tag}")
            else:
                labels.append(f"{p} — {_KNOWN_PORTS.get(p, 'неизвестный сервис')}")
        findings.append(_f("info", "Снаружи открыты порты: " + (", ".join(str(p) for p in vis) or "нет"),
                           "; ".join(labels)))
        if 5000 in vis and https_on:
            findings.append(_f("warn", "Панель доступна по http://IP:5000",
                               "Панель уже работает по домену — порт 5000 больше не нужен и выдаёт сервер: "
                               "sudo ufw delete allow 5000/tcp"))
        stray = [p for p in vis if p not in _KNOWN_PORTS and p not in xray_ports]
        if stray:
            findings.append(_f("warn", "Посторонние открытые порты: " + ", ".join(map(str, stray)),
                               "Каждый лишний сервис — дополнительный отпечаток сервера. "
                               "Если это не ваше — закройте в UFW или остановите сервис."))
        odd = [p for p in vis if p in xray_ports and p != 443]
        if odd:
            findings.append(_f("info", "Подключения на отдельных портах: " + ", ".join(map(str, odd)),
                               "Порт 443 занят панелью и вашим сайтом, поэтому подключения «под известный "
                               "сайт» стоят на своих портах — это нормально. К сведению: сканер видит, что "
                               "на сервере открыт не только 443."))

    # --- 2. Домены указывают на этот сервер ---
    domains = []
    if panel_domain:
        domains.append(("панели", panel_domain))
    for ib in inbounds:
        if ib.domain and ib.domain.lower() != panel_domain:
            domains.append((f"подключения {ib.tag}", ib.domain.lower()))
    for what, d in domains:
        ips = resolve_v4(d)
        if not ips:
            findings.append(_f("bad", f"Домен {what} {d} не находится в DNS",
                               "Клиенты не смогут подключиться по имени, сертификат не выпустится."))
        elif server_ip and server_ip not in ips:
            findings.append(_f("warn", f"Домен {what} {d} указывает не на этот сервер",
                               f"DNS: {', '.join(ips)}, а сервер — {server_ip}. Если домен за CDN "
                               f"(оранжевое облако Cloudflare) — выключите проксирование."))
        else:
            findings.append(_f("ok", f"Домен {what} {d} указывает на этот сервер"))

    # --- 3. Что видит посторонний на :443 ---
    reality443 = find_reality_443_inbound()
    if server_ip:
        blank = tls_probe(server_ip, 443, sni=None, timeout=4)
        if not blank.get("ok"):
            if "закрыт" in (blank.get("error") or ""):
                findings.append(_f("info", "На :443 ничего не отвечает", "Сервер не похож на сайт вовсе."))
            else:
                findings.append(_f("ok", "Без имени сайта :443 не отдаёт сертификат",
                                   "Сканер, пришедший по голому IP, ничего не узнаёт."))
        elif blank.get("names"):
            findings.append(_f("info", "По голому IP :443 отдаёт сертификат " + ", ".join(blank["names"][:3]),
                               "Сканер по IP узнаёт ваш домен. Это нормально для обычного сайта, "
                               "но домен панели в этом списке выдавать не стоит."))

    if panel_domain:
        # Страница входа панели по домену — прямой признак прокси-сервера
        # для любого, кто откроет адрес (в режиме «общий 443» этот домен ещё
        # и попадает в SNI ключей Reality).
        try:
            import http.client
            conn = http.client.HTTPSConnection(panel_domain, 443, timeout=5,
                                               context=ssl.create_default_context())
            conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0"})
            resp = conn.getresponse()
            body = resp.read(20000).decode(errors="replace")
            location = resp.getheader("Location") or ""
            conn.close()
            if "/auth/login" in location or "Codex of Admin" in body or "/auth/login" in body:
                in_sni = reality443 is not None
                findings.append(_f("warn" if in_sni else "info",
                                   f"По адресу https://{panel_domain} открывается вход в панель",
                                   "Любой, кто откроет домен, видит панель управления прокси. "
                                   + ("В режиме «общий 443» этот домен ещё и стоит в SNI ключей Reality — "
                                      "проверяющий по SNI попадёт прямо на панель. " if in_sni else "")
                                   + "Не публикуйте домен панели и держите на нём включённую 2FA."))
        except Exception:
            pass   # домен не открылся — об этом уже сказал пункт про DNS

    # --- 4. Reality-подключения ---
    for ib in inbounds:
        if ib.engine != "xray" or not _is_reality_inbound(ib):
            continue
        tcfg = ib.get_transport_config()
        if ib.port == 443:
            findings.append(_f("ok", f"Reality {ib.tag} — на 443 за вашим же сайтом",
                               "Посторонний видит ваш настоящий сайт с настоящим сертификатом. "
                               "Если у пользователей текст проходит, а картинки и страницы нет — "
                               "создайте ещё подключение «под известный сайт»."))
        else:
            dest = (tcfg.get("reality_dest") or "").strip()
            host = dest.rsplit(":", 1)[0] if dest else ""
            names = tcfg.get("reality_server_names") or []
            if host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                t = check_target(host, 443, server_ip)
                if t["ok"]:
                    findings.append(_f("ok", f"Reality {ib.tag}: маскировка под {host} подходит",
                                       ", ".join(t["pluses"])))
                else:
                    findings.append(_f("warn", f"Reality {ib.tag}: маскировка под {host} — есть проблемы",
                                       "; ".join(t["problems"]) + ". Подберите другой сайт ниже — лучше крупный и известный."))
                if names and host not in names:
                    findings.append(_f("info", f"Reality {ib.tag}: имя в ключах ({names[0]}) не совпадает с сайтом маскировки ({host})",
                                       "Так бывает (у сайта несколько имён), но надёжнее, когда совпадают."))
    return findings
