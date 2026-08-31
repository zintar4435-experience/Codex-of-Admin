#!/usr/bin/env bash
# diag-06c.sh — диагностика режима 06·C (shared-443): Reality на :443 +
# «За настоящим сайтом» за Caddy на одном сервере.
#
# Зачем. 06·C — наш ЗАДОКУМЕНТИРОВАННЫЙ способ (раздел 06·C гайда), он
# обязан работать на чистой установке. Полевой случай: «подключено, но
# ничего не грузит», а панель по домену «легла наглухо». `xray run -test`
# этого НЕ ловит — он валидирует текст конфига, а не живой путь. Этот
# скрипт проходит цепочку 06·C end-to-end и показывает ТОЧКУ обрыва.
#
# Что делает: ТОЛЬКО читает состояние и делает локальные TLS-пробы к
# 127.0.0.1. Ничего не меняет, не перезапускает, не пишет на диск.
#
# Запуск на сервере, где стоит 06·C:
#     sudo bash diag-06c.sh [PANEL_DOMAIN] [SITE_DOMAIN] [SECRET_PATH]
# Домены/путь можно не указывать — скрипт вытащит их из конфигов Caddy/Xray.
# Вывод целиком скопируйте и пришлите — по нему видно, ЧТО именно рвётся.

set -u
LC_ALL=C

sec(){ printf '\n===== %s =====\n' "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

PANEL="${1:-}"; SITE="${2:-}"; SPATH="${3:-}"

sec "0. ВРЕМЯ / ХОСТ / ВЕРСИИ"
date -u 2>/dev/null; hostname 2>/dev/null
have xray  && xray version 2>/dev/null | head -1
have caddy && caddy version 2>/dev/null | head -1

sec "1. СЛУШАТЕЛИ :80 :443 :5000 :8443 :2019 (кто держит порт)"
if have ss; then
  ss -ltnp 2>/dev/null | grep -E ':(80|443|5000|8443|2019)([^0-9]|$)' || echo "(ничего на этих портах — плохой знак для :443)"
elif have netstat; then
  netstat -ltnp 2>/dev/null | grep -E ':(80|443|5000|8443|2019)([^0-9]|$)'
else
  echo "нет ни ss, ни netstat"
fi

sec "2. СЕРВИСЫ xray / caddy"
for s in xray caddy; do
  printf '  %-6s: ' "$s"
  systemctl is-active "$s" 2>/dev/null || echo "неизвестно"
done
echo "-- последние ошибки journal (xray) --"
journalctl -u xray --no-pager -n 15 -p warning 2>/dev/null | tail -15 || echo "(journalctl недоступен)"
echo "-- последние ошибки journal (caddy) --"
journalctl -u caddy --no-pager -n 15 -p warning 2>/dev/null | tail -15 || echo "(journalctl недоступен)"

sec "3. CADDY: running config (admin API 2019)"
CADDY_CFG="$(curl -sS --max-time 5 http://127.0.0.1:2019/config/ 2>/dev/null)"
if [ -n "$CADDY_CFG" ] && have python3; then
  printf '%s' "$CADDY_CFG" | python3 - <<'PY' 2>/dev/null || printf '%s' "$CADDY_CFG" | head -c 1500
import sys, json
try:
    c = json.load(sys.stdin)
except Exception as e:
    print("(config не разобран как JSON:", e, ")"); sys.exit()
srv = c.get("apps", {}).get("http", {}).get("servers", {})
for name, s in srv.items():
    wr = [w.get("wrapper") for w in s.get("listener_wrappers", [])]
    print("server", name, "listen", s.get("listen"), "| listener_wrappers", wr or "-")
    for r in s.get("routes", []):
        m = r.get("match", [{}])
        hosts = sorted({h for mm in m for h in mm.get("host", [])})
        paths = sorted({p for mm in m for p in mm.get("path", [])})
        handlers = [h.get("handler") for h in r.get("handle", [])]
        # разворачиваем subroute/reverse_proxy upstream
        ups = []
        for h in r.get("handle", []):
            for u in h.get("upstreams", []) or []:
                ups.append(u.get("dial"))
        print("   route host", hosts or "-", "path", paths or "-",
              "handlers", handlers, ("-> " + ",".join(ups) if ups else ""))
autop = c.get("apps", {}).get("tls", {}).get("automation", {}).get("policies", [])
print("tls automation subjects:", [p.get("subjects") for p in autop])
PY
else
  echo "(admin API 2019 не ответил — Caddy не запущен, или порт закрыт)"
fi

sec "4. CADDY: сертификаты на диске (есть ли LE-cert для доменов)"
found_certs=0
for base in /var/lib/caddy/.local/share/caddy/certificates \
            /root/.local/share/caddy/certificates \
            /home/*/.local/share/caddy/certificates; do
  [ -d "$base" ] || continue
  found_certs=1
  echo "$base:"
  find "$base" -name '*.crt' 2>/dev/null | sed 's/^/  /' | sed "s#$base/##"
done
[ "$found_certs" = 0 ] && echo "(каталог сертификатов Caddy не найден — cert ещё не выпущен?)"

sec "5. XRAY: Reality-инбаунд на :443 (dest / xver / serverNames)"
XRAY_CFG=""
for f in /usr/local/etc/xray/config.json /etc/xray/config.json /opt/xray/config.json /usr/local/etc/xray/*.json; do
  [ -f "$f" ] || continue
  XRAY_CFG="$f"
  echo "файл: $f"
  if have python3; then
    python3 - "$f" <<'PY' 2>/dev/null || sed -n '1,60p' "$f"
import sys, json
c = json.load(open(sys.argv[1]))
for ib in c.get("inbounds", []):
    if ib.get("port") != 443:
        continue
    ss = ib.get("streamSettings", {}); r = ss.get("realitySettings", {})
    print("  proto", ib.get("protocol"), "| listen", ib.get("listen", "0.0.0.0"),
          "| security", ss.get("security"))
    print("  dest       :", r.get("dest"))
    print("  xver       :", r.get("xver"))
    print("  serverNames:", r.get("serverNames"))
# перечислим loopback-инбаунды «за сайтом» (ws/httpupgrade на 127.0.0.1)
for ib in c.get("inbounds", []):
    if ib.get("listen") in ("127.0.0.1", "localhost"):
        ss = ib.get("streamSettings", {}); net = ss.get("network")
        cfg = ss.get(net + "Settings", {}) if net else {}
        print("  [за сайтом] port", ib.get("port"), "net", net,
              "path", cfg.get("path"), "host", cfg.get("host"))
PY
  fi
  break
done
[ -z "$XRAY_CFG" ] && echo "(xray config не найден по стандартным путям)"

# ── Автоопределение доменов/пути, если не заданы аргументами ──
if have python3 && [ -n "$CADDY_CFG" ]; then
  read -r AUTO_PANEL AUTO_SITE AUTO_PATH < <(printf '%s' "$CADDY_CFG" | python3 - <<'PY' 2>/dev/null
import sys, json
c = json.load(sys.stdin)
panel = site = path = "-"
srv = c.get("apps", {}).get("http", {}).get("servers", {})
for s in srv.values():
    for r in s.get("routes", []):
        handlers = [h.get("handler") for h in r.get("handle", [])]
        m = r.get("match", [{}])
        hosts = [h for mm in m for h in mm.get("host", [])]
        paths = [p for mm in m for p in mm.get("path", [])]
        # панель = reverse_proxy на :5000
        for h in r.get("handle", []):
            for u in h.get("upstreams", []) or []:
                if "5000" in (u.get("dial") or "") and hosts:
                    panel = hosts[0]
        # «за сайтом» = reverse_proxy + есть path-матч (host+path)
        if "reverse_proxy" in handlers and paths and hosts:
            if not any("5000" in (u.get("dial") or "")
                       for h in r.get("handle", []) for u in h.get("upstreams", []) or []):
                site = hosts[0]; path = paths[0]
print(panel, site, path)
PY
)
  [ -z "$PANEL" ] && [ -n "${AUTO_PANEL:-}" ] && [ "$AUTO_PANEL" != "-" ] && PANEL="$AUTO_PANEL"
  [ -z "$SITE" ]  && [ -n "${AUTO_SITE:-}" ]  && [ "$AUTO_SITE" != "-" ]  && SITE="$AUTO_SITE"
  [ -z "$SPATH" ] && [ -n "${AUTO_PATH:-}" ]  && [ "$AUTO_PATH" != "-" ]  && SPATH="$AUTO_PATH"
fi

echo
echo "Используемые для проб домены: PANEL='${PANEL:-?}' SITE='${SITE:-?}' PATH='${SPATH:-?}'"
echo "(если ? — задайте аргументами: sudo bash diag-06c.sh PANEL SITE /секретныйпуть)"

# ── Проба: TLS к :443 как обычный (не-Reality) браузер ──
# Reality обязан сфолбечить и прорелеить на Caddy; Caddy — стерминировать TLS.
probe_https(){ # $1=sni  $2=path  $3=extra_headers  $4=подпись
  local sni="$1" p="$2" extra="$3" label="$4"
  echo "── $label (SNI=$sni, path=$p) ──"
  if ! have openssl; then echo "  нет openssl — пропуск"; return; fi
  local req
  req="$(printf 'GET %s HTTP/1.1\r\nHost: %s\r\n%sUser-Agent: diag-06c\r\nConnection: close\r\n\r\n' "$p" "$sni" "$extra")"
  local out
  out="$(printf '%s' "$req" | timeout 10 openssl s_client -connect 127.0.0.1:443 \
        -servername "$sni" -quiet 2>/dev/null | head -c 500)"
  if [ -z "$out" ]; then
    echo "  ПУСТО — рукопожатие/relay не прошли (reset/таймаут). :443 не обслуживает."
  else
    printf '  ответ: %s\n' "$(printf '%s' "$out" | head -1)"
    printf '%s' "$out" | grep -qi 'HTTP/1' && printf '  первые строки:\n' && printf '%s\n' "$out" | sed -n '1,6p' | sed 's/^/    /'
  fi
  # какой сертификат предъявлен для этого SNI
  local subj
  subj="$(timeout 10 openssl s_client -connect 127.0.0.1:443 -servername "$sni" </dev/null 2>/dev/null \
          | openssl x509 -noout -subject -issuer 2>/dev/null)"
  if [ -n "$subj" ]; then printf '  cert:\n%s\n' "$subj" | sed 's/^/    /'; else echo "  cert: НЕ получен (рукопожатие не завершилось)"; fi
}

sec "6. ПРОБА A — :443, SNI=PANEL (должна вернуться панель = relay Reality→Caddy жив)"
if [ -n "${PANEL:-}" ] && [ "$PANEL" != "?" ]; then
  probe_https "$PANEL" "/" "" "панель через :443"
else echo "PANEL неизвестен — пропуск"; fi

sec "7. ПРОБА B — :443, SNI=SITE + секретный путь (ws-upgrade должен дойти до Xray)"
if [ -n "${SITE:-}" ] && [ -n "${SPATH:-}" ] && [ "$SITE" != "?" ] && [ "$SPATH" != "?" ]; then
  probe_https "$SITE" "$SPATH" \
    "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" \
    "секретный путь через :443"
  echo
  echo "  Как читать ответ пробы B:"
  echo "   • 101 Switching Protocols → ws дошёл до Xray, путь OK (обрыв глубже: Reality/VLESS)."
  echo "   • 404 → у Caddy нет route на этот host+path (route не собрался / домен не тот)."
  echo "   • 200 + html → путь провалился в сайт-обманку: путь в ССЫЛКЕ ≠ путь в Caddy (РАССИНХРОН)."
  echo "   • 502 → route есть, но loopback-Xray не поднят."
  echo "   • пусто/reset/таймаут → relay Reality→Caddy сломан (та же причина, что «панель легла»)."
else echo "SITE/PATH неизвестны — пропуск (задайте аргументами)"; fi

sec "8. ИТОГ"
echo "Скопируйте ВЕСЬ вывод выше и пришлите. Ключевые места: раздел 1 (кто на :443),"
echo "раздел 5 (dest=127.0.0.1:8443? xver=1? serverNames содержит PANEL и SITE?),"
echo "и пробы A/B (где именно обрывается цепочка)."
