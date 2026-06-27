# proxy-panel — stage2-2 — shared-443 (Reality + Caddy на одном порту)

FULL-архив на базе stage1-17. Включает в себя fix-ы поверх первой
попытки stage2-1 (которая была развёрнута, но потребовала двух hotfix-ов
по ходу тестирования — см. ниже).

## Что делает

Когда в БД есть включённый Reality-инбаунд с `port=443`, Caddy переезжает
на `127.0.0.1:8443` (loopback), а Reality становится фронтом на публичном
`:443`. Reality сам обрабатывает Reality-клиентов (по public_key и
SNI=один из наших доменов), а всё остальное (NaiveProxy-туннели, обращения
к панели, обычные браузеры, сканеры) — TCP-проксирует на Caddy через
`realitySettings.dest=127.0.0.1:8443`.

Снаружи весь трафик идёт на :443 и неотличим от обычного HTTPS-сайта с
валидным Let's Encrypt cert. Лучше для DPI-устойчивости.

Когда Reality на 443 нет (удалён, отключен или сидит на другом порту) —
Caddy слушает `:443` публично, как в stage1-17. Полный fallback,
автоматически.

**Переключение по факту:** меняешь port у Reality в UI с `8443 → 443` —
включается shared. С `443 → 8443` — выключается.

## Что отличается от stage2-1

stage2-1 был развёрнут и работал в общих чертах, но потребовал два
hotfix-а по ходу тестирования. Они уже встроены сюда:

**Fix 1 (caddy.py):** в первой версии я указал
`issuer.disable_tls_alpn_challenge=true` — это синтаксис Caddyfile-уровня,
а Caddy JSON-API не знает такого поля и возвращает 400 на /load. Правильно:
вложенный объект `issuer.challenges = {http: {}, tls-alpn: {disabled: true}}`.

**Fix 2 (inbounds.py):** в первой версии `_apply_for_engine` в
shared-режиме делал apply_caddy → apply_xray. Если apply_xray падал
(битый xray-конфиг, например дубликаты клиентов, конфликт портов и т.п.),
Caddy уже успевал уехать на loopback, а Xray не вставал на :443 →
публичный :443 пустой → ERR_TIMED_OUT, панель недоступна. Теперь сначала
**pre-validation** Xray-конфига через `xray run -test`. Если xray не
примет — ошибка возвращается в UI **до того как тронуть Caddy**, состояние
сохраняется.

## Изменённые файлы (vs stage1-17)

5 файлов:

| Файл | Изменения |
|---|---|
| `app/core/input_validators.py` | `validate_port(..., allow_reality_443=True)` |
| `app/core/xray.py` | helpers `find_reality_443_inbound`, `_is_reality_*`, `_shared_443_server_names`; в `_build_stream_settings` для Reality на 443 принудительно `dest=127.0.0.1:8443`, `serverNames` из panel/naive доменов БД, xver=0 |
| `app/core/caddy.py` | `generate_caddy_config` определяет shared по наличию Reality на 443, меняет `listen` и добавляет `challenges.tls-alpn.disabled=true` в ACME issuer для shared-режима |
| `app/api/inbounds.py` | `_request_is_reality`, `_check_port_conflicts` (разрешает 443 для Reality, резервирует 8443 в shared), переписан `_apply_for_engine` с pre-validation Xray |
| `app/templates/pages/inbounds.html` | шаблон vless-reality → port 443, info-bar shared-режима, advanced-раскрывашка для dest/serverNames |

`install.sh`, `update.sh`, `requirements.txt`, `run.py` — без изменений.

## Применение

### Шаг 1 — бэкап

```bash
sudo cp /etc/xray/config.json /etc/xray/config.json.before-stage2-2
curl -s http://127.0.0.1:2019/config/ | sudo tee /etc/caddy/caddy.json.before-stage2-2 >/dev/null
sudo cp /opt/proxy-panel/instance/panel.db /opt/proxy-panel/instance/panel.db.before-stage2-2
ls -la /etc/xray/config.json.before-stage2-2 /etc/caddy/caddy.json.before-stage2-2 /opt/proxy-panel/instance/panel.db.before-stage2-2
```

### Шаг 2 — выгрузить FULL архив на VPS и распаковать

```bash
cd /tmp && tar -xzf proxy-panel-v11-stage2-2-shared443-FULL.tar.gz
cd /tmp/proxy-panel-v11-stage2-2-shared443-FULL && ls
```

Ожидаемое: `README-stage2-2.md  README.md  app  install.sh  requirements.txt  run.py  update.sh`

### Шаг 3 — применить

```bash
cd /tmp/proxy-panel-v11-stage2-2-shared443-FULL && sudo bash update.sh panel
```

Ожидаемое: знакомый вывод update.sh, в конце сервис `proxy-panel` рестартован, статус active.

### Шаг 4 — sanity (внешне ничего не должно поменяться)

```bash
sudo systemctl status proxy-panel --no-pager | head -10
sudo journalctl -u proxy-panel --since "2 minutes ago" --no-pager | grep -iE "error|exception|traceback" | head -10
```

NaiveProxy продолжает работать, панель доступна. Reality (если был на 8443) — на 8443 как раньше.

### Шаг 5 — переезд на shared-443

Если Reality на 8443: в UI открой Reality-инбаунд → поменяй port `8443 → 443` → сохрани. Backend сделает: pre-validate Xray (OK) → apply Caddy (уедет на 127.0.0.1:8443) → apply Xray (займёт :443).

Если Reality ещё нет: в UI «Создать» → шаблон «VLESS + Reality» → port подставится 443 → сохрани.

**Важно:** при сохранении инбаунда/клиента в shared-режиме браузер
может показать «Failed to fetch». **Это нормально** — apply Caddy
дропает текущее соединение (см. ниже Known issues). Backend заканчивает
операцию, обнови страницу — увидишь результат.

### Шаг 6 — проверки после переезда

```bash
sudo ss -lntp | grep -E ':(443|8443) '
```

Ожидаем: `*:443` — xray, `127.0.0.1:8443` — caddy.

```bash
curl -s http://127.0.0.1:2019/config/ | jq '.apps.http.servers.https.listen, .apps.tls.automation.policies[0].issuers[0]'
```

Ожидаем: `["127.0.0.1:8443"]` и в issuer `challenges: {http: {}, tls-alpn: {disabled: true}}`.

```bash
sudo jq '.inbounds[] | select(.protocol=="vless") | {tag, port, network: .streamSettings.network, dest: .streamSettings.realitySettings.dest, serverNames: .streamSettings.realitySettings.serverNames}' /etc/xray/config.json
```

Ожидаем: port=443, dest=`127.0.0.1:8443`, serverNames содержит panel и naive домены.

```bash
curl -kI https://YOUR_PANEL_DOMAIN 2>&1 | head -3
```

Ожидаем `HTTP/2 302` (редирект /dashboard) или 200.

```bash
curl -v -x 'https://USER:PASS@naive.YOUR_DOMAIN:443' https://ifconfig.me 2>&1 | tail -5
```

Ожидаем: IP VPS.

Reality-клиент из Karing/v2rayN:
- port: **443**
- SNI: один из serverNames (panel или naive домен)
- public_key, short_id из UI

### Шаг 7 — UFW (опционально)

После переезда порт 8443 публично не нужен (там Caddy на loopback):

```bash
sudo ufw delete allow 8443/tcp
```

Гигиена, не критично.

## Откат

```bash
sudo cp /opt/proxy-panel/instance/panel.db.before-stage2-2 /opt/proxy-panel/instance/panel.db
cd /tmp && tar -xzf proxy-panel-v11-stage1-17-FULL.tar.gz
cd /tmp/proxy-panel-v11-stage1-17-FULL && sudo bash update.sh panel
```

## Known issues / lessons learned

Эти моменты обнаружились в процессе тестирования stage2-1/2-2 и НЕ
являются blocking-багами, но стоит знать.

**1. «Failed to fetch» в UI при apply в shared-режиме.** При сохранении
любого инбаунда/клиента backend дёргает `apply_caddy_config()`, который
делает `/load` в Caddy admin API. Caddy перевешивает routes/listeners.
Твоё текущее HTTPS-соединение через цепочку Reality → Caddy → gunicorn
в этот момент может прерваться, и браузер показывает fetch error.
Backend почти всегда успешно завершает операцию — обнови страницу,
увидишь результат. Лечится либо async apply (отправлять HTTP-ответ
до /load), либо retry в UI fetch — отдельная задача.

**2. Real IP клиента в логах Caddy = 127.0.0.1.** Побочный эффект `xver=0`
(Reality пробрасывает TCP без PROXY-protocol). Outbound (IP, который
видят сайты в интернете) — это IP VPS, как и было. Подсчёт трафика
per-user в Caddy работает через basic-auth `user`, не страдает.
Если нужен real-IP в access.log — поднять xver=1 + listener_wrapper
proxy_protocol в Caddy. Отдельная задача.

**3. Двойное создание клиента (баг unrelated к shared-443).** При POST
`/api/clients/` иногда создаются ДВА клиента с одинаковыми email/username
— затем Xray валидно отказывается принимать конфиг с дубликатами
(`proxy/vless: User XXX already exists`). В stage2-2 это ловит
pre-validation и возвращает ошибку в UI без поломки. Корневая причина —
в логике create_client (возможно double-submit в UI, race в backend,
или отсутствие уникального констрейнта в БД). Отдельная задача.

**4. Reality + gRPC работает в shared-443.** Изначально я подозревал что
gRPC-транспорт в связке с Reality+shared может ломать конфиг. Это
оказалось неверно — gRPC+Reality в shared прекрасно работает (Reality
сам не лезет в HTTP/gRPC уровень, он чистый TCP-proxy для не-Reality
трафика; для Reality-клиента tunnel поверх TLS-обёртки, и поверх него
gRPC). Гипотеза была ложной, корень был в дубликате клиента.

**5. Порт :5000 (gunicorn) держать открытым в UFW.** Это «emergency
access» путь к панели, когда основной :443 сломан (например, после
неудачного apply в shared-режиме). Без него восстановление сложнее —
SSH-туннель тоже работает, но менее удобно.

**6. xver=0 и потеря IP в логах.** Уже упомянуто в (2). Не путать с тем
что Reality-клиент **на стороне клиента** видит IP VPS как outbound.

## Архитектурные ограничения (by design)

- **Один Reality-инбаунд на 443.** В `_check_port_conflicts` захардкожено.
  Второй Reality можно на любом другом порту (8444, 9443), но не shared.
- **Порт 8443 зарезервирован под Caddy в shared.** Никакой другой
  Xray-инбаунд не может занять 8443 пока активен shared. Валидируется.
- **ACME только HTTP-01 в shared.** TLS-ALPN-01 невозможен (Caddy не
  слушает публичный :443). HTTP-01 на :80 работает как обычно.
- **Reality-клиент использует SNI = panel_domain или naive_domain.**
  Reality «крадёт» handshake у Caddy, и Caddy выдаёт LE-сертификат для
  одного из своих доменов. Это лучше чем SNI=microsoft.com: cert
  соответствует IP VPS, никаких расхождений.
