# ProxyPanel v11 stage1-5 — собранная сборка

Эта сборка содержит исходный `proxy-panel-v11-stage1-5.tar.gz` плюс
несколько групп правок поверх него.

## Что было сломано в оригинале

### 1. Сборка Caddy без NaiveProxy

В `install.sh` и `update.sh` стояло:

```bash
go get github.com/caddyserver/forwardproxy@v0.0.0-20250118002110-d62c80d3dd2c
```

Это смесь двух разных репозиториев: путь модуля каддисерверовский, а
коммит — из `github.com/klzgrad/forwardproxy` (NaiveProxy fork с
padding'ом). Go-модули так не работают, загрузка падала с "unknown
revision". Замена на `@latest` сборку чинит, но затягивает официальный
форвард-прокси без padding — клиент Karing с таким сервером не получит
правильный NaiveProxy-протокол.

**Исправлено**: сборка через `xcaddy` с replace на `klzgrad/forwardproxy@
naive`. В конце сборки проверяется наличие `http.handlers.forward_proxy`.

### 2. JS-синтакс-ошибка в `setup_progress.html`

Строка `'Ждём ответа от Let's Encrypt…'` — апостроф закрывал строковый
литерал, парсер обрывал всё. Поллинг не запускался, страница висела
навечно.

**Исправлено**: переписано через двойные кавычки + добавлен handoff-
токен (см. ниже).

### 3. Cross-host куки сессии в онбординге

Логин на `http://<IP>:5000` создаёт куку, привязанную к хосту-IP.
Редирект на `https://<domain>/dashboard` не передаёт эту куку — юзер
оказывается на форме логина.

**Исправлено**: страница `setup-progress` после выпуска сертификата
получает одноразовый handoff-токен через `POST /api/system/onboarding-
handoff` (где куки ещё работают), редиректит на `https://<domain>/auth/
onboarding-handoff?token=…`. Этот эндпоинт без авторизации логинит
админа на новом origin и редиректит на `/dashboard`. Дополнительно
планирует отложенный рестарт `proxy-panel.service` через 3 секунды —
чтобы новый процесс gunicorn подхватил `HTTPS_ENABLED=true` из `.env`.

## Что добавлено помимо исправлений

### Уровень 1: кликабельные подсказки в Routing

В разделе **Маршрутизация** — справочные коды (`geosite:geolocation-ru`,
`geoip:ru`, `domain:vk.com`, `regexp:\.ru$`, примеры портов) теперь
**кликабельны**. Клик добавляет код в соответствующее поле формы и
открывает модалку, если она была закрыта.

Над текстовым полем «Протоколы» добавлены чипы-переключатели для
четырёх единственных значений, которые понимает sniffer Xray: `http`,
`tls`, `bittorrent`, `quic`. Чипы двунаправленно синхронизированы с
input'ом — кастомные значения, введённые руками, сохраняются.

Меняется только один файл: `app/templates/pages/routing.html`. Никаких
изменений в БД, API, бэкенде.

### Уровень 2: вкладка «Безопасность»

Новая страница `/security` с тумблерами:

- **Блокировать BitTorrent трафик** — sniffer Xray распознаёт BT-
  протокол и обрывает соединение. Работает только для Xray-инбаундов
  (VLESS/VMess/Trojan/Shadowsocks), не для NaiveProxy.
- **Блокировать рекламу и трекеры** — `geosite:category-ads-all`.
- **Блокировать adult-контент** — `geosite:category-porn`.

Каждый тумблер создаёт обычные `RoutingRule` с префиксом `[security]` в
имени. Эти правила видны и редактируемы на странице **Маршрутизация** —
пресет это не магия, а просто sugar поверх существующего routing-движка.

При выключении тумблера правила удаляются. Если вы вручную отредактируете
правило `[security] *` (например, поменяете priority), при следующем
**включении** того же пресета мы не перезатрём ваши изменения — мы
только добавляем недостающие. При **выключении** удаляем по имени.

Если у вас на момент посещения страницы **нет ни одного Xray-инбаунда**
(только NaiveProxy через Caddy), сверху появится баннер: «Эти пресеты
ничего не заблокируют — Caddy не делает routing». В этом случае
пользоваться нужно server-side мерами (DNS-фильтрация, лимиты трафика).

### Уровень 3: поле `network` (TCP/UDP/Both) в Routing

У Xray в routing rules есть поле `network` — теперь оно есть и в нашей
панели. В модалке создания/редактирования правила появилась строка
**Транспорт (network)** с тремя radio-кнопками:

- **Оба** — фильтр не применяется (поведение по умолчанию, обратная
  совместимость с существующими правилами)
- **Только TCP** — правило сработает только на TCP-соединениях
- **Только UDP** — правило сработает только на UDP

Применения: «направить только UDP-трафик в каскад» (для DNS-через-VPN),
«заблокировать UDP полностью» (защита от DNS-rebinding атак),
«TCP-only пересылка через внешний прокси». В списке правил рядом с
условиями появляется бейдж `TCP` / `UDP`, чтобы фильтр был виден без
открытия модалки.

Колонка `match_network` (`VARCHAR(8)`) добавлена в таблицу
`routing_rules` через `_ensure_schema()` — миграция идемпотентная,
повторные запуски ничего не делают. Существующие правила получают
`NULL` (= «оба»), их поведение не меняется.

### Защита от битых `geosite:`/`geoip:`-кодов в правилах

**Контекст бага.** В стандартной `geosite.dat` от v2fly (которую ставит
`install.sh` из `v2fly/domain-list-community`) **нет короткого алиаса
`ru`** — для российских доменов используется `geosite:geolocation-ru`.
В оригинальной подсказке в `routing.html` был клик с `geosite:ru` (имя
из другой базы — Loyalsoldier). Клик создавал правило с несуществующим
кодом, `apply_xray_config` его молча сохранял, и Xray на старте падал с
`code not found in geosite.dat: RU`, после чего systemd крутил его в
crash loop. Доступ к проксе пропадал, в логе панели — ничего.

**Фикс — три слоя:**

1. **Корректная подсказка.** Кликабельный код в правой колонке формы
   и `placeholder` поля «Домены» теперь `geosite:geolocation-ru` (это
   имя реально есть в `dlc.dat`).

2. **Валидация на входе.** `POST /api/routing/` и `PUT /api/routing/<id>`
   прогоняют все `geosite:`/`geoip:`-коды из `match_domains`/`match_ips`
   через сам Xray: строится временный пробный конфиг с этими кодами,
   `xray run -test -c <tmp>` пытается его распарсить. Если в выводе —
   `code not found in <…>.dat: XYZ`, эндпоинт возвращает 400 с понятным
   сообщением и подсказкой («для России в v2fly/dlc используйте
   `geosite:geolocation-ru`»). Прочие записи (`domain:foo.com`, CIDR,
   `regexp:…`) валидатор не трогает — их синтаксис проверится дальше
   по цепочке.

3. **Защита при apply.** `_build_routing_rules` теперь пропускает
   правила с битыми кодами, логируя `warning` с id правила. Перед
   атомарной заменой `/etc/xray/config.json` `write_xray_config`
   гоняет финальный конфиг через `xray run -test`; если xray его не
   примет — рабочий файл остаётся нетронутым, ошибка возвращается
   наверх (в `apply_xray_config` → API). Эта связка означает, что
   **уже сохранённое битое правило в БД не сможет уронить Xray** —
   оно просто будет пропущено при сборке конфига.

В UI на странице **Маршрутизация** в столбце с именем правила появляется
оранжевый бейдж `⚠ битый код` для правил, чьи коды xray не распознал.
В tooltip'е — список конкретных строк, которые нужно поправить. Само
правило остаётся в БД, чтобы юзер не потерял свои настройки — просто
открывайте редактирование и меняйте код на корректный.

**Где код.** Новый модуль `app/core/geo_validator.py` (один публичный
вход — `validate_codes()`, плюс `validate_config()` для использования
из `apply_xray_config`). Кэш валидных кодов в памяти процесса
инвалидируется по mtime файлов `geosite.dat`/`geoip.dat` — обновление
.dat через cron/ручной wget подхватывается без рестарта панели.

**Fail-open.** Если xray-бинарь отсутствует или дал таймаут на пробном
конфиге, валидатор считает коды валидными и пишет warning в лог. Логика:
лучше позволить юзеру сохранить правило, чем заблокировать панель из-за
проблем с самим валидатором.

### Входная валидация для инбаундов и правил роутинга

Продолжение того же подхода — fail-early фильтр перед записью в БД, для
тех полей, кривое значение в которых упёрлось бы потом в `xray run -test`
с непонятным сообщением, или вообще не дало бы Xray стартовать.

**В инбаундах** (`app/api/inbounds.py`, POST и PUT):

- **`tag`** обязан матчить `^[A-Za-z0-9_-]{1,64}$`. Раньше принималась
  любая непустая строка — тег с пробелом, точкой или слешем валидно
  попадал в БД, но потом ломал JSON-ключ Xray-конфига и имя outbound для
  каскадов (`cascade-{src}->{dst}`). Также зарезервированы имена,
  занятые ядром: `direct`, `block`, `api` (case-insensitive).
- **`port`** должен быть int (или числовая строка, приведём к int), в
  диапазоне 1..65535, и не пересекаться с инфраструктурой панели:
  80/443 (Caddy), 2019 (Caddy admin), 5000 (gunicorn). Дополнительно
  проверяется конфликт с другими Xray-инбаундами (по id, не по тегу) и
  с настройкой `xray_api_port` (по умолчанию 10085). При PUT'е своё
  предыдущее значение порта не считается конфликтом.
- **TLS-пути** (`tls_cert_path`, `tls_key_path`) если `tls_enabled=true`:
  файл должен существовать и быть не нулевого размера. Читаемость
  именно xray-юзером не проверяем (у `proxypanel` могут быть другие
  права) — это поймает позже `xray run -test`. Цель валидатора —
  отловить опечатку в пути и пустые файлы после неудачного `scp`.

**В правилах роутинга** (`app/api/routing.py`):

- **`match_ports`** должно быть в формате Xray: список через запятую,
  каждый элемент — число или диапазон `from-to`. Числа в `1..65535`,
  начало диапазона `<=` конца. Пустая строка / null — валидно (фильтра
  по портам нет).
- **`regexp:...`** записи в `match_domains` прогоняются через `re.compile`.
  Python re и Go re (которым пользуется Xray внутри) на базовом
  синтаксисе совпадают, и самые частые user-ошибки (незакрытые
  скобки, битые `\`) ловятся одинаково.

**На PUT валидация не блокирует «уборку» битых данных.** Если у вас в
БД уже лежит инбаунд с TLS-путём, который перестал существовать (или
правило с устаревшим regex), PUT, который этих полей не касается
(`{"enabled": false}`, смена `priority`, `name`), пройдёт нормально.
Валидируется только то, что юзер реально посылает в текущем запросе.
Это сознательное решение, чтобы новая защита не блокировала исправление
существующих «давно-битых» сущностей.

**Где код.** Чистые функции — `app/core/input_validators.py`. Без I/O,
без БД, без subprocess. БД-зависимые проверки (уникальность tag,
конфликт port с другим инбаундом) делаются в вызывающем коде —
`_check_port_conflicts()` в `app/api/inbounds.py`.

### Входная валидация для клиентов, outbound'ов и системных настроек

Тот же подход, расширенный на остальные API:

**Клиенты** (`app/api/clients.py`):

- **UUID**. Если юзер при создании передал свой UUID — проверяется
  формат `8-4-4-4-12 hex` (RFC 4122). Если не передал — генерим
  свежий `uuid4()` (как и раньше). На UPDATE UUID immutable.
- **Email**. Не строгий формат: достаточно отсутствия `>`, `<`, `\n`,
  `\r`, `\t` — символов, которые ломают xray stats-query (`user>>>
  email>>>traffic`). Точка и собака в email НЕ требуются — у нас
  дефолтное значение `{name}@panel` может содержать пробел в name.

**Внешние outbound** (`app/api/outbounds.py`):

- **tag** через тот же `validate_tag` (что и для инбаундов).
- **protocol** — только `socks` или `http` (другие Xray не поддерживает
  как outbound).
- **address** — IPv4, IPv6 или hostname (через
  `validate_hostname_or_ip`). Особый случай: если строка выглядит как
  IPv4-shape (4 числовые группы через точку), валидируем строго как
  IP. То есть `256.0.0.1` — точно опечатка в IP, а не «exotic hostname».
- **port** — диапазон 1..65535 БЕЗ проверки на инфраструктурные порты
  панели (это удалённый порт удалённого таргета — 443 на нём норма).

**Системные настройки** (`app/api/system.py PUT /settings`):

Раньше был только whitelist ключей, значения принимались как-есть.
Теперь каждый ключ имеет валидатор:

- `panel_domain` — формат DNS-имени (`a-z0-9-`, несколько уровней,
  длина ≤ 253). Пустая строка допустима (сбросить домен и вернуться
  на HTTP).
- `acme_email` — строгий email-формат (Let's Encrypt всё равно
  откажет на мусоре, но лучше сообщить юзеру сразу).
- `xray_log_level` — enum `{debug, info, warning, error, none}`.
- `xray_domain_strategy` — enum `{AsIs, IPIfNonMatch, IPOnDemand}`.
- `xray_api_port` — `validate_port` строго, плюс проверка что этот
  порт не занят ни одним Xray-инбаундом (иначе при apply будет
  конфликт двух bind'ов на один порт).
- `server_ip` — display-only, валидация мягкая (принимаем любую
  непустую строку, реальную работу проксы это не ломает).

PUT /settings теперь fail-fast: при первом же кривом значении
возвращается 400, ничего не сохраняется. Раньше кривые значения
молча пропускались (`if key in ALLOWED_SETTINGS:` без валидации), что
маскировало юзер-ошибки.

**Routing-правила** (`app/api/routing.py`):

- `dst_outbound_tag` для action=outbound — теперь проверяется не
  только на непустоту, но и на существование такого outbound'а в
  `ExternalOutbound` таблице. Иначе `apply_xray_config` сгенерировал
  бы правило с ссылкой на несуществующий тег и `xray run -test` упал
  бы с «tag not found» — а юзер увидел бы непонятную ошибку.

**На PUT — те же правила что и раньше:** валидируется ТОЛЬКО то поле,
которое юзер реально прислал. PUT с `{enabled: false}` или
`{username: "new"}` не падает из-за давно-битого email в БД.

### Индикатор UFW в форме инбаунда

Под полем «Порт» в форме создания/редактирования инбаунда (только для
engine=xray; для naive порт фиксирован — 443 через Caddy) показывается
живой статус из системного файрвола:

- 🟢 «Порт N/tcp открыт в UFW» — если есть явное правило ALLOW или
  default-policy = allow.
- 🟠 «Порт N/tcp не открыт в UFW. Откройте: `sudo ufw allow N/tcp`» —
  если UFW активен в default-deny и нет ALLOW-правила. Команду можно
  выделить кликом и скопировать.
- ⚪ Нейтральный нотис, если UFW неактивен, не установлен, или панель
  не смогла проверить (например, после обновления со старой версии,
  где не было нужной sudoers-записи).

**Как это устроено.** Панель работает от `proxypanel`, а `ufw status`
без `sudo` молчит. В `/etc/sudoers.d/proxypanel-xray-update`
добавлены **только read-only** строки:

```
proxypanel ALL=(root) NOPASSWD: /usr/sbin/ufw status
proxypanel ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose
```

Никаких `allow`/`delete` команд панель в файрвол не отправляет —
сознательное решение: UFW работает поверх iptables/nftables, attack
surface большой, автоматизировать менять системные правила из
веб-приложения опасно. Если порт закрыт — панель показывает готовую
команду, админ копирует её в SSH-сессию.

Существующим установкам `update.sh panel` сам подложит нужную
sudoers-запись через `ensure_panel_ufw_sudoers` (идемпотентно,
с бэкапом старого файла рядом и `visudo -c` проверкой синтаксиса).

`GET /api/system/firewall` отдаёт распарсенный JSON с разрешёнными
портами; модуль `app/core/firewall.py` кэширует результат на 10 секунд
в памяти процесса, чтобы быстрая печать в поле «Порт» не плодила
subprocess-вызовов.

### Скрытый баг Xray + systemd: HUP убивает Xray «чисто»

Этот баг сидел с самых первых версий и проявлялся только когда у Xray
был валидный конфиг. До этого его маскировал `geosite:ru` в подсказках
(старый Xray уходил в crash-loop'е со status=23, ловился `Restart=on-failure`).

**Что было.** `install.sh` создавал юнит:
```ini
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
```

А `reload_xray()` вызывал `systemctl reload-or-restart xray`. Цепочка
при попытке применить новый конфиг:

1. `reload-or-restart` видит «юнит активен, есть ExecReload» → запускает reload.
2. ExecReload отправляет Xray `SIGHUP`. **Xray не имеет обработчика
   HUP**, процесс умирает по дефолтному поведению ОС (term).
3. systemd видит «ExecReload отработал со статусом 0, процесс
   закончился сигналом HUP» — считает это успешным reload'ом, не
   failure'ом.
4. `Restart=on-failure` НЕ срабатывает (clean exit).
5. Xray мёртв, порт не слушается, клиенты получают `i/o timeout`,
   панель об этом не знает.

**Как починено** (одновременно в трёх местах):

- **`reload_xray()`** в `app/core/xray.py` теперь делает
  `systemctl restart xray` напрямую. Кратковременный downtime ~1-2 сек
  при применении конфига неизбежен, но он предсказуем — раньше Xray
  мог «уехать» в мёртвое состояние навсегда.
- **`install.sh`** создаёт юнит без `ExecReload=` и с `Restart=always`.
  Без `ExecReload=` `systemctl reload` корректно отваливается на
  restart. `Restart=always` ловит любой exit, не только failure.
- **`update.sh`** через `ensure_xray_service_unit_safe()` мигрирует
  старые установки: переписывает юнит-файл, делает `daemon-reload`, и
  если Xray в этот момент мёртв (типичное состояние при попавших под
  баг) — поднимает его. Идемпотентно: если файл уже починен,
  ничего не делает. Старый файл сохраняется рядом как
  `xray.service.before-fix-reload` для отката вручную при необходимости.

### NaiveProxy: корректное поле `auth_credentials` и обязательный отдельный домен

В этой панели NaiveProxy = Caddy + плагин `klzgrad/forwardproxy@naive`.
Раньше панель пушила в JSON-конфиг Caddy поле `basic_auth: [{user, pass}, …]`,
которого у плагина нет — Caddy отдавал `400 unknown field "basic_auth"` при
попытке добавить клиента в NaiveProxy-инбаунд. Помимо этого была фича
«combined route»: если домен naive-инбаунда совпадал с панельным, в Caddy
эмитился route с цепочкой `[forward_proxy, reverse_proxy]` на одном
матче. На практике forward_proxy для не-CONNECT GET-запросов возвращал
301 с Location на ту же URL, браузер уходил в петлю и панель становилась
недоступна с `ERR_TOO_MANY_REDIRECTS`.

**Что починили в stage1-12:**

- **Правильное имя поля и кодировка** в `_build_naive_route()`.
  Плагин ожидает `auth_credentials` — массив строк, каждая из которых
  это base64 от внутреннего base64 от `"user:pass"`. Двойная кодировка
  возникает потому, что в Go-структуре поле объявлено как `[][]byte`:
  внутренний слой — HTTP Basic auth challenge, внешний — стандартная
  Go-сериализация `[]byte` в JSON. Корректная форма проверена
  byte-for-byte против вывода `caddy adapt` на эталонном Caddyfile
  `forward_proxy { basic_auth alice secret123 }`.
- **«Combined route» убран целиком.** Функция `_build_combined_route()`
  удалена, ветка в `generate_caddy_config()` упрощена. В `caddy.py`
  оставлен подробный комментарий с историей бага — чтобы будущие
  редакторы не пытались «вернуть фичу».
- **API-валидация: NaiveProxy-инбаунд обязан иметь свой домен.**
  В `app/api/inbounds.py` появилась функция
  `_validate_naive_inbound_domain()`: пустой `domain` отклоняется
  (NaiveProxy матчится по SNI на конкретный домен — без него ничего не
  заработает), и `domain == panel_domain` тоже отклоняется (это бы
  вернуло старый редирект-баг). Сообщение об ошибке предлагает создать
  отдельный субдомен.
- **Defense-in-depth в генераторе.** `generate_caddy_config()` дополнительно
  пропускает с warning'ом любые naive-инбаунды, которые проскочили
  в БД с пустым `domain` или с `domain == panel_domain` (например,
  старые записи из v11-stage1-1 эры). API такие создать не даст, но
  данные на диске могут существовать.
- **Обёртка `subroute` для forward_proxy** (добавлено в stage1-13). Без
  неё Caddy получал CONNECT-запрос, отвечал 200 OK, но реального
  hijack'а TCP-сокета не происходило — байты после 200 интерпретировались
  как новый HTTP-запрос, NaiveProxy-клиенты в Karing видели «Соединение
  установлено успешно», но настоящий трафик не шёл. Симптом в логах
  Caddy: `msg:"NOP", status:0, bytes_read:0, duration:~66µs` и лишние
  заголовки `Content-Length: 0`, `Alt-Svc`, `Server: Caddy` в
  CONNECT-ответе. Структура валидирована через `caddy adapt`: адаптер
  Caddyfile→JSON всегда оборачивает forward_proxy в subroute, и плагин
  без этой обёртки не доходит до connection-hijack. Теперь генерируем
  идентичную каноничной структуру:
  ```
  match: host
  handle: [subroute → routes[0].handle[0] = forward_proxy]
  ```
  вместо прежнего плоского `handle: [forward_proxy]`.

### Logrotate-бэкап вне `/etc/logrotate.d/`

Прошлая версия `ensure_caddy_logrotate_safe()` сохраняла оригинал
`/etc/logrotate.d/caddy` как `/etc/logrotate.d/caddy.before-copytruncate`
в той же папке. **`logrotate` читает ВСЕ файлы в `/etc/logrotate.d/`
независимо от имени** — он видел два правила для одного
`/var/log/caddy/access.log` (текущее + бэкап) и падал с
`error: duplicate log entry`, отказываясь ротировать что-либо. Логи
Caddy у пострадавших установок копились без ротации с момента
stage1-1.

В stage1-12:

- Новый каталог `/var/lib/proxy-panel/migrations/` под бэкапы миграций.
- `ensure_caddy_logrotate_safe()` теперь пишет туда
  (`caddy-logrotate.before-copytruncate.YYYYMMDD-HHMMSS`).
- Если в `/etc/logrotate.d/caddy.before-copytruncate` остался файл от
  старой миграции — он переносится в безопасную локацию как
  `.legacy` суффикс. Идемпотентно.

### Безопасность обновлений: pre-flight в `update.sh`

В `update_panel()` добавлена pre-flight проверка перед остановкой
сервиса: компиляция всех `.py` через `compileall` + парсинг всех Jinja-
шаблонов. Если что-то синтаксически битое — ничего не трогается,
сервис не останавливается, выдаётся понятная ошибка. Установка
остаётся в рабочем состоянии.

### Защита Caddy от потери runtime-конфига

**Контекст бага.** В оригинальном `install.sh` файл
`/etc/logrotate.d/caddy` содержал `postrotate: systemctl reload caddy`.
Это правильная техника, чтобы Caddy перепинал свои log-файлы после
ротации. Но в архитектуре панели был неучтённый нюанс: Caddyfile на
диске минимальный (только admin endpoint), а полная конфигурация HTTPS-
серверов генерируется панелью и пушится через Caddy admin API. Эта
конфигурация живёт только в памяти Caddy. Когда logrotate в полночь
делал `systemctl reload caddy`, Caddy перечитывал минимальный Caddyfile
и runtime-конфиг исчезал. Панель становилась недоступна по HTTPS до
следующего пуша конфига (обычно — пока админ не залогинится и не
сохранит домен заново).

**Фикс — defense in depth:**

1. **`copytruncate` в `/etc/logrotate.d/caddy`** — logrotate теперь
   не делает reload вообще. Файлы обрезаются на месте, Caddy
   продолжает писать в тот же handle. `update.sh panel`
   автоматически обновляет этот файл на уже работающих установках
   (функция `ensure_caddy_logrotate_safe`, идемпотентно).
2. **Панель пушит конфиг в Caddy при своём старте.** В `create_app()`
   стартует фоновый поток, который через 5 секунд после запуска
   панели вызывает `apply_caddy_config()`. Если Caddy по любой
   причине потеряет runtime-конфиг — `systemctl restart proxy-panel`
   всё восстановит.

Поток фоновый и daemon — не блокирует старт gunicorn'а; ошибки
(например, Caddy admin не отвечает) только логируются как warning,
панель продолжает работать.

### VLESS + Reality в quick-start

Добавлен пятый шаблон быстрого старта — **VLESS + Reality**.
Reality — это TLS-маскировка под чужой домен (например,
`www.cloudflare.com`): сервер «одалживает» TLS-handshake у выбранного
сайта, поэтому **свой сертификат и свой домен не нужны вообще**.

**Что делает кнопка «VLESS + Reality» в шаблонах:**

1. Заполняет форму: `engine=xray`, `protocol=vless`, `port=8443`,
   `transport=tcp`, TLS-чекбокс выключен.
2. Делает `POST /api/inbounds/reality-keys` — серверный эндпоинт
   оборачивает `xray x25519` и возвращает свежую пару ключей
   X25519 (`private_key` для сервера, `public_key` для клиента).
3. Показывает секцию «Reality settings» с заполненными дефолтами:
   - **Decoy (dest):** `www.cloudflare.com:443`
   - **Server Names:** `www.cloudflare.com`
   - **Short IDs:** пусто (Xray примет `[""]`)
   - **Public key** показан в read-only поле — для verification.

После сохранения панель пушит правильный Xray-конфиг
(`security: "reality"`, `realitySettings`), а клиентский генератор
`vless://` ссылок (в `app/api/clients.py`) автоматически включает
`security=reality&pbk=...&sni=...&sid=...&fp=chrome` — клиенту ничего
больше делать не нужно, ссылка содержит всё.

**Важно про сеть:** для тестового порта `8443` нужно открыть UFW:
```bash
sudo ufw allow 8443/tcp
```
Шаблон сам этого не делает — UFW менять из веб-морды было бы
небезопасно. После открытия порта инбаунд готов принимать клиентов.

**При редактировании существующего Reality-инбаунда** секция
автоматически разворачивается с актуальными значениями. Кнопка
«Перегенерировать ключи» рядом — выписывает новые ключи (старые
клиенты после этого перестанут работать, придётся раздавать новый
URL).

## Что меняется относительно оригинала

| Файл                                       | Что                              |
|--------------------------------------------|----------------------------------|
| `install.sh`                               | xcaddy + klzgrad/forwardproxy@naive; sanity-проверки; `copytruncate` в logrotate-caddy (фикс ночных обрывов HTTPS); read-only sudo на `ufw status`/`ufw status verbose` для UI-индикатора файрвола |
| `update.sh`                                | то же для Caddy; pre-flight py_compile + Jinja; `ensure_caddy_logrotate_safe` для миграции старых установок; `ensure_panel_ufw_sudoers` для подкладывания новой sudoers-записи под `ufw status` на уже работающих установках |
| `app/__init__.py`                          | регистрация security-blueprint; миграция `routing_rules.match_network`; фоновый поток `_start_caddy_config_pusher` для авто-восстановления Caddy после рестарта |
| `app/models.py`                            | колонка `RoutingRule.match_network`; поле `validation_warnings` в `RoutingRule.to_dict()` |
| `app/api/system.py`                        | handoff-токены; `/https-status` без `@login_required`; per-key валидация в PUT `/settings` (panel_domain, acme_email, log_level, domain_strategy, xray_api_port); `GET /firewall` — UFW-статус для UI-индикатора |
| `app/api/auth.py`                          | `/auth/onboarding-handoff?token=…` |
| `app/api/routing.py`                       | приём `match_network` в create/update + валидация; валидация `geosite:`/`geoip:`-кодов через `xray run -test` в `_validate_rule_data`; валидация `match_ports` (формат) и `regexp:` (компиляция) через `app/core/input_validators.py`; проверка существования `dst_outbound_tag` |
| `app/api/security.py`                      | новый файл — API пресетов безопасности; в `/presets` теперь возвращается `has_xray_inbounds` |
| `app/api/inbounds.py`                      | `POST /api/inbounds/reality-keys` — генерация X25519 пар через `xray x25519`; в POST/PUT — валидация `tag` (формат + резерв), `port` (range, инфра-конфликты, уникальность), TLS-путей (только когда юзер их трогает) |
| `app/api/clients.py`                       | валидация UUID (формат RFC 4122) и email (запрет символов, ломающих xray stats) |
| `app/api/outbounds.py`                     | валидация tag/protocol/address/port; адрес может быть IPv4/IPv6/hostname, ловит опечатки в IP типа `256.0.0.1` |
| `app/core/xray.py`                         | проброс `network` в Xray routing rules; пропуск правил с битыми geo-кодами в `_build_routing_rules`; валидация финального конфига через `xray run -test` перед атомарной заменой в `write_xray_config` |
| `app/core/geo_validator.py`                | **новый файл** — валидация `geosite:`/`geoip:`-кодов через `xray run -test`, кэш с инвалидацией по mtime .dat-файлов, fail-open при недоступности xray |
| `app/core/input_validators.py`             | **новый файл** — чистые функции: `validate_tag`, `validate_port` (с флагом `check_panel_conflicts`), `validate_match_ports`, `validate_regexp_entries`, `validate_tls_paths`, `validate_uuid`, `validate_email`, `validate_domain`, `validate_hostname_or_ip`, `validate_enum`. Без I/O и БД, легко тестируются |
| `app/core/firewall.py`                     | **новый файл** — read-only UFW-статус через `sudo ufw status verbose`, парсер вывода (с дедупом IPv4/IPv6 близнецов и обработкой диапазонов вида `8000:9000`), кэш 10 сек, fail-open если UFW недоступен |
| `app/templates/pages/inbounds.html`        | под полем «Порт» — живой индикатор UFW (🟢 открыт / 🟠 закрыт с готовой командой / ⚪ unavailable). Скрывается при engine=naive. Данные UFW грузятся один раз через `GET /api/system/firewall` и кэшируются на стороне фронта |
| `app/views.py`                             | роут `/security`                 |
| `app/templates/base.html`                  | пункт «Безопасность» в навигации |
| `app/templates/pages/routing.html`         | подсказка `geosite:ru` заменена на `geosite:geolocation-ru` (real-name в v2fly/dlc); кликабельные подсказки, чипы протоколов, radio-кнопки Транспорт, бейдж network в таблице; бейдж `⚠ битый код` для правил с невалидными geo-кодами |
| `app/templates/pages/security.html`        | новый файл — страница пресетов; баннер про NaiveProxy |
| `app/templates/pages/inbounds.html`        | шаблон «VLESS + Reality»; секция Reality-полей с авто-генерацией ключей |
| `app/templates/pages/setup_progress.html`  | фикс JS-синтаксиса; handoff-флоу; manual-link |

Остальные файлы — без изменений.

## Установка с нуля

```bash
mkdir -p /root/proxy-panel-v11
cd /root/proxy-panel-v11
tar -xzf /path/to/proxy-panel-v11-stage1-5-FULL.tar.gz

# Если в системе уже была попытка установки — снести её начисто
systemctl stop proxy-panel proxy-panel-scheduler caddy xray 2>/dev/null || true
systemctl disable proxy-panel proxy-panel-scheduler 2>/dev/null || true
rm -f /etc/systemd/system/proxy-panel*.service
systemctl daemon-reload
rm -rf /opt/proxy-panel
rm -f /usr/local/bin/caddy

bash install.sh
```

## Обновление работающей установки (БД и конфиги сохраняются)

```bash
mkdir -p /root/pp-new
cd /root/pp-new
tar -xzf /path/to/proxy-panel-v11-stage1-5-FULL.tar.gz

sudo bash update.sh panel
```

Скрипт:

1. Делает pre-flight: компилит весь Python и парсит все Jinja-шаблоны
   из распакованного архива. Если что-то битое — выходит, текущая
   панель остаётся работать.
2. Останавливает `proxy-panel` и `proxy-panel-scheduler`.
3. Делает `rsync` (instance/, venv/ и мусор исключены — БД сохраняется).
4. Pip install свежих зависимостей.
5. Запускает сервисы.

После рестарта в боковой панели появится пункт «Безопасность».

## Проверка после установки

```bash
systemctl status caddy xray proxy-panel proxy-panel-scheduler
caddy list-modules | grep forward_proxy
curl -sf http://127.0.0.1:5000/api/system/health
```

Логи для диагностики:

```bash
journalctl -u caddy                  -n 100 --no-pager
journalctl -u xray                   -n 100 --no-pager
journalctl -u proxy-panel            -n 100 --no-pager
journalctl -u proxy-panel-scheduler  -n 100 --no-pager
```

## Stage 1-14: фикс NaiveProxy сборки (pin версий)

Stage1-13 собирал Caddy `v2.11.3` + `klzgrad/forwardproxy@naive`
(HEAD ветки). Плагин в этом форке называется `v2.10.0-naive` —
это semantic-versioning сигнал, что плагин таргетит Caddy 2.10.x
line. На Caddy 2.11.x плагин **загружается** (виден в
`caddy list-modules`), но в request-цепочку CONNECT-запросов не
подключается: между 2.10 и 2.11 в `caddyhttp` менялся обработчик
HTTP/1/2/3 запросов (см. PR caddyserver/caddy#6961, упомянутый в
release notes Caddy v2.10.1). Симптом — `"msg":"NOP", "status":0` в
access-логе и `wrong version number` на стороне curl/Karing после
CONNECT.

### Что изменилось

- `CADDY_VERSION="v2.10.2"` (последний hotfix в 2.10.x line, был
  `v2.11.3`).
- Новая переменная `FORWARDPROXY_VERSION="v2.10.0-naive"` — явный
  тэг вместо плавающего `@naive` (HEAD ветки). На момент stage1-14
  HEAD ветки совпадает с тэгом (commit `d62c80d`), но в будущем
  может уехать — фиксируем для воспроизводимости.
- После сборки записывается маркер `/etc/caddy/.naive-build-info` с
  Caddy-версией, тэгом плагина, pseudo-version плагина в runtime,
  Go-версией и временем сборки. `update.sh caddy` читает его при
  старте и печатает "было → стало".

Файлы Python-кода и БД не изменены — stage1-14 это только пара sh-скриптов.

### Применение

```bash
mkdir -p /root/pp-stage14
cd /root/pp-stage14
tar -xzf /path/to/proxy-panel-v11-stage1-14-FULL.tar.gz
sudo bash update.sh caddy
```

`update.sh caddy` остановит Caddy, пересоберёт его через xcaddy с
новыми pin'ами, запустит обратно и запишет
`/etc/caddy/.naive-build-info`. Конфиги в `/etc/caddy/` и
runtime-конфиг через admin-API не трогаются — после рестарта Caddy
живой конфиг панели подтягивается фоновым `_start_caddy_config_pusher`
из `app/__init__.py` (как обычно).

Если предпочитаешь чистый рестарт всего:
```bash
sudo bash update.sh all
```
(переустановит xray + caddy + код панели; БД сохранится).

### Проверка после применения

```bash
cat /etc/caddy/.naive-build-info
caddy version
caddy list-modules --versions | grep forward_proxy
```

Ожидаемо: `caddy_version=v2.10.2`, `forwardproxy_pin=v2.10.0-naive`,
`forwardproxy_runtime=v0.0.0-20250118002110-d62c80d3dd2c` (тот же
commit `d62c80d`, что и в тэге — но через go-modules он показывается
как pseudo-version).

Затем повтори curl-тест из handover'а:
```bash
curl -v -x 'https://NPTEST2:444@naive-myvpstest2.duckdns.org:443' \
     https://ifconfig.me
```

Если по-прежнему NOP — корень проблемы где-то ещё (например, в
JSON-конфиге Caddy, формируемом панелью); тогда следующий шаг —
посмотреть, что реально лежит в `curl http://127.0.0.1:2019/config/`
после рестарта.

## Stage 1-15: фикс stage1-14 (commit hash вместо тэга)

В stage1-14 я закрепил `FORWARDPROXY_VERSION="v2.10.0-naive"` — это
валидный git-тэг, но **невалидный Go-modules reference**. Правила
Go-модулей требуют, чтобы пакеты с major version ≥ 2 либо имели
`/v2` суффикс в module path (`github.com/klzgrad/forwardproxy/v2`),
либо `+incompatible`. У этого форка ни того, ни другого нет, поэтому
`go get` падает с:

```
go.mod: replace github.com/klzgrad/forwardproxy:
version "v2.10.0-naive" invalid: should be v0 or v1, not v2
```

Фикс — указывать тот же контент по commit hash:

```bash
FORWARDPROXY_VERSION="d62c80d3dd2c706b6b87579844d2397bddd18317"
```

Это commit, на который указывает тэг `v2.10.0-naive`. Go-модули
обращение по hash принимают (major-version-check к commit hashes
не применяется), и сами строят pseudo-version
`v0.0.0-20250118002110-d62c80d3dd2c`. Поведение и контент те же,
что у stage1-14 — отличается только формат ссылки.

Применение, маркер-файл и проверки — как в stage1-14:

```bash
sudo bash update.sh caddy           # на работающей установке
# или
sudo bash install.sh                # с нуля
cat /etc/caddy/.naive-build-info
```

## Stage 1-16: фикс NaiveProxy конфига (catch-all без host-match)

Stage 1-14/15 пытался починить NaiveProxy через подбор версий Caddy
и плагина — это была неверная гипотеза. Бинарь и плагин были
рабочие всё это время (что подтвердил prebuilt-бинарь от автора
плагина). Реальная причина — JSON-конфиг, который панель пушит в Caddy.

В `app/core/caddy.py::_build_naive_route` каждый naive-route создавался
с `"match": [{"host": [inbound.domain]}]`. В CONNECT-запросе HTTP-
заголовок `Host:` равен **target:port** (например `ifconfig.me:443`),
а не нашему naive-домену. Host-matcher не срабатывал → CONNECT
проходил мимо forward_proxy handler'а → дефолтный Caddy отвечал
пустым 200 OK и закрывал сокет (`msg:"NOP", status:0` в логах).
GET/HEAD-probes на сам наш домен матчились (там Host правильный),
поэтому 407 Proxy-Authenticate работал — что вводило в заблуждение,
будто плагин жив.

Проверено: эталонный Caddyfile `:443, naive.domain { forward_proxy }`
после `caddy adapt` даёт ровно один route **без host-matcher**
(`:443` = catch-all). Минимальный canonical Caddyfile, запущенный
параллельно systemd-Caddy, дал реально рабочий туннель в curl-тесте.

### Что изменилось

- `app/core/caddy.py`:
  - Удалён `_build_naive_route` (per-inbound с host-match).
  - Добавлен `_build_naive_catchall_route` — один общий route **без
    `match`**. Если активных naive-инбаундов несколько, их
    `auth_credentials` объединяются в общий список (фильтрацию по
    SNI обеспечивает `tls_connection_policies`).
  - В `generate_caddy_config` поменян порядок routes: сначала panel
    (host-match + terminal), потом naive catch-all. Обратный порядок
    ломал бы панель — catch-all перехватил бы её запросы.

`install.sh` / `update.sh` без изменений; пересобирать Caddy не надо
(значения `CADDY_VERSION` / `FORWARDPROXY_VERSION` остались как в
stage1-15, но они и не задействуются — `update.sh panel` Caddy не
трогает). Текущий бинарь от автора плагина (`v2.10.0-naive`,
prebuilt) полностью подходит.

### Применение

```bash
mkdir -p /root/pp-stage16
cd /root/pp-stage16
tar -xzf /path/to/proxy-panel-v11-stage1-16-FULL.tar.gz
sudo bash update.sh panel
```

После `update.sh panel` панель запустится с новым кодом и через
`_start_caddy_config_pusher` дотолкнёт новый JSON-конфиг в Caddy
через admin API.

### Проверка

```bash
# конфиг должен содержать ровно один naive route БЕЗ "match"
curl -s http://127.0.0.1:2019/config/ \
  | jq '.apps.http.servers.https.routes'

# тест туннеля
curl -v -x 'https://USER:PASS@naive.YOUR-DOMAIN.com:443' \
     https://ifconfig.me 2>&1 | tail -10
```

Должно выдать IP VPS, а не `wrong version number`.

## Stage 1-17: фикс TLS handshake (host OR method matcher)

Stage 1-16 убрал host-match совсем — CONNECT через туннель заработал
в minimal-Caddyfile тесте, но через панель Caddy перестал отдавать cert
на naive-домене (`tls.handshake: no certificate available`, curl падает
с `internal error`). Причина: Caddy `auto_https` определяет какие
сертификаты выпускать/обновлять через ACME **сканируя host-matchers
routes**. Catch-all без `match` не даёт ему ни одного домена, поэтому
cert для naive-домена не управляется и не загружается в memory cache,
даже если `tls.automation.policies.subjects` его явно содержит.

### Что изменилось

В `_build_naive_catchall_route` добавлен OR-matcher:

```json
"match": [
  {"host": ["naive.domain", ...]},
  {"method": ["CONNECT"]}
]
```

В Caddy JSON массив `match` — это OR между объектами. Запрос попадает
в route если выполнено любое из условий: либо host равен одному из
naive-доменов (probe/auth-check GET/HEAD), либо метод = CONNECT
(туннель — там Host = target:port, не наш домен). host-matcher даёт
`auto_https` информацию для ACME, method-matcher ловит CONNECT.

### Применение

```bash
mkdir -p /root/pp-stage17
cd /root/pp-stage17
tar -xzf /path/to/proxy-panel-v11-stage1-17-FULL.tar.gz
sudo bash update.sh panel
sleep 4
```

### Проверка

```bash
# в конфиге наив-route теперь имеет OR-matcher
curl -s http://127.0.0.1:2019/config/ \
  | jq '.apps.http.servers.https.routes[1].match'
# ожидаем: [{"host":["naive-..."]},{"method":["CONNECT"]}]

# тест
curl -v -x 'https://USER:PASS@naive.YOUR-DOMAIN:443' \
     https://ifconfig.me 2>&1 | tail -10
```

Должно вернуть IP VPS. И в Caddy-логе должно быть
`enabling automatic TLS certificate management","domains":["panel.domain","naive.domain"]`
(оба домена в managed-list).
