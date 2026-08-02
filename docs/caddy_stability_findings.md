# Caddy: таймауты, keepalive и вклад сервера в обрывы naive

Дата: 2026-07-26. Статус: **исследование, изменений в коде не делалось.**

Серверная часть разбора обрывов NaiveProxy. Полное исследование (механика
обрыва на стороне клиента, диагноз по логу, ветка QUIC, тупики) —
в репозитории `Codex_connect`, файл `docs/naive_stability_investigation.md`.
Здесь только то, что относится к панели и Caddy.

Проверено по исходникам Caddy v2.10.2, `golang.org/x/net` v0.42.0,
quic-go v0.54.0, `klzgrad/forwardproxy@naive` на нашем пине `d62c80d3`.

> **Область применения (уточнение 27.07).** Всё в этом файле касается
> **только naive**. VLESS/Reality через Caddy не ходит: Reality держит свой
> инбаунд, а Caddy при занятом 443 уезжает на `127.0.0.1:8443`
> (`caddy.py:315`). Если обрывы происходят на VLESS — смотреть надо не сюда,
> а на рестарты Xray: `apply_xray_config()` (`app/core/xray.py:799`) делает
> **`systemctl restart xray`** без проверки «конфиг не изменился», то есть
> каждая правка клиента/инбаунда/аутбаунда/маршрутизации мгновенно убивает
> все живые VLESS-соединения. Замер: `journalctl -u xray | grep -c Started`.
> Подробности — в `Codex_connect/docs/stability_fix_plan.md`, раздел P0a.

---

## 1. Что мы сейчас кладём в конфиг

`app/core/caddy.py`, `generate_caddy_config()`. HTTPS-сервер (`:377`):

```python
https_server: dict[str, Any] = {
    "listen": [https_listen],                      # ":443" или "127.0.0.1:8443"
    "automatic_https": {"disable_redirects": True},
    "routes": routes,
    "logs": {"default_logger_name": "naive_access"},
}
```

**Секции таймаутов нет вообще.** Ни `read_timeout`, ни `read_header_timeout`,
ни `write_timeout`, ни `idle_timeout`, ни `keepalive_interval`, ни
`protocols`, ни `grace_period`. У `forward_proxy` (`:143`) не задан
`dial_timeout`.

## 2. Какие дефолты из-за этого действуют

| Поле | Дефолт | Где в Caddy 2.10.2 |
|---|---|---|
| `idle_timeout` | **5 минут** | `modules/caddyhttp/app.go:817`, применяется `:385` |
| `read_header_timeout` | 1 минута | `app.go:824` |
| `read_timeout` / `write_timeout` | 0 (без таймаута) | `app.go:460,462` |
| `keepalive_interval` | 0 → TCP keepalive **включён**, 15 с, 9 проб | `app.go:536-541` |
| `protocols` | `["h1","h2","h3"]` | `app.go:231-233` |
| `grace_period` | 0 → «вечный» | `app.go:684-692` |
| `http2.Server` | все поля нулевые | `app.go:496-499` |
| `forward_proxy.dial_timeout` | 30 с | `forwardproxy.go:124-125` |

## 3. Рвёт ли сервер активные туннели

**Нет.** В HTTP/2 idle-таймер останавливается при открытии стрима
(`x/net/http2/server.go:2057-2059`) и перевзводится только когда стримов
не осталось (`:1734-1737`). Пока есть хоть один открытый CONNECT — GOAWAY
по idle не прилетит. На клиентский PING сервер отвечает всегда
(`:1640-1661`); PING-ACK под flow-control не попадает.

Симптом `http2 ping failed` в логе клиента означает, что **клиент** не
дождался ACK на свой health-check. Будь сервер жив и путь цел — ACK бы
пришёл. Первопричина на пути (NAT/оператор), серверный конфиг её не
вызывает.

## 4. Где сервер всё-таки усугубляет

1. **`idle_timeout` 5 минут.** Когда клиент закрыл все туннели (телефон в
   кармане), соединение простаивает и получает `GOAWAY(NO_ERROR)`
   (`server.go:1026-1027`), закрытие через `goAwayTimeout = 1s`. При выходе
   из простоя нужен полный TCP+TLS+h2 handshake — ровно тогда, когда
   мобильная сеть хуже всего.

2. **Сервер не шлёт своих h2-PING.** Из нулевого `http2.Server` следует
   `ReadIdleTimeout = 0`, а условие отправки — `SendPingTimeout > 0`
   (`x/net/http2/server.go:972`). Единственный keepalive со стороны сервера —
   TCP-уровневый раз в 15 с; он держит NAT-маппинг, но h2-проверки живости
   не даёт.

3. **Каждая реальная перезагрузка Caddy = GOAWAY всем naive-клиентам.**
   `http2.ConfigureServer` регистрирует `RegisterOnShutdown(startGracefulShutdown)`,
   Caddy при reload вызывает `server.Shutdown(ctx)`. Панель пушит конфиг:
   - при изменении инбаунда (`app/api/inbounds.py`),
   - при изменении клиента (`app/api/clients.py:514`),
   - при изменении split-tunnel (`app/api/split_tunnel.py:17`),
   - при каждом старте панели — **дважды**, по разу на gunicorn-воркер
     (`app/__init__.py:314`, `_start_caddy_config_pusher`).

   Смягчает то, что Caddy короткозамыкает побайтово идентичный конфиг
   (`caddy.go:221`, лог `config is unchanged`). Но любой реальный diff — или
   недетерминированный порядок `auth_credentials` — рвёт всех.

4. **Анонс h3 в никуда.** `protocols` не задан → Caddy поднимает QUIC-сокет
   на UDP/443 (`app.go:606-622` → `server.go:604 serveHTTP3`) и добавляет
   `Alt-Svc: h3=":443"` во все ответы, включая ответ на CONNECT
   (`server.go:281-290`). При этом UFW UDP не пропускает: `install.sh:698-701`
   открывает только `ssh`, `80/tcp`, `443/tcp`, `5000/tcp`. Настоящий сайт
   либо отвечает по QUIC, либо не рекламирует его — дешёвый фингерпринт-сигнал.

## 5. Что стоит рассмотреть (точные имена полей)

Всё внутри `apps.http.servers.https`, т.е. в `https_server` в `caddy.py:377`,
если не указано иное.

| Поле | Предложение | Что даст |
|---|---|---|
| `idle_timeout` | `"1h"` | простаивающее соединение не получает GOAWAY через 5 минут; при возврате из фона клиент переиспользует живое |
| `keepalive_interval` | `"10s"` | TCP-пробы держат NAT-маппинг оператора живым между всплесками трафика |
| `read_timeout`, `write_timeout` | **НЕ задавать** | в HTTP/2 становятся per-stream дедлайнами (`x/net/http2/server.go:2119`, `:2218`) и гарантированно убьют долгий CONNECT-туннель |
| `protocols` | `["h1","h2"]` — либо оставить дефолт и открыть UDP/443 | убирает расхождение «Alt-Svc есть, QUIC молчит» |
| `apps.http.grace_period` | `"30s"` | делает reload предсказуемым; на обрывы влияет слабо |
| `forward_proxy.dial_timeout` (`caddy.py:143`) | `"10s"` вместо дефолтных 30 с | клиент быстрее получает ошибку на мёртвый апстрим |

**Важно про `idle_timeout`:** ставить большое **положительное** значение.
Отрицательное (снятие таймаута) сломает h1-запросы к панели — они получат
уже истёкший read-дедлайн.

### Чего из JSON сделать нельзя

Grep по всему дереву тега v2.10.2 даёт **0 совпадений** для `ReadIdleTimeout`
и `PingTimeout`; `http.Server.HTTP2Config` (Go 1.24+) Caddy не заполняет.
То есть включить серверные h2-keepalive-PING, поменять
`MaxConcurrentStreams` (250), `MaxReadFrameSize` или окна flow-control
(1 MiB) из конфига **невозможно** — только форком Caddy (правка
`modules/caddyhttp/app.go:497`, где создаётся `new(http2.Server)`).
Как первый шаг не рекомендуется.

### Системное (рекомендации naiveproxy Performance Tuning)

`net.ipv4.tcp_congestion_control=bbr`, `net.ipv4.tcp_notsent_lowat=131072`.
TCP Fast Open **не** включать.

## 6. Сверка с эталонным Caddyfile из README naiveproxy

Наш конфиг эквивалентен по `forward_proxy`: `hide_ip`, `hide_via`,
`auth_credentials`, `probe_resistance` — всё на месте. Отличия:

- **У нас нет `file_server` fallback.** На naive-домене неавторизованный
  или непроксирующий запрос не отдаёт правдоподобный сайт: при
  `probe_resistance` запрос уходит в `next.ServeHTTP`, а следующего
  хендлера нет. Стоит рассмотреть отдельно — это вопрос маскировки, а не
  стабильности.
- Нет `encode` на naive-маршруте — **осознанно и правильно**.
- Эталон тоже не задаёт никаких таймаутов: канонической рекомендации по
  keepalive для naive у апстрима просто нет.

## 7. HTTP/3: что нужно, если решим пробовать

Плагин h3 умеет на уровне кода: `forwardproxy.go:279` пропускает
`ProtoMajor == 3`, `:297` проверяет псевдо-хедеры для h2/h3, `:345-352`
обрабатывает `case 3` через `dualStream` с паддингом. Файл на нашем пине
и на HEAD ветки `naive` **побайтово идентичен**. Пересборка Caddy не нужна —
h3 уже включён по умолчанию.

Блокеры на нашей стороне:

1. **Открыть UDP/443 в UFW** (`install.sh:698-701`) — блокер №1.
2. **Выйти из режима общего 443.** Если на 443 живёт Reality-инбаунд, Caddy
   слушает `127.0.0.1:8443` (`caddy.py:315`), туда же уйдёт QUIC-сокет —
   снаружи недостижим. Reality проксирует только TCP, а `listener_wrappers`
   (proxy_protocol) к QUIC не применяются вовсе: `server.go:610` вызывает
   `addr.ListenQUIC(...)` напрямую. **h3 и shared-443 несовместимы.**
3. Поднять `net.core.rmem_max` / `wmem_max`, иначе quic-go предупреждает о
   недостаточном буфере.
4. Генератор ссылок отдаёт `naive+https://` (`app/api/clients.py:166`) —
   при переходе на h3 это нужно учесть.

**Но прежде чем это делать — см. §4 полного исследования в `Codex_connect`.**
Автор NaiveProxy удалил инструкцию по h3 из своего README в ноябре 2022 и
не вернул; в релизах плагина h3 не упоминается ни разу; единственная
документированная попытка включить `protocols h1 h2 h3` на Caddy 2.6.1 не
помогла. Код есть, работоспособность связки не доказана. **Шаг «проверить,
что CONNECT реально работает по h3» обязателен до любых правок клиента.**

Прочее по QUIC в Caddy 2.10.2: `QUICConfig` захардкожен
(`server.go:621-626` — только `Versions` и `Tracer`), JSON-ручек нет.
`h3server.IdleTimeout` берётся из того же `s.IdleTimeout`, но для QUIC это
`max_idle_timeout` на всё соединение.

## 8. Порядок действий

1. **`journalctl -u caddy`** — посчитать реальные reload против
   `config is unchanged`. Проверить watchdog (`proxy-panel-watchdog.sh`,
   cron каждые 2 минуты): если он регулярно рестартует панель, это прямой
   источник периодических разрывов. Стоит ноль, эффект может быть большим.
2. Два поля в `https_server`: `idle_timeout` и `keepalive_interval` (§5).
3. Полевая проверка UDP/443 и работоспособности CONNECT по h3 (§7) — до
   любых правок клиента.
