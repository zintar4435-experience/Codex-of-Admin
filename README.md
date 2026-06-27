# Codex-of-Admin — ProxyPanel

Веб-панель управления прокси-сервером (Xray + NaiveProxy через Caddy) для
VPS на Ubuntu 22.04 / 24.04 (x86_64): инбаунды, клиенты, лимиты трафика,
маршрутизация, подписки, 2FA.

---

## Установка и обновление одной командой

Выполните на сервере **от root**:

```bash
curl -fsSL https://raw.githubusercontent.com/zintar4435-experience/Codex-of-Admin/main/bootstrap.sh | sudo bash
```

Эта команда **сама определяет**, что делать:

| Состояние сервера | Что произойдёт |
|-------------------|----------------|
| Панель ещё не установлена | Полная установка с нуля (Xray, Caddy с NaiveProxy, панель, firewall) |
| Панель уже установлена | Обновление кода панели. **База данных и настройки сохраняются** |

Команду можно запускать повторно — она безопасна и при обновлении не
трогает `instance/panel.db`.

После установки панель доступна на `http://<IP-сервера>:5000` — зайдите,
укажите домен в настройках, и панель сама переедет на HTTPS.

### Дополнительные режимы (необязательно)

Чтобы при обновлении пересобрать и компоненты (Xray / Caddy), скачайте
скрипт и запустите с переменной `PP_MODE`:

```bash
curl -fsSL https://raw.githubusercontent.com/zintar4435-experience/Codex-of-Admin/main/bootstrap.sh -o bootstrap.sh
sudo PP_MODE=all bash bootstrap.sh      # обновить панель + Xray + Caddy
```

| Переменная | Значения | По умолчанию | Назначение |
|------------|----------|--------------|------------|
| `PP_MODE`  | `panel` · `xray` · `caddy` · `all` | `panel` | что обновлять у существующей установки |
| `PP_REF`   | ветка или тег | `main` | какую версию кода ставить |

---

## Проверка после установки

```bash
systemctl status proxy-panel proxy-panel-scheduler xray caddy
curl -sf http://127.0.0.1:5000/api/system/health
```

Все четыре сервиса должны быть `active (running)`, а healthcheck —
вернуть `{"status":"ok"}`.

Логи для диагностики:

```bash
journalctl -u proxy-panel  -n 100 --no-pager
journalctl -u xray         -n 100 --no-pager
journalctl -u caddy        -n 100 --no-pager
```

---

## Рекомендации по безопасности

После установки обязательно:

1. **Задайте надёжный пароль администратора** (не короче 10 символов).
2. **Включите двухфакторную аутентификацию (2FA)** в настройках панели —
   это самая важная защита от подбора пароля.
3. **Закройте порт 5000** после перехода на HTTPS:
   ```bash
   sudo ufw delete allow 5000/tcp
   ```
4. Если у провайдера есть облачный firewall — оставьте открытыми только
   `22` (SSH), `80` и `443`.

---

## Структура репозитория

| Путь | Назначение |
|------|------------|
| `bootstrap.sh` | единый загрузчик: установка или обновление одной командой |
| `proxy-panel-v11-stage2-4-uifix-FIXED8/` | исходный код панели |
| `proxy-panel-v11-stage2-4-uifix-FIXED8/install.sh` | установка с нуля |
| `proxy-panel-v11-stage2-4-uifix-FIXED8/update.sh` | обновление компонентов |
| `proxy-panel-v11-stage2-4-uifix-FIXED8/README.md` | подробная техническая документация и история изменений |

---

## Ручная установка (без загрузчика)

Если нужно поставить вручную из исходников:

```bash
git clone https://github.com/zintar4435-experience/Codex-of-Admin.git
cd Codex-of-Admin/proxy-panel-v11-stage2-4-uifix-FIXED8
sudo bash install.sh          # установка с нуля
# или
sudo bash update.sh panel     # обновление (БД сохраняется)
```
