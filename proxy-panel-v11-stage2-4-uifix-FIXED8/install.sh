#!/usr/bin/env bash
# ============================================================
# ProxyPanel — установочный скрипт (stage1-15)
# Ubuntu 22.04 / 24.04 x86_64
# Использование: sudo bash install.sh [--dry-run]
#
# Отличия от исходной версии:
#   1. Caddy собирается через xcaddy с НАСТОЯЩИМ NaiveProxy-форком
#      (github.com/klzgrad/forwardproxy), padding-заголовки клиента
#      Karing работают только с этим форком, не с caddyserver/forwardproxy.
#   2. Sanity-check перед rsync: скрипт сразу падает с понятным
#      сообщением, если запущен не из корня архива (т.е. рядом нет
#      requirements.txt / run.py / app/).
#   3. Defensive-check после rsync: убеждаемся, что ключевые файлы
#      реально оказались в /opt/proxy-panel, а не «потерялись».
#
# Stage1-14 (только NaiveProxy сборка, остальное без изменений):
#   - CADDY_VERSION понижена с v2.11.3 на v2.10.2: плагин называется
#     v2.10.0-naive (явный таргет на Caddy 2.10.x line) и не работает
#     с Caddy 2.11.x (там менялся caddyhttp request handling — см.
#     PR caddyserver/caddy#6961). На v2.11.x плагин загружается, но
#     в request chain не подключается — выдаёт NOP с status:0.
#   - Плагин forwardproxy теперь фиксирован на тэг v2.10.0-naive
#     вместо плавающего @naive (HEAD ветки).
#   - После сборки записывается /etc/caddy/.naive-build-info с
#     версиями Caddy / плагина / Go / временем сборки.
#
# Stage1-15 (фикс stage1-14):
#   - FORWARDPROXY_VERSION теперь полный commit hash вместо тэга.
#     Go-модули не принимают тэги "v2.x.y-*" для модулей без /v2
#     суффикса в module path — отказывались собирать stage1-14 с
#     ошибкой "version invalid: should be v0 or v1, not v2".
#     d62c80d3dd2c706b6b87579844d2397bddd18317 — это commit, на
#     который указывает тэг v2.10.0-naive. Контент тот же.
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Dry-run mode ──────────────────────────────────────────────
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

run() {
    if $DRY_RUN; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

download() {
    local url="$1" dest="$2"
    if $DRY_RUN; then
        echo "[dry-run] wget ${url} -> ${dest}"
        return
    fi
    wget --show-progress -q -O "${dest}" "${url}" \
        || error "Не удалось скачать ${url}. Проверьте сеть."
}

write_file() {
    local dest="$1"
    if $DRY_RUN; then
        echo "[dry-run] write ${dest}"
        cat > /dev/null
    else
        cat > "${dest}"
    fi
}

[[ $EUID -ne 0 ]] && error "Запустите скрипт от root: sudo bash install.sh"
[[ $(uname -m) != "x86_64" ]] && error "Поддерживается только x86_64"

# ── Версии компонентов (менять здесь при обновлении) ─────────
XRAY_VERSION="1.8.10"           # https://github.com/XTLS/Xray-core/releases
GO_VERSION="1.25.0"              # нужен для xcaddy
CADDY_VERSION="v2.10.2"          # последний hotfix в 2.10.x line
                                 # ВАЖНО: НЕ повышать до v2.11.x без
                                 # одновременной проверки совместимости с
                                 # FORWARDPROXY_VERSION. Плагин в наименовании
                                 # явно таргетит 2.10, в v2.11 ломается hijack
                                 # (см. комментарий в шапке файла).
FORWARDPROXY_VERSION="d62c80d3dd2c706b6b87579844d2397bddd18317"
                                 # Pin по commit hash, НЕ по тэгу.
                                 # Этот commit — содержимое релиза
                                 # v2.10.0-naive (от 2025-01-18).
                                 # ПОЧЕМУ ХЭШ, А НЕ ТЭГ: Go-модули
                                 # отказываются принимать тэги вида
                                 # v2.x.y-* для модулей, чей module path
                                 # не оканчивается на /v2 — major version
                                 # v2+ требует /v2 суффикс в импорт-пути.
                                 # klzgrad/forwardproxy этого суффикса не
                                 # имеет, поэтому `go get @v2.10.0-naive`
                                 # падает с "version invalid: should be
                                 # v0 or v1, not v2". При обращении по
                                 # commit hash Go major-version-check
                                 # пропускает и строит pseudo-version
                                 # v0.0.0-20250118002110-d62c80d3dd2c.

# ── Пути установки ────────────────────────────────────────────
PANEL_DIR="/opt/proxy-panel"
PANEL_USER="proxypanel"
CADDY_USER="caddy"
XRAY_USER="xray"
ENV_FILE="${PANEL_DIR}/instance/.env"

# ── 0. Sanity-check: install.sh запущен из корня архива ──────
# Делаем это в самом начале — до любых системных изменений.
# Иначе скрипт молча устанавливает Caddy/Xray и падает позже на pip.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for required in requirements.txt run.py app; do
    if [[ ! -e "${SCRIPT_DIR}/${required}" ]]; then
        error "В каталоге ${SCRIPT_DIR} отсутствует '${required}'.
Запустите install.sh из корня распакованного архива
(там должны лежать install.sh, run.py, requirements.txt и app/)."
    fi
done

# ── 1. Системные зависимости ──────────────────────────────────
info "Обновление пакетов..."
run apt-get update -qq
run apt-get install -y -qq \
    curl wget git unzip jq rsync \
    python3 python3-pip python3-venv \
    sqlite3 \
    ufw logrotate

# ── 2. Системные пользователи и директории ───────────────────
info "Создание системных пользователей..."
if ! $DRY_RUN; then
    id "${CADDY_USER}"  &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "${CADDY_USER}"
    id "${XRAY_USER}"   &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "${XRAY_USER}"
    id "${PANEL_USER}"  &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "${PANEL_USER}"
    # Панель читает логи Xray (/var/log/xray/*.log) — добавляем в группу xray
    usermod -aG "${XRAY_USER}" "${PANEL_USER}"
else
    echo "[dry-run] useradd --system ... ${CADDY_USER} ${XRAY_USER} ${PANEL_USER}"
    echo "[dry-run] usermod -aG ${XRAY_USER} ${PANEL_USER}"
fi

run mkdir -p /var/lib/caddy /home/proxypanel
run chown "${CADDY_USER}:${CADDY_USER}" /var/lib/caddy
run chown "${PANEL_USER}:${PANEL_USER}" /home/proxypanel
run chmod 750 /var/lib/caddy /home/proxypanel

# ── 3. Caddy + NaiveProxy ─────────────────────────────────────
info "Сборка Caddy с NaiveProxy форвард-прокси..."

# Caddy v2.9+ требует Go 1.24+. xcaddy тоже.
export PATH="/usr/local/go/bin:$PATH"

if ! command -v go &>/dev/null; then
    need_go=1
else
    current_go=$(go version 2>/dev/null | awk '{print $3}' | tr -d 'go')
    [[ "${current_go}" < "1.24" ]] && need_go=1 || need_go=0
fi

if [[ "${need_go:-0}" == "1" ]]; then
    info "Установка Go ${GO_VERSION} для сборки Caddy..."
    download "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" /tmp/go.tar.gz
    GO_SHA256_URL="https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz.sha256"
    download "${GO_SHA256_URL}" /tmp/go.tar.gz.sha256
    if ! $DRY_RUN; then
        echo "$(cat /tmp/go.tar.gz.sha256)  /tmp/go.tar.gz" | sha256sum --check \
            || error "Проверка SHA-256 для go.tar.gz не прошла. Прерываем установку."
        rm /tmp/go.tar.gz.sha256
    else
        echo "[dry-run] sha256sum --check /tmp/go.tar.gz"
    fi
    run rm -rf /usr/local/go
    run tar -C /usr/local -xzf /tmp/go.tar.gz
    run rm /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    run bash -c 'echo export PATH="/usr/local/go/bin:\$PATH" >> /etc/profile'
fi
if ! $DRY_RUN; then
    info "Go: $(go version)"
fi

# Собираем Caddy через xcaddy с klzgrad/forwardproxy по commit hash.
# ── Почему именно так ──
# Исходный install.sh пытался "go get github.com/caddyserver/forwardproxy
# @v0.0.0-20250118002110-d62c80d3dd2c" — но этот pseudo-version указывает
# на коммит из репозитория github.com/klzgrad/forwardproxy, а не из
# caddyserver/forwardproxy. Поэтому загрузка падала с "unknown revision".
# Замена на @latest "лечит" сборку, но даёт официальный caddy-форк БЕЗ
# padding-заголовков NaiveProxy — клиент Karing с таким сервером не
# работает (он ждёт именно naive-протокол).
# Правильный путь — собрать caddy через xcaddy, заменив импорт
# caddyserver/forwardproxy на klzgrad/forwardproxy по commit hash:
# его Go modules принимает без проверки major-version, в отличие от
# semver-тэга вида v2.10.0-naive (см. шапку файла).
info "Сборка caddy ${CADDY_VERSION} с NaiveProxy плагином (commit ${FORWARDPROXY_VERSION:0:12}, 2-5 мин)..."
if ! $DRY_RUN; then
    info "Установка xcaddy..."
    GOBIN=/usr/local/bin /usr/local/go/bin/go install \
        github.com/caddyserver/xcaddy/cmd/xcaddy@latest \
        || error "Не удалось установить xcaddy. Проверьте сеть и доступность proxy.golang.org."

    BUILD_DIR=$(mktemp -d)
    cd "${BUILD_DIR}"
    HOME=/root /usr/local/bin/xcaddy build "${CADDY_VERSION}" \
        --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@${FORWARDPROXY_VERSION} \
        --output /usr/local/bin/caddy \
        || error "Не удалось собрать Caddy ${CADDY_VERSION} с NaiveProxy форком (klzgrad/forwardproxy@${FORWARDPROXY_VERSION})."
    cd /root
    rm -rf "${BUILD_DIR}"
else
    echo "[dry-run] xcaddy build ${CADDY_VERSION} --with forwardproxy=klzgrad/forwardproxy@${FORWARDPROXY_VERSION}"
fi

run setcap cap_net_bind_service=+ep /usr/local/bin/caddy

run mkdir -p /etc/caddy /var/log/caddy /etc/ssl/caddy
run chown -R "${CADDY_USER}:${CADDY_USER}" /etc/caddy /var/log/caddy /etc/ssl/caddy

# Начальный Caddyfile (панель перейдёт на JSON API)
write_file /etc/caddy/Caddyfile <<'EOF'
{
  admin localhost:2019
  email placeholder@change.me
}
# Панель настроит домены через API
EOF

if ! $DRY_RUN; then
    caddy fmt --overwrite /etc/caddy/Caddyfile 2>/dev/null || true
fi

# systemd unit
write_file /etc/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy Web Server
After=network.target

[Service]
User=caddy
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535
Environment=HOME=/var/lib/caddy

[Install]
WantedBy=multi-user.target
EOF

run systemctl daemon-reload
run systemctl enable caddy
run systemctl restart caddy
if ! $DRY_RUN; then
    info "Caddy установлен: $(caddy version)"
    # Проверка: убеждаемся, что в собранном Caddy есть NaiveProxy модуль
    if ! caddy list-modules 2>/dev/null | grep -q "http.handlers.forward_proxy"; then
        warn "В собранном Caddy нет модуля forward_proxy. NaiveProxy работать НЕ будет."
    else
        info "Модуль http.handlers.forward_proxy на месте."
        # Логируем реальную (псевдо-)версию плагина — полезно для отладки.
        # `caddy list-modules --versions` показывает строку вида
        #   http.handlers.forward_proxy v0.0.0-20250118002110-d62c80d3dd2c
        # — то есть commit hash и дату. Если эта дата отстаёт от тэга
        # v2.10.0-naive, значит мы тащим не то что хотели (см. xcaddy build).
        fp_ver=$(caddy list-modules --versions 2>/dev/null \
                 | awk '/http\.handlers\.forward_proxy/ {print $2}')
        info "forward_proxy: ${fp_ver:-неизвестна}"
        # Маркер-файл с метаданными сборки. На него ссылаются README и
        # update.sh при сравнении «что было / что стало».
        cat > /etc/caddy/.naive-build-info <<NAIVEINFO
caddy_version=${CADDY_VERSION}
forwardproxy_pin=${FORWARDPROXY_VERSION}
forwardproxy_runtime=${fp_ver:-unknown}
go_version=$(go version 2>/dev/null | awk '{print $3}')
built_at=$(date -Iseconds)
NAIVEINFO
        chmod 644 /etc/caddy/.naive-build-info
        chown "${CADDY_USER}:${CADDY_USER}" /etc/caddy/.naive-build-info
    fi
fi

# ── 3. Xray ───────────────────────────────────────────────────
info "Установка Xray ${XRAY_VERSION}..."
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"
download "${XRAY_URL}" /tmp/xray.zip
run unzip -o /tmp/xray.zip -d /tmp/xray \
    || error "Не удалось распаковать /tmp/xray.zip."
run install -m 755 /tmp/xray/xray /usr/local/bin/xray
run rm -rf /tmp/xray /tmp/xray.zip

run mkdir -p /usr/local/share/xray
download "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" \
    /usr/local/share/xray/geoip.dat
download "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" \
    /usr/local/share/xray/geosite.dat

run mkdir -p /etc/xray /var/log/xray
write_file /etc/xray/config.json <<'EOF'
{
  "log": {"loglevel": "warning", "error": "/var/log/xray/error.log"},
  "inbounds": [],
  "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
  "routing": {"rules": []}
}
EOF

run setcap cap_net_bind_service=+ep /usr/local/bin/xray
run chown -R "${XRAY_USER}:${PANEL_USER}" /etc/xray
run chmod -R 775 /etc/xray
run chown -R "${XRAY_USER}:${XRAY_USER}" /var/log/xray
run chmod -R 750 /var/log/xray

write_file /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network.target

[Service]
User=xray
ExecStart=/usr/local/bin/xray run -c /etc/xray/config.json
# ExecReload намеренно НЕ задаём. Xray-core не умеет hot-reload по
# SIGHUP — он молча умирает. Если бы здесь стоял
# `ExecReload=/bin/kill -HUP $MAINPID`, любой systemctl reload xray
# (включая `reload-or-restart`) убивал бы Xray «чисто» и Restart=
# не срабатывал. Без ExecReload `systemctl reload` корректно
# отваливается на restart.
# Restart=always (не on-failure!): если по любой причине Xray
# завершится — clean exit, kill -9 кем-то снаружи, OOM, systemctl
# reload (legacy) — systemd поднимет его заново. Конкретно для
# не-failure exits старый Restart=on-failure НЕ срабатывал.
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

run systemctl daemon-reload
run systemctl enable xray
run systemctl restart xray
if ! $DRY_RUN; then
    info "Xray установлен: $(xray version | head -1)"
fi

# ── 4. Updater-скрипт для Xray ───────────────────────────────
info "Установка xray-update.sh..."
write_file /usr/local/bin/xray-update.sh <<'UPDATER'
#!/usr/bin/env bash
# Вызывается панелью через sudo: xray-update.sh <version>
set -euo pipefail

VERSION="${1:-}"
[[ -z "${VERSION}" ]] && { echo "Использование: xray-update.sh <version>"; exit 1; }

XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v${VERSION}/Xray-linux-64.zip"
XRAY_SHA256_URL="https://github.com/XTLS/Xray-core/releases/download/v${VERSION}/Xray-linux-64.zip.sha256sum"

echo "Скачивание Xray v${VERSION}..."
wget -q -O /tmp/xray-upd.zip          "${XRAY_URL}"       || { echo "Ошибка загрузки архива"; exit 1; }
if wget -q -O /tmp/xray-upd.zip.sha256sum "${XRAY_SHA256_URL}" 2>/dev/null; then
    ( cd /tmp && sha256sum --check <(sed 's|Xray-linux-64.zip|/tmp/xray-upd.zip|' xray-upd.zip.sha256sum) ) \
        || { echo "Проверка SHA-256 не прошла"; rm -f /tmp/xray-upd.zip /tmp/xray-upd.zip.sha256sum; exit 1; }
    rm /tmp/xray-upd.zip.sha256sum
else
    echo "Предупреждение: SHA-256 для v${VERSION} недоступен, проверка пропущена"
    rm -f /tmp/xray-upd.zip.sha256sum
fi

unzip -q -o /tmp/xray-upd.zip -d /tmp/xray-upd
systemctl stop xray
install -m 755 /tmp/xray-upd/xray /usr/local/bin/xray
setcap cap_net_bind_service=+ep /usr/local/bin/xray
rm -rf /tmp/xray-upd /tmp/xray-upd.zip
systemctl start xray

echo "Xray обновлён до v${VERSION}"
UPDATER
run chmod 755 /usr/local/bin/xray-update.sh
run chown root:root /usr/local/bin/xray-update.sh

# ── Cert-bridge: сертификаты Caddy → Xray ────────────────────
# Xray-инбаунд с TLS (Trojan/VLESS+TLS) не может читать сертификаты Caddy
# напрямую (600 caddy:caddy). Этот скрипт копирует их в /etc/xray/certs/
# с правами 640 root:xray. Запускается по cron.daily (продление) и панелью
# через sudo при создании TLS-инбаунда.
info "Установка cert-bridge (сертификаты Caddy → Xray)..."
run mkdir -p /etc/xray/certs
run chown root:"${XRAY_USER}" /etc/xray/certs
run chmod 750 /etc/xray/certs

write_file /usr/local/bin/xray-cert-sync.sh <<'CERTSYNC'
#!/usr/bin/env bash
# Копирует TLS-сертификаты, выпущенные Caddy (Let's Encrypt), в читаемое
# Xray место: /etc/xray/certs/<domain>/{cert.pem,key.pem} (640 root:xray).
set -euo pipefail
CADDY_CERTS="${CADDY_CERTS_DIR:-/var/lib/caddy/.local/share/caddy/certificates}"
XRAY_CERTS="${XRAY_CERTS_DIR:-/etc/xray/certs}"
CERT_GROUP="${XRAY_CERT_GROUP:-xray}"
[[ -d "$CADDY_CERTS" ]] || { echo "Caddy cert storage не найден: $CADDY_CERTS"; exit 0; }
mkdir -p "$XRAY_CERTS"
shopt -s nullglob
synced=0
for cadir in "$CADDY_CERTS"/*/; do
  for domdir in "$cadir"*/; do
    domain="$(basename "$domdir")"
    crt="$domdir$domain.crt"; key="$domdir$domain.key"
    [[ -f "$crt" && -f "$key" ]] || continue
    dst="$XRAY_CERTS/$domain"; mkdir -p "$dst"
    if getent group "$CERT_GROUP" >/dev/null 2>&1; then
      install -m 640 -o root -g "$CERT_GROUP" "$crt" "$dst/cert.pem"
      install -m 640 -o root -g "$CERT_GROUP" "$key" "$dst/key.pem"
    else
      install -m 640 "$crt" "$dst/cert.pem"; install -m 640 "$key" "$dst/key.pem"
    fi
    synced=$((synced+1))
  done
done
echo "xray-cert-sync: synced ${synced} cert(s) into ${XRAY_CERTS}"
CERTSYNC
run chmod 755 /usr/local/bin/xray-cert-sync.sh
run chown root:root /usr/local/bin/xray-cert-sync.sh

write_file /etc/cron.daily/proxy-panel-cert-sync <<'EOF'
#!/bin/bash
# Ежедневно подхватываем продлённые сертификаты Caddy для Xray-инбаундов.
/usr/local/bin/xray-cert-sync.sh >/dev/null 2>&1 || true
EOF
run chmod +x /etc/cron.daily/proxy-panel-cert-sync

write_file /etc/sudoers.d/proxypanel-xray-update <<SUDOERS
# Позволяет сервису панели обновлять Xray через веб-интерфейс.
${PANEL_USER} ALL=(root) NOPASSWD: /usr/local/bin/xray-update.sh
${PANEL_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl reload-or-restart xray
${PANEL_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl reload-or-restart caddy
${PANEL_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl reload-or-restart proxy-panel
${PANEL_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl restart xray
${PANEL_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl restart caddy
${PANEL_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl restart proxy-panel
${PANEL_USER} ALL=(root) NOPASSWD: /usr/sbin/ufw delete allow 5000/tcp
# Cert-bridge: панель просит скопировать сертификаты Caddy в читаемое Xray
# место при создании TLS-инбаунда (Trojan/VLESS+TLS). Скрипт root-owned,
# без аргументов, только копирует cert/key — менять ничего не может.
${PANEL_USER} ALL=(root) NOPASSWD: /usr/local/bin/xray-cert-sync.sh
# Read-only: панель показывает в UI, какие порты открыты в UFW при
# создании/редактировании инбаунда. Только read-команды, никаких
# allow/delete — менять файрвол должен админ руками (см. README).
${PANEL_USER} ALL=(root) NOPASSWD: /usr/sbin/ufw status
${PANEL_USER} ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose
SUDOERS
run chmod 440 /etc/sudoers.d/proxypanel-xray-update
run visudo -c -f /etc/sudoers.d/proxypanel-xray-update \
    || { rm -f /etc/sudoers.d/proxypanel-xray-update; error "Ошибка синтаксиса sudoers-файла"; }

# ── Сторож (watchdog): авто-восстановление панели ────────────
# Раз в 2 минуты проверяет здоровье сервисов и панели. При реальном сбое
# (сервис упал, gunicorn завис, Caddy потерял runtime-конфиг в HTTPS-режиме)
# перезапускает proxy-panel — панель заново пушит конфиг в Caddy. Есть
# cooldown и перепроверки, чтобы не зациклиться и не реагировать на «моргание».
info "Установка сторожа (авто-восстановление)..."
write_file /usr/local/bin/proxy-panel-watchdog.sh <<'WATCHDOG'
#!/usr/bin/env bash
# Сторож панели: раз в ~2 минуты (cron.d) проверяет здоровье и при реальном
# сбое восстанавливает. Запускается root'ом. Команды переопределяемы env
# (для тестов). Не трогает ничего, если всё в порядке.
set -uo pipefail

SYSTEMCTL="${WD_SYSTEMCTL:-systemctl}"
CURL="${WD_CURL:-curl}"
STATE="${WD_STATE:-/var/lib/proxy-panel/watchdog.state}"
ENV_FILE="${WD_ENV_FILE:-/opt/proxy-panel/instance/.env}"
LOG="${WD_LOG:-/var/log/proxy-panel-watchdog.log}"
COOLDOWN="${WD_COOLDOWN:-300}"
HEALTH_URL="http://127.0.0.1:5000/api/system/health"
CADDY_CFG_URL="http://127.0.0.1:2019/config/"

log(){ echo "$(date -Is) $*" >> "$LOG" 2>/dev/null || true; command -v logger >/dev/null 2>&1 && logger -t proxy-panel-watchdog "$*" || true; }
mkdir -p "$(dirname "$STATE")" 2>/dev/null || true

now=$(date +%s)
last=0; [[ -f "$STATE" ]] && last=$(cat "$STATE" 2>/dev/null || echo 0)
cooldown_active(){ (( now - last < COOLDOWN )); }

restart_panel(){  # минимальное восстановление: панель заново пушит конфиг в Caddy
  if cooldown_active; then log "проблема [$1], но cooldown ($(( COOLDOWN-(now-last) ))с) — пропуск"; return 1; fi
  echo "$now" > "$STATE"
  log "ВОССТАНОВЛЕНИЕ [$1]: restart proxy-panel"
  $SYSTEMCTL restart proxy-panel 2>/dev/null || true
  $SYSTEMCTL start proxy-panel-scheduler 2>/dev/null || true
  return 0
}

svc_active(){ $SYSTEMCTL is-active "$1" --quiet 2>/dev/null; }
svc_enabled(){ $SYSTEMCTL is-enabled "$1" --quiet 2>/dev/null; }
panel_healthy(){ $CURL -m 5 -sf "$HEALTH_URL" >/dev/null 2>&1; }

# 1) Включённый сервис не активен → поднять (с перепроверкой на «моргание»).
for svc in xray caddy proxy-panel proxy-panel-scheduler; do
  if svc_enabled "$svc" && ! svc_active "$svc"; then
    sleep 6
    svc_active "$svc" && continue     # само поднялось — это было «моргание»
    if cooldown_active; then log "$svc не активен, но cooldown — пропуск"; exit 0; fi
    echo "$now" > "$STATE"
    log "ВОССТАНОВЛЕНИЕ: сервис $svc не активен → start"
    $SYSTEMCTL start "$svc" 2>/dev/null || true
    exit 0
  fi
done

# 2) Панель не отвечает локально (gunicorn завис) → restart panel.
if ! panel_healthy; then
  sleep 8
  panel_healthy && exit 0            # транзиентно — игнор
  restart_panel "панель не отвечает /health"; exit 0
fi

# 3) HTTPS-режим, но Caddy потерял runtime-конфиг (нет https-routes) → re-push.
https_on="false"
[[ -f "$ENV_FILE" ]] && grep -qi '^HTTPS_ENABLED=true' "$ENV_FILE" && https_on="true"
if [[ "$https_on" == "true" ]]; then
  cfg=$($CURL -m 5 -s "$CADDY_CFG_URL" 2>/dev/null || echo "")
  if [[ -n "$cfg" ]]; then
    routes="?"
    if command -v jq >/dev/null 2>&1; then
      routes=$(echo "$cfg" | jq -r '((.apps.http.servers.https.routes)//[])|length' 2>/dev/null || echo "?")
    else
      echo "$cfg" | grep -q '"routes"' && routes=1 || routes=0
    fi
    if [[ "$routes" == "0" ]]; then
      sleep 6
      cfg2=$($CURL -m 5 -s "$CADDY_CFG_URL" 2>/dev/null || echo "")
      echo "$cfg2" | grep -q '"routes"' && exit 0   # появилось — игнор
      restart_panel "Caddy без https-routes (потерян конфиг)"; exit 0
    fi
  fi
fi
exit 0
WATCHDOG
run chmod 755 /usr/local/bin/proxy-panel-watchdog.sh
run chown root:root /usr/local/bin/proxy-panel-watchdog.sh

write_file /etc/cron.d/proxy-panel-watchdog <<'EOF'
# Сторож панели: авто-восстановление при сбоях. Каждые 2 минуты, от root.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/2 * * * * root /usr/local/bin/proxy-panel-watchdog.sh >/dev/null 2>&1
EOF
run chmod 644 /etc/cron.d/proxy-panel-watchdog
run chown root:root /etc/cron.d/proxy-panel-watchdog

# ── 5. Панель ────────────────────────────────────────────────
info "Установка ProxyPanel..."

# SCRIPT_DIR уже определён в шаге 0 (вместе с sanity-check).
# Копируем файлы через rsync. Добавлен exclude='venv/' — на случай,
# если в исходной директории осталась venv от прошлой неудачной попытки.
run mkdir -p "${PANEL_DIR}"
run rsync -a \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.bak' \
    --exclude='patch_v*.sh' \
    --exclude='instance/' \
    --exclude='venv/' \
    "${SCRIPT_DIR}/" "${PANEL_DIR}/"

# Defensive: убеждаемся, что rsync действительно перенёс ключевые файлы.
# Если их нет — выходим с понятным сообщением (а не падаем позже на pip).
if ! $DRY_RUN; then
    for required in requirements.txt run.py app/__init__.py; do
        if [[ ! -e "${PANEL_DIR}/${required}" ]]; then
            error "После rsync в ${PANEL_DIR} нет '${required}'.
Проверьте, что rsync отработал корректно и что в ${SCRIPT_DIR}/
лежит полный набор файлов архива."
        fi
    done
fi

run chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"

# Python venv. Удаляем старый venv перед созданием — гарантия чистой
# установки зависимостей, если предыдущий запуск install.sh упал
# на середине и оставил битый venv.
run rm -rf "${PANEL_DIR}/venv"
run python3 -m venv "${PANEL_DIR}/venv"
run "${PANEL_DIR}/venv/bin/pip" install -q --upgrade pip
run "${PANEL_DIR}/venv/bin/pip" install -q -r "${PANEL_DIR}/requirements.txt" gunicorn

# instance dir
run mkdir -p "${PANEL_DIR}/instance"
run chown "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}/instance"

# Сгенерировать SECRET_KEY и записать в .env
if ! $DRY_RUN; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > "${ENV_FILE}" <<EOF
SECRET_KEY=${SECRET_KEY}
HTTPS_ENABLED=false
EOF
    chmod 600 "${ENV_FILE}"
    chown "${PANEL_USER}:${PANEL_USER}" "${ENV_FILE}"
    echo "${SECRET_KEY}" > "${PANEL_DIR}/instance/.secret_key"
    chmod 600 "${PANEL_DIR}/instance/.secret_key"
    chown "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}/instance/.secret_key"
else
    echo "[dry-run] write ${ENV_FILE} (SECRET_KEY=<random_hex_32>, HTTPS_ENABLED=false)"
    echo "[dry-run] chmod 600 ${ENV_FILE}"
    echo "[dry-run] chown ${PANEL_USER}:${PANEL_USER} ${ENV_FILE}"
fi

run chown root:"${PANEL_USER}" /usr/local/bin /usr/local/share/xray
run chmod 775 /usr/local/bin /usr/local/share/xray

# systemd unit для панели
if ! $DRY_RUN; then
    cat > /etc/systemd/system/proxy-panel.service <<EOF
[Unit]
Description=ProxyPanel
After=network.target xray.service caddy.service

[Service]
User=${PANEL_USER}
WorkingDirectory=${PANEL_DIR}
Environment=HOME=/home/proxypanel
EnvironmentFile=${ENV_FILE}
ExecStartPre=+/bin/chown -R ${PANEL_USER}:${PANEL_USER} ${PANEL_DIR}/instance
ExecStart=/bin/sh -c 'exec ${PANEL_DIR}/venv/bin/gunicorn --bind "\$\${GUNICORN_BIND:-0.0.0.0:5000}" --workers 2 --threads 4 --timeout 30 run:app'
ExecStartPost=/bin/sh -c 'for i in 1 2 3 4 5; do curl -sf http://127.0.0.1:5000/api/system/health && exit 0; sleep 2; done; exit 1'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
else
    echo "[dry-run] write /etc/systemd/system/proxy-panel.service"
fi

run systemctl daemon-reload
run systemctl enable proxy-panel

# systemd unit для фонового шедулера
if ! $DRY_RUN; then
    cat > /etc/systemd/system/proxy-panel-scheduler.service <<EOF
[Unit]
Description=ProxyPanel Background Scheduler
After=network.target proxy-panel.service xray.service caddy.service
Wants=proxy-panel.service

[Service]
User=${PANEL_USER}
WorkingDirectory=${PANEL_DIR}
Environment=HOME=/home/proxypanel
EnvironmentFile=${ENV_FILE}
ExecStart=${PANEL_DIR}/venv/bin/python run.py --scheduler
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
else
    echo "[dry-run] write /etc/systemd/system/proxy-panel-scheduler.service"
fi

run systemctl daemon-reload
run systemctl enable proxy-panel-scheduler

# ── 6. Firewall ───────────────────────────────────────────────
info "Настройка UFW..."
run ufw --force reset
run ufw default deny incoming
run ufw default allow outgoing
run ufw allow ssh
run ufw allow 80/tcp
run ufw allow 443/tcp
run ufw allow 5000/tcp  # temporary for initial setup
run ufw --force enable
info "UFW настроен"

# ── 7. Logrotate ─────────────────────────────────────────────
write_file /etc/logrotate.d/xray <<'EOF'
/var/log/xray/*.log {
    daily
    missingok
    rotate 7
    compress
    notifempty
    create 640 xray xray
    postrotate
        systemctl reload xray 2>/dev/null || true
    endscript
}
EOF

write_file /etc/logrotate.d/caddy <<'EOF'
/var/log/caddy/*.log {
    daily
    missingok
    rotate 14
    compress
    notifempty
    # copytruncate: копирует файл и обрезает оригинал на месте.
    # Caddy сохраняет открытый file handle на /var/log/caddy/*.log,
    # поэтому НЕ нужен reload. Раньше использовался postrotate с
    # `systemctl reload caddy` — это ломало панель раз в сутки:
    # caddy reload перечитывал минимальный /etc/caddy/Caddyfile (там
    # только admin endpoint), runtime-конфиг панели из памяти исчезал,
    # HTTPS-серверы на :443 переставали слушать.
    # Минимальный недостаток copytruncate — окно в долю секунды между
    # copy и truncate, в которое записи могут быть потеряны.
    # Для access-логов это допустимо.
    copytruncate
}
EOF

# ── 8. Резервное копирование БД (cron) ───────────────────────
write_file /etc/cron.daily/proxy-panel-backup <<'EOF'
#!/bin/bash
BACKUP_DIR="/opt/proxy-panel/instance/backups"
DB="/opt/proxy-panel/instance/panel.db"
mkdir -p "$BACKUP_DIR"
sqlite3 "$DB" ".backup $BACKUP_DIR/panel-$(date +%Y%m%d).db"
ls -t "$BACKUP_DIR"/panel-*.db | tail -n +8 | xargs -r rm
EOF
run chmod +x /etc/cron.daily/proxy-panel-backup

# ── 9. Создать первого админа ─────────────────────────────────
if ! $DRY_RUN; then
    info "Инициализация БД и создание администратора..."
    if ! su -s /bin/bash "${PANEL_USER}" -c \
        "export HOME=/home/proxypanel; cd '${PANEL_DIR}' && '${PANEL_DIR}/venv/bin/python' run.py --create-admin"; then
        warn "su не сработал — запуск от root, права будут исправлены chown'ом"
        cd "${PANEL_DIR}"
        "${PANEL_DIR}/venv/bin/python" run.py --create-admin
    fi

    chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}/instance"
    chmod 750 "${PANEL_DIR}/instance"
    find "${PANEL_DIR}/instance" -maxdepth 1 -name "panel.db*" -exec chmod 640 {} \;

    info "Запуск сервиса панели..."
    systemctl start proxy-panel
    info "Запуск шедулера..."
    systemctl start proxy-panel-scheduler
else
    echo "[dry-run] ${PANEL_DIR}/venv/bin/python run.py --create-admin"
    echo "[dry-run] systemctl start proxy-panel"
    echo "[dry-run] systemctl start proxy-panel-scheduler"
fi

# ── 10. Итог ───────────────────────────────────────────────────
if ! $DRY_RUN; then
    all_ok=true
    for svc in xray caddy proxy-panel proxy-panel-scheduler; do
        if ! systemctl is-active --quiet "$svc"; then
            warn "Сервис $svc не запущен. Проверьте: journalctl -u $svc"
            all_ok=false
        fi
    done
    $all_ok && info "Все сервисы работают"
else
    info "Dry-run завершён. Реальных изменений не внесено."
fi

echo ""
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
SERVER_IP=${SERVER_IP:-"<ваш-IP>"}
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ProxyPanel установлен!                  ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Панель доступна на:  http://${SERVER_IP}:5000      ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  UFW уже открыл порт 5000 для первоначальной       ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  настройки. После привязки домена закройте его:    ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}    ufw delete allow 5000/tcp                       ${GREEN}║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Следующие шаги:                                   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  1. Зайдите в панель, укажите домен в Настройках   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  2. Создайте первый Inbound                        ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  3. Добавьте клиентов и скопируйте ссылки          ${GREEN}║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  systemctl status proxy-panel                      ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  systemctl status xray                             ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  systemctl status caddy                            ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
