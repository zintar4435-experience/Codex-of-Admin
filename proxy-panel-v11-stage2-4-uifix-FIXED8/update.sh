#!/usr/bin/env bash
# ============================================================
# ProxyPanel — скрипт обновления компонентов (stage1-15)
# Использование: sudo bash update.sh [xray|caddy|panel|all]
#
# Отличия от исходной версии:
#   1. Caddy пересобирается через xcaddy с настоящим NaiveProxy-форком
#      (github.com/klzgrad/forwardproxy), а не официальным
#      caddyserver/forwardproxy. См. комментарий в install.sh.
#   2. update_panel() — sanity-check перед rsync (требует наличия
#      requirements.txt / run.py / app/ рядом с update.sh).
#
# Stage1-14 (только NaiveProxy сборка, остальное без изменений):
#   - CADDY_VERSION понижена с v2.11.3 на v2.10.2.
#   - update_caddy() записывает /etc/caddy/.naive-build-info с
#     версиями для отладки. Печатает "было → стало" если файл уже есть.
#
# Stage1-15 (фикс stage1-14):
#   - FORWARDPROXY_VERSION теперь полный commit hash вместо тэга
#     v2.10.0-naive. Go-модули не принимают тэги "v2.x.y-*" для
#     модулей без /v2 в module path; та же сборка по hash работает.
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Запустите от root: sudo bash update.sh [xray|caddy|panel|all]"

usage() {
    echo "Использование: sudo bash update.sh [xray|caddy|panel|all]"
    exit 1
}

[[ $# -eq 0 ]] && usage

# ── Версии компонентов (менять здесь при обновлении) ─────────
XRAY_VERSION="1.8.10"          # https://github.com/XTLS/Xray-core/releases
GO_VERSION="1.25.0"             # нужен только для пересборки Caddy
CADDY_VERSION="v2.10.2"         # последний hotfix в 2.10.x line
                                # ВАЖНО: НЕ повышать до v2.11.x без
                                # одновременной проверки совместимости с
                                # FORWARDPROXY_VERSION. См. шапку install.sh.
FORWARDPROXY_VERSION="d62c80d3dd2c706b6b87579844d2397bddd18317"
                                # Commit hash, к которому привязан тэг
                                # v2.10.0-naive. Pin по hash, не по тэгу:
                                # Go-модули отказываются собирать модули
                                # без /v2 суффикса по тэгам "v2.x.y-*"
                                # (подробнее в шапке install.sh).

# ── Пути установки ────────────────────────────────────────────
PANEL_DIR="/opt/proxy-panel"
PANEL_USER="proxypanel"
ENV_FILE="${PANEL_DIR}/instance/.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─────────────────────────────────────────────────────────────
# ensure_xray_service_unit_safe — чинит /etc/systemd/system/xray.service
# у старых установок, в которых:
#   - ExecReload=/bin/kill -HUP $MAINPID  → Xray не умеет HUP-reload,
#     процесс молча умирал при `systemctl reload-or-restart xray` и
#     дальше не поднимался, потому что Restart=on-failure clean-exit
#     не ловит. Симптом: после любой смены конфига Xray мёртв, порт
#     не слушает, клиенты получают timeout.
#   - Restart=on-failure → не покрывает clean-exits. Меняем на always.
# Идемпотентно. Если xray в момент миграции был мёртв (как раз из-за
# этого бага) — поднимаем.
# ─────────────────────────────────────────────────────────────
ensure_xray_service_unit_safe() {
    local unit="/etc/systemd/system/xray.service"
    [[ -f "${unit}" ]] || return 0
    # Уже починено?
    if ! grep -q "ExecReload=" "${unit}" && grep -q "^Restart=always" "${unit}"; then
        return 0
    fi
    info "Обновление ${unit}: убираем ExecReload (Xray не поддерживает HUP) + Restart=always..."
    cp -p "${unit}" "${unit}.before-fix-reload" 2>/dev/null || true
    # Полная перезапись (содержание короткое, проще чем sed-патчить).
    cat > "${unit}" <<'XRAY_UNIT'
[Unit]
Description=Xray Service
After=network.target

[Service]
User=xray
ExecStart=/usr/local/bin/xray run -c /etc/xray/config.json
# ExecReload намеренно отсутствует — см. комментарий в install.sh.
# Tl;dr: Xray не умеет hot-reload по SIGHUP, поэтому единственный
# корректный способ применить новый конфиг — systemctl restart.
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
XRAY_UNIT
    chmod 644 "${unit}"
    systemctl daemon-reload

    # Если Xray в данный момент мёртв (типичная ситуация для тех, кого
    # этот баг укусил) и enabled — поднимаем сразу.
    if systemctl is-enabled xray --quiet 2>/dev/null \
       && ! systemctl is-active xray --quiet 2>/dev/null; then
        info "  ✓ Xray был остановлен, поднимаю с новой политикой Restart=always..."
        systemctl start xray || warn "Не удалось стартовать xray, проверьте journalctl -u xray"
    fi
    info "  ✓ Юнит-файл xray.service починен"
}

# ─────────────────────────────────────────────────────────────
# ensure_panel_ufw_sudoers — добавляет в /etc/sudoers.d/proxypanel-xray-update
# read-only права на `ufw status`/`ufw status verbose`, если их там ещё нет.
# Нужно для фичи «панель показывает в UI, какие порты открыты в UFW при
# создании инбаунда». Только чтение, никакого allow/delete.
# Идемпотентно — если строки уже есть, ничего не делает.
# ─────────────────────────────────────────────────────────────
ensure_panel_ufw_sudoers() {
    local sudoers="/etc/sudoers.d/proxypanel-xray-update"
    # Если самого файла нет — установка нетипична, не лезем (фикс к этой
    # установке не применяется — у юзера должно было быть всё сделано
    # руками или старым install.sh).
    [[ -f "${sudoers}" ]] || return 0
    # Уже добавлено?
    if grep -q "/usr/sbin/ufw status" "${sudoers}"; then
        return 0
    fi
    info "Добавляем read-only права на 'ufw status' в sudoers (для UI-индикатора файрвола)..."
    # Бэкап перед изменением.
    cp -p "${sudoers}" "${sudoers}.before-ufw-status" 2>/dev/null || true
    # Подставляем PANEL_USER из текущего файла (на случай нестандартного юзера).
    local panel_user
    panel_user=$(awk -F'[[:space:]]+' '/NOPASSWD:/ {print $1; exit}' "${sudoers}")
    if [[ -z "${panel_user}" ]]; then
        warn "Не смог определить PANEL_USER из ${sudoers}; пропускаем."
        return 0
    fi
    cat >> "${sudoers}" <<EOF
# Read-only: панель показывает в UI, какие порты открыты в UFW при
# создании/редактировании инбаунда. Только read-команды, никаких
# allow/delete — менять файрвол должен админ руками (см. README).
${panel_user} ALL=(root) NOPASSWD: /usr/sbin/ufw status
${panel_user} ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose
EOF
    chmod 440 "${sudoers}"
    if ! visudo -c -f "${sudoers}" >/dev/null 2>&1; then
        warn "Синтаксис sudoers после добавления невалиден, откатываемся."
        mv -f "${sudoers}.before-ufw-status" "${sudoers}"
        return 1
    fi
    info "  ✓ ufw status разрешён для ${panel_user}"
}

# ─────────────────────────────────────────────────────────────
# ensure_caddy_logrotate_safe — гарантирует, что
# /etc/logrotate.d/caddy использует copytruncate, а не reload.
# Идемпотентно — повторные вызовы ничего не делают, если файл
# уже корректный.
#
# Важный нюанс (исправлено в stage1-12). Прошлая версия этой
# функции писала бэкап как /etc/logrotate.d/caddy.before-copytruncate
# — НО logrotate читает ВСЕ файлы в /etc/logrotate.d/ независимо от
# имени, и видя два правила для одного /var/log/caddy/access.log
# (текущее + бэкап) отказывался работать с ошибкой
# "duplicate log entry". В результате logrotate-сервис падал каждую
# ночь, логи Caddy накапливались без ротации. Теперь бэкапы кладём в
# /var/lib/proxy-panel/migrations/ — отдельная директория, logrotate
# туда не смотрит.
# ─────────────────────────────────────────────────────────────
ensure_caddy_logrotate_safe() {
    local target="/etc/logrotate.d/caddy"
    local backup_dir="/var/lib/proxy-panel/migrations"
    [[ -f "${target}" ]] || return 0

    # Уборка артефакта старой миграции, если он есть. До stage1-12 бэкап
    # сохранялся прямо в /etc/logrotate.d/caddy.before-copytruncate, что
    # ломало logrotate. Если такой файл есть — переносим в safe-место.
    if [[ -f "/etc/logrotate.d/caddy.before-copytruncate" ]]; then
        mkdir -p "${backup_dir}"
        mv -f "/etc/logrotate.d/caddy.before-copytruncate" \
              "${backup_dir}/caddy-logrotate.before-copytruncate.legacy"
        info "  Перенёс старый бэкап logrotate-каддy из /etc/logrotate.d/ в ${backup_dir}/ (фикс ночного logrotate-фейла)"
    fi

    # Если в файле УЖЕ есть copytruncate и НЕТ postrotate-reload — всё ок.
    if grep -q "copytruncate" "${target}" && ! grep -q "systemctl reload caddy" "${target}"; then
        return 0
    fi
    info "Обновление /etc/logrotate.d/caddy на copytruncate (фикс ночных обрывов HTTPS)..."
    mkdir -p "${backup_dir}"
    # Бэкап в /var/lib/proxy-panel/migrations/ — logrotate туда не лезет.
    local stamp; stamp=$(date +%Y%m%d-%H%M%S)
    cp -p "${target}" "${backup_dir}/caddy-logrotate.before-copytruncate.${stamp}" 2>/dev/null || true
    cat > "${target}" <<'LRCADDY'
/var/log/caddy/*.log {
    daily
    missingok
    rotate 14
    compress
    notifempty
    # copytruncate вместо postrotate-reload: чтобы Caddy не терял
    # runtime-конфиг при ротации логов. См. install.sh комментарий.
    copytruncate
}
LRCADDY
    chmod 644 "${target}"
}

# ─────────────────────────────────────────────────────────────
# ensure_scheduler_unit — устанавливает systemd-юнит для шедулера,
# если его ещё нет (для апгрейда со старых версий, где шедулер
# работал внутри gunicorn). Идемпотентно.
# ─────────────────────────────────────────────────────────────
ensure_scheduler_unit() {
    if [[ -f /etc/systemd/system/proxy-panel-scheduler.service ]]; then
        return 0
    fi
    info "Установка systemd-юнита proxy-panel-scheduler..."
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
    systemctl daemon-reload
    systemctl enable proxy-panel-scheduler
}

# ─────────────────────────────────────────────────────────────
# update_xray — скачивает и заменяет бинарник, не трогает конфиг
# ─────────────────────────────────────────────────────────────
update_xray() {
    info "=== Обновление Xray ==="

    local version_before
    version_before=$(xray version 2>/dev/null | head -1 || echo "не установлен")
    info "Версия до:  ${version_before}"

    info "Остановка сервиса xray..."
    systemctl stop xray

    info "Загрузка Xray v${XRAY_VERSION}..."
    local xray_url="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"
    local xray_sha_url="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip.sha256sum"
    wget -q -O /tmp/xray.zip          "${xray_url}"
    wget -q -O /tmp/xray.zip.sha256sum "${xray_sha_url}"
    ( cd /tmp && sha256sum --check <(sed 's|Xray-linux-64.zip|/tmp/xray.zip|' xray.zip.sha256sum) ) \
        || error "Проверка SHA-256 для xray.zip не прошла. Обновление прервано."
    rm /tmp/xray.zip.sha256sum
    unzip -q -o /tmp/xray.zip -d /tmp/xray
    install -m 755 /tmp/xray/xray /usr/local/bin/xray
    rm -rf /tmp/xray /tmp/xray.zip
    setcap cap_net_bind_service=+ep /usr/local/bin/xray

    info "Запуск сервиса xray..."
    systemctl start xray

    local version_after
    version_after=$(xray version 2>/dev/null | head -1 || echo "не определена")
    info "Версия после: ${version_after}"
    info "Xray обновлён. Конфиг (/etc/xray/config.json) не изменён."
    echo ""
}

# ─────────────────────────────────────────────────────────────
# update_caddy — пересобирает Caddy через xcaddy с klzgrad/forwardproxy
#                на ЯВНОМ ТЭГЕ v2.10.0-naive (а не на плавающем @naive)
#                и Caddy v2.10.2 (последний hotfix в 2.10.x line,
#                совместим с плагином). Не трогает конфиги в /etc/caddy/.
# ─────────────────────────────────────────────────────────────
update_caddy() {
    info "=== Обновление Caddy (пересборка с NaiveProxy) ==="
    info "    Caddy ${CADDY_VERSION} + forwardproxy commit ${FORWARDPROXY_VERSION:0:12}"

    # Печатаем, что было раньше — особенно полезно для диагностики при
    # переходе с stage1-13 (Caddy v2.11.3) на stage1-14 (v2.10.2).
    local version_before
    version_before=$(caddy version 2>/dev/null || echo "не установлен")
    info "Версия Caddy до:  ${version_before}"
    if [[ -f /etc/caddy/.naive-build-info ]]; then
        info "Текущая сборка (из /etc/caddy/.naive-build-info):"
        sed 's/^/    /' /etc/caddy/.naive-build-info
    else
        # На stage1-13 этого файла нет — это нормально.
        local fp_before
        fp_before=$(caddy list-modules --versions 2>/dev/null \
                    | awk '/http\.handlers\.forward_proxy/ {print $2}')
        info "Текущий forward_proxy: ${fp_before:-неизвестна} (маркер-файла нет — это сборка ≤ stage1-13)"
    fi

    export PATH="/usr/local/go/bin:$PATH"
    if ! command -v go &>/dev/null; then
        error "Go не найден в PATH. Установите Go ${GO_VERSION} или выполните install.sh."
    fi
    info "Используется: $(go version)"

    info "Остановка сервиса caddy..."
    systemctl stop caddy

    info "Установка/обновление xcaddy..."
    GOBIN=/usr/local/bin /usr/local/go/bin/go install \
        github.com/caddyserver/xcaddy/cmd/xcaddy@latest \
        || error "Не удалось установить xcaddy. Проверьте сеть и доступность proxy.golang.org."

    info "Сборка Caddy ${CADDY_VERSION} с NaiveProxy плагином (commit ${FORWARDPROXY_VERSION:0:12}, 2-5 мин)..."
    local build_dir
    build_dir=$(mktemp -d)
    cd "${build_dir}"

    HOME=/root /usr/local/bin/xcaddy build "${CADDY_VERSION}" \
        --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@${FORWARDPROXY_VERSION} \
        --output /usr/local/bin/caddy \
        || error "Не удалось собрать Caddy ${CADDY_VERSION} с NaiveProxy форком (klzgrad/forwardproxy@${FORWARDPROXY_VERSION})."

    cd /root
    rm -rf "${build_dir}"
    setcap cap_net_bind_service=+ep /usr/local/bin/caddy

    info "Запуск сервиса caddy..."
    systemctl start caddy

    local version_after
    version_after=$(caddy version 2>/dev/null || echo "не определена")
    info "Версия Caddy после: ${version_after}"

    # Проверка: модуль forward_proxy должен присутствовать
    if caddy list-modules 2>/dev/null | grep -q "http.handlers.forward_proxy"; then
        info "Модуль http.handlers.forward_proxy на месте."
        local fp_after
        fp_after=$(caddy list-modules --versions 2>/dev/null \
                   | awk '/http\.handlers\.forward_proxy/ {print $2}')
        info "forward_proxy после: ${fp_after:-неизвестна}"
        # Обновляем маркер-файл.
        cat > /etc/caddy/.naive-build-info <<NAIVEINFO
caddy_version=${CADDY_VERSION}
forwardproxy_pin=${FORWARDPROXY_VERSION}
forwardproxy_runtime=${fp_after:-unknown}
go_version=$(go version 2>/dev/null | awk '{print $3}')
built_at=$(date -Iseconds)
NAIVEINFO
        chmod 644 /etc/caddy/.naive-build-info
        chown caddy:caddy /etc/caddy/.naive-build-info 2>/dev/null || true
    else
        warn "В собранном Caddy НЕТ модуля forward_proxy. NaiveProxy работать НЕ будет."
    fi

    info "Caddy обновлён. Конфиги (/etc/caddy/) не изменены."
    echo ""
}

# ─────────────────────────────────────────────────────────────
# update_panel — синхронизирует файлы панели, не трогает БД
# ─────────────────────────────────────────────────────────────
update_panel() {
    info "=== Обновление панели ==="

    # Sanity-check: убеждаемся, что update.sh запущен из корня
    # распакованного архива, а не из произвольного места.
    for required in requirements.txt run.py app; do
        if [[ ! -e "${SCRIPT_DIR}/${required}" ]]; then
            error "В каталоге ${SCRIPT_DIR} отсутствует '${required}'.
Запустите update.sh из корня распакованного архива
(там должны лежать update.sh, run.py, requirements.txt и app/)."
        fi
    done

    # ─────────────────────────────────────────────────────────────
    # PRE-FLIGHT: компилим все .py и парсим все .html у НОВОГО кода
    # ДО того, как остановим сервис и тронем файлы. Так панель
    # никогда не уезжает в "сломан до перезапуска" состояние из-за
    # синтакс-ошибки в каком-то одном файле.
    # ─────────────────────────────────────────────────────────────
    info "Pre-flight: компиляция Python и проверка Jinja..."
    if [[ -x "${PANEL_DIR}/venv/bin/python" ]]; then
        local PY="${PANEL_DIR}/venv/bin/python"
    else
        local PY="python3"
    fi

    # py_compile: компилирует все .py в SCRIPT_DIR/app — если синтакс
    # битый, упадёт с понятным сообщением. Не трогает /opt/proxy-panel.
    if ! "${PY}" -m compileall -q "${SCRIPT_DIR}/app" "${SCRIPT_DIR}/run.py"; then
        error "Pre-flight: ошибка компиляции Python в ${SCRIPT_DIR}/app.
Обновление прервано, текущая установка не тронута."
    fi

    # Jinja: парсим каждый шаблон. Sintax errors там не ловятся py_compile'ом.
    if ! "${PY}" - <<PYCHECK
import os, sys
from jinja2 import Environment, FileSystemLoader, exceptions
tdir = "${SCRIPT_DIR}/app/templates"
env = Environment(loader=FileSystemLoader(tdir))
bad = []
for root, _, files in os.walk(tdir):
    for f in files:
        if not f.endswith(".html"):
            continue
        rel = os.path.relpath(os.path.join(root, f), tdir)
        try:
            env.parse(open(os.path.join(root, f)).read())
        except exceptions.TemplateSyntaxError as e:
            bad.append(f"  {rel}: {e}")
if bad:
    print("Jinja syntax errors:\n" + "\n".join(bad), file=sys.stderr)
    sys.exit(1)
PYCHECK
    then
        error "Pre-flight: один или несколько Jinja-шаблонов содержат ошибки.
Обновление прервано, текущая установка не тронута."
    fi
    info "Pre-flight: код синтаксически валиден."

    # Чистим .pyc-артефакты от compileall, чтобы они не уехали в rsync.
    find "${SCRIPT_DIR}/app" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

    local version_before="не определена"
    [[ -f "${PANEL_DIR}/VERSION" ]] && version_before=$(cat "${PANEL_DIR}/VERSION")
    info "Версия до:  ${version_before}"

    info "Остановка сервиса proxy-panel..."
    systemctl stop proxy-panel
    systemctl stop proxy-panel-scheduler 2>/dev/null || true

    info "Синхронизация файлов (instance/, venv/ и мусор исключены)..."
    rsync -a \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='*.bak' \
        --exclude='patch_v*.sh' \
        --exclude='instance/' \
        --exclude='venv/' \
        "${SCRIPT_DIR}/" "${PANEL_DIR}/"

    # Defensive-check после rsync
    for required in requirements.txt run.py app/__init__.py; do
        if [[ ! -e "${PANEL_DIR}/${required}" ]]; then
            error "После rsync в ${PANEL_DIR} нет '${required}'. Обновление прервано."
        fi
    done

    chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"

    # Уверяемся, что /etc/logrotate.d/caddy использует copytruncate, а не
    # postrotate-reload. На старых установках там стоял reload — он по
    # ночам выбивал runtime-конфиг Caddy и панель становилась недоступна
    # по HTTPS. Этот блок — идемпотентный фикс той ошибки для всех уже
    # работающих установок.
    ensure_caddy_logrotate_safe

    # Уверяемся, что у proxypanel есть read-only sudo на `ufw status`.
    # Нужно для нового UI-индикатора «порт открыт в UFW или нет»
    # в форме создания/редактирования инбаунда. Идемпотентно.
    ensure_panel_ufw_sudoers

    # Чиним /etc/systemd/system/xray.service — на старых установках
    # там стоял ExecReload=/bin/kill -HUP $MAINPID и Restart=on-failure.
    # Xray не умеет HUP-reload, процесс умирал на любой apply_xray_config
    # и больше не поднимался. См. полный разбор в комментарии функции.
    # Идемпотентно: если файл уже правильный — ничего не делает.
    ensure_xray_service_unit_safe

    info "Обновление Python-зависимостей..."
    "${PANEL_DIR}/venv/bin/pip" install -q --upgrade pip
    "${PANEL_DIR}/venv/bin/pip" install -q -r "${PANEL_DIR}/requirements.txt" gunicorn

    ensure_scheduler_unit

    info "Запуск сервиса proxy-panel..."
    systemctl start proxy-panel
    info "Запуск шедулера..."
    systemctl start proxy-panel-scheduler

    local version_after="не определена"
    [[ -f "${PANEL_DIR}/VERSION" ]] && version_after=$(cat "${PANEL_DIR}/VERSION")
    info "Версия после: ${version_after}"
    info "Панель обновлена. База данных (instance/panel.db) не тронута."
    echo ""
}

# ── Диспетчер ─────────────────────────────────────────────────
case "$1" in
    xray)  update_xray ;;
    caddy) update_caddy ;;
    panel) update_panel ;;
    all)   update_xray; update_caddy; update_panel ;;
    *)     usage ;;
esac
