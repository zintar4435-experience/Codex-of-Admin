#!/usr/bin/env bash
# ============================================================
# ProxyPanel — единый загрузчик (install ИЛИ update).
#
# Назначение: одна команда в терминале сервера, которая
#   - если панель ещё НЕ установлена  → ставит с нуля (install.sh);
#   - если панель УЖЕ установлена      → обновляет код, СОХРАНЯЯ данные
#                                        (update.sh panel — БД не трогается).
#
# Запуск (одной строкой, от root):
#   curl -fsSL <RAW-URL-этого-файла> | sudo bash
#
# Переопределение по желанию (переменные окружения):
#   PP_REF=main          ветка/тег репозитория для загрузки (по умолч. main)
#   PP_MODE=panel        что обновлять у существующей установки:
#                          panel (по умолч.) | xray | caddy | all
#   PP_REPO=<git-url>    другой репозиторий
#   PP_SUBDIR=<dir>      подкаталог с кодом панели внутри репозитория
#
# Пример с переопределением (сначала скачать, потом запустить):
#   curl -fsSL <RAW-URL> -o bootstrap.sh
#   sudo PP_REF=main PP_MODE=all bash bootstrap.sh
# ============================================================
set -euo pipefail

# ── Конфиг (можно переопределить через окружение) ────────────
PP_REPO="${PP_REPO:-https://github.com/zintar4435-experience/Codex-of-Admin.git}"
PP_REF="${PP_REF:-main}"
PP_SUBDIR="${PP_SUBDIR:-proxy-panel-v11-stage2-4-uifix-FIXED8}"
PP_MODE="${PP_MODE:-panel}"
PANEL_DIR="/opt/proxy-panel"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Запустите от root. Пример: curl -fsSL <URL> | sudo bash"

# ── 1. Зависимости самого загрузчика (git) ───────────────────
if ! command -v git >/dev/null 2>&1; then
    info "Устанавливаю git (нужен для загрузки кода)..."
    apt-get update -qq && apt-get install -y -qq git \
        || error "Не удалось установить git. Установите вручную: apt-get install git"
fi

# ── 2. Клон репозитория во временный каталог ─────────────────
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT

info "Загрузка кода панели (ветка/тег: ${PP_REF})..."
git clone --depth 1 --branch "${PP_REF}" "${PP_REPO}" "${WORKDIR}/repo" 2>/dev/null \
    || error "Не удалось загрузить репозиторий ${PP_REPO} (ref=${PP_REF}). Проверьте сеть и имя ветки."

SRC="${WORKDIR}/repo/${PP_SUBDIR}"
[[ -d "${SRC}" ]] || error "В репозитории нет каталога '${PP_SUBDIR}'. Укажите верный PP_SUBDIR."
for required in install.sh update.sh requirements.txt run.py app; do
    [[ -e "${SRC}/${required}" ]] || error "В '${PP_SUBDIR}' отсутствует '${required}' — архив повреждён."
done
cd "${SRC}"

# ── 3. Install ИЛИ Update ────────────────────────────────────
# Признак существующей установки: есть БД панели ИЛИ зарегистрирован
# systemd-юнит proxy-panel. Любого из условий достаточно.
is_installed=false
if [[ -f "${PANEL_DIR}/instance/panel.db" ]]; then
    is_installed=true
elif systemctl list-unit-files 2>/dev/null | grep -q '^proxy-panel\.service'; then
    is_installed=true
fi

if $is_installed; then
    info "Найдена существующая установка в ${PANEL_DIR}."
    info "→ Обновление (режим '${PP_MODE}'). База данных и конфиги сохраняются."
    case "${PP_MODE}" in
        panel|xray|caddy|all) ;;
        *) error "PP_MODE должен быть panel|xray|caddy|all, получено: '${PP_MODE}'." ;;
    esac
    bash update.sh "${PP_MODE}"
else
    info "Существующая установка не найдена."
    info "→ Установка с нуля."
    bash install.sh
fi

info "Готово."
