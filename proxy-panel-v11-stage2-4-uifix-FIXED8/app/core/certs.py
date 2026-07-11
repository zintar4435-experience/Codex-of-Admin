"""
Мост TLS-сертификатов Caddy → Xray.

Проблема. Xray-инбаунду с настоящим TLS (Trojan/VLESS+TLS) нужен файл
сертификата. Сертификаты для доменов панели уже выпускает и продлевает
Caddy (Let's Encrypt), но хранит их в /var/lib/caddy/... с правами
600 caddy:caddy — Xray (пользователь xray) их прочитать не может.

Решение. Root-скрипт /usr/local/bin/xray-cert-sync.sh копирует cert+key
из хранилища Caddy в /etc/xray/certs/<domain>/{cert.pem,key.pem} с правами
640 root:xray (Xray в группе xray читает). Скрипт запускается:
  - по cron.daily (продление сертификатов Caddy подхватывается),
  - и панелью через sudo при создании/сохранении TLS-инбаунда (немедленно).

Этот модуль — тонкая обёртка: где лежат готовые для Xray сертификаты,
как их обновить и есть ли они для домена. Установку самого скрипта,
cron и sudoers делают install.sh / update.sh.
"""
from __future__ import annotations

import logging
import os
import subprocess

log = logging.getLogger(__name__)

XRAY_CERTS_DIR = "/etc/xray/certs"
CERT_SYNC_SCRIPT = "/usr/local/bin/xray-cert-sync.sh"
SUDO_BINARY = "/usr/bin/sudo"


def xray_cert_paths(domain: str) -> tuple[str, str]:
    """Пути cert/key для домена в читаемом Xray месте (могут ещё не существовать)."""
    d = os.path.join(XRAY_CERTS_DIR, domain)
    return os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")


def cert_available(domain: str) -> bool:
    """True если для домена уже есть готовые (непустые) cert и key для Xray."""
    cert, key = xray_cert_paths(domain)
    try:
        return (os.path.isfile(cert) and os.path.getsize(cert) > 0
                and os.path.isfile(key) and os.path.getsize(key) > 0)
    except OSError:
        return False


def trigger_cert_sync() -> bool:
    """
    Просит root-скрипт синхронизировать сертификаты Caddy → Xray (все домены).
    Вызывается перед сохранением TLS-инбаунда, чтобы файлы появились сразу.

    Возвращает True при успехе. Fail-safe: любые ошибки (нет скрипта, sudo
    не настроен) логируются и возвращают False — вызывающий код сам решит,
    что делать (обычно продолжит и упрётся в проверку наличия файла).
    """
    if not os.path.exists(CERT_SYNC_SCRIPT):
        log.info("cert-sync: скрипт %s не установлен (нужно update.sh)", CERT_SYNC_SCRIPT)
        return False
    try:
        r = subprocess.run(
            [SUDO_BINARY, "-n", CERT_SYNC_SCRIPT],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            return True
        log.warning("cert-sync RC=%d: %s", r.returncode,
                    (r.stderr or r.stdout or "").strip()[:200])
        return False
    except FileNotFoundError:
        log.info("cert-sync: sudo/скрипт не найдены")
        return False
    except subprocess.TimeoutExpired:
        log.warning("cert-sync: таймаут")
        return False
    except Exception as e:  # noqa: BLE001
        log.warning("cert-sync: неожиданная ошибка: %s", e)
        return False
