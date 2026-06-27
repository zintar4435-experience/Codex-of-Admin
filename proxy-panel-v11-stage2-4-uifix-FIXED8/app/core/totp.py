"""TOTP (RFC 6238) на стандартной библиотеке — без внешних зависимостей.

Совместимо с Google Authenticator / Authy / 1Password и т.п.:
алгоритм SHA1, 6 цифр, шаг 30 секунд.

Здесь только криптография и кодирование. Хранение секрета и резервных
кодов — в модели User (app/models.py).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

_STEP = 30          # секунд на один код
_DIGITS = 6
_WINDOW = 1         # принимаем код из соседних окон (±30 сек) — допуск на рассинхрон часов


def generate_secret(length: int = 20) -> str:
    """Случайный секрет в Base32 (как ожидают authenticator-приложения)."""
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _code_at(secret: str, counter: int) -> str:
    # Base32 без padding → дополняем до кратной 8 длины
    pad = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret.upper() + pad)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** _DIGITS)).zfill(_DIGITS)


def verify(secret: str, code: str, at: float | None = None) -> bool:
    """Проверка кода с допуском ±_WINDOW окон. Сравнение постоянного времени."""
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != _DIGITS:
        return False
    now = int((at if at is not None else time.time()) // _STEP)
    for w in range(-_WINDOW, _WINDOW + 1):
        try:
            if hmac.compare_digest(_code_at(secret, now + w), code):
                return True
        except Exception:
            return False
    return False


def provisioning_uri(secret: str, account: str, issuer: str = "ProxyPanel") -> str:
    """otpauth://-ссылка для QR-кода (его рисует фронт через qrcodejs)."""
    label = urllib.parse.quote(f"{issuer}:{account}", safe=":")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": _DIGITS,
        "period": _STEP,
    })
    return f"otpauth://totp/{label}?{params}"


def generate_recovery_codes(n: int = 10) -> list[str]:
    """Список одноразовых резервных кодов вида 'a1b2-c3d4' (показываются один раз)."""
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(4)          # 8 hex-символов
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes
