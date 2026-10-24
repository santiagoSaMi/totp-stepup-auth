"""TOTP (RFC 6238) implemented from scratch on top of HOTP (RFC 4226).

Only the standard library is used: `hmac`/`hashlib` for HMAC-SHA1 and
`base64` for Base32. The dynamic truncation and time-window logic are ours.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass
from urllib.parse import quote, urlencode

PERIOD_SECONDS = 30
DIGITS = 6
# Windows accepted around the current counter C: C-1, C, C+1 (±30s of clock skew).
WINDOW_OFFSETS = (-1, 0, 1)
SECRET_BYTES = 20  # 160 bits, the size recommended by RFC 4226 for HMAC-SHA1


@dataclass(frozen=True)
class TOTPMatch:
    """Which time window validated a code."""

    offset: int  # -1, 0 or +1 relative to the server's current counter
    counter: int  # absolute counter value that matched

    @property
    def label(self) -> str:
        if self.offset == 0:
            return "C"
        return f"C{self.offset:+d}"


def generate_secret(num_bytes: int = SECRET_BYTES) -> str:
    """Random secret encoded as unpadded uppercase Base32 (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def decode_secret(secret_b32: str) -> bytes:
    """Decode a Base32 secret, tolerating lowercase, spaces and missing padding."""
    normalized = secret_b32.replace(" ", "").upper()
    padding = "=" * (-len(normalized) % 8)
    return base64.b32decode(normalized + padding)


def time_counter(timestamp: float, period: int = PERIOD_SECONDS) -> int:
    """T = floor(unix_time / period)."""
    return int(timestamp // period)


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^digits."""
    message = struct.pack(">Q", counter)  # counter as 8-byte big-endian
    digest = hmac.new(key, message, hashlib.sha1).digest()

    # Dynamic truncation: the low 4 bits of the last byte pick a 4-byte slice,
    # and the top bit is masked off to get a positive 31-bit integer.
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF

    return str(binary % 10**digits).zfill(digits)


def totp(
    secret_b32: str,
    timestamp: float | None = None,
    period: int = PERIOD_SECONDS,
    digits: int = DIGITS,
) -> str:
    """Code for the window containing `timestamp` (defaults to now)."""
    if timestamp is None:
        timestamp = time.time()
    return hotp(decode_secret(secret_b32), time_counter(timestamp, period), digits)


def verify(
    secret_b32: str,
    code: str,
    timestamp: float | None = None,
    period: int = PERIOD_SECONDS,
    digits: int = DIGITS,
) -> TOTPMatch | None:
    """Check `code` against windows C-1, C and C+1. Returns the matching window or None."""
    # isascii() matters: isdigit() alone also accepts e.g. Arabic-Indic digits.
    if len(code) != digits or not (code.isascii() and code.isdigit()):
        return None
    if timestamp is None:
        timestamp = time.time()

    key = decode_secret(secret_b32)
    current = time_counter(timestamp, period)
    for window_offset in WINDOW_OFFSETS:
        counter = current + window_offset
        if hmac.compare_digest(hotp(key, counter, digits), code):
            return TOTPMatch(offset=window_offset, counter=counter)
    return None


def build_otpauth_uri(secret_b32: str, account_name: str, issuer: str) -> str:
    """Key URI understood by Google/Microsoft Authenticator and by our own app.

    Format: otpauth://totp/{issuer}:{account}?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
    """
    label = quote(f"{issuer}:{account_name}")
    params = urlencode(
        {
            "secret": secret_b32,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": PERIOD_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{params}"
