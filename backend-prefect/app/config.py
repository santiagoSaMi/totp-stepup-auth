import base64
import binascii
import os
from dataclasses import dataclass, field
from functools import lru_cache

GENERATE_KEY_HINT = 'python3 -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"'


@dataclass(frozen=True)
class Settings:
    # repr=False keeps credentials out of logs and tracebacks.
    database_url: str = field(repr=False)
    jwt_secret: str = field(repr=False)
    mfa_encryption_key: bytes = field(repr=False)
    pre_auth_token_ttl_seconds: int
    access_token_ttl_seconds: int
    totp_issuer: str


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is not set; copy .env.example to .env and fill it in")
    return value


def _encryption_key() -> bytes:
    raw = _required("MFA_ENCRYPTION_KEY")
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != 32:
        raise RuntimeError(f"MFA_ENCRYPTION_KEY must be 32 random bytes in base64; generate one with: {GENERATE_KEY_HINT}")
    return key


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=_required("DATABASE_URL"),
        jwt_secret=_required("JWT_SECRET"),
        mfa_encryption_key=_encryption_key(),
        pre_auth_token_ttl_seconds=int(os.environ.get("PRE_AUTH_TOKEN_TTL_SECONDS", "300")),
        access_token_ttl_seconds=int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "900")),
        totp_issuer=os.environ.get("TOTP_ISSUER", "Lab2FA"),
    )
