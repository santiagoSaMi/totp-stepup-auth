import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    database_url: str
    jwt_secret: str
    pre_auth_token_ttl_seconds: int
    access_token_ttl_seconds: int
    totp_issuer: str


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is not set; copy .env.example to .env and fill it in")
    return value


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=_required("DATABASE_URL"),
        jwt_secret=_required("JWT_SECRET"),
        pre_auth_token_ttl_seconds=int(os.environ.get("PRE_AUTH_TOKEN_TTL_SECONDS", "300")),
        access_token_ttl_seconds=int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "900")),
        totp_issuer=os.environ.get("TOTP_ISSUER", "Lab2FA"),
    )
