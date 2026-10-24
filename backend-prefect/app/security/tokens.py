"""JWTs for Step-Up Authentication.

- pre_auth token: issued after username + password. Its scope only allows the
  2FA endpoints (verify, enroll, activate). It never opens protected resources.
- access token: issued after the second factor, with `mfa_verified: true`.
"""

import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

import jwt

from app.config import get_settings

ALGORITHM = "HS256"
ISSUER = "backend-prefect"


class TokenScope(StrEnum):
    PRE_AUTH = "pre_auth"
    ACCESS = "access"


class InvalidToken(Exception):
    pass


@dataclass(frozen=True)
class TokenClaims:
    user_id: UUID
    username: str
    scope: TokenScope
    mfa_verified: bool
    mfa_method: str | None
    expires_at: int


def _encode(claims: dict, ttl_seconds: int) -> str:
    now = int(time.time())
    payload = {**claims, "iss": ISSUER, "iat": now, "exp": now + ttl_seconds, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, get_settings().jwt_secret, algorithm=ALGORITHM)


def issue_pre_auth_token(user_id: UUID, username: str) -> str:
    claims = {"sub": str(user_id), "username": username, "scope": TokenScope.PRE_AUTH, "mfa_verified": False}
    return _encode(claims, get_settings().pre_auth_token_ttl_seconds)


def issue_access_token(user_id: UUID, username: str, mfa_method: str) -> str:
    claims = {
        "sub": str(user_id),
        "username": username,
        "scope": TokenScope.ACCESS,
        "mfa_verified": True,
        "mfa_method": mfa_method,
    }
    return _encode(claims, get_settings().access_token_ttl_seconds)


def decode_token(token: str, expected_scope: TokenScope) -> TokenClaims:
    try:
        payload = jwt.decode(
            token,
            get_settings().jwt_secret,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["sub", "scope", "exp", "iat", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise InvalidToken("token expired") from None
    except jwt.InvalidTokenError as e:
        raise InvalidToken(f"invalid token: {e}") from None

    if payload["scope"] != expected_scope:
        raise InvalidToken(f"token scope is {payload['scope']!r}, expected {expected_scope.value!r}")

    return TokenClaims(
        user_id=UUID(payload["sub"]),
        username=payload.get("username", ""),
        scope=TokenScope(payload["scope"]),
        mfa_verified=bool(payload.get("mfa_verified", False)),
        mfa_method=payload.get("mfa_method"),
        expires_at=payload["exp"],
    )
