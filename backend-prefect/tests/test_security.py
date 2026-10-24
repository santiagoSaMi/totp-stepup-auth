import time
from uuid import uuid4

import jwt
import pytest

from app.config import get_settings
from app.security import passwords, tokens
from app.security.tokens import InvalidToken, TokenScope

USER_ID = uuid4()


# --- passwords ---


def test_password_roundtrip():
    h = passwords.hash_password("correct horse")
    assert h.startswith("$2")
    assert passwords.verify_password("correct horse", h)
    assert not passwords.verify_password("wrong horse", h)


def test_verify_password_without_user_returns_false():
    assert not passwords.verify_password("anything", None)


def test_password_over_72_bytes_is_rejected():
    with pytest.raises(passwords.PasswordTooLong):
        passwords.hash_password("a" * 73)
    assert not passwords.verify_password("a" * 73, passwords.hash_password("a" * 72))


# --- tokens ---


def test_pre_auth_token_claims():
    claims = tokens.decode_token(tokens.issue_pre_auth_token(USER_ID, "alice"), TokenScope.PRE_AUTH)
    assert claims.user_id == USER_ID
    assert claims.username == "alice"
    assert claims.scope is TokenScope.PRE_AUTH
    assert claims.mfa_verified is False


def test_access_token_claims():
    claims = tokens.decode_token(tokens.issue_access_token(USER_ID, "alice", "totp"), TokenScope.ACCESS)
    assert claims.scope is TokenScope.ACCESS
    assert claims.mfa_verified is True
    assert claims.mfa_method == "totp"


def test_pre_auth_token_cannot_be_used_as_access_token():
    # The core of Step-Up Auth: password alone never opens protected routes.
    with pytest.raises(InvalidToken, match="scope"):
        tokens.decode_token(tokens.issue_pre_auth_token(USER_ID, "alice"), TokenScope.ACCESS)


def test_access_token_cannot_be_used_as_pre_auth_token():
    with pytest.raises(InvalidToken, match="scope"):
        tokens.decode_token(tokens.issue_access_token(USER_ID, "alice", "totp"), TokenScope.PRE_AUTH)


def _forge(payload: dict, secret: str | None = None) -> str:
    return jwt.encode(payload, secret or get_settings().jwt_secret, algorithm="HS256")


def test_expired_token_is_rejected():
    now = int(time.time())
    token = _forge(
        {"sub": str(USER_ID), "scope": "pre_auth", "iss": tokens.ISSUER, "jti": "x", "iat": now - 600, "exp": now - 1}
    )
    with pytest.raises(InvalidToken, match="expired"):
        tokens.decode_token(token, TokenScope.PRE_AUTH)


def test_token_signed_with_other_key_is_rejected():
    now = int(time.time())
    token = _forge(
        {"sub": str(USER_ID), "scope": "access", "mfa_verified": True, "iss": tokens.ISSUER, "jti": "x", "iat": now, "exp": now + 60},
        secret="attacker-key-" + "y" * 40,
    )
    with pytest.raises(InvalidToken):
        tokens.decode_token(token, TokenScope.ACCESS)


def test_unsigned_token_is_rejected():
    now = int(time.time())
    token = jwt.encode(
        {"sub": str(USER_ID), "scope": "access", "mfa_verified": True, "iss": tokens.ISSUER, "jti": "x", "iat": now, "exp": now + 60},
        key=None,
        algorithm="none",
    )
    with pytest.raises(InvalidToken):
        tokens.decode_token(token, TokenScope.ACCESS)
