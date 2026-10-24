from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from app.security import tokens
from app.security.tokens import TokenClaims, TokenScope

_bearer = HTTPBearer(auto_error=False)


def _bearer_token(credentials: HTTPAuthorizationCredentials | None) -> str:
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="missing Authorization: Bearer <token> header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


def pre_auth_token(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> SecretStr:
    """Raw pre_auth_token. Its validation is Task 1 of the flow, so it shows up in Prefect."""
    return SecretStr(_bearer_token(credentials))


def require_mfa_session(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> TokenClaims:
    """Protected resources need an access token that went through the second factor."""
    claims = tokens.decode_token(_bearer_token(credentials), TokenScope.ACCESS)
    if not claims.mfa_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="second factor required")
    return claims
