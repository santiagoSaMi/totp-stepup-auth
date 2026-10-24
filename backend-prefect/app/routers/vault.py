from fastapi import APIRouter, Depends

from app.deps import require_mfa_session
from app.schemas import VaultResponse
from app.security.tokens import TokenClaims

router = APIRouter(prefix="/api", tags=["protected"])


@router.get("/boveda-secreta")
def boveda_secreta(claims: TokenClaims = Depends(require_mfa_session)) -> VaultResponse:
    return VaultResponse(
        message=f"Bienvenido a la bóveda, {claims.username}",
        username=claims.username,
        mfa_verified=claims.mfa_verified,
        mfa_method=claims.mfa_method,
        token_expires_at=claims.expires_at,
        treasure="La contraseña sola no basta: este recurso exige mfa_verified=true.",
    )
