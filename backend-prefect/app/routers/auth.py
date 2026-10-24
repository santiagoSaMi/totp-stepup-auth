from fastapi import APIRouter, Depends, status
from pydantic import SecretStr

from app import repositories
from app.config import get_settings
from app.deps import pre_auth_token
from app.flows.login_flow import login_flow
from app.flows.verify_2fa_flow import verify_2fa_flow
from app.schemas import LoginRequest, LoginResponse, RegisterRequest, SessionResponse, UserResponse, VerifyRequest
from app.security import passwords

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest) -> UserResponse:
    user = repositories.user_repository().create(body.username, passwords.hash_password(body.password))
    return UserResponse(id=str(user.id), username=user.username)


@router.post("/login")
def login(body: LoginRequest) -> LoginResponse:
    """Username + password. Returns a pre_auth_token, never an access token."""
    result = login_flow(body.username, SecretStr(body.password))
    return LoginResponse(
        pre_auth_token=result.pre_auth_token,
        expires_in=get_settings().pre_auth_token_ttl_seconds,
        mfa_status=result.mfa_status,
        next_step=result.next_step,
    )


@router.post("/verify-2fa")
def verify_2fa(body: VerifyRequest, token: SecretStr = Depends(pre_auth_token)) -> SessionResponse:
    """pre_auth_token (Bearer) + TOTP or backup code. Returns the access token with mfa_verified."""
    result = verify_2fa_flow(token, SecretStr(body.code), body.method)
    return SessionResponse(
        access_token=result.access_token,
        expires_in=get_settings().access_token_ttl_seconds,
        mfa_method=result.method,
        window=result.window,
    )
