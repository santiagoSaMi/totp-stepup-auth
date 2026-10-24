"""Request and response bodies of the HTTP API."""

from pydantic import BaseModel, Field, field_validator

from app.mfa.state import MFAStatus
from app.mfa.strategies.base import MFAMethod
from app.security.passwords import MAX_PASSWORD_BYTES


def _normalize_username(value: str) -> str:
    return value.strip().lower()


def _check_password_bytes(value: str) -> str:
    if len(value.encode()) > MAX_PASSWORD_BYTES:
        raise ValueError(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    return value


class RegisterRequest(BaseModel):
    username: str = Field(pattern=r"^[a-z0-9._-]{3,32}$", description="3-32 chars: a-z, 0-9, . _ -")
    password: str = Field(min_length=8)

    _username = field_validator("username", mode="before")(_normalize_username)
    _password = field_validator("password")(_check_password_bytes)


class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str

    _username = field_validator("username", mode="before")(_normalize_username)
    _password = field_validator("password")(_check_password_bytes)


class CodeRequest(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class VerifyRequest(CodeRequest):
    method: MFAMethod = MFAMethod.TOTP


class UserResponse(BaseModel):
    id: str
    username: str


class LoginResponse(BaseModel):
    pre_auth_token: str
    token_type: str = "bearer"
    expires_in: int
    mfa_status: MFAStatus
    next_step: str


class EnrollResponse(BaseModel):
    otpauth_uri: str
    secret: str
    qr_svg: str  # data: URI, ready for an <img src>


class SessionResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    mfa_method: MFAMethod
    window: str | None  # TOTP only: "C-1", "C" or "C+1"


class ActivateResponse(SessionResponse):
    backup_codes: list[str]


class VaultResponse(BaseModel):
    message: str
    username: str
    mfa_verified: bool
    mfa_method: str | None
    token_expires_at: int
    treasure: str
