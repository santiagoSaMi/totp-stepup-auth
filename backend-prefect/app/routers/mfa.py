from fastapi import APIRouter, Depends
from pydantic import SecretStr

from app.config import get_settings
from app.deps import pre_auth_token
from app.flows.provisioning_flow import activate_2fa_flow, enroll_2fa_flow
from app.mfa.strategies.base import MFAMethod
from app.qr import svg_data_uri
from app.schemas import ActivateResponse, CodeRequest, EnrollResponse

router = APIRouter(prefix="/2fa", tags=["2fa provisioning"])


@router.post("/enroll")
def enroll(token: SecretStr = Depends(pre_auth_token)) -> EnrollResponse:
    """New secret and QR. 2FA stays PENDING_VERIFICATION until /2fa/activate succeeds."""
    enrollment = enroll_2fa_flow(token)
    return EnrollResponse(
        otpauth_uri=enrollment.otpauth_uri,
        secret=enrollment.secret_base32,
        qr_svg=svg_data_uri(enrollment.otpauth_uri),
    )


@router.post("/activate")
def activate(body: CodeRequest, token: SecretStr = Depends(pre_auth_token)) -> ActivateResponse:
    """First code from the app: PENDING_VERIFICATION -> ACTIVE. Backup codes are shown only here."""
    result = activate_2fa_flow(token, SecretStr(body.code))
    return ActivateResponse(
        access_token=result.access_token,
        expires_in=get_settings().access_token_ttl_seconds,
        mfa_method=MFAMethod.TOTP,
        window=result.window,
        backup_codes=result.backup_codes,
    )
