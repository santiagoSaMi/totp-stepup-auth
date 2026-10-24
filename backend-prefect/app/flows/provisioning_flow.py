"""Secure provisioning (Process Manager): DISABLED -> PENDING_VERIFICATION -> ACTIVE."""

from dataclasses import dataclass

from prefect import flow
from pydantic import SecretStr

from app.flows.tasks import (
    Enrollment,
    activate_mfa,
    check_anti_replay_cache,
    issue_elevated_session,
    normalize_code,
    start_enrollment,
    validate_pre_auth_state,
    verify_enrollment_code,
)
from app.mfa.state import MFAStatus
from app.mfa.strategies.base import MFAMethod


@dataclass(frozen=True)
class ActivationResult:
    access_token: str
    backup_codes: list[str]
    window: str | None


@flow(name="enroll-2fa", persist_result=False)
def enroll_2fa_flow(pre_auth_token: SecretStr) -> Enrollment:
    """Generate a secret and QR URI; 2FA stays PENDING until a first code is verified."""
    user = validate_pre_auth_state(pre_auth_token, (MFAStatus.DISABLED, MFAStatus.PENDING_VERIFICATION))
    return start_enrollment(user)


@flow(name="activate-2fa", persist_result=False)
def activate_2fa_flow(pre_auth_token: SecretStr, code: SecretStr) -> ActivationResult:
    """First valid code from the app: PENDING -> ACTIVE, backup codes, and a full session."""
    code = SecretStr(normalize_code(MFAMethod.TOTP, code.get_secret_value()))

    user = validate_pre_auth_state(pre_auth_token, (MFAStatus.PENDING_VERIFICATION,))
    check_anti_replay_cache(user, code)
    match = verify_enrollment_code(user, code)
    codes = activate_mfa(user)
    access_token = issue_elevated_session(user, code, MFAMethod.TOTP)
    return ActivationResult(access_token, codes, match.window)
