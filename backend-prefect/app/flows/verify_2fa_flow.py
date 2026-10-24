from dataclasses import dataclass

from prefect import flow
from pydantic import SecretStr

from app.flows.tasks import (
    check_anti_replay_cache,
    execute_mfa_strategy,
    issue_elevated_session,
    normalize_code,
    validate_pre_auth_state,
)
from app.mfa.state import MFAStatus
from app.mfa.strategies.base import MFAMethod


@dataclass(frozen=True)
class VerifyResult:
    access_token: str
    method: MFAMethod
    window: str | None  # TOTP only: "C-1", "C" or "C+1"


@flow(name="verify-2fa", flow_run_name="verify-2fa-{method}", persist_result=False)
def verify_2fa_flow(pre_auth_token: SecretStr, code: SecretStr, method: MFAMethod = MFAMethod.TOTP) -> VerifyResult:
    """Step 2 of Step-Up Auth: pre_auth_token + second factor -> access_token (mfa_verified)."""
    code = SecretStr(normalize_code(method, code.get_secret_value()))

    user = validate_pre_auth_state(pre_auth_token, (MFAStatus.ACTIVE,))  # Task 1
    check_anti_replay_cache(user, code)  # Task 2
    result = execute_mfa_strategy(user, code, method)  # Task 3
    access_token = issue_elevated_session(user, code, method)  # Task 4
    return VerifyResult(access_token, method, result.window)
