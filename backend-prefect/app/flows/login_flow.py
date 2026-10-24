from dataclasses import dataclass

from prefect import flow
from pydantic import SecretStr

from app.flows.tasks import issue_pre_auth_token, verify_credentials
from app.mfa.state import MFAStatus


@dataclass(frozen=True)
class LoginResult:
    pre_auth_token: str
    mfa_status: MFAStatus

    @property
    def next_step(self) -> str:
        """Where the web app goes next: verify a code, or finish/start enrollment."""
        return "verify-2fa" if self.mfa_status is MFAStatus.ACTIVE else "enroll-2fa"


@flow(name="login", flow_run_name="login-{username}", persist_result=False)
def login_flow(username: str, password: SecretStr) -> LoginResult:
    """Step 1 of Step-Up Auth: username + password -> restricted pre_auth_token."""
    user = verify_credentials(username, password)
    token = issue_pre_auth_token(user)
    return LoginResult(token, user.mfa_status)
