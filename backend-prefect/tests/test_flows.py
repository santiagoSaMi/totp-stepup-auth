"""End-to-end tests of the Prefect flows against a temporary Prefect server."""

import time

import pytest
from prefect.client.orchestration import get_client
from prefect.client.schemas.filters import FlowRunFilter, FlowRunFilterId
from pydantic import SecretStr

from app.flows.errors import (
    InvalidCredentials,
    InvalidPreAuthState,
    InvalidSecondFactor,
    PreAuthTokenAlreadyUsed,
    ReplayAttackDetected,
    TooManyAttempts,
)
from app.flows.login_flow import login_flow
from app.flows.provisioning_flow import activate_2fa_flow, enroll_2fa_flow
from app.flows.verify_2fa_flow import verify_2fa_flow
from app.mfa import totp
from app.mfa.replay_cache import replay_cache
from app.mfa.state import MFAStatus
from app.mfa.strategies.base import MFAMethod
from app.security import passwords, tokens
from app.security.tokens import TokenScope

PASSWORD = "s3cret-password"


@pytest.fixture(autouse=True)
def _isolated(prefect_server, fake_repos):
    pass


@pytest.fixture
def alice(fake_repos):
    users, _ = fake_repos
    return users.create("alice", passwords.hash_password(PASSWORD))


def login() -> str:
    return login_flow("alice", SecretStr(PASSWORD)).pre_auth_token


def enroll_and_activate() -> tuple[str, list[str], str]:
    """Returns (secret, backup_codes, code used for activation)."""
    pre_auth = login()
    secret = enroll_2fa_flow(SecretStr(pre_auth)).secret_base32
    code = totp.totp(secret)
    result = activate_2fa_flow(SecretStr(pre_auth), SecretStr(code))
    return secret, result.backup_codes, code


def wait_for_task_states(flow_run_id, expected_count: int, timeout: float = 10) -> dict[str, str]:
    """Task run states reach the server asynchronously; poll until they're all there."""
    deadline = time.monotonic() + timeout
    with get_client(sync_client=True) as client:
        while True:
            runs = client.read_task_runs(flow_run_filter=FlowRunFilter(id=FlowRunFilterId(any_=[flow_run_id])))
            states = {r.name.rsplit("-", 1)[0]: r.state_type.value for r in runs if r.state_type}
            if len(states) >= expected_count or time.monotonic() > deadline:
                return states
            time.sleep(0.2)


# --- login ---


def test_login_returns_pre_auth_token_only(alice):
    result = login_flow("alice", SecretStr(PASSWORD))
    claims = tokens.decode_token(result.pre_auth_token, TokenScope.PRE_AUTH)
    assert claims.user_id == alice.id
    assert claims.mfa_verified is False
    assert result.next_step == "enroll-2fa"


@pytest.mark.parametrize("username, password", [("alice", "wrong"), ("nobody", PASSWORD)])
def test_login_rejects_bad_credentials(alice, username, password):
    with pytest.raises(InvalidCredentials):
        login_flow(username, SecretStr(password))


def test_password_is_masked_in_prefect(alice):
    state = login_flow("alice", SecretStr(PASSWORD), return_state=True)
    with get_client(sync_client=True) as client:
        params = client.read_flow_run(state.state_details.flow_run_id).parameters
    assert PASSWORD not in str(params)
    assert params["username"] == "alice"


# --- provisioning ---


def test_enroll_leaves_2fa_pending(alice, fake_repos):
    _, mfa = fake_repos
    enrollment = enroll_2fa_flow(SecretStr(login()))
    assert mfa.get_config(alice.id).status is MFAStatus.PENDING_VERIFICATION
    assert f"secret={enrollment.secret_base32}" in enrollment.otpauth_uri
    assert "Lab2FA:alice" in enrollment.otpauth_uri


def test_activate_requires_a_valid_code(alice, fake_repos):
    _, mfa = fake_repos
    pre_auth = login()
    enroll_2fa_flow(SecretStr(pre_auth))
    with pytest.raises(InvalidSecondFactor):
        activate_2fa_flow(SecretStr(pre_auth), SecretStr("000000"))
    assert mfa.get_config(alice.id).status is MFAStatus.PENDING_VERIFICATION


def test_activate_moves_to_active_and_returns_session(alice, fake_repos):
    _, mfa = fake_repos
    pre_auth = login()
    secret = enroll_2fa_flow(SecretStr(pre_auth)).secret_base32
    result = activate_2fa_flow(SecretStr(pre_auth), SecretStr(totp.totp(secret)))

    assert mfa.get_config(alice.id).status is MFAStatus.ACTIVE
    assert len(result.backup_codes) == 10
    assert tokens.decode_token(result.access_token, TokenScope.ACCESS).mfa_verified
    assert login_flow("alice", SecretStr(PASSWORD)).next_step == "verify-2fa"


def test_cannot_re_enroll_once_active(alice):
    enroll_and_activate()
    with pytest.raises(InvalidPreAuthState):
        enroll_2fa_flow(SecretStr(login()))


def test_verify_requires_active_2fa(alice):
    pre_auth = login()
    secret = enroll_2fa_flow(SecretStr(pre_auth)).secret_base32
    with pytest.raises(InvalidPreAuthState):
        verify_2fa_flow(SecretStr(pre_auth), SecretStr(totp.totp(secret)))


# --- verify-2fa ---


def test_verify_with_totp_issues_mfa_verified_token(alice):
    secret, _, activation_code = enroll_and_activate()
    code = totp.totp(secret, time.time() + 30)  # different code, valid in window C+1
    assert code != activation_code

    result = verify_2fa_flow(SecretStr(login()), SecretStr(code))
    claims = tokens.decode_token(result.access_token, TokenScope.ACCESS)
    assert claims.mfa_verified is True
    assert claims.mfa_method == "totp"
    assert result.window == "C+1"


def test_replay_fails_at_check_anti_replay_cache(alice):
    secret, _, _ = enroll_and_activate()
    code = totp.totp(secret, time.time() - 30)
    verify_2fa_flow(SecretStr(login()), SecretStr(code))

    state = verify_2fa_flow(SecretStr(login()), SecretStr(code), return_state=True)
    assert state.is_failed()
    with pytest.raises(ReplayAttackDetected):
        state.result()

    task_states = wait_for_task_states(state.state_details.flow_run_id, expected_count=2)
    assert task_states == {"validate_pre_auth_state": "COMPLETED", "check_anti_replay_cache": "FAILED"}


def test_activation_code_cannot_be_replayed_to_log_in(alice):
    _, _, activation_code = enroll_and_activate()
    with pytest.raises(ReplayAttackDetected):
        verify_2fa_flow(SecretStr(login()), SecretStr(activation_code))


def test_wrong_totp_fails_at_execute_mfa_strategy(alice):
    secret, _, _ = enroll_and_activate()
    valid = {totp.totp(secret, time.time() + d) for d in (-30, 0, 30)}
    wrong = next(c for c in ("000000", "111111", "222222") if c not in valid)

    state = verify_2fa_flow(SecretStr(login()), SecretStr(wrong), return_state=True)
    assert state.is_failed()
    task_states = wait_for_task_states(state.state_details.flow_run_id, expected_count=3)
    assert task_states["execute_mfa_strategy"] == "FAILED"


def test_backup_code_works_once(alice, fake_repos):
    _, mfa = fake_repos
    _, codes, _ = enroll_and_activate()

    result = verify_2fa_flow(SecretStr(login()), SecretStr(codes[0].lower()), MFAMethod.BACKUP)
    assert tokens.decode_token(result.access_token, TokenScope.ACCESS).mfa_method == "backup"
    assert result.window is None
    assert mfa.remaining_backup_codes(alice.id) == 9

    # Same code again (in another format) is caught by the replay cache first.
    with pytest.raises(ReplayAttackDetected):
        verify_2fa_flow(SecretStr(login()), SecretStr(codes[0].replace("-", "")), MFAMethod.BACKUP)

    # Once the cache entry expires, the database still refuses it.
    replay_cache.clear()
    with pytest.raises(InvalidSecondFactor):
        verify_2fa_flow(SecretStr(login()), SecretStr(codes[0]), MFAMethod.BACKUP)


def test_access_token_cannot_be_used_as_pre_auth(alice):
    secret, _, _ = enroll_and_activate()
    access = verify_2fa_flow(SecretStr(login()), SecretStr(totp.totp(secret, time.time() - 30))).access_token
    with pytest.raises(InvalidPreAuthState):
        verify_2fa_flow(SecretStr(access), SecretStr(totp.totp(secret, time.time() + 30)))


# --- pre_auth_token limits ---


def test_pre_auth_token_locks_after_5_failures(alice):
    secret, _, _ = enroll_and_activate()
    pre_auth = login()
    valid = {totp.totp(secret, time.time() + d) for d in (-60, -30, 0, 30, 60)}
    wrong = next(c for c in ("000000", "111111", "222222") if c not in valid)

    for _ in range(5):
        with pytest.raises(InvalidSecondFactor):
            verify_2fa_flow(SecretStr(pre_auth), SecretStr(wrong))

    # Even a correct code is refused now; the user must enter the password again.
    with pytest.raises(TooManyAttempts):
        verify_2fa_flow(SecretStr(pre_auth), SecretStr(totp.totp(secret, time.time() + 30)))

    assert verify_2fa_flow(SecretStr(login()), SecretStr(totp.totp(secret, time.time() + 30))).access_token


def test_pre_auth_token_is_single_use(alice):
    secret, _, _ = enroll_and_activate()
    pre_auth = login()
    verify_2fa_flow(SecretStr(pre_auth), SecretStr(totp.totp(secret, time.time() - 30)))
    with pytest.raises(PreAuthTokenAlreadyUsed):
        verify_2fa_flow(SecretStr(pre_auth), SecretStr(totp.totp(secret, time.time() + 30)))


def test_activation_consumes_the_pre_auth_token(alice):
    pre_auth = login()
    secret = enroll_2fa_flow(SecretStr(pre_auth)).secret_base32
    activate_2fa_flow(SecretStr(pre_auth), SecretStr(totp.totp(secret)))
    with pytest.raises(PreAuthTokenAlreadyUsed):
        verify_2fa_flow(SecretStr(pre_auth), SecretStr(totp.totp(secret, time.time() + 30)))
