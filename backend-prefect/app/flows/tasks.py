"""Prefect tasks shared by the login, provisioning and verification flows.

Secrets (passwords, codes, tokens) travel as pydantic `SecretStr`, so the
Prefect UI shows them as `**********` in the run parameters. Tasks never cache
or persist results, so no token or secret is written to Prefect's storage.
"""

import time
from dataclasses import dataclass
from uuid import UUID

from prefect import get_run_logger, task
from prefect.cache_policies import NONE
from pydantic import SecretStr

from app import repositories
from app.config import get_settings
from app.flows.errors import InvalidCredentials, InvalidPreAuthState, InvalidSecondFactor
from app.mfa import backup_codes, totp
from app.mfa.replay_cache import DEFAULT_TTL_SECONDS, ReplayAttackDetected, replay_cache
from app.mfa.state import InvalidTransition, MFAEvent, MFAStatus, next_status
from app.mfa.strategies.base import MFAMethod, VerificationResult
from app.mfa.strategies.factory import build_strategy
from app.mfa.strategies.totp_strategy import TOTPStrategy
from app.security import passwords, tokens
from app.security.tokens import InvalidToken, TokenScope

_TASK_OPTIONS = {"cache_policy": NONE, "persist_result": False, "retries": 0}

_WINDOW_EXPLANATIONS = {
    "C-1": "phone clock is behind the server, or the code was sent right after it rolled over",
    "C": "phone and server clocks are in sync",
    "C+1": "phone clock is ahead of the server",
}


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: UUID
    username: str
    mfa_status: MFAStatus


def mask(code: str) -> str:
    """`123456` -> `****56`: enough to recognise a code in the logs without revealing it."""
    return "*" * max(len(code) - 2, 0) + code[-2:]


def normalize_code(method: MFAMethod, code: str) -> str:
    """Canonical form used both for verification and as the anti-replay key."""
    if method is MFAMethod.BACKUP:
        return backup_codes.normalize(code)
    return code.strip().replace(" ", "")


# --- login ---


@task(name="verify_credentials", **_TASK_OPTIONS)
def verify_credentials(username: str, password: SecretStr) -> AuthenticatedUser:
    logger = get_run_logger()
    user = repositories.user_repository().get_by_username(username)
    if not passwords.verify_password(password.get_secret_value(), user.password_hash if user else None):
        logger.warning("invalid username or password for %r", username)
        raise InvalidCredentials("invalid username or password")

    status = repositories.mfa_repository().get_config(user.id).status
    logger.info("password OK for %r (2FA status: %s)", username, status)
    return AuthenticatedUser(user.id, user.username, status)


@task(name="issue_pre_auth_token", **_TASK_OPTIONS)
def issue_pre_auth_token(user: AuthenticatedUser) -> str:
    token = tokens.issue_pre_auth_token(user.user_id, user.username)
    get_run_logger().info(
        "issued pre_auth_token (scope=pre_auth, mfa_verified=false, expires in %ss)",
        get_settings().pre_auth_token_ttl_seconds,
    )
    return token


# --- Task 1 ---


@task(name="validate_pre_auth_state", **_TASK_OPTIONS)
def validate_pre_auth_state(
    pre_auth_token: SecretStr, allowed_statuses: tuple[MFAStatus, ...]
) -> AuthenticatedUser:
    logger = get_run_logger()
    try:
        claims = tokens.decode_token(pre_auth_token.get_secret_value(), TokenScope.PRE_AUTH)
    except InvalidToken as e:
        logger.error("rejected pre_auth_token: %s", e)
        raise InvalidPreAuthState(str(e)) from e

    status = repositories.mfa_repository().get_config(claims.user_id).status
    if status not in allowed_statuses:
        allowed = ", ".join(allowed_statuses)
        logger.error("user %r has 2FA %s; this step requires %s", claims.username, status, allowed)
        raise InvalidPreAuthState(f"2FA is {status}; this step requires {allowed}")

    logger.info(
        "pre_auth_token valid for %r (2FA status: %s, expires in %ss)",
        claims.username,
        status,
        claims.expires_at - int(time.time()),
    )
    return AuthenticatedUser(claims.user_id, claims.username, status)


# --- Task 2 ---


@task(name="check_anti_replay_cache", **_TASK_OPTIONS)
def check_anti_replay_cache(user: AuthenticatedUser, code: SecretStr) -> None:
    logger = get_run_logger()
    value = code.get_secret_value()
    if replay_cache.was_used(user.user_id, value):
        logger.error(
            "REPLAY ATTACK: code %s was already used by %r in the last %ss",
            mask(value),
            user.username,
            DEFAULT_TTL_SECONDS,
        )
        raise ReplayAttackDetected(user.user_id)
    logger.info("code %s not used by %r in the last %ss", mask(value), user.username, DEFAULT_TTL_SECONDS)


# --- Task 3 ---


def _log_match(result: VerificationResult) -> None:
    logger = get_run_logger()
    logger.info("%s", result.detail)
    if result.window:
        logger.info("TOTP window %s: %s", result.window, _WINDOW_EXPLANATIONS[result.window])


@task(name="execute_mfa_strategy", **_TASK_OPTIONS)
def execute_mfa_strategy(user: AuthenticatedUser, code: SecretStr, method: MFAMethod) -> VerificationResult:
    logger = get_run_logger()
    repo = repositories.mfa_repository()
    strategy = build_strategy(method, secret_provider=repo.active_secret, backup_store=repo)
    logger.info("strategy selected: %s", type(strategy).__name__)

    result = strategy.verify(user.user_id, code.get_secret_value())
    if not result.success:
        logger.error("second factor rejected for %r: %s", user.username, result.detail)
        raise InvalidSecondFactor(result.detail)

    _log_match(result)
    if method is MFAMethod.BACKUP:
        logger.info("%r has %s backup codes left", user.username, repo.remaining_backup_codes(user.user_id))
    return result


# --- Task 4 ---


@task(name="issue_elevated_session", **_TASK_OPTIONS)
def issue_elevated_session(user: AuthenticatedUser, code: SecretStr, method: MFAMethod) -> str:
    logger = get_run_logger()
    # Raises ReplayAttackDetected if a concurrent request used the same code
    # between Task 2 and now.
    replay_cache.mark_used(user.user_id, code.get_secret_value())
    logger.info("code %s marked as used for %ss", mask(code.get_secret_value()), DEFAULT_TTL_SECONDS)

    token = tokens.issue_access_token(user.user_id, user.username, method)
    logger.info(
        "issued access_token for %r (mfa_verified=true, method=%s, expires in %ss)",
        user.username,
        method,
        get_settings().access_token_ttl_seconds,
    )
    return token


# --- provisioning ---


@dataclass(frozen=True)
class Enrollment:
    secret_base32: str
    otpauth_uri: str


@task(name="start_enrollment", **_TASK_OPTIONS)
def start_enrollment(user: AuthenticatedUser) -> Enrollment:
    logger = get_run_logger()
    new_status = next_status(user.mfa_status, MFAEvent.ENROLL)

    secret = totp.generate_secret()
    if not repositories.mfa_repository().save_pending_secret(user.user_id, secret):
        # 2FA became ACTIVE between Task 1 and now.
        raise InvalidTransition(MFAStatus.ACTIVE, MFAEvent.ENROLL)

    logger.info("2FA state for %r: %s -> %s (new secret generated)", user.username, user.mfa_status, new_status)
    uri = totp.build_otpauth_uri(secret, user.username, get_settings().totp_issuer)
    return Enrollment(secret, uri)


@task(name="verify_enrollment_code", **_TASK_OPTIONS)
def verify_enrollment_code(user: AuthenticatedUser, code: SecretStr) -> VerificationResult:
    logger = get_run_logger()
    strategy = TOTPStrategy(repositories.mfa_repository().pending_secret)
    result = strategy.verify(user.user_id, code.get_secret_value())
    if not result.success:
        logger.error("first code from the app rejected for %r: %s", user.username, result.detail)
        raise InvalidSecondFactor(result.detail)

    _log_match(result)
    return result


@task(name="activate_mfa", **_TASK_OPTIONS)
def activate_mfa(user: AuthenticatedUser) -> list[str]:
    logger = get_run_logger()
    new_status = next_status(user.mfa_status, MFAEvent.ACTIVATE)

    codes = backup_codes.generate_codes()
    if not repositories.mfa_repository().activate(user.user_id, [backup_codes.hash_code(c) for c in codes]):
        raise InvalidTransition(user.mfa_status, MFAEvent.ACTIVATE)

    logger.info("2FA state for %r: %s -> %s", user.username, user.mfa_status, new_status)
    logger.info("generated %s single-use backup codes (stored hashed)", len(codes))
    return codes
