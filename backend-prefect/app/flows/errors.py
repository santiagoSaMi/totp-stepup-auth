"""Exceptions raised inside Prefect tasks. Each one marks its task (and the flow) as Failed.

ReplayAttackDetected, TooManyAttempts, PreAuthTokenAlreadyUsed and
InvalidTransition live next to the code that raises them; they are re-exported
here so the API can map all of them in one place.
"""

from app.mfa.pre_auth_guard import PreAuthTokenAlreadyUsed, TooManyAttempts
from app.mfa.replay_cache import ReplayAttackDetected
from app.mfa.state import InvalidTransition


class InvalidCredentials(Exception):
    pass


class InvalidPreAuthState(Exception):
    pass


class InvalidSecondFactor(Exception):
    pass


__all__ = [
    "InvalidCredentials",
    "InvalidPreAuthState",
    "InvalidSecondFactor",
    "InvalidTransition",
    "PreAuthTokenAlreadyUsed",
    "ReplayAttackDetected",
    "TooManyAttempts",
]
