"""Exceptions raised inside Prefect tasks. Each one marks its task (and the flow) as Failed.

ReplayAttackDetected lives in app.mfa.replay_cache and InvalidTransition in
app.mfa.state; they are re-exported here so the API can map all of them in one place.
"""

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
    "ReplayAttackDetected",
]
