"""Limits what a single pre_auth_token can do.

- Brute force: after MAX_FAILURES wrong codes the token is locked and the user
  must log in again with their password. Without this, 5 minutes of guessing
  against 3 valid windows out of 10^6 codes would be a real risk.
- Single use: once a token has produced an access token it can't be used again.

Tokens are tracked by their `jti` until they expire, in memory, like the replay cache.
"""

import threading
import time
from collections.abc import Callable

MAX_FAILURES = 5


class TooManyAttempts(Exception):
    def __init__(self):
        super().__init__(f"{MAX_FAILURES} failed attempts with this pre_auth_token; log in again")


class PreAuthTokenAlreadyUsed(Exception):
    def __init__(self):
        super().__init__("this pre_auth_token was already exchanged for an access token; log in again")


class PreAuthGuard:
    def __init__(self, max_failures: int = MAX_FAILURES, clock: Callable[[], float] = time.time):
        self._max_failures = max_failures
        self._clock = clock
        self._failures: dict[str, int] = {}
        self._consumed: set[str] = set()
        self._expires_at: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, token_id: str) -> None:
        with self._lock:
            self._purge_expired()
            if token_id in self._consumed:
                raise PreAuthTokenAlreadyUsed()
            if self._failures.get(token_id, 0) >= self._max_failures:
                raise TooManyAttempts()

    def record_failure(self, token_id: str, expires_at: float) -> int:
        """Count a failed attempt. Returns how many attempts are left."""
        with self._lock:
            self._failures[token_id] = self._failures.get(token_id, 0) + 1
            self._expires_at[token_id] = expires_at
            return max(self._max_failures - self._failures[token_id], 0)

    def consume(self, token_id: str, expires_at: float) -> None:
        with self._lock:
            if token_id in self._consumed:
                raise PreAuthTokenAlreadyUsed()
            self._consumed.add(token_id)
            self._expires_at[token_id] = expires_at

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()
            self._consumed.clear()
            self._expires_at.clear()

    def _purge_expired(self) -> None:
        now = self._clock()
        for token_id in [t for t, exp in self._expires_at.items() if exp <= now]:
            self._failures.pop(token_id, None)
            self._consumed.discard(token_id)
            del self._expires_at[token_id]


pre_auth_guard = PreAuthGuard()
