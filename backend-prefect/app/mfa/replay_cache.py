"""In-memory anti-replay cache for second-factor codes.

A TOTP code is accepted in windows C-1, C and C+1, so it stays valid for up
to 3 x 30s = 90s. Remembering each used (user_id, code) for 90s is enough to
make every code single-use.
"""

import threading
import time
from collections.abc import Callable
from uuid import UUID

DEFAULT_TTL_SECONDS = 90


class ReplayAttackDetected(Exception):
    def __init__(self, user_id: UUID):
        super().__init__(f"code already used by user {user_id} within the last {DEFAULT_TTL_SECONDS}s")
        self.user_id = user_id


class ReplayCache:
    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS, clock: Callable[[], float] = time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._expires_at: dict[tuple[UUID, str], float] = {}
        # FastAPI runs sync endpoints in a thread pool, so access must be locked.
        self._lock = threading.Lock()

    def was_used(self, user_id: UUID, code: str) -> bool:
        with self._lock:
            self._purge_expired()
            return (user_id, code) in self._expires_at

    def mark_used(self, user_id: UUID, code: str) -> None:
        """Record the code. Raises if a concurrent request marked it first."""
        with self._lock:
            self._purge_expired()
            key = (user_id, code)
            if key in self._expires_at:
                raise ReplayAttackDetected(user_id)
            self._expires_at[key] = self._clock() + self._ttl

    def clear(self) -> None:
        with self._lock:
            self._expires_at.clear()

    def _purge_expired(self) -> None:
        now = self._clock()
        for key in [k for k, expiry in self._expires_at.items() if expiry <= now]:
            del self._expires_at[key]


# Single process-wide cache shared by every request.
replay_cache = ReplayCache()
