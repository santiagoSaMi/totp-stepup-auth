import time
from collections.abc import Callable
from uuid import UUID

from app.mfa import totp
from app.mfa.strategies.base import MFAMethod, SecondFactorStrategy, VerificationResult

# Returns the user's Base32 secret, or None if there is none. Login passes a
# provider for ACTIVE configs; activation passes one for the PENDING secret.
SecretProvider = Callable[[UUID], str | None]


class TOTPStrategy(SecondFactorStrategy):
    method = MFAMethod.TOTP

    def __init__(self, secret_provider: SecretProvider, clock: Callable[[], float] = time.time):
        self._secret_provider = secret_provider
        self._clock = clock

    def verify(self, user_id: UUID, code: str) -> VerificationResult:
        secret = self._secret_provider(user_id)
        if secret is None:
            return VerificationResult(False, self.method, "user has no TOTP secret configured")

        match = totp.verify(secret, code, self._clock())
        if match is None:
            return VerificationResult(False, self.method, "code does not match windows C-1, C or C+1")

        return VerificationResult(
            True,
            self.method,
            f"code matched window {match.label} (counter {match.counter})",
            window=match.label,
        )
