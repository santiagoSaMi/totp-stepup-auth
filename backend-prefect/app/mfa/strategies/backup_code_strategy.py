from typing import Protocol
from uuid import UUID

from app.mfa import backup_codes
from app.mfa.strategies.base import MFAMethod, SecondFactorStrategy, VerificationResult


class BackupCodeStore(Protocol):
    def consume(self, user_id: UUID, code_hash: str) -> bool:
        """Atomically mark an unused code as used. True if a code was consumed."""
        ...


class BackupCodeStrategy(SecondFactorStrategy):
    method = MFAMethod.BACKUP

    def __init__(self, store: BackupCodeStore):
        self._store = store

    def verify(self, user_id: UUID, code: str) -> VerificationResult:
        if not backup_codes.is_well_formed(code):
            return VerificationResult(False, self.method, "malformed backup code")

        if not self._store.consume(user_id, backup_codes.hash_code(code)):
            return VerificationResult(False, self.method, "backup code is invalid or already used")

        return VerificationResult(True, self.method, "backup code accepted and consumed")
