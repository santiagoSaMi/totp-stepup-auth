"""Strategy pattern for the second authentication factor."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar
from uuid import UUID


class MFAMethod(StrEnum):
    TOTP = "totp"
    BACKUP = "backup"


@dataclass(frozen=True)
class VerificationResult:
    success: bool
    method: MFAMethod
    detail: str  # human-readable, meant for the Prefect logs
    window: str | None = None  # TOTP only: "C-1", "C" or "C+1"


class SecondFactorStrategy(ABC):
    """Interchangeable way of checking a user's second factor."""

    method: ClassVar[MFAMethod]

    @abstractmethod
    def verify(self, user_id: UUID, code: str) -> VerificationResult: ...
