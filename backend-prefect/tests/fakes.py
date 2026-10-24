"""In-memory stand-ins for the Supabase repositories."""

import uuid
from uuid import UUID

from app.mfa.state import MFAStatus
from app.repositories import MFAConfig, User, UsernameTaken


class FakeUserRepository:
    def __init__(self):
        self.by_username: dict[str, User] = {}

    def create(self, username: str, password_hash: str) -> User:
        if username in self.by_username:
            raise UsernameTaken(username)
        user = User(uuid.uuid4(), username, password_hash)
        self.by_username[username] = user
        return user

    def get_by_username(self, username: str) -> User | None:
        return self.by_username.get(username)


class FakeMFARepository:
    def __init__(self):
        self.configs: dict[UUID, MFAConfig] = {}
        self.backup: dict[UUID, dict[str, bool]] = {}  # user -> {hash: used}

    def get_config(self, user_id: UUID) -> MFAConfig:
        return self.configs.get(user_id, MFAConfig(user_id, MFAStatus.DISABLED, None))

    def active_secret(self, user_id: UUID) -> str | None:
        c = self.get_config(user_id)
        return c.secret_base32 if c.status is MFAStatus.ACTIVE else None

    def pending_secret(self, user_id: UUID) -> str | None:
        c = self.get_config(user_id)
        return c.secret_base32 if c.status is MFAStatus.PENDING_VERIFICATION else None

    def save_pending_secret(self, user_id: UUID, secret_base32: str) -> bool:
        if self.get_config(user_id).status is MFAStatus.ACTIVE:
            return False
        self.configs[user_id] = MFAConfig(user_id, MFAStatus.PENDING_VERIFICATION, secret_base32)
        return True

    def activate(self, user_id: UUID, backup_code_hashes: list[str]) -> bool:
        c = self.get_config(user_id)
        if c.status is not MFAStatus.PENDING_VERIFICATION:
            return False
        self.configs[user_id] = MFAConfig(user_id, MFAStatus.ACTIVE, c.secret_base32)
        self.backup[user_id] = {h: False for h in backup_code_hashes}
        return True

    def consume(self, user_id: UUID, code_hash: str) -> bool:
        codes = self.backup.get(user_id, {})
        if codes.get(code_hash) is False:
            codes[code_hash] = True
            return True
        return False

    def remaining_backup_codes(self, user_id: UUID) -> int:
        return sum(not used for used in self.backup.get(user_id, {}).values())
