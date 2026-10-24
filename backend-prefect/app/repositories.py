"""Data access for users, 2FA configs and backup codes (Supabase Postgres)."""

from dataclasses import dataclass, field
from functools import lru_cache
from uuid import UUID

import psycopg
from psycopg.rows import class_row
from psycopg_pool import ConnectionPool

from app.db import get_pool
from app.mfa.state import MFAStatus
from app.security.secret_box import decrypt_secret, encrypt_secret


@dataclass(frozen=True)
class User:
    id: UUID
    username: str
    password_hash: str


@dataclass(frozen=True)
class MFAConfig:
    user_id: UUID
    status: MFAStatus
    secret_base32: str | None = field(repr=False)  # decrypted; only ever held in memory


class UsernameTaken(Exception):
    pass


class UserRepository:
    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def create(self, username: str, password_hash: str) -> User:
        try:
            with self._pool.connection() as conn:
                return conn.cursor(row_factory=class_row(User)).execute(
                    "insert into users (username, password_hash) values (%s, %s)"
                    " returning id, username, password_hash",
                    (username, password_hash),
                ).fetchone()
        except psycopg.errors.UniqueViolation:
            raise UsernameTaken(username) from None

    def get_by_username(self, username: str) -> User | None:
        with self._pool.connection() as conn:
            return conn.cursor(row_factory=class_row(User)).execute(
                "select id, username, password_hash from users where username = %s", (username,)
            ).fetchone()


class MFARepository:
    """2FA config and backup codes. Also implements the BackupCodeStore protocol.

    TOTP secrets are encrypted here before they reach the database and
    decrypted here when read; the rest of the code only sees the plain secret.
    """

    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def get_config(self, user_id: UUID) -> MFAConfig:
        with self._pool.connection() as conn:
            row = conn.execute(
                "select status, secret_encrypted from mfa_configs where user_id = %s", (user_id,)
            ).fetchone()
        if row is None:
            return MFAConfig(user_id, MFAStatus.DISABLED, None)
        status, encrypted = row
        secret = decrypt_secret(encrypted, user_id) if encrypted else None
        return MFAConfig(user_id, MFAStatus(status), secret)

    def active_secret(self, user_id: UUID) -> str | None:
        config = self.get_config(user_id)
        return config.secret_base32 if config.status is MFAStatus.ACTIVE else None

    def pending_secret(self, user_id: UUID) -> str | None:
        config = self.get_config(user_id)
        return config.secret_base32 if config.status is MFAStatus.PENDING_VERIFICATION else None

    def save_pending_secret(self, user_id: UUID, secret_base32: str) -> bool:
        """Store a new secret as PENDING_VERIFICATION. False if 2FA is already ACTIVE."""
        with self._pool.connection() as conn:
            row = conn.execute(
                """
                insert into mfa_configs (user_id, secret_encrypted, status)
                values (%s, %s, 'PENDING_VERIFICATION')
                on conflict (user_id) do update
                    set secret_encrypted = excluded.secret_encrypted,
                        status = excluded.status,
                        updated_at = now()
                    where mfa_configs.status <> 'ACTIVE'
                returning user_id
                """,
                (user_id, encrypt_secret(secret_base32, user_id)),
            ).fetchone()
        return row is not None

    def activate(self, user_id: UUID, backup_code_hashes: list[str]) -> bool:
        """PENDING_VERIFICATION -> ACTIVE and replace the backup codes, atomically."""
        with self._pool.connection() as conn, conn.transaction():
            row = conn.execute(
                """
                update mfa_configs
                set status = 'ACTIVE', activated_at = now(), updated_at = now()
                where user_id = %s and status = 'PENDING_VERIFICATION'
                returning user_id
                """,
                (user_id,),
            ).fetchone()
            if row is None:
                return False
            conn.execute("delete from backup_codes where user_id = %s", (user_id,))
            conn.cursor().executemany(
                "insert into backup_codes (user_id, code_hash) values (%s, %s)",
                [(user_id, h) for h in backup_code_hashes],
            )
        return True

    def consume(self, user_id: UUID, code_hash: str) -> bool:
        with self._pool.connection() as conn:
            row = conn.execute(
                """
                update backup_codes set used_at = now()
                where user_id = %s and code_hash = %s and used_at is null
                returning id
                """,
                (user_id, code_hash),
            ).fetchone()
        return row is not None

    def remaining_backup_codes(self, user_id: UUID) -> int:
        with self._pool.connection() as conn:
            return conn.execute(
                "select count(*) from backup_codes where user_id = %s and used_at is null", (user_id,)
            ).fetchone()[0]


@lru_cache
def user_repository() -> UserRepository:
    return UserRepository(get_pool())


@lru_cache
def mfa_repository() -> MFARepository:
    return MFARepository(get_pool())
