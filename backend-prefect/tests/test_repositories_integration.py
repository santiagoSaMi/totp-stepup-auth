"""Runs the real repositories against Supabase. Opt-in: RUN_DB_TESTS=1 pytest tests/test_repositories_integration.py

Creates a throwaway user and deletes it (cascading to its 2FA rows) at the end.
"""

import os
import uuid
from pathlib import Path

import psycopg
import pytest
from dotenv import dotenv_values
from psycopg_pool import ConnectionPool

from app.mfa import backup_codes, totp
from app.mfa.state import MFAStatus
from app.repositories import MFARepository, UserRepository, UsernameTaken

pytestmark = pytest.mark.skipif(os.environ.get("RUN_DB_TESTS") != "1", reason="set RUN_DB_TESTS=1 to run")


@pytest.fixture(scope="module")
def pool():
    # conftest.py replaces DATABASE_URL with a dummy, so read the real one from .env.
    url = dotenv_values(Path(__file__).resolve().parent.parent / ".env").get("DATABASE_URL")
    with ConnectionPool(url, min_size=1, max_size=2, kwargs={"autocommit": True}) as p:
        yield p


@pytest.fixture
def user(pool):
    created = UserRepository(pool).create(f"it-{uuid.uuid4().hex[:12]}", "not-a-real-hash")
    yield created
    with pool.connection() as conn:
        conn.execute("delete from users where id = %s", (created.id,))


def test_user_lookup_and_unique_username(pool, user):
    repo = UserRepository(pool)
    assert repo.get_by_username(user.username) == user
    assert repo.get_by_username("does-not-exist-" + uuid.uuid4().hex) is None
    with pytest.raises(UsernameTaken):
        repo.create(user.username, "x")


def test_full_mfa_lifecycle(pool, user):
    repo = MFARepository(pool)
    assert repo.get_config(user.id).status is MFAStatus.DISABLED

    secret = totp.generate_secret()
    assert repo.save_pending_secret(user.id, secret)
    assert repo.get_config(user.id).status is MFAStatus.PENDING_VERIFICATION
    assert repo.pending_secret(user.id) == secret

    # What actually sits in Supabase is ciphertext, never the secret.
    with pool.connection() as conn:
        stored = conn.execute("select secret_encrypted from mfa_configs where user_id = %s", (user.id,)).fetchone()[0]
    assert stored.startswith("v1:")
    assert secret not in stored
    assert repo.active_secret(user.id) is None

    codes = backup_codes.generate_codes()
    assert repo.activate(user.id, [backup_codes.hash_code(c) for c in codes])
    assert repo.get_config(user.id).status is MFAStatus.ACTIVE
    assert repo.active_secret(user.id) == secret
    assert repo.remaining_backup_codes(user.id) == 10

    # Already ACTIVE: neither activating again nor re-enrolling is allowed.
    assert not repo.activate(user.id, [])
    assert not repo.save_pending_secret(user.id, totp.generate_secret())
    assert repo.active_secret(user.id) == secret

    # The database refuses a plain-text secret even if the code had a bug.
    with pytest.raises(psycopg.errors.CheckViolation), pool.connection() as conn:
        conn.execute("update mfa_configs set secret_encrypted = %s where user_id = %s", (secret, user.id))

    code_hash = backup_codes.hash_code(codes[0])
    assert repo.consume(user.id, code_hash)
    assert not repo.consume(user.id, code_hash)
    assert repo.remaining_backup_codes(user.id) == 9
