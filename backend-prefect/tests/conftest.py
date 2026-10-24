import os

# Set before `app` is imported: app/__init__.py loads .env without overriding,
# so unit tests never use the real JWT secret or touch Supabase by accident.
os.environ["JWT_SECRET"] = "test-secret-" + "x" * 40
os.environ["DATABASE_URL"] = "postgresql://unused-in-unit-tests"
os.environ["MFA_ENCRYPTION_KEY"] = "dGVzdC1rZXktMzItYnl0ZXMtbG9uZy0tLS0tLS0tLS0"  # 32 bytes, tests only
os.environ["PRE_AUTH_TOKEN_TTL_SECONDS"] = "300"
os.environ["ACCESS_TOKEN_TTL_SECONDS"] = "900"
os.environ["TOTP_ISSUER"] = "Lab2FA"

import pytest  # noqa: E402
from prefect.testing.utilities import prefect_test_harness  # noqa: E402

from app import repositories  # noqa: E402
from app.mfa.pre_auth_guard import pre_auth_guard  # noqa: E402
from app.mfa.replay_cache import replay_cache  # noqa: E402
from tests.fakes import FakeMFARepository, FakeUserRepository  # noqa: E402


@pytest.fixture(scope="session")
def prefect_server():
    """Temporary Prefect server (SQLite) shared by every test that runs flows."""
    with prefect_test_harness():
        yield


@pytest.fixture
def fake_repos(monkeypatch):
    """In-memory repositories and a clean anti-replay / attempt-limit state."""
    users, mfa = FakeUserRepository(), FakeMFARepository()
    monkeypatch.setattr(repositories, "user_repository", lambda: users)
    monkeypatch.setattr(repositories, "mfa_repository", lambda: mfa)
    replay_cache.clear()
    pre_auth_guard.clear()
    return users, mfa
