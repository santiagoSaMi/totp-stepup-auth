"""HTTP API tests: the whole Step-Up flow as the web app performs it."""

import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.mfa import totp

PASSWORD = "s3cret-password"


@pytest.fixture(autouse=True)
def _isolated(prefect_server, fake_repos):
    pass


@pytest.fixture
def client():
    return TestClient(app)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def register_and_login(client, username="alice") -> dict:
    assert client.post("/auth/register", json={"username": username, "password": PASSWORD}).status_code == 201
    res = client.post("/auth/login", json={"username": username, "password": PASSWORD})
    assert res.status_code == 200
    return res.json()


def enroll_and_activate(client) -> tuple[str, list[str]]:
    pre_auth = register_and_login(client)["pre_auth_token"]
    secret = client.post("/2fa/enroll", headers=bearer(pre_auth)).json()["secret"]
    res = client.post("/2fa/activate", headers=bearer(pre_auth), json={"code": totp.totp(secret)})
    assert res.status_code == 200
    return secret, res.json()["backup_codes"]


def login(client) -> str:
    return client.post("/auth/login", json={"username": "alice", "password": PASSWORD}).json()["pre_auth_token"]


# --- registration and login ---


def test_register_normalizes_username(client):
    res = client.post("/auth/register", json={"username": "  Alice ", "password": PASSWORD})
    assert res.status_code == 201
    assert res.json()["username"] == "alice"


def test_register_rejects_duplicates_and_bad_input(client):
    client.post("/auth/register", json={"username": "alice", "password": PASSWORD})
    dup = client.post("/auth/register", json={"username": "alice", "password": PASSWORD})
    assert dup.status_code == 409
    assert dup.json()["error"] == "username_taken"

    assert client.post("/auth/register", json={"username": "a", "password": PASSWORD}).status_code == 422
    assert client.post("/auth/register", json={"username": "bob", "password": "short"}).status_code == 422
    assert client.post("/auth/register", json={"username": "bob", "password": "x" * 73}).status_code == 422


def test_login_gives_pre_auth_token_and_next_step(client):
    body = register_and_login(client)
    assert body["next_step"] == "enroll-2fa"
    assert body["mfa_status"] == "DISABLED"
    assert "access_token" not in body


def test_login_with_wrong_password_is_401(client):
    register_and_login(client)
    res = client.post("/auth/login", json={"username": "alice", "password": "nope-nope"})
    assert res.status_code == 401
    assert res.json() == {"error": "invalid_credentials", "detail": "invalid username or password"}


def test_token_responses_are_not_cacheable(client):
    res = client.post("/auth/login", json={"username": "nobody", "password": "whatever"})
    assert res.headers["cache-control"] == "no-store"


# --- provisioning ---


def test_enroll_returns_qr_and_secret(client):
    pre_auth = register_and_login(client)["pre_auth_token"]
    body = client.post("/2fa/enroll", headers=bearer(pre_auth)).json()
    assert body["otpauth_uri"].startswith("otpauth://totp/Lab2FA:alice?secret=")
    assert body["qr_svg"].startswith("data:image/svg+xml;base64,")
    assert len(body["secret"]) == 32


def test_activate_returns_session_and_backup_codes(client):
    secret, codes = enroll_and_activate(client)
    assert len(codes) == 10
    assert client.post("/auth/login", json={"username": "alice", "password": PASSWORD}).json()["next_step"] == "verify-2fa"


def test_endpoints_require_bearer(client):
    assert client.post("/2fa/enroll").status_code == 401
    assert client.post("/auth/verify-2fa", json={"code": "123456"}).status_code == 401
    assert client.get("/api/boveda-secreta").status_code == 401


# --- the 4 demo tests ---


def test_step_up_vault_needs_mfa(client):
    secret, _ = enroll_and_activate(client)
    pre_auth = login(client)

    denied = client.get("/api/boveda-secreta", headers=bearer(pre_auth))
    assert denied.status_code == 401
    assert denied.json()["error"] == "invalid_token"

    res = client.post("/auth/verify-2fa", headers=bearer(pre_auth), json={"code": totp.totp(secret, time.time() + 30)})
    assert res.status_code == 200
    assert res.json()["window"] == "C+1"

    vault = client.get("/api/boveda-secreta", headers=bearer(res.json()["access_token"]))
    assert vault.status_code == 200
    assert vault.json()["mfa_verified"] is True


def test_replay_is_409(client):
    secret, _ = enroll_and_activate(client)
    code = totp.totp(secret, time.time() - 30)
    assert client.post("/auth/verify-2fa", headers=bearer(login(client)), json={"code": code}).status_code == 200

    replay = client.post("/auth/verify-2fa", headers=bearer(login(client)), json={"code": code})
    assert replay.status_code == 409
    assert replay.json()["error"] == "replay_detected"


def test_backup_code_login(client):
    _, codes = enroll_and_activate(client)
    res = client.post("/auth/verify-2fa", headers=bearer(login(client)), json={"code": codes[3], "method": "backup"})
    assert res.status_code == 200
    assert res.json()["mfa_method"] == "backup"
    assert res.json()["window"] is None


def test_too_many_attempts_is_429(client):
    secret, _ = enroll_and_activate(client)
    pre_auth = login(client)
    valid = {totp.totp(secret, time.time() + d) for d in (-60, -30, 0, 30, 60)}
    wrong = next(c for c in ("000000", "111111", "222222") if c not in valid)

    for _ in range(5):
        assert client.post("/auth/verify-2fa", headers=bearer(pre_auth), json={"code": wrong}).status_code == 401
    res = client.post("/auth/verify-2fa", headers=bearer(pre_auth), json={"code": wrong})
    assert res.status_code == 429
    assert res.json()["error"] == "too_many_attempts"


def test_unknown_method_is_422(client):
    res = client.post("/auth/verify-2fa", headers=bearer("x"), json={"code": "123456", "method": "sms"})
    assert res.status_code == 422


# --- static web app ---


@pytest.mark.parametrize("page", ["/", "/enroll.html", "/verify.html", "/vault.html", "/js/api.js", "/style.css"])
def test_web_pages_are_served(client, page):
    assert client.get(page).status_code == 200
