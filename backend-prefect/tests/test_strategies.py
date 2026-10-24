from uuid import UUID, uuid4

import pytest

from app.mfa import backup_codes, totp
from app.mfa.strategies.backup_code_strategy import BackupCodeStrategy
from app.mfa.strategies.base import MFAMethod, SecondFactorStrategy
from app.mfa.strategies.factory import UnknownMFAMethod, build_strategy
from app.mfa.strategies.totp_strategy import TOTPStrategy

NOW = 1_700_000_000.0
SECRET = totp.generate_secret()
ALICE = uuid4()
BOB = uuid4()


class InMemoryBackupStore:
    def __init__(self, codes_by_user: dict[UUID, list[str]]):
        self.unused = {(user, backup_codes.hash_code(c)) for user, codes in codes_by_user.items() for c in codes}

    def consume(self, user_id: UUID, code_hash: str) -> bool:
        key = (user_id, code_hash)
        if key in self.unused:
            self.unused.remove(key)
            return True
        return False


def secrets_for(mapping: dict[UUID, str]):
    return lambda user_id: mapping.get(user_id)


# --- TOTPStrategy ---


@pytest.mark.parametrize("skew, label", [(-30, "C-1"), (0, "C"), (30, "C+1")])
def test_totp_strategy_reports_matching_window(skew, label):
    strategy = TOTPStrategy(secrets_for({ALICE: SECRET}), clock=lambda: NOW)
    result = strategy.verify(ALICE, totp.totp(SECRET, NOW + skew))
    assert result.success
    assert result.method is MFAMethod.TOTP
    assert result.window == label
    assert label in result.detail


def test_totp_strategy_rejects_code_outside_windows():
    strategy = TOTPStrategy(secrets_for({ALICE: SECRET}), clock=lambda: NOW)
    result = strategy.verify(ALICE, totp.totp(SECRET, NOW + 90))
    assert not result.success
    assert result.window is None


def test_totp_strategy_fails_when_user_has_no_secret():
    strategy = TOTPStrategy(secrets_for({ALICE: SECRET}), clock=lambda: NOW)
    result = strategy.verify(BOB, totp.totp(SECRET, NOW))
    assert not result.success
    assert "no TOTP secret" in result.detail


def test_totp_strategy_uses_each_users_own_secret():
    bob_secret = totp.generate_secret()
    strategy = TOTPStrategy(secrets_for({ALICE: SECRET, BOB: bob_secret}), clock=lambda: NOW)
    assert not strategy.verify(BOB, totp.totp(SECRET, NOW)).success
    assert strategy.verify(BOB, totp.totp(bob_secret, NOW)).success


# --- backup code helpers ---


def test_generate_codes_format():
    codes = backup_codes.generate_codes()
    assert len(codes) == backup_codes.DEFAULT_COUNT
    assert len(set(codes)) == len(codes)
    for code in codes:
        first, second = code.split("-")
        assert len(first) == len(second) == 5
        assert backup_codes.is_well_formed(code)


def test_hash_ignores_formatting():
    assert backup_codes.hash_code("K7QX2-MNP4R") == backup_codes.hash_code(" k7qx2 mnp4r")


@pytest.mark.parametrize("code", ["", "K7QX2-MNP4", "K7QX2-MNP4RR", "K7QX0-MNP4R", "K7QX2-MNP4!"])
def test_is_well_formed_rejects_bad_codes(code):
    assert not backup_codes.is_well_formed(code)


# --- BackupCodeStrategy ---


def test_backup_code_is_single_use():
    code = backup_codes.generate_codes(1)[0]
    strategy = BackupCodeStrategy(InMemoryBackupStore({ALICE: [code]}))

    first = strategy.verify(ALICE, code)
    assert first.success
    assert first.method is MFAMethod.BACKUP

    second = strategy.verify(ALICE, code)
    assert not second.success
    assert "already used" in second.detail


def test_backup_code_accepts_lowercase_without_dash():
    code = backup_codes.generate_codes(1)[0]
    strategy = BackupCodeStrategy(InMemoryBackupStore({ALICE: [code]}))
    assert strategy.verify(ALICE, code.replace("-", "").lower()).success


def test_backup_code_belongs_to_its_user():
    code = backup_codes.generate_codes(1)[0]
    strategy = BackupCodeStrategy(InMemoryBackupStore({ALICE: [code]}))
    assert not strategy.verify(BOB, code).success
    assert strategy.verify(ALICE, code).success


def test_malformed_backup_code_does_not_touch_store():
    class ExplodingStore:
        def consume(self, user_id, code_hash):
            raise AssertionError("store should not be called")

    result = BackupCodeStrategy(ExplodingStore()).verify(ALICE, "123456")
    assert not result.success
    assert "malformed" in result.detail


# --- factory ---


@pytest.mark.parametrize(
    "method, expected_type",
    [("totp", TOTPStrategy), (MFAMethod.TOTP, TOTPStrategy), ("backup", BackupCodeStrategy)],
)
def test_factory_builds_requested_strategy(method, expected_type):
    strategy = build_strategy(method, secret_provider=secrets_for({}), backup_store=InMemoryBackupStore({}))
    assert isinstance(strategy, expected_type)
    assert isinstance(strategy, SecondFactorStrategy)


def test_factory_rejects_unknown_method():
    with pytest.raises(UnknownMFAMethod):
        build_strategy("sms", secret_provider=secrets_for({}), backup_store=InMemoryBackupStore({}))
