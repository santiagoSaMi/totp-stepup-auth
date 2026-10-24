import pytest

from app.mfa.pre_auth_guard import PreAuthGuard, PreAuthTokenAlreadyUsed, TooManyAttempts


class FakeClock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


def test_locks_after_max_failures():
    guard = PreAuthGuard(max_failures=3)
    assert guard.record_failure("t1", expires_at=9e9) == 2
    assert guard.record_failure("t1", expires_at=9e9) == 1
    guard.check("t1")  # still allowed
    assert guard.record_failure("t1", expires_at=9e9) == 0
    with pytest.raises(TooManyAttempts):
        guard.check("t1")


def test_failures_are_counted_per_token():
    guard = PreAuthGuard(max_failures=1)
    guard.record_failure("t1", expires_at=9e9)
    guard.check("t2")  # a fresh login is not affected


def test_consumed_token_cannot_be_used_again():
    guard = PreAuthGuard()
    guard.check("t1")
    guard.consume("t1", expires_at=9e9)
    with pytest.raises(PreAuthTokenAlreadyUsed):
        guard.check("t1")
    with pytest.raises(PreAuthTokenAlreadyUsed):
        guard.consume("t1", expires_at=9e9)


def test_entries_are_forgotten_once_the_token_expires():
    clock = FakeClock()
    guard = PreAuthGuard(max_failures=1, clock=clock)
    guard.record_failure("t1", expires_at=clock.now + 300)
    guard.consume("t2", expires_at=clock.now + 300)

    clock.now += 300
    guard.check("t1")  # the JWT itself is expired by now, so nothing is lost
    guard.check("t2")
