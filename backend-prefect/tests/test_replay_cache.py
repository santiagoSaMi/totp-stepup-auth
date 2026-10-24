from uuid import uuid4

import pytest

from app.mfa.replay_cache import ReplayAttackDetected, ReplayCache

ALICE = uuid4()
BOB = uuid4()


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_unused_code_is_not_flagged():
    assert not ReplayCache().was_used(ALICE, "123456")


def test_used_code_is_flagged():
    cache = ReplayCache()
    cache.mark_used(ALICE, "123456")
    assert cache.was_used(ALICE, "123456")


def test_codes_are_tracked_per_user():
    cache = ReplayCache()
    cache.mark_used(ALICE, "123456")
    assert not cache.was_used(BOB, "123456")


def test_entry_expires_after_ttl():
    clock = FakeClock()
    cache = ReplayCache(ttl_seconds=90, clock=clock)
    cache.mark_used(ALICE, "123456")

    clock.now += 89.9
    assert cache.was_used(ALICE, "123456")
    clock.now += 0.1
    assert not cache.was_used(ALICE, "123456")


def test_marking_twice_raises():
    # Covers the race where two requests pass the check before either marks the code.
    cache = ReplayCache()
    cache.mark_used(ALICE, "123456")
    with pytest.raises(ReplayAttackDetected):
        cache.mark_used(ALICE, "123456")


def test_code_can_be_marked_again_after_expiry():
    clock = FakeClock()
    cache = ReplayCache(ttl_seconds=90, clock=clock)
    cache.mark_used(ALICE, "123456")
    clock.now += 90
    cache.mark_used(ALICE, "123456")  # does not raise
