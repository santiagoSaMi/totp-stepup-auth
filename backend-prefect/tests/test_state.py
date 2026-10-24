import pytest

from app.mfa.state import InvalidTransition, MFAEvent, MFAStatus, next_status


@pytest.mark.parametrize(
    "current, event, expected",
    [
        (MFAStatus.DISABLED, MFAEvent.ENROLL, MFAStatus.PENDING_VERIFICATION),
        (MFAStatus.PENDING_VERIFICATION, MFAEvent.ENROLL, MFAStatus.PENDING_VERIFICATION),
        (MFAStatus.PENDING_VERIFICATION, MFAEvent.ACTIVATE, MFAStatus.ACTIVE),
    ],
)
def test_allowed_transitions(current, event, expected):
    assert next_status(current, event) is expected


@pytest.mark.parametrize(
    "current, event",
    [
        (MFAStatus.DISABLED, MFAEvent.ACTIVATE),  # can't activate without a scanned secret
        (MFAStatus.ACTIVE, MFAEvent.ENROLL),  # can't silently replace an active secret
        (MFAStatus.ACTIVE, MFAEvent.ACTIVATE),
    ],
)
def test_forbidden_transitions(current, event):
    with pytest.raises(InvalidTransition) as exc:
        next_status(current, event)
    assert exc.value.current is current
    assert exc.value.event is event
