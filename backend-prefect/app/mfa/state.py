"""State machine for a user's 2FA configuration (secure provisioning).

    DISABLED ──enroll──▶ PENDING_VERIFICATION ──activate──▶ ACTIVE
                              │      ▲
                              └enroll┘  (re-enrolling regenerates the QR)

2FA only becomes ACTIVE after the user proves, with a valid code from their
app, that they scanned the QR. A user who generates a QR and never scans it
stays PENDING and can still log in to finish enrollment instead of being locked out.
"""

from enum import StrEnum


class MFAStatus(StrEnum):
    DISABLED = "DISABLED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"


class MFAEvent(StrEnum):
    ENROLL = "enroll"
    ACTIVATE = "activate"


class InvalidTransition(Exception):
    def __init__(self, current: MFAStatus, event: MFAEvent):
        super().__init__(f"cannot {event} while 2FA is {current}")
        self.current = current
        self.event = event


_TRANSITIONS: dict[tuple[MFAStatus, MFAEvent], MFAStatus] = {
    (MFAStatus.DISABLED, MFAEvent.ENROLL): MFAStatus.PENDING_VERIFICATION,
    (MFAStatus.PENDING_VERIFICATION, MFAEvent.ENROLL): MFAStatus.PENDING_VERIFICATION,
    (MFAStatus.PENDING_VERIFICATION, MFAEvent.ACTIVATE): MFAStatus.ACTIVE,
}


def next_status(current: MFAStatus, event: MFAEvent) -> MFAStatus:
    try:
        return _TRANSITIONS[(current, event)]
    except KeyError:
        raise InvalidTransition(current, event) from None
