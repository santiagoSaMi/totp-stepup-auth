import base64
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from app.mfa import totp

# Shared secret used by the RFC 4226 / RFC 6238 test vectors (ASCII "12345678901234567890").
RFC_KEY = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_KEY).decode()  # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ


# RFC 4226, Appendix D: HOTP values for counters 0..9.
@pytest.mark.parametrize(
    "counter, expected",
    list(
        enumerate(
            [
                "755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489",
            ]
        )
    ),
)
def test_hotp_rfc4226_vectors(counter, expected):
    assert totp.hotp(RFC_KEY, counter) == expected


# RFC 6238, Appendix B: TOTP (SHA1, 30s step, 8 digits).
RFC6238_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("timestamp, expected", RFC6238_VECTORS)
def test_totp_rfc6238_vectors_8_digits(timestamp, expected):
    assert totp.totp(RFC_SECRET_B32, timestamp, digits=8) == expected


@pytest.mark.parametrize("timestamp, expected", RFC6238_VECTORS)
def test_totp_rfc6238_vectors_6_digits(timestamp, expected):
    # A 6-digit code is the same truncated value mod 10^6, i.e. the last 6 digits.
    assert totp.totp(RFC_SECRET_B32, timestamp) == expected[-6:]


def test_time_counter_boundaries():
    assert totp.time_counter(0) == 0
    assert totp.time_counter(29.999) == 0
    assert totp.time_counter(30) == 1
    assert totp.time_counter(59) == 1


def test_code_is_stable_within_a_window_and_changes_after():
    start = 1_700_000_010 - (1_700_000_010 % 30)  # first second of a window
    code = totp.totp(RFC_SECRET_B32, start)
    assert totp.totp(RFC_SECRET_B32, start + 29) == code
    assert totp.totp(RFC_SECRET_B32, start + 30) != code


# --- verify(): C-1, C, C+1 windows ---

NOW = 1_700_000_000.0


@pytest.mark.parametrize(
    "client_skew, expected_offset, expected_label",
    [(-30, -1, "C-1"), (0, 0, "C"), (30, 1, "C+1")],
)
def test_verify_accepts_adjacent_windows(client_skew, expected_offset, expected_label):
    # The phone generated the code with its clock `client_skew` seconds off the server's.
    code = totp.totp(RFC_SECRET_B32, NOW + client_skew)
    match = totp.verify(RFC_SECRET_B32, code, NOW)
    assert match is not None
    assert match.offset == expected_offset
    assert match.label == expected_label
    assert match.counter == totp.time_counter(NOW) + expected_offset


@pytest.mark.parametrize("client_skew", [-60, 60, -90, 90])
def test_verify_rejects_codes_outside_tolerance(client_skew):
    code = totp.totp(RFC_SECRET_B32, NOW + client_skew)
    assert totp.verify(RFC_SECRET_B32, code, NOW) is None


@pytest.mark.parametrize("bad_code", ["", "12345", "1234567", "12a456", " 12345", "١٢٣٤٥٦"])
def test_verify_rejects_malformed_codes(bad_code):
    assert totp.verify(RFC_SECRET_B32, bad_code, NOW) is None


def test_verify_rejects_wrong_code():
    good = totp.totp(RFC_SECRET_B32, NOW)
    wrong = f"{(int(good) + 1) % 1_000_000:06d}"
    # Guard against the (tiny) chance that `wrong` is valid in an adjacent window.
    adjacent = {totp.totp(RFC_SECRET_B32, NOW + d) for d in (-30, 0, 30)}
    if wrong not in adjacent:
        assert totp.verify(RFC_SECRET_B32, wrong, NOW) is None


# --- secrets ---


def test_generate_secret_is_unpadded_base32_of_20_bytes():
    secret = totp.generate_secret()
    assert len(secret) == 32  # 20 bytes -> 32 Base32 chars, no padding needed
    assert "=" not in secret
    assert secret == secret.upper()
    assert len(totp.decode_secret(secret)) == 20


def test_generate_secret_is_random():
    assert totp.generate_secret() != totp.generate_secret()


def test_decode_secret_is_lenient_with_formatting():
    # 11 bytes -> Base32 needs "=" padding, which users usually omit when typing.
    raw = b"hello-2fa!!"
    canonical = base64.b32encode(raw).decode().rstrip("=")
    spaced_lower = " ".join(canonical[i : i + 4] for i in range(0, len(canonical), 4)).lower()
    assert totp.decode_secret(canonical) == raw
    assert totp.decode_secret(spaced_lower) == raw


# --- otpauth URI ---


def test_build_otpauth_uri():
    uri = totp.build_otpauth_uri(RFC_SECRET_B32, "alice@example.com", "Lab2FA")
    parsed = urlparse(uri)
    assert parsed.scheme == "otpauth"
    assert parsed.netloc == "totp"
    assert unquote(parsed.path) == "/Lab2FA:alice@example.com"

    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    assert params == {
        "secret": RFC_SECRET_B32,
        "issuer": "Lab2FA",
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    }
