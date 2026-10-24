import base64
import os
import uuid

import pytest

from app.config import get_settings
from app.mfa import totp
from app.security.secret_box import SecretDecryptionError, decrypt_secret, encrypt_secret, is_encrypted

ALICE = uuid.uuid4()
BOB = uuid.uuid4()
SECRET = totp.generate_secret()


def test_roundtrip():
    stored = encrypt_secret(SECRET, ALICE)
    assert decrypt_secret(stored, ALICE) == SECRET


def test_stored_value_does_not_reveal_the_secret():
    stored = encrypt_secret(SECRET, ALICE)
    assert is_encrypted(stored)
    assert SECRET not in stored
    assert stored.count(":") == 2


def test_same_secret_encrypts_differently_each_time():
    # Random nonce: two users with the same secret don't look alike in the database.
    assert encrypt_secret(SECRET, ALICE) != encrypt_secret(SECRET, ALICE)


def test_tampered_ciphertext_is_rejected():
    version, nonce, ciphertext = encrypt_secret(SECRET, ALICE).split(":")
    raw = bytearray(base64.b64decode(ciphertext))
    raw[0] ^= 0x01  # flip one bit
    tampered = f"{version}:{nonce}:{base64.b64encode(bytes(raw)).decode()}"
    with pytest.raises(SecretDecryptionError):
        decrypt_secret(tampered, ALICE)


def test_ciphertext_copied_to_another_user_is_rejected():
    stored = encrypt_secret(SECRET, ALICE)
    with pytest.raises(SecretDecryptionError):
        decrypt_secret(stored, BOB)


def test_wrong_key_is_rejected():
    stored = encrypt_secret(SECRET, ALICE)
    with pytest.raises(SecretDecryptionError):
        decrypt_secret(stored, ALICE, key=os.urandom(32))


@pytest.mark.parametrize("bad", ["", SECRET, "v1:abc", "v2:AAAA:AAAA", "v1:not base64!:AAAA"])
def test_malformed_values_are_rejected(bad):
    with pytest.raises(SecretDecryptionError):
        decrypt_secret(bad, ALICE)


def test_key_is_not_in_settings_repr():
    settings = get_settings()
    text = repr(settings)
    assert "mfa_encryption_key" not in text
    assert "jwt_secret" not in text
    assert base64.urlsafe_b64encode(settings.mfa_encryption_key).decode().rstrip("=") not in text
