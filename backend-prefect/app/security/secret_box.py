"""Encryption at rest for TOTP secrets (AES-256-GCM).

The TOTP secret can't be hashed like a password: to verify a code the server
must compute HMAC-SHA1(secret, time // 30) itself, so it needs the original
secret. Instead it is stored encrypted, with the key outside the database
(MFA_ENCRYPTION_KEY in .env). A leaked database dump only exposes ciphertext.

Stored format: "v1:<nonce b64>:<ciphertext+tag b64>"
- v1:    key/format version, so the key can be rotated later.
- nonce: 12 random bytes, new on every encryption. Not secret.
- tag:   GCM authentication tag; any change to the ciphertext makes decryption fail.

The user_id is passed as associated data: a ciphertext copied into another
user's row fails to decrypt.
"""

import base64
import binascii
import os
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

VERSION = "v1"
NONCE_BYTES = 12


class SecretDecryptionError(Exception):
    pass


def is_encrypted(value: str) -> bool:
    return value.startswith(f"{VERSION}:")


def encrypt_secret(secret_base32: str, user_id: UUID, key: bytes | None = None) -> str:
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key or get_settings().mfa_encryption_key).encrypt(
        nonce, secret_base32.encode("ascii"), user_id.bytes
    )
    return f"{VERSION}:{base64.b64encode(nonce).decode()}:{base64.b64encode(ciphertext).decode()}"


def decrypt_secret(stored: str, user_id: UUID, key: bytes | None = None) -> str:
    try:
        version, nonce_b64, ciphertext_b64 = stored.split(":")
        if version != VERSION:
            raise SecretDecryptionError(f"unknown secret format {version!r}")
        nonce = base64.b64decode(nonce_b64, validate=True)
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except (ValueError, binascii.Error) as e:
        raise SecretDecryptionError("malformed encrypted secret") from e

    try:
        plaintext = AESGCM(key or get_settings().mfa_encryption_key).decrypt(nonce, ciphertext, user_id.bytes)
    except InvalidTag:
        # Wrong key, tampered ciphertext, or a ciphertext belonging to another user.
        raise SecretDecryptionError("TOTP secret could not be decrypted") from None
    return plaintext.decode("ascii")
