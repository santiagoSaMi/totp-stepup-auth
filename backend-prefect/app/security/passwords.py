import bcrypt

# bcrypt only looks at the first 72 bytes; bcrypt>=5 refuses longer input.
MAX_PASSWORD_BYTES = 72

# Checked when the username doesn't exist, so that "unknown user" and "wrong
# password" take the same time and can't be told apart.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt()).decode()


class PasswordTooLong(ValueError):
    pass


def hash_password(password: str) -> str:
    encoded = password.encode()
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordTooLong(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str | None) -> bool:
    encoded = password.encode()
    if password_hash is None or len(encoded) > MAX_PASSWORD_BYTES:
        bcrypt.checkpw(b"dummy-password", _DUMMY_HASH.encode())
        return False
    return bcrypt.checkpw(encoded, password_hash.encode())
