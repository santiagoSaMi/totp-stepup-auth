"""Generation and hashing of single-use backup codes.

Codes look like `K7QX2-MNP4R`: 10 characters from a 32-symbol alphabet
(50 bits of entropy). Because they are random rather than user-chosen, a fast
SHA-256 hash is enough to store them; passwords need bcrypt, these don't.
"""

import hashlib
import secrets

# No 0/O or 1/I, so codes can be read off paper without ambiguity.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 10
GROUP_SIZE = 5
DEFAULT_COUNT = 10


def generate_codes(count: int = DEFAULT_COUNT) -> list[str]:
    """Plain-text codes to show the user once."""
    codes = set()
    while len(codes) < count:
        raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
        codes.add(f"{raw[:GROUP_SIZE]}-{raw[GROUP_SIZE:]}")
    return sorted(codes)


def normalize(code: str) -> str:
    """Accept `k7qx2-mnp4r`, `K7QX2 MNP4R`, `K7QX2MNP4R`..."""
    return code.replace("-", "").replace(" ", "").upper()


def is_well_formed(code: str) -> bool:
    normalized = normalize(code)
    return len(normalized) == CODE_LENGTH and all(c in ALPHABET for c in normalized)


def hash_code(code: str) -> str:
    return hashlib.sha256(normalize(code).encode("ascii")).hexdigest()
