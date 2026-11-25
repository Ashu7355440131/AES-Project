import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.config import (
    AES_KEY_SIZE,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    SALT_SIZE,
)


def generate_salt(length: int = SALT_SIZE) -> bytes:
    """Generate cryptographically secure random salt."""
    return os.urandom(length)


def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit master key from a user password using memory-hard Argon2id.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    kdf = Argon2id(
        salt=salt,
        length=AES_KEY_SIZE,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_subkey(
    ikm: bytes,
    info: bytes,
    salt: bytes | None = None,
    length: int = AES_KEY_SIZE,
) -> bytes:
    """
    Derive domain-separated subkeys using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)