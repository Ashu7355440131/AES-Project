import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

from src.config import AES_KEY_SIZE, GCM_NONCE_SIZE


class CryptographicIntegrityError(Exception):
    """Raised when AEAD tag verification or RFC 3394 key unwrapping fails."""


def generate_aes_key() -> bytes:
    """Generate a 256-bit AES key via OS CSPRNG."""
    return os.urandom(AES_KEY_SIZE)


def wrap_key(kek: bytes, target_key: bytes) -> bytes:
    """
    Wrap a cryptographic key using RFC 3394 AES-256 Key Wrap.
    """
    if len(kek) != AES_KEY_SIZE:
        raise ValueError("KEK must be 32 bytes (256 bits).")
    return aes_key_wrap(kek, target_key)


def unwrap_key(kek: bytes, wrapped_key: bytes) -> bytes:
    """
    Unwrap a cryptographic key using RFC 3394 AES-256 Key Unwrap.
    """
    if len(kek) != AES_KEY_SIZE:
        raise ValueError("KEK must be 32 bytes (256 bits).")
    try:
        return aes_key_unwrap(kek, wrapped_key)
    except InvalidUnwrap as exc:
        raise CryptographicIntegrityError(
            "Key unwrap failed: invalid password, recovery key, or tampered vault."
        ) from exc


def encrypt_chunk(
    key: bytes,
    plaintext: bytes,
    aad: bytes,
    nonce: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypt a data chunk using AES-256-GCM with Associated Authenticated Data (AAD).
    Returns (nonce, ciphertext_with_tag).
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    iv = nonce if nonce is not None else os.urandom(GCM_NONCE_SIZE)
    if len(iv) != GCM_NONCE_SIZE:
        raise ValueError("GCM nonce must be 12 bytes.")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)
    return iv, ciphertext


def decrypt_chunk(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    """
    Decrypt and authenticate a data chunk using AES-256-GCM.
    Raises CryptographicIntegrityError on bit-flip, truncation, or AAD mismatch.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptographicIntegrityError(
            "AES-GCM authentication failed: ciphertext or AAD was tampered with."
        ) from exc