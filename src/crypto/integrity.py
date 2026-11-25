import hashlib
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sha256_bytes(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_merkle_root(hex_digests: list[str]) -> str:
    """
    Compute a binary SHA-256 Merkle root over an ordered list of hex digests.
    Uses domain separation prefixes (0x00 for leaves, 0x01 for internal nodes)
    to prevent second-preimage attacks.
    """
    if not hex_digests:
        return hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest()

    nodes = [
        hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest()
        for h in sorted(hex_digests)
    ]

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        next_level = []
        for i in range(0, len(nodes), 2):
            combined = b"\x01" + nodes[i] + nodes[i + 1]
            next_level.append(hashlib.sha256(combined).digest())
        nodes = next_level

    return nodes[0].hex()


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """
    Generate an Ed25519 keypair for backup manifest signing.
    Returns (raw_private_bytes_32B, raw_public_bytes_32B).
    """
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw_priv, raw_pub


def canonical_manifest_bytes(manifest_payload: dict) -> bytes:
    """Serialize manifest dictionary deterministically for signing/verification."""
    return json.dumps(
        manifest_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_manifest(manifest_payload: dict, raw_private_key: bytes) -> str:
    """Sign canonical manifest JSON using Ed25519 and return hex signature."""
    priv = Ed25519PrivateKey.from_private_bytes(raw_private_key)
    signature = priv.sign(canonical_manifest_bytes(manifest_payload))
    return signature.hex()


def verify_manifest_signature(
    manifest_payload: dict,
    signature_hex: str,
    raw_public_key: bytes,
) -> bool:
    """Verify Ed25519 signature over canonical manifest JSON."""
    pub = Ed25519PublicKey.from_public_bytes(raw_public_key)
    try:
        pub.verify(
            bytes.fromhex(signature_hex),
            canonical_manifest_bytes(manifest_payload),
        )
        return True
    except (InvalidSignature, ValueError):
        return False