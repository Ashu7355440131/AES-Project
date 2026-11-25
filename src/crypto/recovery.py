import os
from dataclasses import dataclass

# AES / Rijndael GF(2^8) irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
GF256_MODULUS = 0x1B


def gf256_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= GF256_MODULUS
        b >>= 1
    return product


def gf256_inv(a: int) -> int:
    """Compute multiplicative inverse in GF(2^8) via Fermat's Little Theorem (a^254)."""
    if a == 0:
        raise ZeroDivisionError("Zero has no multiplicative inverse in GF(256).")
    result = 1
    base = a
    exponent = 254
    while exponent > 0:
        if exponent & 1:
            result = gf256_mul(result, base)
        base = gf256_mul(base, base)
        exponent >>= 1
    return result


def gf256_div(a: int, b: int) -> int:
    """Divide a by b in GF(2^8)."""
    return gf256_mul(a, gf256_inv(b))


@dataclass(frozen=True)
class RecoveryShare:
    threshold: int
    total_shares: int
    x: int
    y_bytes: bytes

    def encode(self) -> str:
        """Format share as portable human-copyable token."""
        return (
            f"SSS-{self.threshold}-{self.total_shares}-"
            f"{self.x:02x}-{self.y_bytes.hex()}"
        )

    @classmethod
    def decode(cls, token: str) -> "RecoveryShare":
        parts = token.strip().split("-")
        if len(parts) != 5 or parts[0] != "SSS":
            raise ValueError(f"Malformed recovery share format: {token}")
        threshold = int(parts[1])
        total_shares = int(parts[2])
        x = int(parts[3], 16)
        y_bytes = bytes.fromhex(parts[4])
        if not (1 <= x <= 255) or not y_bytes:
            raise ValueError("Invalid share coordinates or empty payload.")
        return cls(
            threshold=threshold,
            total_shares=total_shares,
            x=x,
            y_bytes=y_bytes,
        )


def split_secret_sss(
    secret: bytes,
    threshold: int = 3,
    total_shares: int = 5,
) -> list[str]:
    """
    Split a secret byte string into `total_shares` shares over GF(256)
    such that any `threshold` shares reconstruct the exact secret.
    """
    if not (2 <= threshold <= total_shares <= 255):
        raise ValueError("Require 2 <= threshold <= total_shares <= 255.")
    if not secret:
        raise ValueError("Secret cannot be empty.")

    secret_len = len(secret)
    share_buffers = [bytearray(secret_len) for _ in range(total_shares)]

    for byte_idx, secret_byte in enumerate(secret):
        # Random polynomial f(x) = secret_byte + a_1*x + ... + a_{k-1}*x^{k-1}
        random_coeffs = os.urandom(threshold - 1)
        coeffs = [secret_byte, *random_coeffs]

        for share_idx in range(total_shares):
            x = share_idx + 1  # Evaluation points x = 1..n (never 0)
            y = 0
            for coeff in reversed(coeffs):
                y = gf256_mul(y, x) ^ coeff
            share_buffers[share_idx][byte_idx] = y

    return [
        RecoveryShare(
            threshold=threshold,
            total_shares=total_shares,
            x=i + 1,
            y_bytes=bytes(buf),
        ).encode()
        for i, buf in enumerate(share_buffers)
    ]


def reconstruct_secret_sss(share_tokens: list[str]) -> bytes:
    """
    Reconstruct the original secret at x = 0 via Lagrange interpolation over GF(256).
    """
    if not share_tokens:
        raise ValueError("At least two recovery shares are required.")

    parsed = [RecoveryShare.decode(tok) for tok in share_tokens]
    threshold = parsed[0].threshold
    secret_len = len(parsed[0].y_bytes)

    if len(parsed) < threshold:
        raise ValueError(
            f"Insufficient shares: got {len(parsed)}, require at least {threshold}."
        )

    # Deduplicate by x-coordinate
    unique_shares: dict[int, RecoveryShare] = {}
    for s in parsed:
        if s.threshold != threshold or len(s.y_bytes) != secret_len:
            raise ValueError("Incompatible shares provided.")
        unique_shares[s.x] = s

    if len(unique_shares) < threshold:
        raise ValueError("Duplicate shares detected; need distinct recovery shares.")

    selected = list(unique_shares.values())[:threshold]
    xs = [s.x for s in selected]

    # Precompute Lagrange basis polynomials L_i(0) = prod_{m != i} (x_m / (x_i ^ x_m))
    lagrange_coeffs = []
    for i in range(threshold):
        num = 1
        den = 1
        for m in range(threshold):
            if i == m:
                continue
            num = gf256_mul(num, xs[m])
            den = gf256_mul(den, xs[i] ^ xs[m])
        lagrange_coeffs.append(gf256_div(num, den))

    recovered = bytearray(secret_len)
    for byte_idx in range(secret_len):
        acc = 0
        for i in range(threshold):
            acc ^= gf256_mul(selected[i].y_bytes[byte_idx], lagrange_coeffs[i])
        recovered[byte_idx] = acc

    return bytes(recovered)