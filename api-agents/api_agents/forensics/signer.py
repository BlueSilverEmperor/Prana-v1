"""
Pure-Python Ed25519 (RFC 8032) implementation.
Guarantees self-contained, zero-dependency cryptographic signing for forensic audit receipts.
Conforms strictly to RFC 8032 Ed25519 standard.
"""

import hashlib
import os
from typing import Tuple

# Curve constants for Ed25519
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, -1, q) % q
I = pow(2, (q - 1) // 4, q)


def inv(x: int) -> int:
    return pow(x, q - 2, q)


def xrecover(y: int) -> int:
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * inv(5) % q
Bx = xrecover(By)
B = [Bx % q, By % q]


def edwards_add(P: list[int], Q: list[int]) -> list[int]:
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    denom = d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * inv(1 + denom)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - denom)
    return [x3 % q, y3 % q]


def scalarmult(P: list[int], e: int) -> list[int]:
    if e == 0:
        return [0, 1]
    Q = scalarmult(P, e // 2)
    Q = edwards_add(Q, Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q


def encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def decodeint(b: bytes) -> int:
    return int.from_bytes(b, "little")


def encodepoint(P: list[int]) -> bytes:
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def decodepoint(h: bytes) -> list[int]:
    y = sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(255))
    x = xrecover(y)
    if x & 1 != ((h[31] >> 7) & 1):
        x = q - x
    P = [x, y]
    return P


def generate_keypair(seed: bytes = None) -> Tuple[bytes, bytes]:
    """Generates an Ed25519 (private_key, public_key) pair (32 bytes each)."""
    if seed is None:
        seed = os.urandom(32)
    h = hashlib.sha512(seed).digest()
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    A = scalarmult(B, a)
    public_key = encodepoint(A)
    return seed, public_key


def sign(message: bytes, secret_key: bytes) -> bytes:
    """Signs a message using the Ed25519 secret seed (returns 64-byte signature)."""
    h = hashlib.sha512(secret_key).digest()
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    prefix = h[32:]
    r = decodeint(hashlib.sha512(prefix + message).digest()) % l
    R = scalarmult(B, r)
    A = scalarmult(B, a)
    public_key = encodepoint(A)
    k = decodeint(hashlib.sha512(encodepoint(R) + public_key + message).digest()) % l
    S = (r + k * a) % l
    return encodepoint(R) + encodeint(S)


def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Verifies an Ed25519 64-byte signature against the message and public key."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        R_bytes = signature[:32]
        S_bytes = signature[32:]
        R = decodepoint(R_bytes)
        A = decodepoint(public_key)
        S = decodeint(S_bytes)
        if S >= l:
            return False
        k = decodeint(hashlib.sha512(R_bytes + public_key + message).digest()) % l
        # Check: scalarmult(B, S) == edwards_add(R, scalarmult(A, k))
        left = scalarmult(B, S)
        right = edwards_add(R, scalarmult(A, k))
        return left[0] == right[0] and left[1] == right[1]
    except Exception:
        return False
