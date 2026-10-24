"""Ed25519 (RFC 8032) in pure Python, with the strict rules of spec section 2.3.

A key is 32 bytes that decode to a point on the curve (y below p) that is not of small order. A signature
verifies when S is below the group order, R is not a point of small order, and [S]B - [k]A encodes to
exactly the 32 bytes of R, without the cofactor. Every verifier then agrees on every signature.

Verification handles no secret and need not be constant time. ``sign`` and ``public_key`` are not
constant time either, so ``agnt.keys.SigningKey`` uses them only when the caller opts in.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# Points in extended coordinates (X, Y, Z, T), with x = X/Z, y = Y/Z and xy = T/Z.
IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    """The complete addition law for a = -1 (add-2008-hwcd-3); it also doubles."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % P, g * h % P, f * g % P, e * h % P


def _negate(p):
    x, y, z, t = p
    return -x % P, y, z, -t % P


def _multiply(scalar: int, p):
    q = IDENTITY
    while scalar:
        if scalar & 1:
            q = _add(q, p)
        p = _add(p, p)
        scalar >>= 1
    return q


def _is_identity(p) -> bool:
    return p[0] % P == 0 and (p[1] - p[2]) % P == 0


def _encode(p) -> bytes:
    zinv = pow(p[2], -1, P)
    x, y = p[0] * zinv % P, p[1] * zinv % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _decode(data: bytes):
    """The point 32 bytes encode (RFC 8032 section 5.1.3), or None: y must be below p, x must exist, and
    x = 0 cannot carry the sign bit of an odd x."""
    n = int.from_bytes(data, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= P:
        return None
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if (v * x * x - u) % P:
        x = x * SQRT_M1 % P
        if (v * x * x - u) % P:
            return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return x, y, 1, x * y % P


def _small_order(p) -> bool:
    return _is_identity(_multiply(8, p))


BASE = _decode((4 * pow(5, -1, P) % P).to_bytes(32, "little"))


def is_public_key(raw: bytes) -> bool:
    """Whether 32 bytes are an Ed25519 key: a point on the curve, not of small order."""
    if len(raw) != 32:
        return False
    a = _decode(raw)
    return a is not None and not _small_order(a)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or not is_public_key(public):
        return False
    r_bytes, s = signature[:32], int.from_bytes(signature[32:], "little")
    r = _decode(r_bytes)
    if s >= L or r is None or _small_order(r):
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % L
    return _encode(_add(_multiply(s, BASE), _negate(_multiply(k, _decode(public))))) == r_bytes


def _expand(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    """The public key of a 32-byte seed. Not constant time."""
    return _encode(_multiply(_expand(seed)[0], BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    """An RFC 8032 signature. Not constant time: its timing depends on the key."""
    scalar, prefix = _expand(seed)
    public = _encode(_multiply(scalar, BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_bytes = _encode(_multiply(r, BASE))
    k = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % L
    return r_bytes + ((r + k * scalar) % L).to_bytes(32, "little")
