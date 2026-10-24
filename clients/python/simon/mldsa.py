"""ML-DSA-65 verification (FIPS 204, ML-DSA.Verify with an empty context string), in pure Python.

Verification handles no secret, so nothing here needs to be constant time. Section numbers below are
FIPS 204's algorithms.
"""

from __future__ import annotations

import hashlib

Q = 8_380_417
N = 256
D = 13
K, L = 6, 5
TAU = 49
LAMBDA = 192
GAMMA1 = 1 << 19
GAMMA2 = (Q - 1) // 32
BETA = TAU * 4  # tau * eta
OMEGA = 55

PUBLIC_KEY_BYTES = 32 + K * 320
SIGNATURE_BYTES = LAMBDA // 4 + L * 640 + OMEGA + K

_ZETAS = [pow(1753, int(f"{i:08b}"[::-1], 2), Q) for i in range(N)]
_N_INVERSE = pow(N, -1, Q)


def _ntt(f: list[int]) -> list[int]:
    """Algorithm 41."""
    w = [c % Q for c in f]
    m, length = 0, 128
    while length >= 1:
        for start in range(0, N, 2 * length):
            m += 1
            z = _ZETAS[m]
            for j in range(start, start + length):
                t = z * w[j + length] % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
        length //= 2
    return w


def _inverse_ntt(w: list[int]) -> list[int]:
    """Algorithm 42."""
    f = list(w)
    m, length = N, 1
    while length < N:
        for start in range(0, N, 2 * length):
            m -= 1
            z = Q - _ZETAS[m]
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = z * (t - f[j + length]) % Q
        length *= 2
    return [c * _N_INVERSE % Q for c in f]


def _unpack(data: bytes, bits: int) -> list[int]:
    """N coefficients of `bits` bits each, little-endian (SimpleBitUnpack, Algorithm 18)."""
    n, mask = int.from_bytes(data, "little"), (1 << bits) - 1
    return [(n >> (bits * i)) & mask for i in range(N)]


def _pack(coefficients: list[int], bits: int) -> bytes:
    """SimpleBitPack, Algorithm 16."""
    n = 0
    for i, c in enumerate(coefficients):
        n |= c << (bits * i)
    return n.to_bytes(bits * N // 8, "little")


def _rej_ntt_poly(seed: bytes) -> list[int]:
    """Algorithm 30: coefficients below q, three bytes at a time, from SHAKE128."""
    out: list[int] = []
    length = 840
    while True:
        stream = hashlib.shake_128(seed).digest(length)
        out.clear()
        for i in range(0, length - 2, 3):
            c = stream[i] | stream[i + 1] << 8 | (stream[i + 2] & 0x7F) << 16
            if c < Q:
                out.append(c)
                if len(out) == N:
                    return out
        length *= 2


def _sample_in_ball(seed: bytes) -> list[int]:
    """Algorithm 29: TAU coefficients of +1 or -1, the rest 0."""
    length = 8 + 4 * TAU
    while True:
        stream = hashlib.shake_256(seed).digest(length)
        signs, pos = int.from_bytes(stream[:8], "little"), 8
        c = [0] * N
        try:
            for i in range(N - TAU, N):
                while stream[pos] > i:
                    pos += 1
                j = stream[pos]
                pos += 1
                c[i], c[j] = c[j], 1 - 2 * (signs & 1)
                signs >>= 1
            return c
        except IndexError:
            length *= 2


def _hints(data: bytes) -> list[list[int]] | None:
    """HintBitUnpack, Algorithm 21: None when the hint is malformed."""
    h = [[0] * N for _ in range(K)]
    index = 0
    for i in range(K):
        end = data[OMEGA + i]
        if end < index or end > OMEGA:
            return None
        first = index
        while index < end:
            if index > first and data[index - 1] >= data[index]:
                return None
            h[i][data[index]] = 1
            index += 1
    return h if not any(data[index:OMEGA]) else None


def _use_hint(hint: int, r: int) -> int:
    """UseHint, Algorithm 40, with Decompose, Algorithm 36."""
    r0 = r % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if r - r0 == Q - 1:
        r1, r0 = 0, r0 - 1
    else:
        r1 = (r - r0) // (2 * GAMMA2)
    if not hint:
        return r1
    return (r1 + 1) % 16 if r0 > 0 else (r1 - 1) % 16


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """ML-DSA.Verify (Algorithm 3) with an empty context, then ML-DSA.Verify_internal (Algorithm 8)."""
    if len(public) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    rho = public[:32]
    t1 = [_unpack(public[32 + 320 * i : 32 + 320 * (i + 1)], 10) for i in range(K)]

    c_tilde = signature[: LAMBDA // 4]
    z_bytes = signature[LAMBDA // 4 : LAMBDA // 4 + L * 640]
    z = [[GAMMA1 - c for c in _unpack(z_bytes[640 * i : 640 * (i + 1)], 20)] for i in range(L)]
    h = _hints(signature[LAMBDA // 4 + L * 640 :])
    if h is None or any(abs(c) >= GAMMA1 - BETA for poly in z for c in poly):
        return False

    tr = hashlib.shake_256(public).digest(64)
    mu = hashlib.shake_256(tr + b"\x00\x00" + message).digest(64)
    c_hat = _ntt(_sample_in_ball(c_tilde))
    z_hat = [_ntt(poly) for poly in z]
    w1 = bytearray()
    for i in range(K):
        t1_hat = _ntt([c << D for c in t1[i]])
        acc = [-(a * b) for a, b in zip(c_hat, t1_hat, strict=True)]
        for j in range(L):
            a_hat = _rej_ntt_poly(rho + bytes([j, i]))
            acc = [x + a * b for x, a, b in zip(acc, a_hat, z_hat[j], strict=True)]
        w_approx = _inverse_ntt([x % Q for x in acc])
        w1 += _pack([_use_hint(hint, r) for hint, r in zip(h[i], w_approx, strict=True)], 4)
    return hashlib.shake_256(mu + bytes(w1)).digest(LAMBDA // 4) == c_tilde
