"""Key tokens, the two algorithms of version 1, key history, and the agent's signing key (spec 2.3, 2.4).

A key is written as one string, its key token: the algorithm name, a colon, and the raw public key in
canonical base64url (``ed25519:11qY...``). A token naming an algorithm this reader does not implement is
unknown, never an error. Signatures do not name their algorithm: a verifier tries each of the signer's keys
valid at the moment whose algorithm it implements, against signatures that algorithm calls well formed.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from . import ed25519, mldsa
from .errors import AgntError
from .limits import KEY_ADDED_SKEW_MS
from .wire import b64url, from_b64url, parse_timestamp

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # the optional extra is not installed
    Ed25519PrivateKey = None


@dataclass(frozen=True)
class Algorithm:
    key_bytes: int
    signature_bytes: int
    is_key: Callable[[bytes], bool]
    verify: Callable[[bytes, bytes, bytes], bool]


ALGORITHMS: Mapping[str, Algorithm] = {
    "ed25519": Algorithm(32, 64, ed25519.is_public_key, ed25519.verify),
    # FIPS 204's pkDecode reads any 1952 bytes as a key.
    "ml-dsa-65": Algorithm(mldsa.PUBLIC_KEY_BYTES, mldsa.SIGNATURE_BYTES, lambda raw: True, mldsa.verify),
}

_KEY_TOKEN = re.compile(r"([a-z0-9-]+):([A-Za-z0-9_-]+)")


def parse_key_token(token: object) -> tuple[str, bytes] | None:
    """A token's algorithm name and raw key when it is written as one, whatever the algorithm, or None."""
    m = _KEY_TOKEN.fullmatch(token) if isinstance(token, str) else None
    raw = from_b64url(m.group(2)) if m else None
    return (m.group(1), raw) if raw else None


def is_implemented(token: object) -> bool:
    """Whether a token is written as a key token and names an algorithm implemented here."""
    parsed = parse_key_token(token)
    return parsed is not None and parsed[0] in ALGORITHMS


def is_public_key(token: object) -> bool:
    """Whether a token is a key of an algorithm implemented here: the right length, and for Ed25519 a point
    on the curve that is not of small order."""
    parsed = parse_key_token(token)
    algorithm = ALGORITHMS.get(parsed[0]) if parsed else None
    return algorithm is not None and len(parsed[1]) == algorithm.key_bytes and algorithm.is_key(parsed[1])


def verify(token: object, data: bytes, signature: object) -> bool:
    """Whether a base64url signature over ``data`` verifies with a key token. False for any key of an
    algorithm not implemented here, and for a signature of another length."""
    parsed = parse_key_token(token)
    algorithm = ALGORITHMS.get(parsed[0]) if parsed else None
    raw = from_b64url(signature)
    return (
        algorithm is not None
        and raw is not None
        and len(raw) == algorithm.signature_bytes
        and algorithm.verify(parsed[1], data, raw)
    )


# Key history (section 2.4). An entry is {"key": token, "added": timestamp, "revoked": timestamp or None}.


def valid_at(entry: Mapping[str, Any], at_ms: int) -> bool:
    """Whether a key is valid at a moment: added at most 300 seconds after it, and not revoked by then."""
    added = parse_timestamp(entry.get("added"))
    if added is None or added - KEY_ADDED_SKEW_MS > at_ms:
        return False
    revoked = entry.get("revoked")
    if revoked is None:
        return True
    revoked_ms = parse_timestamp(revoked)
    return revoked_ms is not None and at_ms < revoked_ms


def valid_during(entry: Mapping[str, Any], from_ms: int, to_ms: int) -> bool:
    """Whether a key was valid at some moment from ``from_ms`` to ``to_ms``: the window in which a carrier
    signed a message's claims."""
    added = parse_timestamp(entry.get("added"))
    if added is None or added - KEY_ADDED_SKEW_MS > to_ms:
        return False
    revoked = entry.get("revoked")
    if revoked is None:
        return True
    revoked_ms = parse_timestamp(revoked)
    return revoked_ms is not None and from_ms < revoked_ms


def signature_verdict(
    entries: Iterable[Mapping[str, Any]], at_ms: int, data: bytes, signature: object
) -> str:
    """What a signer's keys say of a signature (sections 2.3 and 6.3): ``verified`` when one valid at
    ``at_ms`` signed these bytes; ``unsupported_algorithm`` when keys valid then exist but none is of an
    algorithm implemented here, so nothing could be tried; otherwise ``bad_signature``, which includes
    having no key valid then at all."""
    valid = [e for e in entries if valid_at(e, at_ms)]
    usable = [e for e in valid if is_implemented(e.get("key"))]
    if not usable:
        return "unsupported_algorithm" if valid else "bad_signature"
    return "verified" if any(verify(e["key"], data, signature) for e in usable) else "bad_signature"


def signed_by_any(entries: Iterable[Mapping[str, Any]], at_ms: int, data: bytes, signature: object) -> bool:
    """Whether one of the keys valid at ``at_ms`` signed these bytes."""
    return signature_verdict(entries, at_ms, data, signature) == "verified"


# The agent's own key.

_PKCS8_ED25519 = bytes.fromhex("302e020100300506032b657004220420")
_PEM = re.compile(r"\s*-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----\s*")
PURE_SIGNING_ENV = "AGNT_ALLOW_PURE_SIGNING"


class SigningKey:
    """An Ed25519 private key, held as its 32-byte seed.

    Signing uses the ``cryptography`` package. Without it, a SigningKey is refused unless the caller opts
    in with ``allow_pure_python_signing=True`` or ``AGNT_ALLOW_PURE_SIGNING=1``, because the pure-Python
    fallback is not constant time and its timing can leak the key.
    """

    def __init__(self, seed: bytes, *, allow_pure_python_signing: bool = False) -> None:
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise ValueError("An Ed25519 seed is 32 bytes.")
        self._seed = seed
        if Ed25519PrivateKey is not None:
            private = Ed25519PrivateKey.from_private_bytes(seed)
            self._sign: Callable[[bytes], bytes] = private.sign
            public = private.public_key().public_bytes_raw()
        elif allow_pure_python_signing or os.environ.get(PURE_SIGNING_ENV) == "1":
            self._sign = lambda data: ed25519.sign(seed, data)
            public = ed25519.public_key(seed)
        else:
            raise AgntError(
                "pure_signing_refused",
                "Signing needs the cryptography package: pip install 'agnt[crypto]'. The pure-Python Ed25519 "
                f"here is not constant time; to sign with it anyway, set {PURE_SIGNING_ENV}=1 or pass "
                "allow_pure_python_signing=True.",
            )
        #: The public key as a key token, ``ed25519:<base64url>``.
        self.token = "ed25519:" + b64url(public)

    @classmethod
    def generate(cls, **options: bool) -> SigningKey:
        return cls(secrets.token_bytes(32), **options)

    @classmethod
    def from_pem(cls, pem: str, **options: bool) -> SigningKey:
        """A key from PKCS #8 PEM, the form ``key.pem`` holds. A literal ``\\n`` reads as a newline."""
        m = _PEM.fullmatch(pem.replace("\\n", "\n"))
        der = base64.b64decode("".join(m.group(1).split())) if m else b""
        if len(der) != 48 or not der.startswith(_PKCS8_ED25519):
            raise ValueError("Not an Ed25519 private key in PKCS #8 PEM.")
        return cls(der[16:], **options)

    def to_pem(self) -> str:
        body = base64.b64encode(_PKCS8_ED25519 + self._seed).decode("ascii")
        return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"

    @property
    def identifier(self) -> str:
        """This key as a key principal's identifier, ``agnt-key:<token>`` (section 2.2)."""
        return "agnt-key:" + self.token

    def sign(self, data: bytes) -> str:
        """The base64url signature of these bytes."""
        return b64url(self._sign(data))

    def __repr__(self) -> str:
        return f"SigningKey({self.token!r})"
