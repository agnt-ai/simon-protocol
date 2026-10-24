"""Signed requests (spec section 8), and the add-key proof (CLIENT.md, register).

    agnt-key:        <key token of the signing key>
    agnt-timestamp:  <unix seconds: 1 to 12 ASCII digits>
    agnt-nonce:      <8 to 128 characters from U+0021 to U+007E>
    agnt-signature:  <base64url signature over the signing string>
    agnt-agent:      <the acting agent's address; on agent requests>
    agnt-server:     <the requesting server's origin, serialised; on server requests>

A request carries one of ``agnt-agent`` and ``agnt-server``, naming who it acts as. The signing string is
eight lines joined by single newlines, with no trailing newline::

    AGNT-REQUEST
    <METHOD, in upper case>
    <the origin of the server being asked, serialised as section 3 says>
    <the acting identity: the value of agnt-agent or of agnt-server>
    <the request target exactly as sent: the path and query of the request line, before any decoding>
    <agnt-timestamp>
    <agnt-nonce>
    <hex SHA-256 of the exact body bytes>
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from .errors import AgntError
from .keys import SigningKey, parse_key_token, valid_at, verify
from .limits import REQUEST_SKEW_SECONDS
from .resolution import server_origin
from .wire import is_address, is_b64url, sha256_hex

_HEADERS = {
    "agnt-key": lambda v: parse_key_token(v) is not None,
    "agnt-timestamp": re.compile(r"[0-9]{1,12}").fullmatch,
    "agnt-nonce": re.compile(r"[\x21-\x7e]{8,128}").fullmatch,
    "agnt-signature": is_b64url,
}


def signing_string(
    method: str, origin: str, actor: str, target: str, timestamp: str, nonce: str, body: bytes = b""
) -> str:
    method = re.sub("[a-z]+", lambda m: m.group().upper(), method)  # ASCII upper case only
    origin = server_origin(origin, allow_local=True)
    if origin is None:
        raise ValueError("A request signing origin must be a server origin.")
    return "\n".join(["AGNT-REQUEST", method, origin, actor, target, timestamp, nonce, sha256_hex(body)])


def actor_of(headers: Mapping[str, str]) -> str:
    """The identity line of a request: its ``agnt-agent`` or ``agnt-server`` value exactly as sent, or empty."""
    value = headers.get("agnt-agent", headers.get("agnt-server"))
    return value if isinstance(value, str) else ""


def split_url(url: str) -> tuple[str, str]:
    """The origin and the request target of an absolute URL, the target as it goes on the request line."""
    parts = urlsplit(url)
    origin = server_origin(f"{parts.scheme}://{parts.netloc}", allow_local=True)
    if origin is None:
        raise ValueError(f"Not a server URL: {url}")
    return origin, (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def sign_request(
    key: SigningKey,
    method: str,
    url: str,
    body: bytes = b"",
    *,
    now: float | None = None,
    nonce: str | None = None,
    agent: str | None = None,
    server: str | None = None,
) -> dict[str, str]:
    """The signature headers for a request to an absolute URL, acting as ``agent`` (an agent's address)
    or as ``server`` (the requesting server's origin). With neither, the identity line is empty: only a
    call authorised by what it carries, such as a register that leases an address, goes without one."""
    if agent is not None and server is not None:
        raise ValueError("A request acts as an agent or a server, not both.")
    timestamp = str(int(time.time() if now is None else now))
    nonce = nonce or secrets.token_urlsafe(18)
    origin, target = split_url(url)
    if server is not None:  # agnt-server carries the serialised origin, as the origin line does
        server = server_origin(server, allow_local=True) or server
    actor = agent if agent is not None else server if server is not None else ""
    headers = {
        "agnt-key": key.token,
        "agnt-timestamp": timestamp,
        "agnt-nonce": nonce,
        "agnt-signature": key.sign(signing_string(method, origin, actor, target, timestamp, nonce, body).encode()),
    }
    if agent is not None:
        headers["agnt-agent"] = agent
    if server is not None:
        headers["agnt-server"] = server
    return headers


def check_request(
    method: str,
    origin: str,
    target: str,
    body: bytes,
    headers: Mapping[str, str],
    *,
    now: float,
    entry: Mapping[str, Any] | None,
    nonce_seen: bool,
    server: bool = False,
    agent: bool = False,
) -> dict[str, str]:
    """What a server answers to a signed request, refusing in the order of section 8 with ``401`` and
    ``details.serverTime``: a missing or malformed header (``signature_required``, with ``details.header``),
    the timestamp outside 300 s of ``now`` (``stale_request``), no ``entry`` for ``agnt-key``
    (``unknown_key``), the key not valid now (``key_revoked``), the signature (``bad_signature``, with
    ``details.signingString``), and only then a nonce this key already used while its request's timestamp
    is in the window (``replayed_request``). A server request (``server``) needs ``agnt-server``, an agent
    request (``agent``) ``agnt-agent``, and a request carries at most one of them; ``agnt-server`` is a
    serialised origin, and the identity line signed is the one sent. Returns the signature headers."""
    server_time = int(now)

    def refuse(code: str, message: str, **details: Any) -> AgntError:
        return AgntError(code, message, 401, False, {"serverTime": server_time, **details})

    def required(name: str) -> AgntError:
        return refuse("signature_required", f"This request needs a well-formed {name} header.", header=name)

    found = {}
    for name, grammar in _HEADERS.items():
        value = headers.get(name)
        if not isinstance(value, str) or not grammar(value):
            raise required(name)
        found[name] = value
    if "agnt-agent" in headers and "agnt-server" in headers:
        raise required("agnt-agent")
    if server:
        origin_named = server_origin(headers.get("agnt-server"))
        if origin_named is None or origin_named != headers.get("agnt-server"):
            raise required("agnt-server")
        found["agnt-server"] = origin_named
    if agent:
        named = headers.get("agnt-agent")
        if not isinstance(named, str) or not is_address(named):
            raise required("agnt-agent")
        found["agnt-agent"] = named
    if abs(int(found["agnt-timestamp"]) - server_time) > REQUEST_SKEW_SECONDS:
        raise refuse(
            "stale_request", f"agnt-timestamp is more than {REQUEST_SKEW_SECONDS} s from this server's clock."
        )
    if entry is None:
        raise refuse("unknown_key", "This server does not know this key.")
    if not valid_at(entry, int(now * 1000)):
        raise refuse("key_revoked", "This key is not valid now.")
    expected = signing_string(
        method, origin, actor_of(headers), target, found["agnt-timestamp"], found["agnt-nonce"], body
    )
    if not verify(entry["key"], expected.encode(), found["agnt-signature"]):
        raise refuse(
            "bad_signature", "The signature does not verify over the signing string.", signingString=expected
        )
    if nonce_seen:
        raise refuse("replayed_request", "This key already used this nonce inside the window.")
    return found


def nonce_expiry(timestamp: str | int) -> int:
    """The first moment, in milliseconds since 1970, at which a request with this ``agnt-timestamp`` is
    stale. The window is checked in whole seconds, so it is open until 301 seconds after the timestamp; a
    server keeps the nonce until then (section 8), and no choice of ``>`` or ``>=`` reopens a replay."""
    return (int(timestamp) + REQUEST_SKEW_SECONDS + 1) * 1000


def add_key_string(address: str, key: str) -> str:
    """What a new key signs to be added to an agent, so no agent can list a key it does not hold."""
    return f"AGNT-ADD-KEY\n{address}\n{key}"


def add_key_proof(new_key: SigningKey, address: str) -> str:
    return new_key.sign(add_key_string(address, new_key.token).encode())


def verify_add_key_proof(address: str, key: str, proof: object) -> bool:
    return verify(key, add_key_string(address, key).encode(), proof)
