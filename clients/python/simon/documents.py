"""The two documents a server publishes, fetched without authentication (spec section 4)::

    GET /simon/server              {server, keys, algorithms, limits}
    GET /simon/agents/<address>    {address, keys, signature}         signed by the server over SIMON-AGENT

A reader takes a document's bytes: at most 131072 of them, JSON under the canonical rules (not necessarily
canonical), with at most 32 total key entries, including retained revoked keys. Members a reader does not know are
ignored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .canonical import parse, signing_bytes
from .errors import SimonError
from .keys import is_implemented, is_public_key, parse_key_token, signed_by_any
from .limits import MAX_DOCUMENT_BYTES, MAX_DOCUMENT_KEYS, MINIMUM_LIMITS, REVOCATION_AHEAD_MS
from .resolution import server_origin
from .wire import is_address, is_b64url, parse_timestamp


def read_keys(value: Any, now_ms: int) -> list[dict[str, Any]] | None:
    """At most 32 total entries, including retained revoked keys. Every entry is parsed; unknown
    algorithms are kept but never tried. Revocations admit only the ordinary 300-second clock tolerance."""
    if not isinstance(value, list) or len(value) > MAX_DOCUMENT_KEYS:
        return None
    keys = []
    for entry in value:
        if not isinstance(entry, dict) or not {"key", "added", "revoked"} <= entry.keys():
            return None
        key, added, revoked = entry["key"], entry["added"], entry["revoked"]
        if parse_key_token(key) is None or parse_timestamp(added) is None:
            return None
        revoked_ms = None if revoked is None else parse_timestamp(revoked)
        if revoked is not None and revoked_ms is None:
            return None
        if revoked_ms is not None and revoked_ms > now_ms + REVOCATION_AHEAD_MS:
            return None
        if is_implemented(key) and not is_public_key(key):
            return None
        keys.append({"key": key, "added": added, "revoked": revoked})
    return keys


def read_server_document(body: bytes, origin: str, now_ms: int) -> dict[str, Any] | None:
    """A fetched server document read at ``now_ms``, as ``{"server", "keys", "algorithms", "limits"}``, or
    None unless it is
    readable, its ``server`` names the origin it was fetched from, it lists its ``algorithms``, and it has
    its four limits. Limits a reader does not know are ignored."""
    doc = _read_object(body)
    if doc is None or server_origin(doc.get("server"), allow_local=True) != origin:
        return None
    keys, limits = read_keys(doc.get("keys"), now_ms), _read_limits(doc.get("limits"))
    algorithms = _read_algorithms(doc.get("algorithms"))
    if keys is None or algorithms is None or limits is None:
        return None
    return {"server": origin, "keys": keys, "algorithms": algorithms, "limits": limits}


def read_agent_document(
    body: bytes, address: str, server_keys: Iterable[Mapping[str, Any]], now_ms: int
) -> dict[str, Any] | None:
    """A fetched agent document as ``{"address", "keys"}``, or None unless it is readable, names exactly
    the address asked for, and is signed by one of the server's keys valid at ``now_ms``. It says nothing
    about whom the agent speaks for: only its messages do, with the evidence that backs them (section 2.2).

    A retired document (section 4) also reads with ``retired``, and ``unpairing`` when an unpairing retired
    the address. It is unreadable unless ``retired`` is a timestamp, ``unpairing`` when present a base64url
    string, and every key revoked at or before ``retired``."""
    doc = _read_object(body)
    if (
        doc is None
        or not is_address(address)
        or doc.get("address") != address
    ):
        return None
    keys = read_keys(doc.get("keys"), now_ms)
    if keys is None or not signed_by_any(
        server_keys, now_ms, signing_bytes("SIMON-AGENT", doc), doc.get("signature")
    ):
        return None
    if "retired" not in doc:
        return {"address": address, "keys": keys}
    retired = parse_timestamp(doc["retired"])
    if retired is None or ("unpairing" in doc and not is_b64url(doc["unpairing"])):
        return None
    if not all(k["revoked"] is not None and parse_timestamp(k["revoked"]) <= retired for k in keys):
        return None
    read = {"address": address, "keys": keys, "retired": doc["retired"]}
    if "unpairing" in doc:
        read["unpairing"] = doc["unpairing"]
    return read


def _read_object(body: bytes) -> dict[str, Any] | None:
    if len(body) > MAX_DOCUMENT_BYTES:
        return None
    try:
        value = parse(body)
    except SimonError:
        return None
    return value if isinstance(value, dict) else None


#: The algorithms version 1 defines (section 2.3).
V1_ALGORITHMS = ("ed25519", "ml-dsa-65")
#: The algorithms every server verifies, and so every server document lists; ml-dsa-65 is optional and advertised.
REQUIRED_ALGORITHMS = ("ed25519",)
_ALGORITHM_NAME = re.compile(r"[a-z0-9-]+")


def _read_algorithms(value: Any) -> list[str] | None:
    """The algorithms a server document lists, in its order, or None: an array of algorithm names
    (lower-case letters, digits and hyphens) that includes every required algorithm. Names this reader
    does not know are kept."""
    if not isinstance(value, list) or not all(
        isinstance(a, str) and _ALGORITHM_NAME.fullmatch(a) for a in value
    ):
        return None
    return list(value) if all(a in value for a in REQUIRED_ALGORITHMS) else None


def _read_limits(value: Any) -> dict[str, int] | None:
    """The four published limits, each a safe integer at least its minimum, or None."""
    if not isinstance(value, dict):
        return None
    limits = {}
    for name, minimum in MINIMUM_LIMITS.items():
        n = value.get(name)
        if type(n) is not int or n < minimum:
            return None
        limits[name] = n
    return limits
