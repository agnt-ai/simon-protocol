"""Signals: small, short-lived notes from one server to another about a message (spec section 6.4),
``POST /simon/signal``::

    {type, from, to, about, at, server, signature}

A signal's ``type`` is a registry name, such as ``typing``, ``collected`` or ``read``; a server never reads
it and passes on one it does not know. A signal is signed by the server of ``from``'s domain, over
``SIMON-SIGNAL`` and the canonical signal without ``signature``, as an envelope is. It is never stored, so
unlike a delivery it has no repeat window, and any server may drop any signal it receives. Members a
receiver does not know are ignored, and signed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .canonical import canonical_bytes, parse, signing_bytes
from .envelope import Receiver
from .errors import SimonError, invalid
from .keys import signed_by_any
from .limits import MAX_SIGNAL_BODY_BYTES, MAX_SIGNAL_BYTES, MINIMUM_LIMITS, SIGNAL_SKEW_MS
from .messages import is_header_name
from .resolution import server_origin
from .wire import is_address, is_b64url, parse_timestamp

_HEX64 = re.compile(r"[0-9a-f]{64}")


def verify_signal(signal: Mapping[str, Any], server_keys: Iterable[Mapping[str, Any]], at_ms: int) -> bool:
    """Whether one of the sending server's keys valid at ``at_ms`` (when the signal arrives) signed it."""
    return signed_by_any(
        server_keys, at_ms, signing_bytes("SIMON-SIGNAL", dict(signal)), signal.get("signature")
    )


def parse_signal(
    body: bytes, receiver: Receiver | None = None, limits: Mapping[str, int] = MINIMUM_LIMITS
) -> dict[str, Any]:
    """Steps 1 to 3 of section 6.4: the body at most 16384 bytes (413), parsed, and the signal without its
    signature at most 4096 canonical bytes; the signal's shape; and, given the receiver, that ``server``
    names it. Steps 4 on need the network."""
    if len(body) > MAX_SIGNAL_BODY_BYTES:
        raise SimonError("body_too_large", f"The body is larger than {MAX_SIGNAL_BODY_BYTES} bytes.", 413)
    signal = parse(body)
    if not isinstance(signal, dict):
        raise invalid("A signal is a JSON object.", field="signal")
    unsigned = {k: v for k, v in signal.items() if k != "signature"}
    if len(canonical_bytes(unsigned)) > MAX_SIGNAL_BYTES:
        raise invalid(f"A signal without its signature is at most {MAX_SIGNAL_BYTES} canonical bytes.", field="signal")

    def check(name: str, ok: bool, what: str) -> None:
        if not ok:
            raise invalid(f"{name} must be {what}.", field=name)

    to = signal.get("to")
    check(
        "type",
        is_header_name(signal.get("type")),
        "a signal type: lower-case letters and digits joined by hyphens",
    )
    check("from", is_address(signal.get("from")), "an address in lower case")
    check(
        "to",
        isinstance(to, list)
        and 0 < len(to) <= limits["recipients"]
        and all(is_address(a) for a in to)
        and len(set(to)) == len(to),
        f"a non-empty array of at most {limits['recipients']} distinct addresses",
    )
    about = signal.get("about")
    check("about", isinstance(about, str) and _HEX64.fullmatch(about) is not None, "a message id")
    check("at", parse_timestamp(signal.get("at")) is not None, "a UTC timestamp")
    allow_local = receiver is not None and receiver.allow_local
    origin = server_origin(signal.get("server"), allow_local=allow_local)
    check("server", origin is not None, "the origin of the receiving server")
    check("signature", is_b64url(signal.get("signature")), "canonical base64url")
    if receiver is not None and server_origin(signal["server"], allow_local=True) != server_origin(
        receiver.origin, allow_local=True
    ):
        raise invalid(f"This signal is for {signal['server']}, not this server.", field="server")
    return signal


def check_signal_freshness(signal: Mapping[str, Any], now_ms: int) -> None:
    """Step 7: ``at`` within 300 seconds of the receiver's clock, either way, or ``400 invalid`` on ``at``."""
    t = parse_timestamp(signal.get("at"))
    if t is None or abs(t - now_ms) > SIGNAL_SKEW_MS:
        raise invalid("A signal is at most 300 seconds old or ahead.", field="at")
