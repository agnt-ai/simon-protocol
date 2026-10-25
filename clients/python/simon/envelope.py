"""The transport envelope one server posts to another, ``POST /simon/deliver`` (spec section 6)::

    {message, server, recipients, claims?, claimsSignature?, hints?, signature}

The message's signature proves its author; the envelope's, by the carrying server, proves which server
carried it, and to whom: ``server`` is the receiving origin and ``recipients`` the addresses in ``to`` it
serves, so an envelope can be neither replayed to another server nor stretched to other recipients. Claims
(statements the carrier makes about the author) are also signed on their own, over ``SIMON-CLAIMS`` and
``{"claims","message":<id>}``, so they travel with the message into inboxes and stay checkable wherever it
goes. Members a receiver does not know are ignored, and signed like any other.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonical, canonical_bytes, parse_with_members, signing_bytes
from .errors import SimonError, invalid
from .keys import signed_by_any, valid_during, verify
from .limits import (
    DELIVERY_AFTER_ACCEPT_MS,
    DELIVERY_AFTER_SENT_MS,
    DELIVERY_WINDOW_MS,
    MAX_CLAIMS,
    MAX_ENVELOPE_BESIDE_MESSAGE_BYTES,
    MAX_ENVELOPE_EXTRAS_BYTES,
    MINIMUM_LIMITS,
    REPEAT_WINDOW_MS,
)
from .messages import check_message, is_fresh, is_principal, message_id
from .reading import claimed_principal
from .reading import claimed_principal
from .resolution import Resolution, server_origin
from .wire import domain_of, is_address, is_b64url, parse_timestamp


@dataclass(frozen=True)
class Receiver:
    """The server a delivery arrives at: its own origin. ``allow_local`` lets ``server`` be ``http:`` or a
    loopback host, for local development only."""

    origin: str
    allow_local: bool = False


def parse_envelope(
    body: bytes, limits: Mapping[str, int] = MINIMUM_LIMITS, receiver: Receiver | None = None
) -> dict[str, Any]:
    """Steps 1 to 4 of section 6.3, in order: the body within ``requestBodyBytes`` (413) and parsed; the
    envelope's shape; the message in canonical form exactly as it arrived (the refusal carries the
    canonical form); then ``check_message``. Given the ``receiver``, also step 5, ``check_destination``,
    which needs no lookup. The envelope itself need not be canonical."""
    if len(body) > limits["requestBodyBytes"]:
        raise SimonError("body_too_large", f"The body is larger than {limits['requestBodyBytes']} bytes.", 413)
    value, members = parse_with_members(body)
    envelope = check_envelope_shape(value, allow_local=receiver is not None and receiver.allow_local)
    form = canonical(envelope["message"])
    if members["message"] != form:
        raise invalid("The message is not in canonical form.", canonical=form)
    check_message(envelope["message"], limits)
    if receiver is not None:
        check_destination(envelope, receiver)
    return envelope


def check_envelope_shape(value: Any, *, allow_local: bool = False) -> dict[str, Any]:
    """Step 2: an object whose ``message`` is an object, ``signature`` base64url, ``server`` an origin and
    ``recipients`` a non-empty array of distinct addresses, with ``claims`` and ``hints``, when present, as
    section 6.2 says, hints keyed only by ``recipients``, and ``claimsSignature`` present exactly when
    ``claims`` is (everything but the message is a server's own bound: ``check_envelope_beside``). Raises
    ``400 invalid`` with ``details.field``."""
    if not isinstance(value, dict):
        raise invalid("The envelope must be a JSON object.", field="envelope")
    if not isinstance(value.get("message"), dict):
        raise invalid("message must be a JSON object.", field="message")
    if not is_b64url(value.get("signature")):
        raise invalid("signature must be canonical base64url.", field="signature")
    if server_origin(value.get("server"), allow_local=allow_local) is None:
        raise invalid("server must be the origin of the server the envelope is for.", field="server")
    recipients = value.get("recipients")
    if (
        not isinstance(recipients, list)
        or not recipients
        or not all(is_address(r) for r in recipients)
        or len(set(recipients)) != len(recipients)
    ):
        raise invalid("recipients must be a non-empty array of distinct addresses.", field="recipients")
    claims, hints = value.get("claims", []), value.get("hints", {})
    if not isinstance(claims, list) or len(claims) > MAX_CLAIMS:
        raise invalid(f"claims must be an array of at most {MAX_CLAIMS} objects.", field="claims")
    if not all(isinstance(c, dict) and isinstance(c.get("type"), str) and c["type"] for c in claims):
        raise invalid("Each claim is an object with a non-empty string type.", field="claims")
    if "claimsSignature" in value if "claims" not in value else not is_b64url(value.get("claimsSignature")):
        raise invalid(
            "claimsSignature, the carrier signature over the claims, is present exactly when claims is.",
            field="claimsSignature",
        )
    if not isinstance(hints, dict):
        raise invalid("hints must be an object keyed by recipient address.", field="hints")
    for recipient, notes in hints.items():
        if recipient not in recipients:
            raise invalid(
                f"hints name {recipient}, which is not one of this envelope's recipients.", field="hints"
            )
        if not isinstance(notes, dict) or not all(isinstance(v, str) for v in notes.values()):
            raise invalid("Each recipient's hints are an object of strings.", field="hints")
    if len(canonical_bytes({"claims": claims, "hints": hints})) > MAX_ENVELOPE_EXTRAS_BYTES:
        raise invalid(
            f"Claims and hints together are at most {MAX_ENVELOPE_EXTRAS_BYTES} canonical bytes.",
            field="claims",
        )
    return value


def check_envelope_beside(
    envelope: Mapping[str, Any], max_bytes: int = MAX_ENVELOPE_BESIDE_MESSAGE_BYTES
) -> None:
    """A server's own bound on everything in an envelope but its message, in canonical bytes. Not a protocol
    rule; the reference server's default is ``MAX_ENVELOPE_BESIDE_MESSAGE_BYTES``."""
    beside = {k: v for k, v in envelope.items() if k != "message"}
    if len(canonical_bytes(beside)) > max_bytes:
        raise invalid(
            f"Everything in an envelope but its message is at most {max_bytes} bytes here.",
            field="envelope",
        )


def check_destination(envelope: Mapping[str, Any], receiver: Receiver) -> None:
    """Step 5: the envelope is for this server, and every recipient is in the message's ``to``. Otherwise
    ``400 invalid`` on ``server`` or ``recipients``. Nothing is resolved: whether this server serves the
    recipients is step 8 (``check_served``), once the carrier is known."""
    if server_origin(envelope["server"], allow_local=True) != server_origin(
        receiver.origin, allow_local=True
    ):
        raise invalid(f"This envelope is for {envelope['server']}, not this server.", field="server")
    for r in envelope["recipients"]:
        if r not in envelope["message"]["to"]:
            raise invalid(f"{r} is not in the message's to.", field="recipients")


def check_served(
    recipients: Iterable[str], serves: Callable[[str], bool], field: str = "recipients"
) -> None:
    """Step 8: every recipient is on a domain this server serves, or ``400 invalid`` on ``field``. A server
    may need to resolve a domain to know, which it does only now, after the carrier's signature verified."""
    for r in recipients:
        if not serves(domain_of(r)):
            raise invalid(f"This server does not serve {r}.", field=field)


def claims_bytes(claims: Iterable[Mapping[str, Any]], message: str) -> bytes:
    """The bytes a carrier signs for its claims about one message (by id): ``SIMON-CLAIMS``, a newline, and
    the canonical ``{"claims","message"}``."""
    return signing_bytes("SIMON-CLAIMS", {"claims": list(claims), "message": message})


def verify_envelope(
    envelope: Mapping[str, Any], server_keys: Iterable[Mapping[str, Any]], at_ms: int
) -> bool:
    """Whether one of the carrying server's keys valid at ``at_ms``, when the envelope arrived, signed it
    and, if it carries claims, signed them."""
    keys = list(server_keys)
    return signed_by_any(
        keys, at_ms, signing_bytes("SIMON-ENVELOPE", dict(envelope)), envelope.get("signature")
    ) and (
        "claims" not in envelope
        or signed_by_any(
            keys,
            at_ms,
            claims_bytes(envelope["claims"], message_id(envelope["message"])),
            envelope.get("claimsSignature"),
        )
    )


def check_envelope_signature(
    envelope: Mapping[str, Any], server_keys: Iterable[Mapping[str, Any]], now_ms: int
) -> None:
    """Step 7 of section 6.3: the envelope, and its claims, verify with a carrier key valid now, or ``403
    bad_signature`` (a failed envelope or message signature is 403; a failed request signature is 401)."""
    if not verify_envelope(envelope, server_keys, now_ms):
        raise SimonError(
            "bad_signature", "The envelope does not verify with a key of the carrier's server valid now.", 403
        )


def verify_claims(
    signed: Mapping[str, Any], message: Mapping[str, Any], carrier_keys: Iterable[Mapping[str, Any]]
) -> bool:
    """Whether a carrier made these claims about this message (section 6.2), checked by anyone, at any
    time: one of the carrier's keys valid at some moment of the message's delivery window, from its
    ``sentAt`` to 144 hours after, signed them. ``signed`` is ``{"claims", "signature"}``, as an inbox entry
    carries them. ``carrier_keys`` are the keys of the server the message's ``from`` domain resolves to,
    read by the checker itself, never taken from whoever handed it the message."""
    sent = parse_timestamp(message.get("sentAt"))
    if sent is None:
        return False
    data = claims_bytes(signed["claims"], message_id(dict(message)))
    return any(
        valid_during(k, sent, sent + DELIVERY_WINDOW_MS) and verify(k.get("key"), data, signed["signature"])
        for k in carrier_keys
    )


def is_repeat(envelope: Mapping[str, Any], accepted_for: Iterable[str], now_ms: int) -> bool:
    """Step 8: a repeat, answered ``202`` at once, when this message was accepted here before for every
    address in ``recipients`` (``accepted_for``) and its ``sentAt`` is within the last 168 hours."""
    accepted = set(accepted_for)
    return is_fresh(envelope["message"]["sentAt"], now_ms, REPEAT_WINDOW_MS, None) and all(
        r in accepted for r in envelope["recipients"]
    )


def claims_about(
    message: Mapping[str, Any], claims: Iterable[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    """The claims a receiver may consider (section 6.2, and the registry's ``identifier``): an ``acts-for``
    claim counts only when its ``agent`` is the message's ``from``, its ``for`` is the message's ``for``
    header, its ``verifiedAt`` a timestamp and its ``scope`` an array of strings; so never for a message
    without a ``for`` header, or of a version whose headers this reader does not know. An ``identifier``
    claim counts only when its ``agent`` is the message's ``from``, its ``identifier`` a ``mailto:`` or
    ``tel:`` identifier, its ``verifiedAt`` a timestamp, and its ``of`` is ``agent``, or ``principal`` on a
    message whose ``for`` header names a key. Other types pass through, opaque."""
    principal = claimed_principal(message)

    def acts_for(c: Mapping[str, Any]) -> bool:
        scope = c.get("scope")
        return (
            principal is not None
            and c.get("agent") == message.get("from")
            and c.get("for") == principal
            and parse_timestamp(c.get("verifiedAt")) is not None
            and isinstance(scope, list)
            and all(isinstance(s, str) for s in scope)
        )

    def identifier(c: Mapping[str, Any]) -> bool:
        value = c.get("identifier")
        return (
            c.get("agent") == message.get("from")
            and (
                c.get("of") == "agent"
                or (
                    c.get("of") == "principal"
                    and isinstance(principal, str)
                    and principal.startswith("simon-key:")
                )
            )
            and is_principal(value)
            and not value.startswith("simon-key:")
            and parse_timestamp(c.get("verifiedAt")) is not None
        )

    checks = {"acts-for": acts_for, "identifier": identifier}
    return [
        c for c in claims if not isinstance(c.get("type"), str) or checks.get(c["type"], lambda _: True)(c)
    ]


def is_authoritative(
    claim: Mapping[str, Any],
    carrier: str,
    resolve: Callable[[str], Resolution],
    agent: str | None = None,
) -> bool:
    """Whether an ``acts-for`` claim is authoritative (section 6.2): its ``for`` is a ``mailto:``
    identifier whose domain names the carrier by its ``_simon`` TXT record, so the domain's DNS speaks for
    its mail as a DKIM key does. A domain whose server only its well-known answer names grants no
    authority: whoever runs a domain's website need not run its mail. Never for a phone number or a key.
    ``resolve(domain)`` answers a Resolution; any outcome but ``server`` is not authority, ``temporary``
    included. The legacy ``agent`` argument is accepted for reader compatibility; author-domain
    alignment does not affect authority."""
    principal = claim.get("for")
    if not isinstance(principal, str) or not principal.startswith("mailto:"):
        return False
    domain = domain_of(principal)
    r = resolve(domain)
    return r.outcome == "server" and r.via == "dns" and r.server == server_origin(carrier, allow_local=True)


def judge_claims(
    message: Mapping[str, Any],
    claims: Iterable[Mapping[str, Any]] | None,
    carrier: str,
    resolve: Callable[[str], Resolution],
) -> list[dict[str, Any]]:
    """The claims a receiver considers, each ``acts-for`` claim marked with ``authoritative``, the
    receiving server's judgement, which it passes to its agents with the claim (CLIENT.md, inbox), and each
    ``identifier`` claim judged the same way by its ``identifier``. A received claim's own
    ``authoritative`` member means nothing (the carrier cannot judge itself), so it is dropped from every
    claim, and only the judged types get one back."""
    judged = {"acts-for": "for", "identifier": "identifier"}
    out = []
    for claim in claims_about(message, claims or ()):
        c = {k: v for k, v in claim.items() if k != "authoritative"}
        if isinstance(c.get("type"), str) and c["type"] in judged:
            c["authoritative"] = is_authoritative(
                {"for": c[judged[c["type"]]]}, carrier, resolve
            )
        out.append(c)
    return out


def delivery_window(sent_at: str, accepted_at_ms: int) -> tuple[int, int]:
    """When an author's server may deliver a message it accepted at ``accepted_at_ms`` (section 6.3), as
    ``(earliest, deadline)`` in milliseconds: not before ``sentAt``, and not at or after the deadline, the
    earlier of five days after acceptance and 143 hours after ``sentAt``."""
    sent = parse_timestamp(sent_at)
    if sent is None:
        raise ValueError(f"{sent_at!r} is not a wire timestamp.")
    return sent, min(accepted_at_ms + DELIVERY_AFTER_ACCEPT_MS, sent + DELIVERY_AFTER_SENT_MS)


def delivery_state(sent_at: str, accepted_at_ms: int, now_ms: int) -> str:
    """Whether a delivery attempt at ``now_ms`` is ``early``, ``due``, or ``expired`` (at or after the
    deadline; ``sent`` then reports the recipients failed with reason ``expired``)."""
    earliest, deadline = delivery_window(sent_at, accepted_at_ms)
    if now_ms >= deadline:
        return "expired"
    return "early" if now_ms < earliest else "due"
