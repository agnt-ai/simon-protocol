"""An agent and its own server: the calls of spec/CLIENT.md, and reading other agents.

    register      POST /simon/register
    send          POST /simon/send
    sync          GET  /simon/sync?since=<token>&limit=<n>&wait=<seconds>
    sent          GET  /simon/sent/<id>
    upload_part   PUT  /simon/parts/<sha256>
    fetch_part    GET  /simon/parts/<sha256>

Every call is signed (spec section 8). A refusal raises SimonError with the server's code, detail and
details, and the status and ``retryable`` of its answer (RFC 9457 problem details, section 9). A failure
that may pass is never read as an absence: it raises a retryable SimonError (``timeout``,
``network_error``, ``unavailable``).

Reading other agents (a Reader, which every Agent is) takes keys only from the server an address's domain
resolves to (sections 3 and 4). Nothing here takes a server to ask instead: a reader told by a message, a
flag or a tool argument which server holds an author's keys would believe whoever told it. Tests and local
development replace the resolver itself, an option only code can pass.
"""

from __future__ import annotations

import dataclasses

import json
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Literal
from urllib.parse import quote, urlencode

from .canonical import canonical_bytes, parse
from .documents import read_agent_document, read_server_document
from .envelope import claims_about, is_authoritative, verify_claims
from .errors import SimonError, is_retryable, parse_problem
from .keys import SigningKey, parse_key_token
from .limits import (
    DOCUMENT_TTL_SECONDS,
    MAX_DOCUMENT_BYTES,
    MINIMUM_LIMITS,
    SERVER_DOCUMENT_REFETCH_SECONDS,
)
from .messages import (
    is_header_name,
    PAIRING_DEFAULT_MS,
    PROTOCOL_HEADERS,
    VERSION,
    check_message,
    check_principal,
    header,
    is_principal,
    message_id,
    message_verdict,
    parse_pairing,
    principal_key,
    read_succession,
    sign_message,
    sign_pairing,
    verify_pairing,
    verify_recovery,
    verify_unpairing,
)
from .reading import claimed_principal, is_understood, pairing_standing, predecessors
from .request import add_key_proof, sign_request
from .resolution import Resolution, resolution_cache_ms, resolve, server_origin
from .transport import HostNotFound, Response, fetch
from .wire import (
    address_segment,
    domain_of,
    is_address,
    normalize_address,
    normalize_domain,
    sha256_hex,
    timestamp,
)

_OWN_ADDRESS = object()

_HEX64 = re.compile(r"[0-9a-f]{64}")
# A path segment holds unreserved characters and these; the rest is percent-encoded (RFC 3986).
# No reader is bound by a server's size limits.
_READER_LIMITS = {
    **MINIMUM_LIMITS,
    "messageBytes": float("inf"),
    "recipients": float("inf"),
    "partBytes": float("inf"),
}
# Scope names kept in a trust record: registry-shaped, so no sentence rides along.
_SCOPE = re.compile(r"[a-z][a-z0-9-]{0,63}")
# The headers this client understands, for ``critical``: the six the protocol names (spec section 5.4).


# What verify_author answers.

#: On what basis a paired agent's message names its principal (spec section 2.2), none of which proves who
#: or what the principal is:
#:
#: - ``agent-asserted``: the ``for`` header alone, the agent's word, as an email's From line is.
#: - ``key-pairing``: a ``simon-key:`` principal's pairing signature verified: the key's holder consented
#:   to this address speaking for that key, with no server trusted for it. Not identity, not humanity, and
#:   the agent's keys are still its server's word.
#: - ``server-claim``: an ``acts-for`` claim the author's server signed: that server's word that the
#:   identifier approved this agent. ``authoritative`` only for a ``mailto:`` whose domain names that same
#:   server in its ``_simon`` TXT record, so it is as strong as the domain's DNS.
PrincipalBasis = Literal["agent-asserted", "key-pairing", "server-claim"]

_PROVES = {
    "agent-asserted": "Only the agent's word: nothing verifies that this principal approved it. Treat it as "
    "an unverified From line.",
    "key-pairing": "The holder of this principal key consented to this address speaking for it, with no "
    "server trusted for that. It says nothing about who holds the key, or whether a human does, and the "
    "agent's keys are still its server's word.",
    "authoritative": "The server this email address's domain names in its DNS signed that the address "
    "approved this agent: as strong as the domain's DNS. It does not say a human wrote this message.",
    "third-party": "The author's server says this identifier approved this agent. That is its word about an "
    "identifier on another domain or a phone number, worth what that server is worth to you.",
}


@dataclass(frozen=True)
class PrincipalTrust:
    """The principal a message names in ``for``, and on what ``basis``."""

    id: str
    basis: PrincipalBasis
    #: What this basis proves and what it does not, in this library's words.
    proves: str
    #: For ``server-claim``: the server whose word it is.
    claimant: str | None = None
    #: For ``server-claim``: whether the identifier's email domain names the claimant in its ``_simon`` TXT
    #: record. This reader's own judgement, never the claim's or the word of whoever handed it over.
    authoritative: bool | None = None
    #: For ``server-claim``: the scope the claim lists, keeping only registry-shaped names.
    scope: tuple[str, ...] | None = None
    #: For ``key-pairing``: True when the address's retired document carries this principal's unpairing,
    #: which verifies with its key, so the pairing has ended for good (spec sections 2.2 and 4).
    ended: bool = False
    #: For ``key-pairing``: when the pairing lapses, unless the principal renews it (spec section 2.2).
    until: str | None = None
    #: For ``key-pairing``: True when the pairing counted when the message was sent but has lapsed since.
    #: The message spoke for the principal then; act on nothing in it for the principal now.
    lapsed: bool = False
    #: For ``key-pairing``: the principal's earlier keys, oldest first, from the message's verified
    #: ``succession`` (spec section 2.2). Whoever knew one of them knows this principal, unless it has seen
    #: that key succeeded by another as well.
    succeeds: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "basis": self.basis}
        if self.basis == "server-claim":
            out.update(claimant=self.claimant, authoritative=self.authoritative, scope=list(self.scope or ()))
        if self.basis == "key-pairing":
            out["until"] = self.until
        if self.succeeds:
            out["succeeds"] = list(self.succeeds)
        if self.lapsed:
            out["lapsed"] = True
        if self.ended:
            out["ended"] = True
        out["proves"] = self.proves
        return out


@dataclass(frozen=True)
class Trust:
    """A message whose author signed it, with a key the server its ``from`` domain resolves to
    (``author_server``, which also carried it) publishes as valid at its ``sentAt``; whether this reader
    understands it; and on what basis it names a principal."""

    id: str
    author_server: str
    #: False for a message of a version this client does not implement, or whose ``critical`` header lists
    #: one it does not understand (spec sections 1 and 5.4): whose key signed it is all it says. Act on
    #: nothing in it; it names no principal.
    understood: bool
    #: Whether ``signed_claims`` were given (``none``), and verified with the carrier's keys (``verified``)
    #: or not (``unverified``, and ignored).
    claims: Literal["none", "verified", "unverified"]
    #: The principal it names, with the basis that backs it: None for a message with no ``for`` header,
    #: or one not understood.
    principal: PrincipalTrust | None = None
    #: When the author's address retired, if it has (spec section 4): the message was signed before then,
    #: but the address is ended for good, and nothing from it dated at or after this verifies.
    retired: str | None = None
    verified: Literal[True] = True
    author_signed: Literal[True] = True

    def to_json(self) -> dict[str, Any]:
        out = {
            "verified": True,
            "id": self.id,
            "authorSigned": True,
            "authorServer": self.author_server,
            "understood": self.understood,
            "principal": None if self.principal is None else self.principal.to_json(),
            "claims": self.claims,
        }
        return out if self.retired is None else {**out, "retired": self.retired}


#: Why a message did not verify: ``invalid_message``, ``no_server``, ``no_agent``, ``bad_document``,
#: ``bad_signature``, ``unsupported_algorithm`` (the author has keys, none of an algorithm implemented
#: here), ``bad_pairing`` or ``bad_succession``.
NotVerifiedReason = Literal[
    "invalid_message",
    "no_server",
    "no_agent",
    "bad_document",
    "bad_signature",
    "unsupported_algorithm",
    "bad_pairing",
    "bad_succession",
]


@dataclass(frozen=True)
class NotVerified:
    """A definite answer that the message's author did not sign it as it stands."""

    id: str | None
    reason: NotVerifiedReason
    verified: Literal[False] = False

    def to_json(self) -> dict[str, Any]:
        return {"verified": False, "id": self.id, "reason": self.reason}


Verification = Trust | NotVerified


class Reader:
    """Reads other agents: resolution, documents, and who wrote a message, on what basis. Holds no key.

    ``resolver`` resolves a domain to a Resolution (default ``resolve``: DNS, then the well-known answer);
    replace it only for tests and local development.
    """

    def __init__(self, *, timeout: float = 30.0, resolver: Callable[[str], Resolution] | None = None) -> None:
        self.timeout = timeout
        self._resolver = resolver or (lambda domain: resolve(domain))
        self._skew = 0.0  # seconds to add to this clock, learned from a server's serverTime
        self._cache: dict[tuple[str, str], tuple[float, Any]] = {}

    def server_of(self, domain: str) -> str:
        """The origin of the server a domain resolves to, always by resolution. Raises ``no_server`` for a
        definite outcome, and retryable ``unavailable`` for ``temporary``. Outcomes are cached as section 3
        allows: a ``server`` for its source's TTL (at most an hour), ``not_found`` ten minutes, and
        ``temporary`` one minute."""
        name = normalize_domain(domain)
        if name is None:
            raise _invalid("domain", f"Not a domain: {domain!r}.")
        resolution = self._resolution(name)
        if resolution.outcome != "server":
            details = {"domain": name, "outcome": resolution.outcome}
            raise SimonError(
                "no_server", f"{name} resolves to no SIMON server: {resolution.outcome}.", details=details
            )
        return resolution.server

    def server_document(self, server: str, *, refresh: bool = False) -> dict[str, Any]:
        """A server's document, ``{"server", "keys", "algorithms", "limits"}``. Cached for ten minutes;
        ``refresh`` fetches it again unless it was fetched in the last minute."""
        origin = _origin_arg("server", server)
        max_age = SERVER_DOCUMENT_REFETCH_SECONDS if refresh else DOCUMENT_TTL_SECONDS
        return self._cached(("server", origin), max_age, lambda: self._read_server_document(origin))

    def agent_document(self, address: str, *, refresh: bool = False) -> dict[str, Any] | None:
        """An agent's document, from the server its address's domain resolves to, verified under that
        server's keys valid now: ``{"address", "server", "keys", "algorithms"}``, ``algorithms``
        being those its server verifies. None when the server answers that no such agent exists. Cached for
        ten minutes."""
        wire = address if is_address(address) else _address_arg("address", address)
        max_age = 0 if refresh else DOCUMENT_TTL_SECONDS
        return self._cached(("agent", wire), max_age, lambda: self._read_agent_document(wire))

    def verify_author(self, message: Any, *, signed_claims: Any = None) -> Verification:
        """Whether a message was signed by its author, with a key the server ``from``'s domain resolves to
        publishes as valid at its ``sentAt``; whether this reader understands it; and if so, on what basis
        it names its principal. A message without a ``for`` header speaks for no one; one with it names a
        principal only as far as a pairing or a trusted claim backs it.

        Pass the sync entry's ``signedClaims`` as ``signed_claims`` so an ``acts-for`` claim counts. They
        count only when their signature verifies with a key of the server ``from``'s domain resolves to,
        the message's carrier (spec 6.1), read here. An entry's ``claims`` never count: they are its
        server's judgement, and anyone can paste an entry. Answers a Trust or a NotVerified; a failure that
        may pass raises a retryable SimonError, never "not verified". There is no option naming the server
        to ask.
        """
        try:
            m = check_message(message, _READER_LIMITS)
        except SimonError:
            return NotVerified(None, "invalid_message")
        id = message_id(m)
        try:
            author = self.agent_document(m["from"])
            verdict = "verified" if author is None else message_verdict(m, author["keys"])
            if verdict != "verified" and author is not None:
                author = self.agent_document(m["from"], refresh=True)  # its keys may have changed
        except SimonError as e:
            if e.code in ("no_server", "bad_document"):
                return NotVerified(id, e.code)
            raise
        if author is None:
            return NotVerified(id, "no_agent")
        verdict = message_verdict(m, author["keys"])
        if verdict != "verified":
            return NotVerified(id, verdict)
        server = author["server"]
        claims = None if signed_claims is None else self._carried_claims(signed_claims, m, server)
        understood = is_understood(m, PROTOCOL_HEADERS)
        status = "none" if signed_claims is None else "unverified" if claims is None else "verified"
        trust = Trust(id, server, understood, status, retired=author.get("retired"))
        principal = claimed_principal(m) if understood else None
        if principal is None:
            return trust
        if principal_key(principal) is not None:
            standing = pairing_standing(m, self._now_ms())
            if standing == "refused":
                return NotVerified(id, "bad_pairing")
            lapsed = standing == "lapsed"
            earlier = predecessors(m)
            if earlier == "refused":
                return NotVerified(id, "bad_succession")
            unpairing = author.get("unpairing")
            # Unpairing always wins: one signed by a key the principal moved on from ends the agent too.
            ended = unpairing is not None and any(
                verify_unpairing(m["from"], p, unpairing) for p in [principal, *earlier]
            )
            until = parse_pairing(header(m, "pairing"))[0]  # type: ignore[index]
            proves = _PROVES["key-pairing"]
            return _with(trust, PrincipalTrust(principal, "key-pairing", proves, ended=ended, until=until, lapsed=lapsed, succeeds=tuple(earlier)))
        considered = claims_about(m, claims or ())
        claim = next((c for c in considered if c["type"] == "acts-for"), None)
        if claim is None:
            return _with(trust, PrincipalTrust(principal, "agent-asserted", _PROVES["agent-asserted"]))
        authoritative = is_authoritative(claim, server, self._resolution, m["from"])
        scope = tuple(s for s in claim["scope"] if _SCOPE.fullmatch(s))
        proves = _PROVES["authoritative" if authoritative else "third-party"]
        return _with(trust, PrincipalTrust(principal, "server-claim", proves, server, authoritative, scope))

    # Plumbing.

    def _carried_claims(
        self, signed: Any, m: Mapping[str, Any], carrier: str
    ) -> list[Mapping[str, Any]] | None:
        """The claims an entry's ``signedClaims`` hold, when their carrier signed them for this message;
        otherwise None, whatever they say."""
        if not isinstance(signed, dict) or not isinstance(signed.get("signature"), str):
            return None
        claims = signed.get("claims")
        if not isinstance(claims, list) or not all(
            isinstance(c, dict) and isinstance(c.get("type"), str) for c in claims
        ):
            return None
        keys = self.server_document(carrier)["keys"]
        try:
            return claims if verify_claims(signed, m, keys) else None
        except (ValueError, TypeError):  # claims with no canonical form were never signed
            return None

    def _resolution(self, name: str) -> Resolution:
        """A domain's resolution, as it came, through this reader's cache; a failure that may pass raises."""
        hit = self._cache.get(("resolution", name))
        if hit and hit[0] > time.monotonic():
            resolution = hit[1]
        else:
            resolution = self._resolver(name)
            ttl_ms = resolution_cache_ms(resolution, resolution.ttl_ms)
            if ttl_ms:
                self._cache[("resolution", name)] = (time.monotonic() + ttl_ms / 1000, resolution)
        if resolution.outcome == "temporary":
            details = {"domain": name, "outcome": resolution.outcome}
            raise SimonError(
                "unavailable", f"Resolving {name} failed for now; try again later.", None, True, details
            )
        return resolution

    def _read_server_document(self, origin: str) -> dict[str, Any]:
        response = self._document(f"{origin}/simon/server")
        doc = read_server_document(response.body, origin, self._now_ms()) if response.status == 200 else None
        if doc is None:
            raise _bad_document(
                response, f"{response.url} is not a readable server document naming {origin}."
            )
        return doc

    def _read_agent_document(self, address: str) -> dict[str, Any] | None:
        server = self.server_of(domain_of(address))
        response = self._document(f"{server}/simon/agents/{address_segment(address)}")
        if response.status == 404:
            return None
        if response.status != 200:
            raise _bad_document(response, f"{response.url} answered {response.status}, not a document.")
        for refresh in (False, True):  # a signature that does not verify: read the server's keys again
            server_doc = self.server_document(server, refresh=refresh)
            doc = read_agent_document(response.body, address, server_doc["keys"], self._now_ms())
            if doc is not None:
                return {**doc, "server": server, "algorithms": server_doc["algorithms"]}
        raise _bad_document(
            response, f"{response.url} is not an agent document for {address} signed by {server}."
        )

    def _document(self, url: str) -> Response:
        response = self._fetch("GET", url, max_bytes=MAX_DOCUMENT_BYTES)
        if is_retryable(response.status):
            raise SimonError(
                "unavailable",
                f"{url} answered {response.status}; try again later.",
                response.status,
                True,
                {"url": url},
                retry_after=_retry_after(response),
            )
        return response

    def _cached(self, key: tuple[str, str], max_age: float, load: Callable[[], Any]) -> Any:
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < max_age:
            return hit[1]
        value = load()
        if value is not None:  # an agent that did not exist is asked about afresh
            self._cache[key] = (time.monotonic(), value)
        return value

    def _fetch(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        **options: Any,
    ) -> Response:
        timeout = options.pop("timeout", self.timeout)
        try:
            return fetch(method, url, body, dict(headers or {}), timeout=timeout, **options)
        except TimeoutError:
            details = {"url": url, "timeout": timeout}
            message = f"{method} {url}: no answer within {timeout} s."
            raise SimonError("timeout", message, None, True, details) from None
        except (HostNotFound, OSError) as e:
            cause = "no such host" if isinstance(e, HostNotFound) else str(e) or type(e).__name__
            message = f"{method} {url} failed: {cause}."
            raise SimonError("network_error", message, None, True, {"url": url, "cause": cause}) from None

    def _now_ms(self) -> int:
        return int((time.time() + self._skew) * 1000)


class Agent(Reader):
    """An agent: its server, its key and, once registered, its address.

    ``principal`` is a paired agent's principal, written into every message as its ``for`` header, and
    ``pairing``, for a key principal, the principal's signature, written as ``pairing``. Both are None for
    a solo agent. An Agent is also a Reader, and reads other agents through resolution like any other,
    never through its own server.
    """

    def __init__(
        self,
        server: str,
        key: SigningKey | None = None,
        address: str | None = None,
        *,
        principal: str | None = None,
        pairing: str | None = None,
        succession: str | None = None,
        timeout: float = 30.0,
        resolver: Callable[[str], Resolution] | None = None,
    ) -> None:
        super().__init__(timeout=timeout, resolver=resolver)
        self.origin = _origin_arg("server", server)
        self.key = key
        self.address = None if address is None else _address_arg("address", address)
        self.principal = principal
        self.pairing = pairing
        self.succession = succession

    def __repr__(self) -> str:
        return f"Agent({self.origin!r}, {self.key!r}, {self.address!r})"

    # The calls of CLIENT.md.

    def register(
        self,
        address: str | None = None,
        *,
        code: str | None = None,
        principal: str | None = None,
        pairing: str | None = None,
        extensions: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Lease, bind or pair this key's address; use recover for an existing address. Success is the account object
        (address, keys, grants, recovery), without a status member. A 202 answer carries
        code_sent or pairing_required; those never bind this key.

        ``extensions`` carries namespaced host-defined creation proofs,
        repeated unchanged when a 202 asks for another call.
        """
        body: dict[str, str] = dict(extensions or {})
        reserved = {"key", "address", "code", "for", "pairing", "at", "recover"}
        if any(k in reserved or re.fullmatch(r"[a-z][a-z0-9.-]*:[a-zA-Z0-9._-]+", k) is None or not isinstance(v, str) for k, v in body.items()):
            raise _invalid("extensions", "Host extensions are strings and cannot replace API members.")
        body["key"] = self._key().token
        if address is not None:
            body["address"] = _address_arg("address", address)
        for name, value in (("code", code), ("for", principal), ("pairing", pairing)):
            if value is not None:
                if not isinstance(value, str):
                    raise _invalid(name, f"{name} is a string.")
                body[name] = value
        # A leased address signs an empty identity even when this object previously had one.
        result = self.call("POST", "/simon/register", canonical_bytes(body), agent=body.get("address"))
        if isinstance(result, dict) and isinstance(result.get("keys"), list):
            self.address = result["address"]
            if principal is not None:
                self.principal, self.pairing, self.succession = principal, pairing, None
        return result

    def account(self) -> dict[str, Any]:
        """The agent's address, keys (including labels), grants and pending recovery."""
        return self.call("GET", "/simon/account")

    def recover(self, address: str, principal_key: SigningKey | None = None, *, code: str | None = None,
                at: str | None = None, recover: str | None = None,
                principal: str | None = None, pairing: str | None = None) -> dict[str, Any]:
        """Recover an existing address through its dedicated endpoint. A principal key may sign the proof;
        otherwise request a mailbox code, then repeat with that code. Only an account answer binds this key.
        """
        address = _address_arg("address", address)
        if principal_key is not None:
            if recover is not None:
                raise _invalid("recover", "Provide a principal key or its signature, not both.")
            if principal is not None and principal != principal_key.identifier:
                raise _invalid("principal", "The recovery principal must match its signing key.")
            principal = principal_key.identifier
            pairing = sign_pairing(principal_key, address, timestamp(self._now_ms() + PAIRING_DEFAULT_MS)) if pairing is None else pairing
            at = timestamp(self._now_ms()) if at is None else at
            recover = principal_key.sign(f"SIMON-RECOVER\n{address}\n{self._key().token}\n{at}".encode())
        if principal is None and self.principal is not None and self.address != address:
            raise _invalid("principal", "Recovery of a different address requires an explicit local principal choice.")
        effective_principal = self.principal if principal is None else principal
        effective_pairing = (self.pairing if pairing is None else pairing) if principal is None else pairing
        if effective_pairing is not None and effective_principal is None:
            raise _invalid("principal", "Pairing needs its principal.")
        if effective_principal is not None and (not is_principal(effective_principal) or (effective_principal.startswith("simon-key:") and not verify_pairing(address, effective_principal, effective_pairing, self._now_ms()))):
            raise _invalid("pairing", "Effective recovery principal must be valid; its key pairing must verify for the target address.")
        if recover is not None and (effective_principal is None or not effective_principal.startswith("simon-key:") or not isinstance(at, str) or not verify_recovery(address, effective_principal, self._key().token, at, recover)):
            raise _invalid("recover", "Recovery proof must verify for this same principal, target address, new key and timestamp.")
        body = {"address": address, "key": self._key().token}
        for name, value in (("code", code), ("at", at), ("recover", recover)):
            if value is not None:
                if not isinstance(value, str):
                    raise _invalid(name, f"{name} is a string.")
                body[name] = value
        result = self.call("POST", "/simon/recovery", canonical_bytes(body), agent=address)
        if isinstance(result, dict) and isinstance(result.get("keys"), list):
            self.address = result["address"]
            if effective_principal != self.principal:
                self.succession = None
            self.principal, self.pairing = effective_principal, effective_pairing
        return result

    def recovery_status(self) -> dict[str, Any]:
        """Read pending recovery state as the authorized agent."""
        self._address()
        return self.call("GET", "/simon/recovery")

    def recover_by_principal(self, address: str, at: str, recover: str, *, principal: str | None = None, pairing: str | None = None) -> dict[str, Any]:
        """Recover with an already-signed principal proof."""
        return self.recover(address, at=at, recover=recover, principal=principal, pairing=pairing)

    def cancel_recovery(self, address: str | None = None, cancel_code: str | None = None) -> dict[str, Any]:
        """Cancel by this agent's key, or by an address and its mailbox cancel code.
        The answer is {status: cancelled, address}; a code requires no registered key.
        """
        if (address is None) != (cancel_code is None):
            raise _invalid("cancelCode", "Provide both address and cancel_code, or neither.")
        if cancel_code is None:
            self._address()
            return self.call("POST", "/simon/recovery/cancel", canonical_bytes({}))
        if not isinstance(cancel_code, str):
            raise _invalid("cancelCode", "cancel_code is a string.")
        address = _address_arg("address", address)
        body = {"address": address, "cancelCode": cancel_code}
        return self.call("POST", "/simon/recovery/cancel", canonical_bytes(body), agent=address)

    def add_key(self, new_key: SigningKey, label: str | None = None) -> dict[str, Any]:
        """Add a device key, with proof of possession and an optional private label."""
        body = {"key": new_key.token, "proof": add_key_proof(new_key, self._address())}
        if label is not None:
            if not isinstance(label, str) or len(label) > 64:
                raise _invalid("label", "label is a string of at most 64 characters.")
            body["label"] = label
        return self.call("POST", "/simon/keys", canonical_bytes(body))

    def revoke_key(self, key: str) -> dict[str, Any]:
        if parse_key_token(key) is None:
            raise _invalid("key", "key is a public key token.")
        return self.call("DELETE", "/simon/keys/" + quote(key, safe=""))

    def end_grant(self, id: str) -> dict[str, Any]:
        if not isinstance(id, str) or not id:
            raise _invalid("id", "A grant id is a nonempty string.")
        return self.call("DELETE", "/simon/grants/" + quote(id, safe=""))

    def unpair(self, address: str, unpairing: str, succession: str | None = None) -> dict[str, Any]:
        """Retire a paired address by its principal's unpairing. One signed by a key the principal moved on
        from also counts, given ``succession``, the chain from that key to the principal the server holds."""
        address = _address_arg("address", address)
        body = {"address": address, "unpairing": unpairing}
        if succession is not None:
            body["succession"] = succession
        return self.call("POST", "/simon/unpair", canonical_bytes(body), agent=address)

    def renew_pairing(self, pairing: str) -> None:
        """Carry a renewed pairing from now on: the principal's signature over a later ``until`` (spec
        section 2.2). The server holds no pairing, so renewing needs no call to it; this checks the pairing
        counts now."""
        address = self._address()
        if self.principal is None or not verify_pairing(address, self.principal, pairing, self._now_ms()):
            raise _invalid("pairing", "A renewed pairing must be the principal's, for this address, and count now.")
        self.pairing = pairing

    def succeed(self, principal: str, pairing: str, succession: str) -> None:
        """Move to the principal's new key (spec section 2.2): ``principal`` its new identifier, a ``pairing``
        that key signed, and the ``succession``, steps both keys signed, leading from the principal this agent
        has to it. The steps from this agent's principal on are added to the chain it already carries, so moving
        twice before sending keeps the whole way. Checked here; the server moves its record on the next
        message, so this needs no call."""
        address = self._address()
        steps = read_succession(succession, principal) or []
        start = next((i for i, step in enumerate(steps) if step["from"] == self.principal), None)
        if start is None:
            raise _invalid("succession", "A succession must verify and lead from this agent's principal to the new one.")
        added = ",".join(succession.split(",")[start:])
        chain = succession if self.succession is None else f"{self.succession},{added}"
        if read_succession(chain, principal) is None:
            raise _invalid("succession", "The chain this agent carries and the new steps do not make one succession.")
        if not verify_pairing(address, principal, pairing, self._now_ms()):
            raise _invalid("pairing", "The new key's pairing must be for this address, and count now.")
        self.principal, self.pairing, self.succession = principal, pairing, chain

    def compose(
        self,
        to: Iterable[str],
        text: str | None = None,
        *,
        parts: Iterable[Mapping[str, Any]] = (),
        headers: Mapping[str, str] | None = None,
        in_reply_to: str | None = None,
    ) -> dict[str, Any]:
        """A signed version 1 message, written now, and checked as this agent's server will check it.

        ``text``, when given, becomes the first part (``text/plain``), ahead of ``parts``; a message may
        carry any parts, or none. An empty ``to`` publishes the message, which then needs an ``audience`` header (``public`` for anyone). The agent writes ``for`` and ``pairing`` itself, so ``headers`` must not.
        """
        headers = dict(headers or {})
        for name in ("for", "pairing", "succession"):
            if name in headers:
                raise _invalid(
                    "headers", f"The agent writes the {name} header from its pairing; leave it out."
                )
        if self.principal is not None:
            headers["for"] = self.principal
        if self.pairing is not None:
            headers["pairing"] = self.pairing
        if self.succession is not None:
            headers["succession"] = self.succession
        message = sign_message(
            {
                "v": VERSION,
                "from": self._address(),
                "to": [_address_arg(f"to[{i}]", a) for i, a in enumerate(to)],
                "inReplyTo": in_reply_to,
                "parts": ([{"type": "text/plain", "data": text}] if text is not None else []) + list(parts),
                "headers": headers,
                "sentAt": timestamp(self._now_ms()),
            },
            self._key(),
        )
        check_message(message)
        if self.principal is not None:
            check_principal(message, "paired", self.principal)
        return message

    def send(
        self,
        to: Iterable[str],
        text: str | None = None,
        *,
        hints: Mapping[str, Mapping[str, str]] | None = None,
        **draft: Any,
    ) -> dict[str, Any]:
        """Compose a message (``draft`` takes compose's options) and send it: ``{"id", "receivedAt"}``."""
        return self.send_message(self.compose(to, text, **draft), hints=hints)

    def send_message(
        self, message: Mapping[str, Any], *, hints: Mapping[str, Mapping[str, str]] | None = None
    ) -> dict[str, Any]:
        """Send a signed message; sending it again is safe. ``hints`` go to each recipient's server, keyed
        by an address in ``to``: ``{"bob@example.net": {"invite": "7KQ2-..."}}``. A message of a version
        the server does not implement is refused with ``400 unsupported_version``."""
        stranger = next((r for r in hints or {} if r not in message["to"]), None)
        if stranger is not None:
            raise _invalid("hints", f"hints name {stranger}, which is not in the message's to.")
        headers = {"simon-hints": _ascii_json(hints)} if hints else None
        result = self.call("POST", "/simon/send", canonical_bytes(message), headers)
        if result.get("id") != message_id(message):
            raise SimonError(
                "bad_response",
                f"The server named the message {result.get('id')}; its id is {message_id(message)}.",
                details={"url": self.origin + "/simon/send"},
            )
        return result

    def sync(self, since: str | None = None, limit: int | None = None, wait: int | None = None, *, request_timeout: float | None = None) -> dict[str, Any]:
        """Received and sent messages, signals and history changes since an opaque token.
        Save ``token`` and pass it next time. ``410 token_expired`` is surfaced, never
        retried from the beginning silently. ``more`` asks for another page at once.
        """
        if request_timeout is not None and (not isinstance(request_timeout, (int, float)) or not 0 < request_timeout < float("inf")):
            raise _invalid("request_timeout", "request_timeout is positive and finite.")
        query: dict[str, str | int] = {}
        if since is not None:
            if not isinstance(since, str) or not since:
                raise _invalid("since", "since is an opaque string from an earlier sync.")
            query["since"] = since
        if limit is not None:
            if type(limit) is not int or not 1 <= limit <= 200:
                raise _invalid("limit", "limit is a whole number from 1 to 200.")
            query["limit"] = limit
        if wait is not None:
            if type(wait) is not int or not 0 <= wait <= 60:
                raise _invalid("wait", "wait is a whole number from 0 to 60.")
            query["wait"] = wait
        return self.call("GET", "/simon/sync" + ("?" + urlencode(query) if query else ""), timeout=request_timeout if request_timeout is not None else max(self.timeout, (wait or 0) + 5))

    def send_signal(self, type: str, about: str, to: Iterable[str]) -> dict[str, Any]:
        """Ask the server to send a signal. Read/typing sharing is always opt-in."""
        if not is_header_name(type):
            raise _invalid("type", "A signal type is a name: a registry name, or a private reverse-domain one.")
        body = {"type": type, "about": _hex64_arg("about", about),
                "to": [_address_arg(f"to[{i}]", a) for i, a in enumerate(to)]}
        return self.call("POST", "/simon/send-signal", canonical_bytes(body))

    def add_webhook(self, url: str) -> dict[str, Any]:
        return self.call("POST", "/simon/webhooks", canonical_bytes({"url": url}))

    def verify_webhook(self, id: str, code: str) -> dict[str, Any]:
        return self.call("POST", "/simon/webhooks/" + quote(id, safe="") + "/verify", canonical_bytes({"code": code}))

    def remove_webhook(self, id: str) -> Any:
        return self.call("DELETE", "/simon/webhooks/" + quote(id, safe=""))

    def sent(self, id: str) -> dict[str, Any]:
        """How delivery of this agent's own message is going, one entry per recipient server:
        ``{"id", "servers": [{"server", "recipients", "status", "reason"?}]}``. ``status`` is ``pending``,
        ``delivered`` or ``failed``; a failure's ``reason`` is the resolution outcome, the code the
        receiving server answered, or ``expired`` when the delivery deadline passed."""
        return self.call("GET", f"/simon/sent/{_hex64_arg('id', id)}")

    def upload_part(
        self, data: bytes, type: str = "application/octet-stream", name: str | None = None
    ) -> dict[str, Any]:
        """Upload a part's bytes before sending a message that names them. Returns the part for ``parts``,
        with ``name``, the file name suggested to its readers, when given."""
        sha256 = sha256_hex(data)
        self.call("PUT", f"/simon/parts/{sha256}", data, {"content-type": "application/octet-stream"})
        part = {"type": type, "sha256": sha256, "size": len(data)}
        return part if name is None else {**part, "name": name}

    def fetch_part(self, sha256: str, size: int | None = None) -> bytes:
        """The bytes of a part this agent uploaded, sent or received, checked against the hash, and the size
        when given. ``503 unavailable`` (retryable, with ``retry_after``) while the server fetches them."""
        response = self._signed("GET", f"/simon/parts/{_hex64_arg('sha256', sha256)}")
        digest = sha256_hex(response.body)
        if digest != sha256 or (size is not None and len(response.body) != size):
            raise SimonError(
                "hash_mismatch",
                f"{response.url} sent {len(response.body)} bytes hashing to {digest}.",
                details={"url": response.url, "sha256": digest, "size": len(response.body)},
            )
        return response.body

    def call(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        *,
        agent: str | None | object = _OWN_ADDRESS,
        timeout: float | None = None,
    ) -> Any:
        """Any signed request to this agent's server, for calls a server adds: ``path`` is the path and
        query, and a body is JSON unless ``headers`` say otherwise. It acts as ``agent``, by default this
        agent's address once it has one. Answers the response's JSON, or None for an empty body."""
        if body is not None:
            headers = {"content-type": "application/json", **(headers or {})}
        response = self._signed(method, path, body, headers, agent=agent, timeout=timeout)
        try:
            return parse(response.body) if response.body else None
        except SimonError:
            raise SimonError(
                "bad_response",
                f"{response.url} answered {response.status} with a body that is not JSON.",
                response.status,
                details={"url": response.url},
            ) from None

    # Plumbing.

    def _signed(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        *,
        agent: str | None | object = _OWN_ADDRESS,
        timeout: float | None = None,
    ) -> Response:
        """A signed request, and its answer when it is a success. A ``stale_request`` refusal teaches this
        agent the server's clock, and the request is signed again, once."""
        if not path.startswith("/") or path.startswith("//"):
            raise _invalid("path", f"A path starts with a single /: {path!r}")
        url = self.origin + path
        budget = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + budget

        def attempt() -> Response:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SimonError("timeout", f"{method} {url}: no answer within {budget} s.", None, True, {"url": url, "timeout": budget})
            signature = sign_request(
                self._key(), method, url, body or b"", now=time.time() + self._skew, agent=self.address if agent is _OWN_ADDRESS else agent
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SimonError("timeout", f"{method} {url}: no answer within {budget} s.", None, True, {"url": url, "timeout": budget})
            return self._fetch(method, url, body, {**signature, **(headers or {})}, timeout=remaining)

        response = attempt()
        if response.status >= 300:
            error = _error(response)
            server_time = error.details.get("serverTime")
            if error.code != "stale_request" or type(server_time) is not int:
                raise error
            self._skew = server_time - time.time()
            response = attempt()
            if response.status >= 300:
                raise _error(response)
        return response

    def _key(self) -> SigningKey:
        if self.key is None:
            raise SimonError("no_key", "This agent has no key to sign with.")
        return self.key

    def _address(self) -> str:
        if self.address is None:
            raise SimonError("not_registered", "This agent has no address yet: register first.")
        return self.address


def verify_author(message: Any, *, signed_claims: Any = None, timeout: float = 30.0) -> Verification:
    """``Reader().verify_author``: who wrote a message, by keys from the server its ``from`` domain
    resolves to, whether it is understood, and on what basis it names a principal."""
    return Reader(timeout=timeout).verify_author(message, signed_claims=signed_claims)


def _with(trust: Trust, principal: PrincipalTrust) -> Trust:
    return dataclasses.replace(trust, principal=principal)


def _ascii_json(value: Any) -> str:
    """JSON in printable ASCII, as an HTTP header carries it: ``json.dumps`` escapes every character
    beyond ASCII (above U+FFFF as a surrogate pair), and DEL too here."""
    return json.dumps(value, separators=(",", ":")).replace("\x7f", "\\u007f")


def _error(response: Response) -> SimonError:
    """The error an answer carries: the server's problem details (section 9), or ``bad_response`` when it
    sent none. ``status`` and ``retryable`` follow the HTTP status; the code, detail and details are the
    server's."""
    retry_after = _retry_after(response)
    error = parse_problem(response.status, response.body, retry_after=retry_after)
    if error is not None:
        return error
    return SimonError(
        "bad_response",
        f"{response.url} answered {response.status} without problem details.",
        response.status,
        is_retryable(response.status),
        {"url": response.url},
        retry_after=retry_after,
    )


def _retry_after(response: Response) -> int | None:
    """``Retry-After`` in seconds: a whole number of seconds, or an HTTP date."""
    value = response.headers.get("retry-after")
    if value is None:
        return None
    if value.isascii() and value.isdigit():
        return int(value)
    try:
        return max(0, int(parsedate_to_datetime(value).timestamp() - time.time() + 0.999))
    except (TypeError, ValueError):
        return None


def _bad_document(response: Response, message: str) -> SimonError:
    return SimonError("bad_document", message, response.status, False, details={"url": response.url})


def _invalid(field: str, message: str) -> SimonError:
    return SimonError("invalid", message, details={"field": field})


def _origin_arg(field: str, value: str) -> str:
    origin = server_origin(value, allow_local=True)
    if origin is None:
        raise _invalid(field, f"{field} is an origin such as https://simon.example.com, not {value!r}.")
    return origin


def _address_arg(field: str, value: str) -> str:
    address = normalize_address(value)
    if address is None:
        raise _invalid(field, f"{field} is not an address (local@domain): {value!r}")
    return address


def _hex64_arg(field: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise _invalid(field, f"{field} is 64 lower-case hex digits, not {value!r}.")
    return value
