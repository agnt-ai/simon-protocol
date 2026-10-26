"""The message, the protocol's only object (spec sections 1, 2.2 and 5).

Every version has ``v``, ``from``, ``to``, ``sentAt`` and ``signature``; those, the canonical form and the
size are all a server checks of a version it does not know. Version 1 has exactly eight fields::

    {v, from, to, inReplyTo, parts, headers, sentAt, signature}

The id is the hex SHA-256 of the canonical bytes without ``signature``. The signature is over
``SIMON-MESSAGE``, a newline, and those same bytes.
"""

from __future__ import annotations

import base64
import re
import time
from collections.abc import Iterable, Mapping
from typing import Any

from .canonical import canonical, canonical_bytes, parse, signing_bytes, unsigned_bytes
from .errors import SimonError, invalid
from .keys import SigningKey, parse_key_token, signature_verdict, verify
from .limits import (
    MAX_ALT_BYTES,
    MAX_HEADERS,
    MAX_NAMED_FILES,
    MAX_NAMED_FILES_PART_MULTIPLE,
    MAX_PART_NAME_BYTES,
    MAX_PARTS,
    MINIMUM_LIMITS,
    SENT_AT_AHEAD_MS,
)
from .wire import is_address, is_b64url, is_base64, is_v1_address, parse_timestamp, sha256_hex, timestamp

# The wire version this port implements (spec section 5.2): one counter for every incompatible revision.
VERSION = 1
FIELDS = frozenset({"v", "from", "to", "inReplyTo", "parts", "headers", "sentAt", "signature"})

_HEX64 = re.compile(r"[0-9a-f]{64}")
# A name (spec section 5.4): hyphen-joined lower-case groups, and for a private name several such labels
# joined by dots, reverse-domain ("com.example.approve").
_HEADER_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)*")
MAX_NAME_LENGTH = 128
# An RFC 6838 restricted name in lower case, then parameters: ";", an optional space, a lower-case name,
# "=", and a value of restricted-name characters in any case or a quoted string of printable ASCII.
_NAME = r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}"
_MEDIA_TYPE = re.compile(rf'{_NAME}/{_NAME}(?:; ?{_NAME}=(?:[A-Za-z0-9!#$&^_.+-]+|"[ !#-\[\]-~]*"))*')
# The headers the protocol names (spec section 5.4); every other header is a registry convention.
PROTOCOL_HEADERS = frozenset({"for", "pairing", "succession", "critical", "rel", "feed", "audience", "listed"})
# What a part's name never holds: "/", a backslash, category Cc, and the bidirectional formatting characters.
_NOT_IN_NAME = re.compile(r"[/\\\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_NOT_IN_ALT = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_TEL = re.compile(r"tel:\+[1-9][0-9]{1,14}")
_KEY_PRINCIPAL = "simon-key:"


def message_id(message: Mapping[str, Any]) -> str:
    """The message's id: the hex SHA-256 of its canonical bytes without ``signature``."""
    return sha256_hex(unsigned_bytes(dict(message)))


def sign_message(unsigned: Mapping[str, Any], key: SigningKey) -> dict[str, Any]:
    message = {k: v for k, v in unsigned.items() if k != "signature"}
    message["signature"] = key.sign(signing_bytes("SIMON-MESSAGE", message))
    return message


def message_verdict(message: Any, keys: Iterable[Mapping[str, Any]]) -> str:
    """What the author's keys say of a message's signature at its ``sentAt``: ``verified``,
    ``unsupported_algorithm`` when keys valid then exist but none is of an algorithm implemented here, or
    ``bad_signature``."""
    at = parse_timestamp(message.get("sentAt")) if isinstance(message, dict) else None
    try:
        data = signing_bytes("SIMON-MESSAGE", message) if at is not None else None
    except (TypeError, ValueError):  # not a JSON value
        return "bad_signature"
    if data is None:
        return "bad_signature"
    return signature_verdict(keys, at, data, message.get("signature"))


def verify_message(message: Any, keys: Iterable[Mapping[str, Any]]) -> bool:
    """Whether the signature verifies with one of the author's keys valid at the message's ``sentAt``."""
    return message_verdict(message, keys) == "verified"


def check_author_signature(message: Any, keys: Iterable[Mapping[str, Any]]) -> None:
    """Step 10 of section 6.3, once the author's agent document is read: ``403 unsupported_algorithm`` when
    the author has keys valid at ``sentAt`` but none of an algorithm implemented here, ``403
    bad_signature`` when none verifies, or no key was valid then at all."""
    verdict = message_verdict(message, keys)
    if verdict == "unsupported_algorithm":
        raise SimonError(
            verdict, "The author has no key valid at sentAt of an algorithm this server implements.", 403
        )
    if verdict == "bad_signature":
        raise SimonError(
            verdict, "The message does not verify with its author's keys valid at its sentAt.", 403
        )


def check_supported_version(message: Mapping[str, Any]) -> None:
    """``send`` takes only versions the server implements (CLIENT.md): ``400 unsupported_version`` on
    ``v`` otherwise, so no agent steps around a version's rules by naming another."""
    if message.get("v") != VERSION:
        raise SimonError(
            "unsupported_version",
            f"This server does not implement version {message.get('v')} messages.",
            400,
            False,
            {"field": "v"},
        )


def parse_message(body: bytes, limits: Mapping[str, int] = MINIMUM_LIMITS) -> dict[str, Any]:
    """A body that is a message, checked as section 6.3 steps 1, 3 and 4 check it: no larger than
    ``requestBodyBytes``, parsed, already in canonical form (the refusal carries the canonical form in
    ``details.canonical``), then ``check_message``."""
    if len(body) > limits["requestBodyBytes"]:
        raise SimonError("body_too_large", f"The body is larger than {limits['requestBodyBytes']} bytes.", 413)
    value = parse(body)
    form = canonical_bytes(value)
    if form != body:
        raise invalid("The message is not in canonical form.", canonical=form.decode("utf-8"))
    return check_message(value, limits)


def check_message(value: Any, limits: Mapping[str, int] = MINIMUM_LIMITS) -> dict[str, Any]:
    """Step 4 of section 6.3: the invariants hold, the size is within ``messageBytes``, ``to`` is within
    ``recipients``, and a version 1 message keeps version 1's rules. A later version passes on its
    invariants alone. Raises ``400 invalid`` with ``details.field``."""
    message = check_invariants(value)
    try:
        size = len(canonical_bytes(message))
    except ValueError as e:  # a float, say: no canonical form, as a parsed message would never hold
        raise invalid(f"The message has no canonical JSON form: {e}", field="message") from None
    if size > limits["messageBytes"]:
        raise invalid(
            f"A message is at most {limits['messageBytes']} canonical bytes; this one is {size}.",
            field="message",
        )
    if len(message["to"]) > limits["recipients"]:
        raise invalid(f"A message names at most {limits['recipients']} recipients.", field="to")
    if message["v"] == VERSION:
        _check_version_rules(message, limits)
    return message


def check_invariants(value: Any) -> dict[str, Any]:
    """The fields every version has (section 1): a positive integer ``v``, ``from``, ``to``, ``sentAt`` and
    ``signature``."""
    if not isinstance(value, dict):
        raise invalid("The message must be a JSON object.", field="message")
    v = value.get("v")
    if type(v) is not int or v < 1:
        raise invalid("v must be a positive integer.", field="v")
    if not is_address(value.get("from")):
        raise invalid("from must be an address in lower case.", field="from")
    to = value.get("to")
    if not isinstance(to, list) or not all(is_address(a) for a in to):
        raise invalid("to must be an array of addresses in lower case.", field="to")
    if parse_timestamp(value.get("sentAt")) is None:
        raise invalid(
            "sentAt must be a UTC timestamp, e.g. 2026-10-14T21:00:00Z or 2026-10-14T21:00:00.000Z.",
            field="sentAt",
        )
    if not is_b64url(value.get("signature")):
        raise invalid("signature must be canonical base64url.", field="signature")
    return value


def _check_version_rules(m: dict[str, Any], limits: Mapping[str, int]) -> None:
    extra = next((k for k in m if k not in FIELDS), None)
    if extra is not None:
        raise invalid(f"A version {VERSION} message has no field {extra}.", field=extra)
    if not is_v1_address(m["from"]):
        raise invalid(f"from must be an ASCII address in version {VERSION}.", field="from")
    if not all(is_v1_address(a) for a in m["to"]):
        raise invalid(f"to must hold ASCII addresses in version {VERSION}.", field="to")
    if len(set(m["to"])) != len(m["to"]):
        raise invalid("An address appears twice in to.", field="to")
    if "inReplyTo" not in m or not (m["inReplyTo"] is None or _is_hex64(m["inReplyTo"])):
        raise invalid("inReplyTo must be null or a message id (64 lower-case hex).", field="inReplyTo")
    parts = m.get("parts")
    if not isinstance(parts, list) or len(parts) > MAX_PARTS:
        raise invalid(f"parts must be an array of 0 to {MAX_PARTS}.", field="parts")
    for i, part in enumerate(parts):
        _check_part(i, part, limits)
    _check_carried_files(m, limits)
    _check_headers(m)


CARRIED_MESSAGE_TYPE = "application/simon-message"
#: How deep messages are carried inline: a message a part of the carrying message carries is at depth 1, one
#: its parts carry at depth 2, and so on. A message carried deeper is refused (section 5.3).
MAX_CARRIED_DEPTH = 8


def _read_carried(data: str) -> dict[str, Any] | None:
    """The message a carried part's inline ``data`` holds (section 5.3, Form): canonical base64 of the
    canonical bytes (section 5.1) of a JSON object whose members of section 1's item 2 are well formed, so its
    id can be computed; or None. Its signature is not checked."""
    if not is_base64(data):
        return None
    raw = base64.b64decode(data)
    try:
        value = parse(raw)
        if not isinstance(value, dict) or canonical_bytes(value) != raw:
            return None
        check_invariants(value)
    except SimonError:
        return None
    return value


def _carried_parts(m: Mapping[str, Any], depth: int = 0) -> list[Any]:
    """The parts of every message ``m`` carries whole inline, at every depth up to ``MAX_CARRIED_DEPTH``. A
    carried message ``_read_carried`` refuses, or one carried deeper, makes the carrying message invalid."""
    parts = m.get("parts") if type(m.get("v")) is int and m.get("v") == VERSION else None
    if not isinstance(parts, list):
        return []
    found: list[Any] = []
    for p in parts:
        if not isinstance(p, dict):
            continue
        if not isinstance(p.get("type"), str) or not isinstance(p.get("data"), str):
            continue
        if p["type"].split(";")[0].strip(" ").lower() != CARRIED_MESSAGE_TYPE:
            continue
        carried = _read_carried(p["data"]) if depth < MAX_CARRIED_DEPTH else None
        if carried is None:
            raise invalid(
                "A message carried inline is the canonical bytes of a message (v, from, to, sentAt and signature well "
                "formed), in canonical base64."
                if depth < MAX_CARRIED_DEPTH
                else f"Messages are carried inline at most {MAX_CARRIED_DEPTH} deep.",
                field="parts",
            )
        if type(carried.get("v")) is int and carried.get("v") == VERSION and isinstance(carried.get("parts"), list):
            found.extend(carried["parts"])
        found.extend(_carried_parts(carried, depth + 1))
    return found


def _is_file_entry(p: Any) -> bool:
    return isinstance(p, dict) and "sha256" in p and "size" in p


def _check_carried_files(m: Mapping[str, Any], limits: Mapping[str, int]) -> None:
    """Section 5.3: every file a message carried inline names has a sha256 of lower-case hex and a size within
    ``partBytes``, and a message names at most ``MAX_NAMED_FILES`` files in all."""
    carried = [p for p in _carried_parts(m) if _is_file_entry(p)]
    own_files = [p for p in m["parts"] if _is_file_entry(p)]
    own = len(own_files)
    if own + len(carried) > MAX_NAMED_FILES:
        raise invalid(
            f"A message names at most {MAX_NAMED_FILES} files, its own and those of the messages it carries.",
            field="parts",
        )
    for f in carried:
        if not _is_hex64(f["sha256"]):
            raise invalid(
                "A file named by a carried message needs a sha256 of 64 lower-case hex.", field="parts"
            )
        size = f["size"]
        if type(size) is not int or size < 0 or size > limits["partBytes"]:
            raise invalid(
                "A file named by a carried message is a whole number of bytes, "
                f"at most {limits['partBytes']} here.",
                field="parts",
            )
    # A hash denotes one byte sequence, so all occurrences must agree before any fetch is deduplicated.
    sizes: dict[str, int] = {}
    for f in own_files + carried:
        earlier = sizes.get(f["sha256"])
        if earlier is not None and earlier != f["size"]:
            raise invalid("Every occurrence of a content hash must declare the same file size.", field="parts")
        sizes[f["sha256"]] = f["size"]
    # Totals count occurrences, not distinct hashes; Python integers preserve the exact bound.
    bound = MAX_NAMED_FILES_PART_MULTIPLE * limits["partBytes"]
    if sum(f["size"] for f in own_files + carried) > bound:
        raise invalid(
            f"The files a message names add up to at most {MAX_NAMED_FILES_PART_MULTIPLE} times partBytes, "
            f"{bound} bytes here.",
            field="parts",
        )


def _check_part(i: int, part: Any, limits: Mapping[str, int]) -> None:
    if not isinstance(part, dict):
        raise invalid(f"Part {i} must be a JSON object.", field="parts")
    if not is_media_type(part.get("type")):
        raise invalid(
            f"Part {i} needs a lower-case media type of at most 200 characters, e.g. text/plain.",
            field="parts",
        )
    if "name" in part and not _is_part_name(part["name"]):
        raise invalid(
            f"Part {i}: name is 1 to {MAX_PART_NAME_BYTES} bytes, not . or .., with no slash, backslash, "
            "control or bidirectional formatting character.",
            field="parts",
        )
    if "alt" in part and not _is_text(part["alt"], MAX_ALT_BYTES, _NOT_IN_ALT):
        raise invalid(
            f"Part {i}: alt is one line of 1 to {MAX_ALT_BYTES} bytes, with no control or bidirectional "
            "formatting character.",
            field="parts",
        )
    # Other members are ignored, so a later one needs no flag day; the content is one of exactly two shapes.
    content = tuple(name in part for name in ("data", "sha256", "size"))
    if content == (True, False, False):
        # One encoding per type: a JSON value for a JSON type, the text for text/*, base64 for anything else.
        if not is_json_type(part["type"]):
            if not isinstance(part["data"], str):
                raise invalid(f"Part {i}: data must be a string.", field="parts")
            if not part["type"].startswith("text/") and not is_base64(part["data"]):
                raise invalid(
                    f"Part {i}: the data of a part that is neither JSON nor text is padded, canonical base64.",
                    field="parts",
                )
    elif content == (False, True, True):
        if not _is_hex64(part["sha256"]):
            raise invalid(f"Part {i}: sha256 must be 64 lower-case hex.", field="parts")
        if type(part["size"]) is not int or part["size"] < 0:
            raise invalid(f"Part {i}: size must be a whole number of bytes.", field="parts")
        if part["size"] > limits["partBytes"]:
            raise invalid(
                f"Part {i}: a part is at most {limits['partBytes']} bytes here; share a larger one by "
                "reference.",
                field="parts",
            )
    else:
        raise invalid(f"Part {i} has data, or sha256 and size, beside its type.", field="parts")


def _is_part_name(value: object) -> bool:
    return value not in (".", "..") and _is_text(value, MAX_PART_NAME_BYTES, _NOT_IN_NAME)


def _is_text(value: object, max_bytes: int, disallowed: re.Pattern[str]) -> bool:
    """Whether a value is a string of 1 to ``max_bytes`` UTF-8 bytes holding no ``disallowed`` character."""
    if not isinstance(value, str):
        return False
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:  # a lone surrogate
        return False
    return 1 <= size <= max_bytes and not disallowed.search(value)


def _check_headers(m: dict[str, Any]) -> None:
    headers = m.get("headers")
    if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
        raise invalid(f"headers must be an object of at most {MAX_HEADERS} strings.", field="headers")
    for name, value in headers.items():
        if not is_header_name(name):
            raise invalid(
                f"A header name is lower-case letters and digits in groups joined by hyphens: {name}",
                field="headers",
            )
        if not isinstance(value, str):
            raise invalid(f"Header {name} must be a string.", field="headers")
    principal, pairing, critical = headers.get("for"), headers.get("pairing"), headers.get("critical")
    if principal is not None and not is_principal(principal):
        raise invalid(
            "The for header is a principal: mailto:<address>, tel:<E.164 number> or simon-key:<key token>.",
            field="headers",
        )
    if pairing is not None and parse_pairing(pairing) is None:
        raise invalid(
            "The pairing header is a timestamp, one space, and a signature in canonical base64url.", field="headers"
        )
    if (pairing is not None) != (principal_key(principal) is not None):
        raise invalid(
            "The pairing header is present exactly when the for header is a simon-key: principal.",
            field="headers",
        )
    succession = headers.get("succession")
    if succession is not None and pairing is None:
        raise invalid("The succession header goes only with a simon-key: for and its pairing.", field="headers")
    if succession is not None and not is_succession_value(succession):
        raise invalid(
            "The succession header is steps joined by commas: a key token and two signatures, one space apart.",
            field="headers",
        )
    if critical is not None and not is_critical_value(critical):
        raise invalid(
            "The critical header is header names joined by commas, with no spaces.", field="headers"
        )
    rel, feed, audience = headers.get("rel"), headers.get("feed"), headers.get("audience")
    # A rel without inReplyTo, or a feed on a message with recipients, means nothing and is ignored; audience
    # is security metadata, so its placement is checked (spec section 5.4).
    if rel is not None and not is_header_name(rel):
        raise invalid("The rel header is a relation name.", field="headers")
    if feed is not None and not is_critical_value(feed):
        raise invalid(
            "The feed header is feed names joined by commas, with no spaces.", field="headers"
        )
    if audience is not None and m["to"]:
        raise invalid(
            "The audience header belongs only on a published message, whose to is empty.", field="headers"
        )
    # Publishing is explicit: a message names recipients, or says who may read it (spec section 5.2).
    if not m["to"] and audience is None:
        raise invalid(
            "A message with no recipients is published, and says who may read it: an audience header, "
            "public for anyone.",
            field="headers",
        )
    listed = headers.get("listed")
    if listed is not None and not (
        is_listed_value(listed) and rel is not None and m["inReplyTo"] is not None and m["to"]
    ):
        raise invalid(
            "The listed header is yes, on a relation (it carries rel) whose to is not empty.", field="headers"
        )


def is_listed_value(value: object) -> bool:
    """Whether a value is a ``listed`` header: exactly ``yes`` (section 5.4), the writer's consent to have
    a relation listed under the published message it names (publishing profile, section 4)."""
    return value == "yes"


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def is_media_type(value: object) -> bool:
    """A lower-case ``type/subtype`` of RFC 6838 restricted names, then parameters; at most 200."""
    return isinstance(value, str) and len(value) <= 200 and _MEDIA_TYPE.fullmatch(value) is not None


def is_header_name(value: object) -> bool:
    """A name: lower-case letters and digits in groups joined by single hyphens, or several such labels
    joined by dots for a private name, at most 128 characters."""
    return isinstance(value, str) and len(value) <= MAX_NAME_LENGTH and _HEADER_NAME.fullmatch(value) is not None


#: How deep a part's ``data`` sits in its message: the message, its ``parts`` list, the part (spec 5.1).
_DATA_DEPTH = 3


def json_data_problem(data: Any) -> str | None:
    """Why a value cannot be a JSON block's ``data``, or None when it can (spec sections 5.1 and 5.3). The
    value is signed inside the message, so canonical JSON limits it: integers within +/-(2^53 - 1), no
    floats, and at most 64 levels of nesting counting the message's own three."""
    nested: Any = data
    for _ in range(_DATA_DEPTH):
        nested = [nested]
    try:
        canonical(nested)
        return None
    except (ValueError, TypeError) as e:
        return (
            f"A JSON block's data must fit canonical JSON (spec section 5.1): {e} Numbers are integers "
            "within +/-(2^53 - 1), with no fraction or exponent, and values nest at most 61 levels; write "
            '19.99 as the string "19.99" or as 1999 in a smaller unit, or send the bytes as a base64 block '
            "of another type."
        )


def is_json_type(media_type: str) -> bool:
    """Whether a media type is a JSON type (spec section 5.3), whose inline ``data`` is a JSON value:
    ``application/json``, or any type with the ``+json`` suffix, whatever its parameters."""
    base = media_type.split(";", 1)[0].strip()
    return base == "application/json" or base.endswith("+json")


def is_critical_value(value: object) -> bool:
    """Header names joined by commas, with no spaces."""
    return isinstance(value, str) and all(is_header_name(name) for name in value.split(","))


def header(message: Mapping[str, Any], name: str) -> str | None:
    """A version 1 header's value, or None."""
    return message["headers"].get(name)


def text_of(message: Mapping[str, Any], separator: str = "\n") -> str:
    """The text of a message's inline ``text/*`` parts."""
    return separator.join(
        p["data"]
        for p in message["parts"]
        if "data" in p and p["type"].startswith("text/") and isinstance(p["data"], str)
    )


def is_fresh(sent_at: str, now_ms: int, past_ms: int, ahead_ms: int | None = SENT_AT_AHEAD_MS) -> bool:
    """Whether ``sent_at`` is at most ``past_ms`` before ``now_ms`` and at most ``ahead_ms`` after it (no
    bound ahead when None). The windows are ``SEND_WINDOW_MS``, ``DELIVERY_WINDOW_MS`` and, with no bound
    ahead, ``REPEAT_WINDOW_MS``."""
    t = parse_timestamp(sent_at)
    return t is not None and now_ms - past_ms <= t and (ahead_ms is None or t <= now_ms + ahead_ms)


# Principals (section 2.2): mailto:<v1 address>, tel:<E.164>, or simon-key:<key token>, written exactly.


def is_principal(value: object) -> bool:
    """Whether a value is a principal's identifier, and so a well-formed ``for`` header."""
    if not isinstance(value, str):
        return False
    if value.startswith("mailto:"):
        return is_v1_address(value[len("mailto:") :])
    if value.startswith(_KEY_PRINCIPAL):
        return parse_key_token(value[len(_KEY_PRINCIPAL) :]) is not None
    return _TEL.fullmatch(value) is not None


def principal_key(principal: object) -> str | None:
    """The key token a key principal names, or None for any other value."""
    if isinstance(principal, str) and principal.startswith(_KEY_PRINCIPAL) and is_principal(principal):
        return principal[len(_KEY_PRINCIPAL) :]
    return None


#: The longest a pairing may last from any moment it counts at: 366 days, so no pairing is for good.
PAIRING_MAX_MS = 366 * 24 * 60 * 60 * 1000

#: How long ``sign_pairing`` makes a pairing last when given no ``until``: 365 days.
PAIRING_DEFAULT_MS = 365 * 24 * 60 * 60 * 1000


def pairing_bytes(agent: str, principal: str, until: str) -> bytes:
    """What a key principal signs to pair with an agent until ``until``, a wire timestamp: ``SIMON-PAIR``,
    the address, the identifier and ``until``."""
    return f"SIMON-PAIR\n{agent}\n{principal}\n{until}".encode()


def unpairing_bytes(agent: str, principal: str) -> bytes:
    """What a key principal signs to end its pairing with an agent: ``SIMON-UNPAIR``, the address and the
    identifier."""
    return f"SIMON-UNPAIR\n{agent}\n{principal}".encode()


def sign_pairing(key: SigningKey, agent: str, until: str | None = None) -> str:
    """The ``pairing`` a key principal gives the agent at ``agent``, ``<until> <signature>``, lasting until
    ``until`` (a year from now by default); its ``for`` is ``key.identifier``."""
    until = timestamp(int(time.time() * 1000) + PAIRING_DEFAULT_MS) if until is None else until
    return f"{until} {key.sign(pairing_bytes(agent, key.identifier, until))}"


def parse_pairing(pairing: object) -> tuple[str, str] | None:
    """A ``pairing`` value's ``(until, signature)``: a wire timestamp, one space and canonical base64url;
    otherwise None."""
    if not isinstance(pairing, str):
        return None
    parts = pairing.split(" ")
    if len(parts) != 2 or parse_timestamp(parts[0]) is None or not is_b64url(parts[1]):
        return None
    return parts[0], parts[1]


def verify_pairing(agent: str, principal: str, pairing: object, at_ms: int | None = None) -> bool:
    """Whether ``pairing`` pairs ``agent`` with the key ``principal`` names at ``at_ms`` (now by default):
    its signature verifies, and the moment is before its ``until`` by at most ``PAIRING_MAX_MS``. A
    reader acting on a message asks for now; one showing an old message may ask for its ``sentAt``."""
    key, parsed = principal_key(principal), parse_pairing(pairing)
    if key is None or parsed is None:
        return False
    until, signature = parsed
    end = parse_timestamp(until)
    t = int(time.time() * 1000) if at_ms is None else at_ms
    if not (end is not None and t < end and end - t <= PAIRING_MAX_MS):
        return False
    return verify(key, pairing_bytes(agent, principal, until), signature)


def recover_bytes(agent: str, new_key: str, at: str) -> bytes:
    """What a key principal signs to recover its agent at once (CLIENT.md register, Appendix A
    ``recover-signed``): ``SIMON-RECOVER``, the address, the new key token and ``at``, a timestamp."""
    return f"SIMON-RECOVER\n{agent}\n{new_key}\n{at}".encode()


def sign_recovery(key: SigningKey, agent: str, new_key: str, at: str) -> str:
    """The ``recover`` a key principal gives to recover ``agent`` to ``new_key``; its ``for`` is
    ``key.identifier``. A server takes it while ``at`` is at most 24 hours old and 5 minutes ahead."""
    return key.sign(recover_bytes(agent, new_key, at))


def verify_recovery(agent: str, principal: str, new_key: str, at: str, recover: object) -> bool:
    """Whether ``recover`` is the signature of the key ``principal`` names, recovering ``agent`` to
    ``new_key`` at ``at``."""
    key = principal_key(principal)
    return key is not None and verify(key, recover_bytes(agent, new_key, at), recover)


def succession_bytes(old: str, new: str) -> bytes:
    """What a key principal's old key and its new key both sign when the new key succeeds the old:
    ``SIMON-SUCCEED``, the old identifier and the new."""
    return f"SIMON-SUCCEED\n{old}\n{new}".encode()


def sign_succession(old: SigningKey, new: SigningKey) -> str:
    """One step of a ``succession`` header, ``<old key token> <old signature> <new signature>``: both of the
    principal's keys signing that ``new`` succeeds ``old`` (section 2.2)."""
    data = succession_bytes(old.identifier, new.identifier)
    return f"{old.token} {old.sign(data)} {new.sign(data)}"


#: The most steps a ``succession`` header holds: a principal moves keys rarely, and each step costs every reader.
MAX_SUCCESSION_STEPS = 16


def is_succession_value(value: object) -> bool:
    """Whether a value has the ``succession`` header's grammar: 1 to 16 steps joined by commas, each a key
    token and two canonical base64url signatures, one space apart."""
    if not isinstance(value, str) or len(value.split(",")) > MAX_SUCCESSION_STEPS:
        return False
    for step in value.split(","):
        parts = step.split(" ")
        if len(parts) != 3 or parse_key_token(parts[0]) is None or not all(is_b64url(p) for p in parts[1:]):
            return False
    return True


def read_succession(value: object, principal: str) -> list[dict[str, str]] | None:
    """The steps a ``succession`` header names, oldest first, as ``{"from", "to"}`` identifiers leading to
    ``principal``, the message's ``for``; None unless the grammar holds, each step's new key is the next
    step's old key (the last's is ``principal``'s), no key appears twice, and both signatures of every step
    verify."""
    if not is_succession_value(value) or principal_key(principal) is None:
        return None
    parsed = [step.split(" ") for step in value.split(",")]  # type: ignore[union-attr]
    ids = [_KEY_PRINCIPAL + key for key, _, _ in parsed] + [principal]
    if len(set(ids)) != len(ids):
        return None
    steps = [{"from": ids[i], "to": ids[i + 1]} for i in range(len(parsed))]
    for (key, old_signature, new_signature), step in zip(parsed, steps):
        data = succession_bytes(step["from"], step["to"])
        if not (verify(key, data, old_signature) and verify(principal_key(step["to"]), data, new_signature)):
            return None
    return steps


def sign_unpairing(key: SigningKey, agent: str) -> str:
    """The unpairing a key principal gives to end the pairing of ``key.identifier`` with ``agent``."""
    return key.sign(unpairing_bytes(agent, key.identifier))


def verify_unpairing(agent: str, principal: str, unpairing: object, succession: object = None) -> bool:
    """Whether ``unpairing`` ends ``agent``'s pairing with the key ``principal`` names: it is that key's
    signature, or, given a ``succession`` leading to ``principal``, the signature of any key the principal
    moved on from along it. Unpairing always wins (section 2.2): a move never shields an agent from a key it
    moved on from."""
    earlier = [] if succession is None else read_succession(succession, principal)
    if earlier is None:
        return False
    for identifier in [principal, *(step["from"] for step in earlier)]:
        key = principal_key(identifier)
        if key is not None and verify(key, unpairing_bytes(agent, identifier), unpairing):
            return True
    return False


def check_principal(
    message: Mapping[str, Any], kind: str, principal: str | None = None, now_ms: int | None = None
) -> None:
    """What an agent's own server checks on send (CLIENT.md), given the agent's kind, ``paired`` or
    ``solo``, and a paired agent's principal. A paired agent's version 1 message carries its principal as
    ``for``, and a ``pairing`` that verifies exactly when the principal is a key. A solo agent's carries
    neither. A ``succession`` must verify; with one, a key principal's ``for`` may be a successor of the
    agent's principal, and the server then moves its record to it (section 2.2). The pairing must count at
    ``sentAt`` and, when ``now_ms`` is given (the server's clock), at that moment too, so a message backdated
    within the send window cannot carry a pairing that has already lapsed. Raises ``400 invalid`` on
    ``headers``. A later version's headers are not known, so it passes."""
    if message["v"] != VERSION:
        return
    found, pairing = header(message, "for"), header(message, "pairing")
    if kind == "solo":
        if found is not None or pairing is not None:
            raise invalid(
                "A solo agent speaks for no one: its messages carry no for and no pairing.", field="headers"
            )
        return
    succession = header(message, "succession")
    steps = [] if succession is None or found is None else read_succession(succession, found)
    if steps is None:
        raise invalid(
            "Each succession step must be signed by both its keys over SIMON-SUCCEED, the old and the new "
            "identifier, leading to for.",
            field="headers",
        )
    if found != principal and not any(step["from"] == principal for step in steps):
        raise invalid(
            f"A paired agent's messages carry its principal as the for header, or a successor it signed: {principal}.",
            field="headers",
        )
    # The agent's principal, or the successor it moves to: either way the one that must have signed the pairing.
    principal = found
    if principal_key(principal) is None:
        if pairing is not None:
            raise invalid(
                "Only a key principal pairs by signature: this message carries no pairing.", field="headers"
            )
    elif (
        (sent := parse_timestamp(message["sentAt"])) is None
        or not verify_pairing(message["from"], principal, pairing, sent)
        or (now_ms is not None and not verify_pairing(message["from"], principal, pairing, now_ms))
    ):
        until = (parse_pairing(pairing) or ("<until>", ""))[0]
        expected = pairing_bytes(message["from"], principal, until).decode("utf-8")
        raise invalid(
            f"The pairing header must be <until> <signature>: the principal's signature over "
            f"{canonical(expected)}, valid at sentAt and now: before until, by at most 366 days. The principal "
            "renews a lapsed pairing by signing a later until.",
            field="headers",
        )
