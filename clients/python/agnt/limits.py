"""Every bound the protocol sets (spec section 9), in one place."""

from types import MappingProxyType

#: What every server accepts. A server may raise these, and publishes what it enforces in its document.
MINIMUM_LIMITS = MappingProxyType(
    {"messageBytes": 262_144, "recipients": 100, "requestBodyBytes": 1_048_576, "partBytes": 26_214_400}
)

MAX_PARTS = 32
#: Files one message names by content address in all: its own and those of the messages it carries inline.
MAX_NAMED_FILES = 1024
#: Those files' sizes add up to at most this many times ``partBytes`` (section 5.3, Totals).
MAX_NAMED_FILES_PART_MULTIPLE = 32
MAX_HEADERS = 32
#: A part's optional ``name`` and ``alt``, in UTF-8 bytes.
MAX_PART_NAME_BYTES = 255
MAX_ALT_BYTES = 1024
MAX_CLAIMS = 16
#: Claims and hints together, as the canonical bytes of ``{"claims":..,"hints":..}``.
MAX_ENVELOPE_EXTRAS_BYTES = 16_384
#: The largest signature an algorithm here makes, in bytes (ML-DSA-65's).
MAX_SIGNATURE_BYTES = 3309


def envelope_beside_bytes(recipients: int) -> int:
    """The most an envelope for ``recipients`` recipients holds beside its message, in canonical bytes: each
    recipient an address of the longest form (a local part of 64 bytes, each of which may be written as two,
    an ``@`` and a domain of 253), claims and hints at their bound, the longest origin, two signatures of the
    largest algorithm here, and the members' names. A bound set at this refuses no envelope the spec allows."""
    address = 2 * 64 + 1 + 253 + len('"",')
    origin = len("https://") + 253 + len(":65535") + len('""')
    signature = -(-MAX_SIGNATURE_BYTES * 4 // 3) + len('""')
    names = len('{"claims":,"claimsSignature":,"hints":,"recipients":[],"server":,"signature":}')
    return recipients * address + MAX_ENVELOPE_EXTRAS_BYTES + origin + 2 * signature + names


#: The reference server's default bound on everything in an envelope but its message, at the minimum
#: ``recipients`` (not a protocol rule).
MAX_ENVELOPE_BESIDE_MESSAGE_BYTES = envelope_beside_bytes(MINIMUM_LIMITS["recipients"])
#: A signal's body, and how far its ``at`` may be from the receiver's clock either way (section 6.4).
MAX_SIGNAL_BYTES = 4096  # a signal without its signature, in canonical bytes
MAX_SIGNAL_BODY_BYTES = 16384  # a signal's whole body, room for any signature
SIGNAL_SKEW_MS = 300_000
MAX_DOCUMENT_BYTES = 131_072
MAX_DOCUMENT_KEYS = 32
#: A document with a key revoked more than this after the time of reading is unreadable (sections 2.4, 4).
REVOCATION_AHEAD_MS = 300_000

_HOUR_MS = 3_600_000
#: How far ahead of a receiver's clock ``sentAt`` may be, everywhere.
SENT_AT_AHEAD_MS = 300_000
#: How old ``sentAt`` may be when an agent sends to its own server (CLIENT.md, send).
SEND_WINDOW_MS = 24 * _HOUR_MS
#: How old ``sentAt`` may be when another server delivers it (section 6.3, step 9).
DELIVERY_WINDOW_MS = 144 * _HOUR_MS
#: How long a receiver recognises a delivery it accepted before (section 6.3, step 8).
REPEAT_WINDOW_MS = 168 * _HOUR_MS
#: An author's server stops delivering at the earlier of these (section 6.3): five days after it accepted
#: the message, and 143 hours after ``sentAt``, an hour inside the receivers' 144.
DELIVERY_AFTER_ACCEPT_MS = 5 * 24 * _HOUR_MS
DELIVERY_AFTER_SENT_MS = 143 * _HOUR_MS
#: How long a resolver may cache each outcome (section 3): a ``server`` for its source's lifetime, at most
#: an hour; ``not_found`` ten minutes; ``temporary`` never past a minute; nothing else at all.
SERVER_CACHE_MAX_MS = _HOUR_MS
NOT_FOUND_CACHE_MS = 600_000
TEMPORARY_CACHE_MS = 60_000
#: A key counts from this long before its ``added``, since a signer's clock may run behind (section 2.4).
KEY_ADDED_SKEW_MS = 300_000
#: A signed request's timestamp is within this many seconds of the server's clock (section 8).
REQUEST_SKEW_SECONDS = 300
#: A signer does not reuse a nonce with the same key within this many seconds (section 8); a server keeps
#: each nonce until its request's timestamp leaves the window (``nonce_expiry``).
NONCE_TTL_SECONDS = 600
#: How long a reader may cache a document (section 4), and how often it may refetch a server document.
DOCUMENT_TTL_SECONDS = 600
SERVER_DOCUMENT_REFETCH_SECONDS = 60
