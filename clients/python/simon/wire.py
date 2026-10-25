"""The small grammars every object uses: encodings, timestamps and addresses (spec sections 2.1 and 2.5).

Every check here is ASCII-exact: ``[0-9]``, never ``\\d``, and ASCII lowercasing only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from datetime import UTC, datetime, timedelta

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Encodings (section 2.5)

_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def b64url(data: bytes) -> str:
    """Unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(text: object) -> bytes | None:
    """The bytes of canonical, unpadded base64url (the one spelling that decodes back to itself), or None."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return data if b64url(data) == text else None


def is_b64url(value: object) -> bool:
    """Whether a value is non-empty canonical base64url, as every signature is written."""
    return bool(from_b64url(value))


def is_base64(value: object) -> bool:
    """Whether a value is padded, canonical base64, as part data is written."""
    if not isinstance(value, str) or not _B64.fullmatch(value):
        return False
    try:
        return base64.b64encode(base64.b64decode(value, validate=True)).decode("ascii") == value
    except binascii.Error:
        return False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Timestamps (section 2.5)

_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{3}))?Z"
)


def parse_timestamp(value: object) -> int | None:
    """The instant a wire timestamp names, in milliseconds since 1970 (negative before it), or None.

    ``YYYY-MM-DDTHH:MM:SSZ`` or ``YYYY-MM-DDTHH:MM:SS.sssZ``, years 0000 to 9999 of the proleptic
    Gregorian calendar, naming a real moment: no 30 February, no hour 24, no leap second.
    """
    m = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if not m:
        return None
    year, month, day, hour, minute, second = map(int, m.groups()[:6])
    if not (1 <= month <= 12 and 1 <= day <= _days_in_month(year, month)):
        return None
    if hour > 23 or minute > 59 or second > 59:
        return None
    seconds = _days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
    return seconds * 1_000 + int(m.group(7) or 0)


def timestamp(ms: int | None = None) -> str:
    """The wire timestamp of a moment in milliseconds since 1970 (now, by default), to the millisecond.
    Raises OverflowError outside years 0001 to 9999."""
    if ms is None:
        ms = time.time_ns() // 1_000_000
    t = _EPOCH + timedelta(milliseconds=ms)
    return (
        f"{t.year:04d}-{t.month:02d}-{t.day:02d}T{t.hour:02d}:{t.minute:02d}:{t.second:02d}.{ms % 1_000:03d}Z"
    )


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 in the proleptic Gregorian calendar, year 0 included (H. Hinnant)."""
    year -= month <= 2
    era = year // 400
    year_of_era = year - era * 400
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    return era * 146_097 + day_of_era - 719_468


# Addresses (section 2.1)

_LOCAL_V1 = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PRINTABLE_ASCII = re.compile(r"[\x21-\x7e]+")
# What no local part holds in any version: @, space, category Cc and, on the wire, ASCII capitals.
_NOT_IN_LOCAL = re.compile(r"[@ \x00-\x1f\x7f-\x9fA-Z]")


def normalize_domain(value: object) -> str | None:
    """A domain in its wire form (lower case), or None: at most 253 bytes of ASCII, two or more labels of
    letters, digits and inner hyphens, the last not all digits."""
    if not isinstance(value, str) or len(value) > 253 or not _PRINTABLE_ASCII.fullmatch(value):
        return None
    domain = value.lower()
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        return None
    return domain


def normalize_address(value: object) -> str | None:
    """A version 2 address in its wire form (ASCII, lower case), from any case, or None."""
    if not isinstance(value, str) or not _PRINTABLE_ASCII.fullmatch(value):
        return None
    local, at, domain = value.lower().rpartition("@")
    domain = normalize_domain(domain)
    if not at or not domain or len(local) > 64 or not _LOCAL_V1.fullmatch(local):
        return None
    return f"{local}@{domain}"


def is_v1_address(value: object) -> bool:
    """Whether a value is an address exactly as a version 2 message writes it."""
    return isinstance(value, str) and normalize_address(value) == value


def is_address(value: object) -> bool:
    """Whether a value is an address as a message of any version may write it (the invariant grammar):
    1 to 64 bytes of UTF-8 with no ``@``, space, character of category Cc or ASCII capital, then a domain
    in its wire form. Normalization is not checked: whether a string is NFC depends on the runtime's
    Unicode tables, and routers on any Unicode version must agree. This is all a server checks of a
    version it does not know."""
    if not isinstance(value, str):
        return False
    local, at, domain = value.rpartition("@")
    try:
        size = len(local.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return (
        bool(at)
        and 1 <= size <= 64
        and not _NOT_IN_LOCAL.search(local)
        and normalize_domain(domain) == domain
    )


def domain_of(address: str) -> str:
    return address.rpartition("@")[2]


_PCHAR = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@")


def address_segment(address: str) -> str:
    """An address as one path segment (section 8): every byte of its UTF-8 that is not an RFC 3986
    ``pchar`` percent-encoded with upper-case hex digits, and nothing else, so ``@`` stays literal and an
    address has one form in a path. In a version 2 address those are ``# % / ? ^ ` { | }``."""
    return "".join(chr(b) if b in _PCHAR else f"%{b:02X}" for b in address.encode("utf-8"))
