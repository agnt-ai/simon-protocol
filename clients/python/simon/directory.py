"""Directory records (discovery profile, section 1): an issuer's signed word that the holder of an email
address or a phone number chose an assistant. The identifier's own domain issues them for its addresses
when its ``_simon`` TXT record names a server; directories a reader trusts issue them for everything else.

    {"identifier","address","revision","issued","expires","issuer","signature"}

signed by the issuer over ``SIMON-DIRECTORY\\n`` and the canonical record without ``signature``: every member
the record carries, those this library does not know included, so a later member is signed as the six are and
nobody can attach one unsigned. Signed with a key of its server document valid at ``issued``. A record lasts
at most 366 days, as a pairing does.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .canonical import signing_bytes
from .keys import SigningKey, signed_by_any
from .limits import SENT_AT_AHEAD_MS
from .messages import PAIRING_MAX_MS, is_principal
from .resolution import server_origin
from .wire import is_b64url, is_v1_address, parse_timestamp

#: The longest a record lasts from when it was issued: as long as a pairing may.
RECORD_MAX_MS = PAIRING_MAX_MS

def is_listable_identifier(value: object) -> bool:
    """Whether a value is an identifier a directory record may name: a ``mailto:`` or ``tel:`` principal."""
    return is_principal(value) and not str(value).startswith("simon-key:")


def directory_bytes(record: Mapping[str, Any]) -> bytes:
    """The bytes an issuer signs for a record: every member but ``signature``, known or not."""
    return signing_bytes("SIMON-DIRECTORY", {k: v for k, v in record.items() if k != "signature"})


def sign_directory_record(record: Mapping[str, Any], issuer_key: SigningKey) -> dict[str, Any]:
    """A record signed by ``issuer_key``, a key of the issuer's server document."""
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return {**unsigned, "signature": issuer_key.sign(directory_bytes(unsigned))}


def read_directory_record(
    value: object, identifier: str, issuer_keys: Iterable[Mapping[str, Any]], now_ms: int, *, allow_local: bool = False
) -> dict[str, Any] | None:
    """The record ``value`` is, when a reader may take it at ``now_ms`` for ``identifier``: every member well
    formed, for that identifier, issued at most 5 minutes ahead of ``now_ms``, not yet expired, lasting at
    most 366 days, and signed by one of ``issuer_keys``, the issuer's server keys, valid at ``issued``.
    Otherwise None. The signature covers every member but ``signature``, so a member this library does not
    know counts only when the issuer signed it, and is then kept. ``issuer`` is an https origin, written as
    resolution writes one; ``allow_local`` admits local http ones too, for development only."""
    if not isinstance(value, Mapping):
        return None
    revision, issuer = value.get("revision"), value.get("issuer")
    start, end = parse_timestamp(value.get("issued")), parse_timestamp(value.get("expires"))
    if (
        value.get("identifier") != identifier
        or not is_listable_identifier(identifier)
        or not is_v1_address(value.get("address"))
        or type(revision) is not int
        or not 1 <= revision <= 2**53 - 1
        or start is None
        or end is None
        or not (start < end and end - start <= RECORD_MAX_MS)
        or start > now_ms + SENT_AT_AHEAD_MS
        or now_ms >= end
        or not isinstance(issuer, str)
        or server_origin(issuer, allow_local=allow_local) != issuer
        or not is_b64url(value.get("signature"))
    ):
        return None
    record = {k: v for k, v in value.items() if k != "signature"}
    try:
        if not signed_by_any(issuer_keys, start, directory_bytes(record), value["signature"]):
            return None
    except (ValueError, TypeError):
        return None  # a member with no canonical form was never signed
    return {**record, "signature": value["signature"]}
