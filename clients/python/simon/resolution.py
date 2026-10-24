"""Resolution: which server a domain's agents live on (spec section 3). Two methods, in this order::

    _simon.<domain>  TXT  "v=simon1; server=https://<host>"
    GET https://<domain>/.well-known/simon            {"server":"https://<host>"}

It ends in exactly one of six outcomes. ``temporary`` is a failure that may pass, never "no server". A
host that does not exist, refuses the connection or presents a certificate not valid for it is an absence
(``not_found``); a DNS server error, a DNSSEC validation failure, a timeout, a dropped connection, and a
``429`` or ``5xx`` are ``temporary``.
"""

from __future__ import annotations

import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime

from .canonical import parse
from .dnsquery import LookupFailed, lookup_txt
from .errors import SimonError
from .limits import MAX_DOCUMENT_BYTES, NOT_FOUND_CACHE_MS, SERVER_CACHE_MAX_MS, TEMPORARY_CACHE_MS
from .transport import HostNotFound, fetch
from .wire import normalize_domain


@dataclass(frozen=True)
class Resolution:
    """``outcome`` is ``server``, ``invalid_domain``, ``invalid_record``, ``conflict``, ``not_found`` or
    ``temporary``; ``server`` is the origin a ``server`` outcome names."""

    outcome: str
    server: str | None = None
    #: ``dns`` or ``well-known`` for a ``server`` outcome.
    via: str | None = None
    #: For a ``server`` outcome, how long its source allows it to be cached, in milliseconds: the TXT
    #: record's TTL, or the well-known answer's HTTP freshness lifetime. None when unknown.
    ttl_ms: int | None = field(default=None, compare=False)


def resolution_cache_ms(result: Resolution, source_ttl_ms: int | None = None) -> int:
    """How long a resolver may cache an outcome (section 3), given the lifetime its source allows: a
    ``server`` for that, at most an hour (not at all when it is unknown); ``not_found`` ten minutes;
    ``temporary`` a minute; any other outcome not at all."""
    if result.outcome == "server":
        return max(0, min(source_ttl_ms or 0, SERVER_CACHE_MAX_MS))
    if result.outcome == "not_found":
        return NOT_FOUND_CACHE_MS
    return TEMPORARY_CACHE_MS if result.outcome == "temporary" else 0


_ORIGIN = re.compile(r"(https?)://([^/:?#]+)(?::([0-9]{1,5}))?/?", re.IGNORECASE)
_LOCAL_HOST = re.compile(
    r"localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.localhost|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
)
_DEFAULT_PORT = {"https": 443, "http": 80}


def server_origin(value: object, *, allow_local: bool = False) -> str | None:
    """A server origin as the URL standard serialises it (lower-case scheme and host, the default port
    dropped, no trailing ``/``), or None. The input is ``https://host[:port]`` and an optional ``/``: the
    scheme in any case, the host a domain, the port 1 to 5 digits whose value is 1 to 65535.

    ``allow_local`` also admits ``http:`` and loopback hosts (``localhost``, ``*.localhost``,
    ``127.x.x.x``), for local development only, never on a network.
    """
    m = _ORIGIN.fullmatch(value) if isinstance(value, str) else None
    if not m:
        return None
    scheme, host = m.group(1).lower(), m.group(2).lower()
    local = allow_local and host.isascii() and _LOCAL_HOST.fullmatch(host) is not None
    if not local and (scheme != "https" or normalize_domain(host) != host):
        return None
    port = _DEFAULT_PORT[scheme] if m.group(3) is None else int(m.group(3))
    if not 1 <= port <= 65_535:
        return None
    return f"{scheme}://{host}" if port == _DEFAULT_PORT[scheme] else f"{scheme}://{host}:{port}"


def _simon_records(records: list[list[str]]) -> list[list[tuple[str, str]]]:
    """The fields of each simon record among these, as ``(name, value)`` pairs; records that are not simon
    records are left out. Each record is its character strings, joined."""
    found = []
    for strings in records:
        first, *rest = (field.strip(" ") for field in "".join(strings).split(";"))
        if first == "v=simon1":
            found.append([(f.partition("=")[0], f.partition("=")[2]) for f in rest])
    return found


def servers_in_txt(records: list[list[str]]) -> list[str] | None:
    """The servers the simon records among these name, in order and without repeats, or None when one of
    them is malformed."""
    servers: list[str] = []
    for fields in _simon_records(records):
        values = [value for name, value in fields if name == "server"]
        origin = server_origin(values[0]) if len(values) == 1 else None
        if origin is None:
            return None
        if origin not in servers:
            servers.append(origin)
    return servers


def well_known_outcome(answer: tuple[int, bytes] | tuple[int, bytes, int | None] | None) -> Resolution:
    """What a well-known answer resolves to: ``(status, body)``, optionally with the answer's HTTP
    freshness lifetime in milliseconds third, or None when there is no answer to be had (a host that does
    not exist, refuses the connection, or presents a certificate not valid for it). A ``200`` JSON object
    under the canonical rules whose ``server`` is a server origin names that server; ``429`` and ``5xx``
    are ``temporary``; anything else is ``not_found``. This reader takes a body of at most 131072 bytes, a
    document's bound; a longer one is no answer."""
    if answer is None:
        return Resolution("not_found")
    status, body = answer[0], answer[1]
    ttl_ms = answer[2] if len(answer) > 2 else None
    if status == 429 or 500 <= status <= 599:
        return Resolution("temporary")
    try:
        value = parse(body) if status == 200 and len(body) <= MAX_DOCUMENT_BYTES else None
    except SimonError:
        value = None
    server = server_origin(value.get("server")) if isinstance(value, dict) else None
    return Resolution("server", server, "well-known", ttl_ms=ttl_ms) if server else Resolution("not_found")


TxtLookup = Callable[[str], list[list[str]]]
WellKnownFetch = Callable[[str], tuple[int, bytes] | tuple[int, bytes, int | None] | None]


def fetch_well_known(url: str, timeout: float = 10.0) -> tuple[int, bytes, int | None] | None:
    """GET without following redirects: the status, the body (cut after 131073 bytes) and the answer's
    freshness lifetime; or None when there is no answer to be had: the host does not exist, refuses the
    connection, or presents a certificate not valid for it. A timeout or a dropped connection raises."""
    try:
        response = fetch("GET", url, timeout=timeout, max_bytes=MAX_DOCUMENT_BYTES)
    except (HostNotFound, ConnectionRefusedError, ssl.SSLCertVerificationError):
        return None
    return response.status, response.body, freshness_ms(response.headers)


def freshness_ms(headers) -> int | None:
    """An HTTP answer's freshness lifetime (RFC 9111 section 4.2.1) less its ``Age``, in milliseconds:
    ``s-maxage``, else ``max-age``, else ``Expires`` less ``Date``; 0 for ``no-store`` or ``no-cache``;
    None when the headers give none."""
    directives = {}
    for item in (headers.get("cache-control") or "").split(","):
        name, _, value = item.strip().partition("=")
        directives[name.lower()] = value.strip('"')
    if "no-store" in directives or "no-cache" in directives:
        return 0
    lifetime = None
    for name in ("s-maxage", "max-age"):
        if directives.get(name, "").isdigit():
            lifetime = int(directives[name])
            break
    if lifetime is None and headers.get("expires"):
        try:
            date = parsedate_to_datetime(headers["date"]).timestamp() if headers.get("date") else time.time()
            lifetime = max(0, int(parsedate_to_datetime(headers["expires"]).timestamp() - date))
        except (TypeError, ValueError):
            lifetime = 0  # an invalid Expires is already stale
    if lifetime is None:
        return None
    age = headers.get("age") or ""
    return max(0, lifetime - (int(age) if age.isdigit() else 0)) * 1000


def resolve(domain: str, txt: TxtLookup = lookup_txt, get: WellKnownFetch = fetch_well_known) -> Resolution:
    """Resolve a domain. ``txt(name)`` returns the TXT records at a name, each as its character strings, or
    [] when there are none, and raises LookupFailed or OSError on a failure that may pass (a DNS server
    error, a DNSSEC validation failure, a timeout). ``get(url)`` returns ``(status, body)`` (and optionally
    a freshness lifetime), or None when there is no answer to be had (no such host, a refused connection,
    a certificate not valid for the domain), and raises the same way for a timeout or a dropped
    connection."""
    name = normalize_domain(domain)
    if name is None:
        return Resolution("invalid_domain")
    try:
        records = txt(f"_simon.{name}")
    except (LookupFailed, OSError):
        return Resolution("temporary")
    servers = servers_in_txt(records)
    if servers is None:
        return Resolution("invalid_record")
    if len(servers) > 1:
        return Resolution("conflict")
    if servers:
        ttl_ms = getattr(records, "ttl_ms", None)
        return Resolution("server", servers[0], "dns", ttl_ms)
    try:
        return well_known_outcome(get(f"https://{name}/.well-known/simon"))
    except (LookupFailed, OSError):
        return Resolution("temporary")
