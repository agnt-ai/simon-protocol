"""TXT lookups for resolution (spec section 3).

dnspython is used when it is installed. Otherwise a small stub resolver asks the nameservers in
/etc/resolv.conf over UDP, and over TCP when an answer is truncated. It reads only an answer to its own
question (matching id and echoed question, from a connected socket), bounds-checks every read, and turns
anything malformed into LookupFailed, which resolution reads as ``temporary``.

A name that does not exist, or has no TXT records, is []. The records come as TxtRecords, a list that also
carries ``ttl_ms``, the shortest TTL among them, for caching (spec section 3).
"""

from __future__ import annotations

import secrets
import socket
import struct
import time

try:
    import dns.exception
    import dns.resolver
except ImportError:  # the optional extra is not installed
    dns = None

_TXT, _CNAME, _IN = 16, 5, 1


class LookupFailed(Exception):
    """A lookup failed in a way that may pass: a DNS server error, a DNSSEC validation failure (a
    validating resolver answers SERVFAIL), a timeout, a malformed answer."""


class TxtRecords(list):
    """TXT records, each as its character strings, and ``ttl_ms``: how long they may be cached, or None
    when there are none or it is not known."""

    def __init__(self, records=(), ttl_ms: int | None = None) -> None:
        super().__init__(records)
        self.ttl_ms = ttl_ms


def lookup_txt(name: str, timeout: float = 5.0) -> TxtRecords:
    """The TXT records at ``name``, each as its character strings."""
    return _lookup_dnspython(name, timeout) if dns is not None else _lookup_stub(name, timeout)


def _lookup_dnspython(name: str, timeout: float) -> TxtRecords:
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return TxtRecords()
    except dns.exception.DNSException as e:
        raise LookupFailed(f"{type(e).__name__}: {e}") from None
    records = [[s.decode("utf-8", "replace") for s in rdata.strings] for rdata in answer]
    return TxtRecords(records, answer.rrset.ttl * 1000 if answer.rrset is not None else None)


def _lookup_stub(name: str, timeout: float) -> TxtRecords:
    question = _question(name)
    failures = []
    for server in _nameservers():
        try:
            return _ask(server, question, time.monotonic() + timeout)
        except (LookupFailed, OSError) as e:
            failures.append(f"{server}: {str(e) or type(e).__name__}")
    raise LookupFailed("; ".join(failures))


def _nameservers() -> list[str]:
    try:
        with open("/etc/resolv.conf", encoding="ascii", errors="replace") as f:
            lines = [line.split() for line in f]
    except OSError as e:
        raise LookupFailed(f"no resolver configuration: {e}") from None
    servers = [words[1] for words in lines if len(words) > 1 and words[0] == "nameserver"]
    if not servers:
        raise LookupFailed("no nameserver in /etc/resolv.conf")
    return servers


def _question(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    if not all(0 < len(label) < 64 and label.isascii() for label in labels):
        raise LookupFailed(f"not a DNS name: {name!r}")
    qname = b"".join(bytes([len(label)]) + label.lower().encode("ascii") for label in labels) + b"\0"
    return qname + struct.pack(">HH", _TXT, _IN)


def _ask(server: str, question: bytes, deadline: float, port: int = 53) -> TxtRecords:
    query_id = secrets.randbits(16)
    query = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question  # recursion desired
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.connect((server, port))  # only this server's datagrams arrive
        s.send(query)
        while True:
            s.settimeout(_remaining(deadline))
            answer = s.recv(65_535)
            if _answers(answer, query_id, question):
                break
    if answer[2] & 0x02:  # truncated: ask again over TCP
        with socket.create_connection((server, port), timeout=_remaining(deadline)) as s:
            s.sendall(struct.pack(">H", len(query)) + query)
            answer = _receive(s, struct.unpack(">H", _receive(s, 2))[0])
        if not _answers(answer, query_id, question):
            raise LookupFailed("a TCP answer to another question")
    return _txt_records(answer, question)


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("timed out")
    return left


def _receive(s: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise LookupFailed("the connection closed mid-answer")
        data += chunk
    return data


def _answers(message: bytes, query_id: int, question: bytes) -> bool:
    """Whether a message is a response to our query: our id, QR set, one question, and ours echoed."""
    if len(message) < 12 + len(question):
        return False
    response_id, flags, questions = struct.unpack_from(">HHH", message)
    echoed = message[12 : 12 + len(question)]
    return response_id == query_id and bool(flags & 0x8000) and questions == 1 and echoed.lower() == question


def _txt_records(message: bytes, question: bytes) -> TxtRecords:
    rcode = message[3] & 0x0F
    if rcode == 3:  # NXDOMAIN
        return TxtRecords()
    if rcode:
        raise LookupFailed(f"the nameserver answered rcode {rcode}")
    owners = {_name(message, 12)[0]}
    pos = 12 + len(question)
    records, ttls = [], []
    for _ in range(struct.unpack_from(">H", message, 6)[0]):
        owner, pos = _name(message, pos)
        if pos + 10 > len(message):
            raise LookupFailed("a record cut short")
        rtype, rclass, ttl, length = struct.unpack_from(">HHIH", message, pos)
        start, pos = pos + 10, pos + 10 + length
        if pos > len(message):
            raise LookupFailed("record data cut short")
        if rclass != _IN or owner not in owners:
            continue
        if rtype == _CNAME:
            owners.add(_name(message[:pos], start)[0])
            ttls.append(ttl)
        elif rtype == _TXT:
            records.append(_strings(message[start:pos]))
            ttls.append(ttl)
    return TxtRecords(records, min(ttls) * 1000 if records else None)


def _name(message: bytes, pos: int) -> tuple[str, int]:
    """The name at ``pos``, in lower case, and where the bytes after it start. Compression pointers must
    point backwards, so no name loops."""
    labels: list[str] = []
    end = None
    while True:
        if pos >= len(message):
            raise LookupFailed("a name cut short")
        n = message[pos]
        if n == 0:
            return ".".join(labels).lower(), pos + 1 if end is None else end
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(message):
                raise LookupFailed("a pointer cut short")
            target = (n & 0x3F) << 8 | message[pos + 1]
            if target >= pos:
                raise LookupFailed("a compression pointer that does not point back")
            end = pos + 2 if end is None else end
            pos = target
        elif n & 0xC0:
            raise LookupFailed("a label of an unknown type")
        else:
            if pos + 1 + n > len(message):
                raise LookupFailed("a label cut short")
            labels.append(message[pos + 1 : pos + 1 + n].decode("latin-1"))
            pos += 1 + n


def _strings(data: bytes) -> list[str]:
    strings, pos = [], 0
    while pos < len(data):
        end = pos + 1 + data[pos]
        if end > len(data):
            raise LookupFailed("a TXT string cut short")
        strings.append(data[pos + 1 : end].decode("utf-8", "replace"))
        pos = end
    return strings
