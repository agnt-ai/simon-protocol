"""Canonical JSON (spec section 5.1): RFC 8785 restricted so that nothing in it needs floating point.

- Numbers are integers between -(2^53 - 1) and 2^53 - 1, in plain decimal.
- Text is valid UTF-8 with no byte order mark, and no string holds a lone surrogate.
- Objects never repeat a key, compared after unescaping, and are written with their keys sorted by
  UTF-16 code units.
- At most 64 arrays and objects sit inside one another.
- Strings escape ``"`` and ``\\``, write U+0008, U+0009, U+000A, U+000C and U+000D as ``\\b \\t \\n \\f \\r``,
  every other code point below U+0020 as ``\\u00xx`` in lower-case hex, and everything else raw.

``parse`` accepts any JSON whitespace and any valid escape, and refuses everything else as ``400 invalid``,
so a value it returns always has exactly one canonical form.
"""

from __future__ import annotations

import re
from typing import Any, NoReturn

from .errors import invalid

MAX_SAFE_INTEGER = 2**53 - 1
# The longest integer token in the safe range: a sign and the 16 digits of 2^53 - 1. Longer ones are refused
# before int() reads them, which would raise its own ValueError past 4,300 digits.
_MAX_INTEGER_CHARS = 17
MAX_DEPTH = 64

_PLAIN = re.compile(r'[^"\\\x00-\x1f]*')
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)")
_HEX4 = re.compile(r"[0-9A-Fa-f]{4}")
_SIMPLE_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_WHITESPACE = " \t\n\r"
_NOT_AFTER_AN_INTEGER = {
    ".": "A number has a fraction; only integers are allowed",
    "e": "A number has an exponent; only integers are allowed",
    "E": "A number has an exponent; only integers are allowed",
    **dict.fromkeys("0123456789", "A number has a leading zero"),
}
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def parse(data: bytes | str) -> Any:
    """Parse JSON text or UTF-8 bytes under the canonical rules (the text itself need not be canonical)."""
    return parse_with_members(data)[0]


def parse_with_members(data: bytes | str) -> tuple[Any, dict[str, str]]:
    """``parse``, also returning the exact text of each member of the outermost object as it arrived.

    An envelope's message must arrive in canonical form, and this is how a reader sees that it did.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            raise invalid(f"The body is not valid UTF-8 (byte {e.start}).") from None
    elif isinstance(data, str):
        if _SURROGATE.search(data):
            raise invalid("Strings may not contain lone surrogates.")
        text = data
    else:
        raise TypeError(f"parse takes bytes or str, not {type(data).__name__}")
    if text.startswith("\ufeff"):
        raise invalid("A byte order mark is not allowed.")
    parser = _Parser(text)
    parser.skip_whitespace()
    value = parser.value(0)
    parser.skip_whitespace()
    if parser.i != len(text):
        parser.fail("Unexpected text after the JSON value")
    return value, parser.members


class _Parser:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.members: dict[str, str] = {}

    def fail(self, what: str) -> NoReturn:
        raise invalid(f"{what} at character {self.i}.")

    def skip_whitespace(self) -> None:
        s, i = self.s, self.i
        while i < len(s) and s[i] in _WHITESPACE:
            i += 1
        self.i = i

    def value(self, depth: int) -> Any:
        c = self.s[self.i : self.i + 1]
        if c in ("{", "[") and depth >= MAX_DEPTH:
            self.fail(f"More than {MAX_DEPTH} arrays and objects nested")
        if c == "{":
            return self.object(depth)
        if c == "[":
            return self.array(depth)
        if c == '"':
            return self.string()
        for word, value in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return value
        if c and c in "-0123456789":
            return self.number()
        self.fail("Expected a JSON value")

    def number(self) -> int:
        m = _INTEGER.match(self.s, self.i)
        if not m:
            self.fail("Expected a digit")
        after = self.s[m.end() : m.end() + 1]
        if after and after in _NOT_AFTER_AN_INTEGER:
            self.i = m.end()
            self.fail(_NOT_AFTER_AN_INTEGER[after])
        if m.group() == "-0":
            self.fail("Negative zero is not allowed")
        if len(m.group()) > _MAX_INTEGER_CHARS:
            self.fail("An integer is outside the safe integer range")
        n = int(m.group())
        if abs(n) > MAX_SAFE_INTEGER:
            self.fail("An integer is outside the safe integer range")
        self.i = m.end()
        return n

    def string(self) -> str:
        s = self.s
        self.i += 1
        out: list[str] = []
        while True:
            m = _PLAIN.match(s, self.i)
            out.append(m.group())
            self.i = m.end()
            c = s[self.i : self.i + 1]
            if c == '"':
                self.i += 1
                break
            if c == "":
                self.fail("Unterminated string")
            if c != "\\":
                self.fail("A raw control character in a string")
            e = s[self.i + 1 : self.i + 2]
            if e in _SIMPLE_ESCAPES:
                out.append(_SIMPLE_ESCAPES[e])
                self.i += 2
            elif e == "u":
                out.append(chr(self.hex4(self.i + 2)))
                self.i += 6
            else:
                self.fail("Not an escape")
        text = "".join(out)
        if _SURROGATE.search(text):
            text = self.pair_surrogates(text)
        return text

    def hex4(self, at: int) -> int:
        if not _HEX4.fullmatch(self.s, at, at + 4):
            self.fail("A \\u escape needs four hex digits")
        return int(self.s[at : at + 4], 16)

    def pair_surrogates(self, text: str) -> str:
        """Join each escaped high surrogate with the low one after it; any other surrogate is lone."""
        try:
            return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        except UnicodeDecodeError:
            self.fail("A string holds a lone surrogate")

    def array(self, depth: int) -> list[Any]:
        self.i += 1
        out: list[Any] = []
        self.skip_whitespace()
        if self.s.startswith("]", self.i):
            self.i += 1
            return out
        while True:
            self.skip_whitespace()
            out.append(self.value(depth + 1))
            self.skip_whitespace()
            c = self.s[self.i : self.i + 1]
            self.i += 1
            if c == "]":
                return out
            if c != ",":
                self.i -= 1
                self.fail("Expected , or ]")

    def object(self, depth: int) -> dict[str, Any]:
        self.i += 1
        out: dict[str, Any] = {}
        self.skip_whitespace()
        if self.s.startswith("}", self.i):
            self.i += 1
            return out
        while True:
            self.skip_whitespace()
            if not self.s.startswith('"', self.i):
                self.fail("Expected a string key")
            key = self.string()
            if key in out:
                self.fail(f'Duplicate key "{key}"')
            self.skip_whitespace()
            if not self.s.startswith(":", self.i):
                self.fail("Expected :")
            self.i += 1
            self.skip_whitespace()
            start = self.i
            out[key] = self.value(depth + 1)
            if depth == 0:
                self.members[key] = self.s[start : self.i]
            self.skip_whitespace()
            c = self.s[self.i : self.i + 1]
            self.i += 1
            if c == "}":
                return out
            if c != ",":
                self.i -= 1
                self.fail("Expected , or }")


_ESCAPE = re.compile(r'[\x00-\x1f"\\]')
_NAMED = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _escape(m: re.Match[str]) -> str:
    c = m.group()
    return _NAMED.get(c) or f"\\u{ord(c):04x}"


def _string(s: str) -> str:
    if _SURROGATE.search(s):
        raise ValueError("Strings may not contain lone surrogates.")
    return '"' + _ESCAPE.sub(_escape, s) + '"'


def canonical(value: Any) -> str:
    """The canonical text of a JSON value: dicts, lists or tuples, str, int, bool and None.

    Raises ValueError for anything outside the rules (a float, an integer out of range, a lone
    surrogate, more than 64 levels of nesting) and TypeError for a value that is not JSON.
    """
    return "".join(_write(value, 0))


def canonical_bytes(value: Any) -> bytes:
    """The canonical form as the UTF-8 bytes that are transmitted, hashed and signed."""
    return canonical(value).encode("utf-8")


def _write(value: Any, depth: int):
    if value is None:
        yield "null"
    elif value is True:
        yield "true"
    elif value is False:
        yield "false"
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{value} is outside the safe integer range.")
        yield str(int(value))
    elif isinstance(value, str):
        yield _string(value)
    elif isinstance(value, (list, tuple, dict)):
        if depth >= MAX_DEPTH:
            raise ValueError(f"More than {MAX_DEPTH} arrays and objects nested.")
        if isinstance(value, dict):
            if not all(isinstance(k, str) for k in value):
                raise TypeError("Object keys must be strings.")
            yield "{"
            for n, key in enumerate(sorted(value, key=_utf16)):
                yield ("," if n else "") + _string(key) + ":"
                yield from _write(value[key], depth + 1)
            yield "}"
        else:
            yield "["
            for n, item in enumerate(value):
                if n:
                    yield ","
                yield from _write(item, depth + 1)
            yield "]"
    elif isinstance(value, float):
        raise ValueError(f"{value!r} is a float; only integers are allowed.")
    else:
        raise TypeError(f"{type(value).__name__} is not a JSON value.")


def _utf16(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def signing_bytes(context: str, signed: dict[str, Any]) -> bytes:
    """What is signed: the context line (``AGNT-MESSAGE``, ``AGNT-ENVELOPE``, ``AGNT-CLAIMS``,
    ``AGNT-SIGNAL`` or ``AGNT-AGENT``), a newline, and the canonical bytes of the object without its
    ``signature``."""
    return context.encode("ascii") + b"\n" + unsigned_bytes(signed)


def unsigned_bytes(signed: dict[str, Any]) -> bytes:
    """The canonical bytes of an object without its ``signature``: what a message id hashes."""
    return canonical_bytes({k: v for k, v in signed.items() if k != "signature"})
