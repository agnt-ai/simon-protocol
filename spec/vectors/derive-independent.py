#!/usr/bin/env python3
"""
Derives spec/vectors/independent.json without the SIMON library.

Nothing here imports, runs or reads the JavaScript library, the reference server or spec/vectors/v1.json.
The inputs are:

  * the text of RFC 8032 (Ed25519 test vectors, section 7.1) and RFC 8785 (JSON sorting example, section 3.2.3),
    which you fetch yourself and pass in;
  * SHA-256 and base64url from Python's standard library;
  * Ed25519 from the `cryptography` package (OpenSSL), which signs and verifies;
  * canonical JSON bytes written out below by hand, from the rules of protocol.md section 5.1.

Usage:

    curl -sLO https://www.rfc-editor.org/rfc/rfc8032.txt
    curl -sLO https://www.rfc-editor.org/rfc/rfc8785.txt
    python3 -I spec/vectors/derive-independent.py rfc8032.txt rfc8785.txt > spec/vectors/independent.json

Ed25519 is deterministic, so the output is the same every time.
"""

import base64
import hashlib
import json
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_of(secret: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign(secret: bytes, data: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(secret).sign(data)


def verify(public: bytes, data: bytes, signature: bytes) -> None:
    Ed25519PublicKey.from_public_bytes(public).verify(signature, data)  # raises on failure


# ---- RFC 8032 section 7.1 ----------------------------------------------------------------------------------

PAGE_BREAK = re.compile(r"^(Josefsson & Liusvaara|RFC 8032 +EdDSA)")


def rfc8032_cases(text: str):
    """Tests 1, 2, 3, 1024 and SHA(abc) of RFC 8032 section 7.1, as the RFC prints them."""
    body = text[text.index("-----TEST 1\n") : text.index("7.2.  Test Vectors for Ed25519ctx", text.index("-----TEST 1\n"))]
    cases = []
    for block in re.split(r"-----TEST ", body)[1:]:
        lines = block.split("\n")
        name = lines[0].strip()

        def field(label: str) -> bytes:
            start = next(i for i, line in enumerate(lines) if line.strip().startswith(label))
            hexes = []
            for line in lines[start + 1 :]:
                s = line.strip()
                if not s or PAGE_BREAK.match(s):
                    continue
                if re.fullmatch(r"[0-9a-f]+", s):
                    hexes.append(s)
                else:
                    break
            return bytes.fromhex("".join(hexes))

        cases.append(
            {
                "name": f"RFC 8032 7.1 TEST {name}",
                "secret": field("SECRET KEY:"),
                "public": field("PUBLIC KEY:"),
                "message": field("MESSAGE"),
                "signature": field("SIGNATURE:"),
            }
        )
    assert [c["name"] for c in cases] == [f"RFC 8032 7.1 TEST {n}" for n in ("1", "2", "3", "1024", "SHA(abc)")]
    return cases


# ---- RFC 8785 section 3.2.3 --------------------------------------------------------------------------------

# The test data of the section, as the RFC prints it, with the property values in the order it says they sort to.
SORTING_INPUT = {
    "€": "Euro Sign",
    "\r": "Carriage Return",
    "דּ": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\U0001F600": "Emoji: Grinning Face",
    "\u0080": "Control",
    "ö": "Latin Small Letter O With Diaeresis",
}
SORTED_VALUES = [
    "Carriage Return",
    "One",
    "Control",
    "Latin Small Letter O With Diaeresis",
    "Euro Sign",
    "Emoji: Grinning Face",
    "Hebrew Letter Dalet With Dagesh",
]
# How protocol.md 5.1 writes each key: U+000D as \r; every other character here raw, as UTF-8.
KEY_TEXT = {
    "\r": '"\\r"',
    "1": '"1"',
    "\u0080": '"\u0080"',
    "ö": '"ö"',
    "€": '"€"',
    "\U0001F600": '"\U0001F600"',
    "דּ": '"דּ"',
}


def sorting_case(rfc8785: str):
    for value in SORTED_VALUES:
        assert value in rfc8785, value
    by_value = {v: k for k, v in SORTING_INPUT.items()}
    members = [f'{KEY_TEXT[by_value[v]]}:"{v}"' for v in SORTED_VALUES]
    return {
        "name": "RFC 8785 3.2.3 sorting by UTF-16 code units",
        "source": "RFC 8785 section 3.2.3: the test data and the order its property values sort to; keys written as protocol.md 5.1 says",
        "value": SORTING_INPUT,
        "canonical": "{" + ",".join(members) + "}",
    }


# ---- by hand -----------------------------------------------------------------------------------------------

# The key every hand-made case below is signed with: RFC 8032 TEST 1.
def signer(rfc):
    first = rfc[0]
    return first["secret"], first["public"]


def message_case(name, secret, public, unsigned, canonical_text):
    """A message whose canonical bytes were written by hand; its id, signature and signing bytes follow from them."""
    assert json.loads(canonical_text) == unsigned, name  # the hand-written bytes mean the object
    raw = canonical_text.encode("utf-8")
    signing = b"SIMON-MESSAGE\n" + raw
    signature = b64u(sign(secret, signing))
    verify(public, signing, base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
    message = dict(unsigned, signature=signature)
    return {
        "name": name,
        "signer": "ed25519:" + b64u(public),
        "unsigned": unsigned,
        "canonical": canonical_text,
        "signingBytes": signing.decode("utf-8"),
        "id": sha256(raw),
        "signature": signature,
        "message": message,
    }


def request_case(name, secret, public, method, origin, actor, target, timestamp, nonce, body: bytes):
    lines = ["SIMON-REQUEST", method, origin, actor, target, timestamp, nonce, sha256(body)]
    signing = "\n".join(lines)
    signature = b64u(sign(secret, signing.encode()))
    return {
        "name": name,
        "key": "ed25519:" + b64u(public),
        "method": method,
        "origin": origin,
        "actor": actor,
        "target": target,
        "timestamp": timestamp,
        "nonce": nonce,
        "body": body.decode("utf-8"),
        "signingString": signing,
        "signature": signature,
    }


def main(rfc8032_path: str, rfc8785_path: str) -> None:
    rfc = rfc8032_cases(open(rfc8032_path, encoding="utf-8").read())
    for c in rfc:
        assert public_of(c["secret"]) == c["public"], c["name"]
        assert sign(c["secret"], c["message"]) == c["signature"], c["name"]
        verify(c["public"], c["message"], c["signature"])
    secret, public = signer(rfc)

    sha_inputs = [
        ("empty input", b"", "NIST FIPS 180-4 examples, SHA-256 of the empty string"),
        ("abc", b"abc", "NIST FIPS 180-4 example, one block"),
        (
            "448-bit message",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "NIST FIPS 180-4 example, two blocks",
        ),
    ]
    sha_cases = [
        {"name": n, "source": s, "input": {"utf8": raw.decode()}, "digest": sha256(raw)} for n, raw, s in sha_inputs
    ]
    sha_cases.append(
        {
            "name": "one million a",
            "source": "NIST FIPS 180-4 example, long message",
            "input": {"repeat": "a", "times": 1_000_000},
            "digest": sha256(b"a" * 1_000_000),
        }
    )

    rfc4648 = [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"]
    base64_cases = [
        {"bytes": raw.hex(), "encoded": b64u(raw)} for raw in rfc4648 + [bytes([0xFB, 0xFF]), bytes([0xFB, 0xEF, 0xBE])]
    ]

    unsigned_plain = {
        "v": 1,
        "from": "rfc8032@example.org",
        "to": ["bob@example.net"],
        "inReplyTo": None,
        "parts": [{"type": "text/plain", "data": "hello"}],
        "headers": {},
        "sentAt": "2026-10-14T21:00:00Z",
    }
    plain_text = (
        '{"from":"rfc8032@example.org","headers":{},"inReplyTo":null,"parts":[{"data":"hello","type":"text/plain"}],'
        '"sentAt":"2026-10-14T21:00:00Z","to":["bob@example.net"],"v":1}'
    )

    # Every escape protocol.md 5.1 lists, and every character it says is written raw, in one string:
    #   " \ U+0008 U+0009 U+000A U+000C U+000D as \" \\ \b \t \n \f \r; U+0001 as \u0001; U+001F as \u001f;
    #   / U+007F < > & U+00E9 U+2028 and U+1F600 raw.
    text = '"\\ \b\t\n\f\r \x01 \x1f / \x7f < > & é   \U0001F600'
    escaped = (
        '"\\"\\\\ \\b\\t\\n\\f\\r \\u0001 \\u001f / \x7f < > & é   \U0001F600"'
    )
    unsigned_escapes = {
        "v": 1,
        "from": "rfc8032@example.org",
        "to": ["bob@example.net", "alice@example.com"],
        "inReplyTo": "0" * 63 + "1",
        "parts": [{"type": "text/plain", "data": text}, {"type": "text/markdown", "data": "# é"}],
        "headers": {"subject": "café"},
        "sentAt": "2026-10-14T21:00:00.123Z",
    }
    escapes_text = (
        '{"from":"rfc8032@example.org","headers":{"subject":"café"},"inReplyTo":"' + "0" * 63 + '1",'
        '"parts":[{"data":' + escaped + ',"type":"text/plain"},{"data":"# é","type":"text/markdown"}],'
        '"sentAt":"2026-10-14T21:00:00.123Z","to":["bob@example.net","alice@example.com"],"v":1}'
    )

    out = {
        "about": (
            "Test cases whose bytes did not come from this repository's library. spec/vectors/v1.json is generated by "
            "that library, so a mistake in it would be in the vectors, the server and the conformance suite alike; these "
            "are derived apart from it, by spec/vectors/derive-independent.py, and independent.md says how. "
            "An implementation checks that it reproduces every byte here."
        ),
        "sha256": {
            "about": "SHA-256 of the input (section 2.5: hashes are lower-case hex).",
            "cases": sha_cases,
        },
        "ed25519": {
            "about": (
                "RFC 8032 section 7.1, copied from the RFC. A key token is ed25519: and the base64url of the 32-byte public "
                "key (section 2.3); signature is the base64url of the 64 bytes. All five signatures are well formed under "
                "section 2.3's strict rules and verify."
            ),
            "cases": [
                {
                    "name": c["name"],
                    "source": c["name"],
                    "secret": c["secret"].hex(),
                    "public": c["public"].hex(),
                    "token": "ed25519:" + b64u(c["public"]),
                    "message": c["message"].hex(),
                    "signature": b64u(c["signature"]),
                }
                for c in rfc
            ],
        },
        "base64url": {
            "about": (
                "Unpadded base64url (section 2.5). The first seven are RFC 4648 section 10's test vectors with the padding "
                "removed and the alphabet of section 5; the next two use the characters that differ between the alphabets. "
                "`refused` are never base64url in this protocol: padded, in the other alphabet, with a length no encoding "
                "has, or with non-zero bits after the last whole byte (RFC 4648 section 3.5), so not the one spelling."
            ),
            "cases": base64_cases,
            "refused": ["Zg==", "Zm8=", "Zh", "Zm9", "Z", "+/8", "Zm9v\n", " Zg"],
        },
        "canonical": {
            "about": "Canonical JSON (section 5.1), written by hand from its rules and from RFC 8785.",
            "cases": [
                sorting_case(open(rfc8785_path, encoding="utf-8").read()),
                {
                    "name": "escapes and raw characters",
                    "source": "by hand from protocol.md 5.1",
                    "value": {"text": text, "list": [1, -9007199254740991, 9007199254740991, 0, True, False, None]},
                    "canonical": '{"list":[1,-9007199254740991,9007199254740991,0,true,false,null],"text":' + escaped + "}",
                },
                {
                    "name": "nesting and order",
                    "source": "by hand from protocol.md 5.1",
                    "value": {"b": {"z": 1, "a": [{"y": 2, "x": 1}]}, "a": "", "B": {}},
                    "canonical": '{"B":{},"a":"","b":{"a":[{"x":1,"y":2}],"z":1}}',
                },
            ],
        },
        "messages": {
            "about": (
                "Messages signed with the RFC 8032 TEST 1 key. canonical is the unsigned message's canonical text, written "
                "by hand; id is the SHA-256 of its bytes and signature is Ed25519 over `SIMON-MESSAGE\\n` and those bytes "
                "(section 1), both made with hashlib and OpenSSL. `message` is the signed message."
            ),
            "cases": [
                message_case("plain message", secret, public, unsigned_plain, plain_text),
                message_case("every escape, raw characters and fractional seconds", secret, public, unsigned_escapes, escapes_text),
            ],
        },
        "requests": {
            "about": (
                "Signed requests (section 8), signed with the RFC 8032 TEST 1 key: the eight-line signing string built by "
                "hand, its body hash made with hashlib, its signature with OpenSSL."
            ),
            "cases": [
                request_case(
                    "agent request with a body",
                    secret,
                    public,
                    "POST",
                    "https://simon.example.net",
                    "rfc8032@example.net",
                    "/simon/send",
                    "1760000000",
                    "dGVzdC1ub25jZS0xMjM0",
                    b'{"v":1}',
                ),
                request_case(
                    "server request without a body",
                    secret,
                    public,
                    "GET",
                    "https://simon.example.net",
                    "https://simon.example.org",
                    "/simon/parts/" + sha256(b"abc"),
                    "1760000001",
                    "abcdefgh12345678",
                    b"",
                ),
            ],
        },
    }
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
