"""Every section and every case of spec/vectors/v2.json.

Ed25519 signatures are reproduced with every signing path available here: the pure-Python one (opted in)
always, and ``cryptography`` when it is installed. ML-DSA-65 signatures are hedged, so they are verified,
not reproduced. Set SIMON_VECTOR_COUNTS=1 to print how many cases of each section passed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import ssl
import sys
import unittest
from collections import Counter
from email.message import Message
from pathlib import Path
from unittest import mock

from simon import keys as keys_module
from simon import mldsa
from simon import resolution as resolution_module
from simon.canonical import canonical, parse, signing_bytes
from simon.dnsquery import LookupFailed
from simon.documents import read_agent_document, read_keys, read_server_document
from simon.envelope import (
    Receiver,
    check_envelope_signature,
    check_served,
    claims_about,
    claims_bytes,
    delivery_state,
    delivery_window,
    is_authoritative,
    judge_claims,
    parse_envelope,
    verify_claims,
    verify_envelope,
)
from simon.errors import SimonError, parse_problem
from simon.keys import SigningKey, is_public_key, verify
from simon.limits import DELIVERY_WINDOW_MS, MINIMUM_LIMITS, REPEAT_WINDOW_MS, SEND_WINDOW_MS
from simon.messages import (
    check_author_signature,
    check_principal,
    is_critical_value,
    is_listed_value,
    is_fresh,
    is_principal,
    message_id,
    pairing_bytes,
    parse_pairing,
    parse_message,
    recover_bytes,
    sign_message,
    sign_recovery,
    sign_pairing,
    sign_unpairing,
    unpairing_bytes,
    verify_message,
    verify_pairing,
    verify_recovery,
    verify_unpairing,
)
from simon.reading import (
    claimed_principal,
    pairing_standing,
    is_understood,
    reads_as,
)
from simon.request import (
    add_key_proof,
    add_key_string,
    check_request,
    nonce_expiry,
    sign_request,
    signing_string,
)
from simon.resolution import Resolution as Resolved
from simon.resolution import fetch_well_known, resolution_cache_ms, resolve, server_origin
from simon.signal import check_signal_freshness, parse_signal, verify_signal
from simon.transport import HostNotFound, Response
from simon.wire import (
    address_segment,
    b64url,
    is_address,
    normalize_address,
    parse_timestamp,
    timestamp,
)

VECTORS = Path(os.environ.get("SIMON_VECTORS") or Path(__file__).resolve().parents[3] / "spec/vectors/v2.json")
V = json.loads(VECTORS.read_text(encoding="utf-8"))
KEYS = {name: k for name, k in V["keys"].items() if name != "about"}
SEEDS = {k["key"]: bytes.fromhex(k["seed"]) for k in KEYS.values()}
MESSAGES = {m["name"]: m for m in V["messages"]["cases"]}
COUNTS: Counter[str] = Counter()


def signing_paths():
    """Each way this machine can sign: pure Python (opted in), and cryptography when it is installed."""
    paths = {"pure-python": mock.patch.object(keys_module, "Ed25519PrivateKey", None)}
    if keys_module.Ed25519PrivateKey is not None:
        paths["cryptography"] = contextlib.nullcontext()
    return paths


def signer(token: str) -> SigningKey:
    return SigningKey(SEEDS[token], allow_pure_python_signing=True)


def ms(text: str) -> int:
    return parse_timestamp(text)


def raw(case: dict, name: str) -> bytes:
    return bytes.fromhex(case[name + "Hex"]) if name + "Hex" in case else case[name].encode("utf-8")


class VectorCase(unittest.TestCase):
    #: The section of v2.json this class runs, and the members of it that hold cases.
    section: str
    members: tuple[str, ...] = ("cases",)

    @contextlib.contextmanager
    def case(self, label: str):
        with self.subTest(label[:120]):
            yield
            COUNTS[self.section] += 1

    def assert_refused(self, call, case: dict) -> None:
        with self.assertRaises(SimonError) as caught:
            call()
        e = caught.exception
        self.assertEqual((e.status, e.code), (case["status"], case["code"]), e.message)
        for name in ("field", "canonical"):
            if name in case:
                self.assertEqual(e.details.get(name), case[name])
        if "details" in case:
            self.assertEqual(e.details, case["details"])


class Keys(VectorCase):
    section = "keys"
    members = tuple(KEYS)

    def test_keys_from_seeds(self):
        for name, k in KEYS.items():
            with self.case(name):
                self.assertTrue(is_public_key(k["key"]))
                if k["alg"] == "ed25519":
                    for path, patch in signing_paths().items():
                        with self.subTest(path), patch:
                            self.assertEqual(signer(k["key"]).token, k["key"])
                else:
                    self.assertEqual(mldsa_public_key(SEEDS[k["key"]]), k["key"])
                if "origin" in k:
                    self.assertEqual(server_origin(k["origin"]), k["origin"])


class Canonical(VectorCase):
    section = "canonical"

    def test_cases(self):
        for c in V["canonical"]["cases"]:
            with self.case(c.get("input", c.get("inputHex"))):
                if "refused" in c:
                    with self.assertRaises(SimonError, msg=c["refused"]) as caught:
                        parse(raw(c, "input"))
                    self.assertEqual((caught.exception.status, caught.exception.code), (400, "invalid"))
                else:
                    self.assertEqual(canonical(parse(raw(c, "input"))), c["canonical"])


class Addresses(VectorCase):
    section = "addresses"

    def test_cases(self):
        for c in V["addresses"]["cases"]:
            with self.case(c["input"]):
                self.assertEqual(normalize_address(c["input"]), c["wire"])
                self.assertEqual(is_address(c["input"]), c["anyVersion"])


class Timestamps(VectorCase):
    section = "timestamps"

    def test_cases(self):
        for c in V["timestamps"]["cases"]:
            with self.case(c["input"]):
                self.assertEqual(parse_timestamp(c["input"]), c["ms"])


class KeyTokens(VectorCase):
    section = "keyTokens"

    def test_cases(self):
        for c in V["keyTokens"]["cases"]:
            with self.case(c["why"]):
                self.assertEqual(is_public_key(c["token"]), c["key"])


class KeyLists(VectorCase):
    section = "keyLists"
    members = ("now", "cases")

    def test_cases(self):
        now = ms(V["keyLists"]["now"])
        for c in V["keyLists"]["cases"]:
            with self.case(c["why"]):
                self.assertEqual(read_keys(c["keys"], now), c["read"])


class Messages(VectorCase):
    section = "messages"

    def test_cases(self):
        for c in V["messages"]["cases"]:
            with self.case(c["name"]):
                m = c["message"]
                self.assertEqual(signing_bytes("SIMON-MESSAGE", m).decode(), c["signingBytes"])
                self.assertEqual(message_id(m), c["id"])
                self.assertEqual(canonical(m), c["transmitted"])
                self.assertEqual(parse_message(c["transmitted"].encode()), m)
                entry = {"key": c["signer"], "added": "2026-10-01T00:00:00Z", "revoked": None}
                self.assertTrue(verify_message(m, [entry]))
                if c["signer"].startswith("ed25519:"):
                    for path, patch in signing_paths().items():
                        with self.subTest(path), patch:
                            self.assertEqual(sign_message(m, signer(c["signer"])), m)


class MessageChecks(VectorCase):
    section = "messageChecks"

    def test_cases(self):
        for c in V["messageChecks"]["cases"]:
            with self.case(c["name"]):
                if c.get("accepted"):
                    parse_message(raw(c, "bytes"))
                else:
                    self.assert_refused(lambda c=c: parse_message(raw(c, "bytes")), c)


class HeaderValues(VectorCase):
    section = "headerValues"
    GRAMMAR = {
        "for": is_principal,
        "critical": is_critical_value,
        "pairing": lambda v: parse_pairing(v) is not None,
        "listed": is_listed_value,
    }

    def test_cases(self):
        for c in V["headerValues"]["cases"]:
            with self.case(f"{c['header']}: {c['value'][:60]}"):
                self.assertEqual(self.GRAMMAR[c["header"]](c["value"]), c["valid"])


class Pairings(VectorCase):
    section = "pairings"

    def test_cases(self):
        for c in V["pairings"]["cases"]:
            with self.case(c["why"]):
                until = parse_pairing(c["pairing"])[0]
                self.assertEqual(pairing_bytes(c["agent"], c["principal"], until).decode(), c["bytes"])
                at = parse_timestamp(c["at"])
                self.assertEqual(verify_pairing(c["agent"], c["principal"], c["pairing"], at), c["verifies"])
                token = c["principal"].removeprefix("simon-key:")
                if c["verifies"] and token.startswith("ed25519:"):
                    for path, patch in signing_paths().items():
                        with self.subTest(path), patch:
                            self.assertEqual(sign_pairing(signer(token), c["agent"], until), c["pairing"])


class Signatures(VectorCase):
    section = "signatures"
    members = ("message", "keyValidAt", "refused", "mixedOrder")

    def setUp(self):
        self.message = MESSAGES[V["signatures"]["message"]]["message"]

    def test_key_valid_at(self):
        for c in V["signatures"]["keyValidAt"]:
            with self.case(c.get("why", "valid")):
                self.assertEqual(verify_message(self.message, c["keys"]), c["verifies"])

    def test_refused(self):
        author = [{"key": KEYS["ada"]["key"], "added": "2026-10-01T00:00:00Z", "revoked": None}]
        for c in V["signatures"]["refused"]:
            with self.case(c["why"]):
                self.assertFalse(verify_message({**self.message, "signature": c["signature"]}, author))

    def test_mixed_order(self):
        mixed = V["signatures"]["mixedOrder"]
        data = signing_bytes("SIMON-MESSAGE", self.message)
        for c in mixed["cases"]:
            with self.case(c["why"]):
                self.assertEqual(verify(mixed["key"], data, c["signature"]), c["verifies"])


class Publications(VectorCase):
    section = "publications"
    members = ("post", "feed", "carrierKeys")

    def test_published_claims(self):
        p = V["publications"]
        r = p["post"]["response"]
        self.assertEqual(message_id(r["message"]), p["post"]["id"])
        self.assertTrue(verify_message(r["message"], p["post"]["authorKeys"]))
        self.assertNotIn("keys", r, "a published message is served without unsigned keys")
        self.assertTrue(verify_claims({"claims": r["claims"], "signature": r["claimsSignature"]}, r["message"], p["carrierKeys"]))


class Requests(VectorCase):
    section = "requests"
    members = ("signed", "signedFor", "addressSegments", "checks", "nonces", "addKeyProofs")

    def test_serialised_origins_and_address_segments(self):
        for c in V["requests"]["signedFor"]:
            with self.case(c["written"]):
                self.assertEqual(server_origin(c["written"]), c["origin"])
        for c in V["requests"]["addressSegments"]:
            with self.case(c["address"]):
                self.assertEqual(address_segment(c["address"]), c["segment"])
        with self.case("a signer sends simon-server serialised"):
            key = signer(KEYS["ada"]["key"])
            url = V["keys"]["server"]["origin"] + "/simon/parts/" + "0" * 64
            headers = sign_request(key, "GET", url, server="HTTPS://SIMON.Example.net:443/")
            self.assertEqual(headers["simon-server"], "https://simon.example.net")

    def test_signed(self):
        for c in V["requests"]["signed"]:
            with self.case(c["target"]):
                body = c["body"].encode()
                text = signing_string(
                    c["method"], c["origin"], c["actor"], c["target"], c["timestamp"], c["nonce"], body
                )
                self.assertEqual(text, c["signingString"])
                headers = c["headers"]
                self.assertTrue(verify(headers["simon-key"], text.encode(), headers["simon-signature"]))
                if headers["simon-key"] in SEEDS and headers["simon-key"].startswith("ed25519:"):
                    for path, patch in signing_paths().items():
                        with self.subTest(path), patch:
                            signed = sign_request(
                                signer(headers["simon-key"]),
                                c["method"],
                                server_origin(c["origin"], allow_local=True) + c["target"],
                                body,
                                now=int(c["timestamp"]),
                                nonce=c["nonce"],
                                agent=headers.get("simon-agent"),
                                server=headers.get("simon-server"),
                            )
                            self.assertEqual(signed, headers)

    def test_checks(self):
        for c in V["requests"]["checks"]:
            with self.case(c["name"]):
                r = c["request"]

                def check(r=r, c=c):
                    return check_request(
                        r["method"],
                        r["origin"],
                        r["target"],
                        r["body"].encode(),
                        r["headers"],
                        now=ms(c["now"]) / 1000,
                        entry=c["entry"],
                        nonce_seen=c["nonceSeen"],
                        server=c["server"],
                        agent=c["agent"],
                    )

                if c.get("accepted"):
                    check()
                else:
                    self.assert_refused(check, c)

    def test_nonces(self):
        for c in V["requests"]["nonces"]:
            with self.case(c["timestamp"]):
                self.assertEqual(timestamp(nonce_expiry(c["timestamp"])), c["keptUntil"])

    def test_add_key_proofs(self):
        for c in V["requests"]["addKeyProofs"]:
            with self.case(c["key"][:40]):
                self.assertEqual(add_key_string(c["address"], c["key"]), c["string"])
                self.assertTrue(verify(c["key"], c["string"].encode(), c["proof"]))
                if c["key"].startswith("ed25519:"):
                    for path, patch in signing_paths().items():
                        with self.subTest(path), patch:
                            self.assertEqual(add_key_proof(signer(c["key"]), c["address"]), c["proof"])


class Documents(VectorCase):
    section = "documents"
    members = ("now", "server", "agent")

    def test_server(self):
        for c in V["documents"]["server"]:
            with self.case(c["name"]):
                now = ms(V["documents"]["now"])
                self.assertEqual(read_server_document(raw(c, "body"), c["origin"], now), c["read"])

    def test_agent(self):
        now = ms(V["documents"]["now"])
        for c in V["documents"]["agent"]:
            with self.case(c["name"]):
                body = raw(c, "body")
                self.assertEqual(read_agent_document(body, c["address"], c["serverKeys"], now), c["read"])
                if "signingBytes" in c:
                    self.assertEqual(signing_bytes("SIMON-AGENT", parse(body)).decode(), c["signingBytes"])


class Envelopes(VectorCase):
    section = "envelopes"
    members = ("now", "serverKeys", "receiver", "accepted", "refused")

    def setUp(self):
        self.e = V["envelopes"]
        self.now = ms(self.e["now"])

    def receive(self, c: dict) -> dict:
        """Steps 1 to 5, 7 and 8 of section 6.3: what the vectors' receiver checks of a delivery, in order."""
        envelope = parse_envelope(raw(c, "bytes"), MINIMUM_LIMITS, Receiver(self.e["receiver"]["origin"]))
        check_envelope_signature(envelope, self.e["serverKeys"], self.now)
        check_served(envelope["recipients"], lambda domain: domain in self.e["receiver"]["serves"])
        return envelope

    def test_accepted(self):
        for c in self.e["accepted"]:
            with self.case(c["name"]):
                envelope = self.receive(c)
                self.assertEqual(signing_bytes("SIMON-ENVELOPE", envelope).decode(), c["signingBytes"])
                if "claims" in envelope:
                    claims = claims_bytes(envelope["claims"], message_id(envelope["message"]))
                    self.assertEqual(claims.decode(), c["claimsSigningBytes"])
                self.assertTrue(verify_envelope(envelope, self.e["serverKeys"], self.now))

    def test_refused(self):
        for c in self.e["refused"]:
            with self.case(c["name"]):
                self.assert_refused(lambda c=c: self.receive(c), c)


class DeliverSignatures(VectorCase):
    section = "deliverSignatures"
    members = ("message", "now", "author", "envelope")

    def test_author(self):
        message = MESSAGES[V["deliverSignatures"]["message"]]["message"]
        for c in V["deliverSignatures"]["author"]:
            with self.case(c["name"]):
                if c.get("accepted"):
                    check_author_signature(message, c["keys"])
                else:
                    self.assert_refused(lambda c=c: check_author_signature(message, c["keys"]), c)

    def test_envelope(self):
        d = V["deliverSignatures"]
        envelope = parse(d["envelope"]["bytes"])
        for c in d["envelope"]["cases"]:
            with self.case(c["name"]):

                def check(c=c):
                    check_envelope_signature(envelope, c["keys"], ms(d["now"]))

                if c.get("accepted"):
                    check()
                else:
                    self.assert_refused(check, c)


class Problems(VectorCase):
    section = "problems"

    def test_cases(self):
        for c in V["problems"]["cases"]:
            with self.case(c["name"]):
                body = c["body"]
                read = parse_problem(c["status"], canonical(body).encode())
                self.assertEqual(
                    (read.code, read.message, read.status, read.retryable, read.details),
                    (body["code"], body["detail"], c["status"], body["retryable"], body.get("details", {})),
                )
                self.assertEqual(read.to_problem(), body)
                self.assertEqual(read.problem_headers(), c["headers"])


class Principals(VectorCase):
    section = "principals"

    def test_cases(self):
        for c in V["principals"]["cases"]:
            with self.case(c["name"]):
                agent = c["agent"]

                def check(c=c, agent=agent):
                    check_principal(c["message"], agent["kind"], agent.get("for"))

                if c.get("accepted"):
                    check()
                else:
                    self.assert_refused(check, c)


class ClaimsConsidered(VectorCase):
    section = "claimsConsidered"
    members = ("message", "claims", "considered")

    def test_claims(self):
        with self.case(V["claimsConsidered"]["message"]):
            message = MESSAGES[V["claimsConsidered"]["message"]]["message"]
            claims = V["claimsConsidered"]["claims"]
            self.assertEqual(claims_about(message, claims), V["claimsConsidered"]["considered"])


class Authority(VectorCase):
    section = "authority"
    members = ("carrier", "resolutions", "cases")

    def test_cases(self):
        a = V["authority"]

        def resolved(domain):
            r = a["resolutions"].get(domain, {"outcome": "not_found"})
            return Resolved(r["outcome"], r.get("server"), r.get("via"))

        for c in a["cases"]:
            with self.case(c["name"]):
                self.assertEqual(is_authoritative(c, a["carrier"], resolved), c["authoritative"])

    def test_legacy_agent_argument_does_not_require_alignment(self):
        calls = []

        def resolved(domain):
            calls.append(domain)
            self.assertEqual(domain, "example.org", "only the claimed mail domain may be resolved")
            return Resolved("server", "https://carrier.example", "dns")

        claim = {"for": "mailto:alice@example.org"}
        self.assertTrue(is_authoritative(claim, "https://carrier.example", resolved))
        self.assertTrue(is_authoritative(claim, "https://carrier.example", resolved, "reader@unrelated.test"))
        self.assertFalse(
            is_authoritative(claim, "https://other.example", resolved, agent="reader@example.org")
        )
        self.assertEqual(calls, ["example.org", "example.org", "example.org"])


class ClaimsJudged(VectorCase):
    section = "claimsJudged"
    members = ("carrier", "resolutions", "cases")

    def test_cases(self):
        j = V["claimsJudged"]

        def resolved(domain):
            r = j["resolutions"].get(domain, {"outcome": "not_found"})
            return Resolved(r["outcome"], r.get("server"), r.get("via"))

        for c in j["cases"]:
            with self.case(c["message"]):
                message = MESSAGES[c["message"]]["message"]
                judged = judge_claims(message, c["claims"], j["carrier"], resolved)
                self.assertEqual(judged, c["judged"])


class ClaimsSignatures(VectorCase):
    section = "claimsSignatures"
    members = ("message", "signature", "signingBytes", "cases")

    def test_cases(self):
        v = V["claimsSignatures"]
        message = MESSAGES[v["message"]]["message"]
        with self.case("signing bytes"):
            data = claims_bytes(v["cases"][0]["claims"], message_id(message))
            self.assertEqual(data.decode(), v["signingBytes"])
            carrier = v["cases"][0]["keys"][0]["key"]
            for path, patch in signing_paths().items():
                with self.subTest(path), patch:
                    self.assertEqual(signer(carrier).sign(data), v["signature"])
        for c in v["cases"]:
            with self.case(c["name"]):
                signed = {"claims": c["claims"], "signature": v["signature"]}
                self.assertEqual(verify_claims(signed, message, c["keys"]), c["verifies"])


class Signals(VectorCase):
    section = "signals"
    members = ("now", "serverKeys", "receiver", "accepted", "refused")

    def setUp(self):
        self.s = V["signals"]
        self.now = ms(self.s["now"])

    def receive(self, c: dict) -> dict:
        """Steps 1 to 3, then the signature, the served recipients and the freshness (section 6.4)."""
        signal = parse_signal(raw(c, "bytes"), Receiver(self.s["receiver"]["origin"]))
        if not verify_signal(signal, self.s["serverKeys"], self.now):
            raise SimonError("bad_signature", "The signal does not verify.", 403)
        check_served(signal["to"], lambda domain: domain in self.s["receiver"]["serves"], "to")
        check_signal_freshness(signal, self.now)
        return signal

    def test_accepted(self):
        for c in self.s["accepted"]:
            with self.case(c["name"]):
                signal = self.receive(c)
                data = signing_bytes("SIMON-SIGNAL", signal)
                self.assertEqual(data.decode(), c["signingBytes"])
                carrier = self.s["serverKeys"][0]["key"]
                if not verify(carrier, data, signal["signature"]):
                    continue  # signed with the server's other key, whose signatures are not deterministic
                for path, patch in signing_paths().items():
                    with self.subTest(path), patch:
                        self.assertEqual(signer(carrier).sign(data), signal["signature"])

    def test_refused(self):
        for c in self.s["refused"]:
            with self.case(c["name"]):
                self.assert_refused(lambda c=c: self.receive(c), c)


class Unpairings(VectorCase):
    section = "unpairings"

    def test_cases(self):
        for c in V["unpairings"]["cases"]:
            with self.case(c["why"]):
                self.assertEqual(unpairing_bytes(c["agent"], c["principal"]).decode(), c["bytes"])
                self.assertEqual(verify_unpairing(c["agent"], c["principal"], c["unpairing"]), c["verifies"])
                token = c["principal"].removeprefix("simon-key:")
                if c["verifies"] and token.startswith("ed25519:"):
                    for path, patch in signing_paths().items():
                        with self.subTest(path), patch:
                            self.assertEqual(sign_unpairing(signer(token), c["agent"]), c["unpairing"])


class Recoveries(VectorCase):
    section = "recoveries"

    def test_cases(self):
        for c in V["recoveries"]["cases"]:
            with self.case(c["why"]):
                self.assertEqual(recover_bytes(c["agent"], c["key"], c["at"]).decode(), c["bytes"])
                verifies = verify_recovery(c["agent"], c["principal"], c["key"], c["at"], c["recover"])
                self.assertEqual(verifies, c["verifies"])
                token = c["principal"].removeprefix("simon-key:")
                if c["verifies"] and token.startswith("ed25519:"):
                    for path, patch in signing_paths().items():
                        with self.subTest(path), patch:
                            signed = sign_recovery(signer(token), c["agent"], c["key"], c["at"])
                            self.assertEqual(signed, c["recover"])


class Reading(VectorCase):
    section = "reading"
    members = ("understoodHeaders", "understood", "principals", "pairings", "knownRelations", "relations")

    def test_understood(self):
        headers = set(V["reading"]["understoodHeaders"])
        for c in V["reading"]["understood"]:
            with self.case(c["name"]):
                self.assertEqual(is_understood(c["message"], headers), c["understood"])

    def test_principals(self):
        for c in V["reading"]["principals"]:
            with self.case(c["name"]):
                self.assertEqual(claimed_principal(c["message"]), c["principal"])

    def test_pairings(self):
        for c in V["reading"]["pairings"]:
            with self.case(c["name"]):
                self.assertEqual(pairing_standing(c["message"], parse_timestamp(c["now"])), c["standing"])

    def test_relations(self):
        known = set(V["reading"]["knownRelations"])
        for c in V["reading"]["relations"]:
            with self.case(c["name"]):
                self.assertEqual(reads_as(c["message"], c["target"], known), c["readsAs"])


class Delivery(VectorCase):
    section = "delivery"
    members = ("sentAt", "cases")

    def test_cases(self):
        sent_at = V["delivery"]["sentAt"]
        for c in V["delivery"]["cases"]:
            with self.case(c["name"]):
                earliest, deadline = delivery_window(sent_at, ms(c["acceptedAt"]))
                self.assertEqual((timestamp(earliest), timestamp(deadline)), (c["earliest"], c["deadline"]))
                self.assertEqual(delivery_state(sent_at, ms(c["acceptedAt"]), ms(c["now"])), c["state"])


#: How each failed well-known fetch reaches this client: as the exception the transport raises.
FETCH_FAILURES = {
    "nxdomain": HostNotFound("no such host"),
    "refused": ConnectionRefusedError(61, "Connection refused"),
    "bad_certificate": ssl.SSLCertVerificationError(1, "certificate verify failed"),
    "timeout": TimeoutError("timed out"),
    "dropped": ConnectionResetError(54, "Connection reset by peer"),
}


class Resolution(VectorCase):
    section = "resolution"
    members = ("cases", "origins", "cacheMs")

    def test_cases(self):
        for c in V["resolution"]["cases"]:
            with self.case(c.get("why") or json.dumps(c["txt"])[:100]):
                domain = c.get("domain", "example.com")
                fetched = []

                def txt(name, c=c, domain=domain):
                    self.assertEqual(name, f"_simon.{domain}")
                    if c["txt"] in ("servfail", "dnssec_failure"):  # a validating resolver's SERVFAIL
                        raise LookupFailed(c["txt"])
                    return c["txt"]

                def transport(method, url, *args, c=c, domain=domain, fetched=fetched, **kwargs):
                    self.assertIn("wellKnown", c, "the well-known answer must not be fetched")
                    self.assertEqual((method, url), ("GET", f"https://{domain}/.well-known/simon"))
                    fetched.append(url)
                    answer = c["wellKnown"]
                    if isinstance(answer, str):
                        raise FETCH_FAILURES[answer]
                    return Response(url, answer["status"], Message(), answer["body"].encode())

                with mock.patch.object(resolution_module, "fetch", transport):
                    result = resolve(domain, txt, fetch_well_known)
                expected = c["result"]
                self.assertEqual(result.outcome, expected["outcome"])
                self.assertEqual(result.server, expected.get("server"))
                self.assertEqual(result.via, expected.get("via"))

    def test_origins(self):
        for c in V["resolution"]["origins"]:
            with self.case(c["input"]):
                self.assertEqual(server_origin(c["input"]), c["origin"])

    def test_cache(self):
        for c in V["resolution"]["cacheMs"]:
            with self.case(json.dumps(c["result"])):
                r = c["result"]
                result = Resolved(r["outcome"], r.get("server"), r.get("via"))
                self.assertEqual(resolution_cache_ms(result, c["sourceTtlMs"]), c["cacheMs"])


class Clock(VectorCase):
    section = "clock"
    members = ("sentAt", "cases")

    def test_cases(self):
        sent_at = V["clock"]["sentAt"]
        for c in V["clock"]["cases"]:
            with self.case(c["name"]):
                now = ms(c["now"])
                self.assertEqual(is_fresh(sent_at, now, SEND_WINDOW_MS), c["send"])
                self.assertEqual(is_fresh(sent_at, now, DELIVERY_WINDOW_MS), c["deliver"])
                self.assertEqual(is_fresh(sent_at, now, REPEAT_WINDOW_MS, None), c["repeat"])


class Coverage(unittest.TestCase):
    """Every section of the file, and every member of each, has a runner here, and says what it means."""

    def test_every_section_is_run(self):
        runners = {cls.section: cls for cls in VectorCase.__subclasses__()}
        self.assertEqual(len(runners), len(VectorCase.__subclasses__()), "two runners for one section")
        self.assertIsInstance(V["about"], str)
        for section, value in V.items():
            if section == "about":
                continue
            with self.subTest(section):
                self.assertIn(section, runners, f"no runner for the vector section {section}")
                self.assertTrue(value.get("about"), f"{section} has no about")
                self.assertEqual(set(value) - {"about"}, set(runners[section].members))


def tearDownModule():
    if os.environ.get("SIMON_VECTOR_COUNTS"):
        for section in V:
            if section != "about":
                print(f"{section:18} {COUNTS[section]}", file=sys.stderr)
        print(f"{'total':18} {sum(COUNTS.values())}", file=sys.stderr)


# ML-DSA-65 key generation (FIPS 204 Algorithms 6, 33, 35), only to check the vector keys from their seeds.


def mldsa_public_key(seed: bytes) -> str:
    q, k, l_ = mldsa.Q, mldsa.K, mldsa.L
    expanded = hashlib.shake_256(seed + bytes([k, l_])).digest(128)
    rho, rho_prime = expanded[:32], expanded[32:96]
    s = [_bounded_poly(rho_prime + r.to_bytes(2, "little")) for r in range(l_ + k)]
    s1_hat = [mldsa._ntt(p) for p in s[:l_]]
    public = bytearray(rho)
    for i in range(k):
        acc = [0] * mldsa.N
        for j in range(l_):
            a_hat = mldsa._rej_ntt_poly(rho + bytes([j, i]))
            acc = [x + a * b for x, a, b in zip(acc, a_hat, s1_hat[j], strict=True)]
        t = [(x + e) % q for x, e in zip(mldsa._inverse_ntt([x % q for x in acc]), s[l_ + i], strict=True)]
        t1 = [(c - _centered(c % 8192, 8192)) >> 13 for c in t]
        public += mldsa._pack(t1, 10)
    return "ml-dsa-65:" + b64url(bytes(public))


def _centered(r: int, m: int) -> int:
    return r - m if r > m // 2 else r


def _bounded_poly(seed: bytes) -> list[int]:
    stream = hashlib.shake_256(seed).digest(1024)
    out = []
    for byte in stream:
        for half in (byte & 15, byte >> 4):
            if half < 9 and len(out) < mldsa.N:
                out.append(4 - half)
        if len(out) == mldsa.N:
            return out
    raise AssertionError("SHAKE256 stream too short for RejBoundedPoly")


if __name__ == "__main__":
    unittest.main()
