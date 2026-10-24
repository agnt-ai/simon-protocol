"""What the vectors cannot reach: values built in Python, the error shape, the DNS stub resolver, the key
and address files, and the command line."""

from __future__ import annotations

import io
import json
import os
import pickle
import subprocess
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from simon import cli, dnsquery, ed25519, transport as http_transport
from simon.canonical import canonical, parse, parse_with_members
from simon.dnsquery import LookupFailed
from simon.errors import SimonError, parse_problem
from simon.keys import SigningKey
from simon.provenance import invisible_in, present_entry, untrusted, unwrap_entry
from simon.resolution import Resolution, freshness_ms, resolve, well_known_outcome
from simon.wait import wait_for_message, save_wait_state, read_wait_state
from simon.transport import _read
from simon.wire import from_b64url, is_base64, parse_timestamp, timestamp


class CanonicalValues(unittest.TestCase):
    def test_python_values(self):
        self.assertEqual(
            canonical({"b": (1, True), "a": None, "é": " /<"}), '{"a":null,"b":[1,true],"é":" /<"}'
        )
        self.assertEqual(canonical({"\U0001f600": 1, "｡": 2}), '{"\U0001f600":1,"｡":2}')  # UTF-16 order
        self.assertEqual(canonical("\x00\x1f\x7f"), '"\\u0000\\u001f\x7f"')

    def test_what_is_not_canonical_json(self):
        for value, error in [
            (1.0, ValueError),
            (2**53, ValueError),
            ("\ud800", ValueError),
            ({1: 2}, TypeError),
        ]:
            with self.subTest(value=value), self.assertRaises(error):
                canonical(value)
        deep: list = []
        for _ in range(64):
            deep = [deep]
        with self.assertRaises(ValueError):
            canonical(deep)
        canonical(deep[0])

    def test_members_as_they_arrived(self):
        value, members = parse_with_members(b'{ "m" : {"b":1, "a":2} ,"n":[ ]}')
        self.assertEqual(value, {"m": {"b": 1, "a": 2}, "n": []})
        self.assertEqual(members, {"m": '{"b":1, "a":2}', "n": "[ ]"})

    def test_an_integer_too_long_to_be_safe_is_refused_by_its_length(self):
        for token in ["9" * 4301, "-" + "1" * 17, "1" * 17]:
            with self.subTest(len(token)), self.assertRaises(SimonError) as caught:
                parse(f'{{"a":{token}}}')
            self.assertEqual(caught.exception.code, "invalid")
            self.assertIn("safe integer range", caught.exception.message)
        self.assertEqual(parse(f'{{"a":-{2**53 - 1}}}'), {"a": -(2**53 - 1)})

    def test_a_refusal_says_where(self):
        with self.assertRaises(SimonError) as caught:
            parse(b'{"a":1.5}')
        self.assertEqual((caught.exception.status, caught.exception.code), (400, "invalid"))
        self.assertIn("character 6", caught.exception.message)


class Wire(unittest.TestCase):
    def test_timestamps_round_trip(self):
        for ms in (0, 1_792_011_600_123, 253_402_300_799_999):
            self.assertEqual(parse_timestamp(timestamp(ms)), ms)
        self.assertIsNone(parse_timestamp("２０２６-10-14T21:00:00Z"))  # digits are ASCII digits

    def test_encodings(self):
        self.assertEqual(from_b64url("AA"), b"\x00")
        for text in ("AB", "A", "AA==", "A+", ""):
            self.assertFalse(from_b64url(text), text)
        self.assertTrue(is_base64("AAE="))
        self.assertFalse(is_base64("AAF="))


class Errors(unittest.TestCase):
    def test_the_shape(self):
        e = SimonError("rate_limited", "Slow down.", 429, True, retry_after=3)
        self.assertEqual(
            e.to_json(),
            {
                "error": {
                    "code": "rate_limited",
                    "message": "Slow down.",
                    "status": 429,
                    "retryable": True,
                    "retryAfter": 3,
                }
            },
        )
        self.assertEqual(str(e), "429 rate_limited: Slow down.")
        self.assertEqual(SimonError("timeout", "No answer.").details, {})
        self.assertTrue(SimonError("unavailable", "Later.", 503).retryable)  # follows the status
        self.assertFalse(SimonError("invalid", "No.", 400).retryable)

    def test_problem_details(self):
        body = (
            b'{"type":"about:blank","title":"Bad signature","status":403,"code":"bad_signature",'
            b'"retryable":true,"detail":"The envelope does not verify.","details":"not an object"}'
        )
        e = parse_problem(403, body)
        self.assertEqual(
            (e.code, e.message, e.status, e.retryable, e.details),
            ("bad_signature", "The envelope does not verify.", 403, False, {}),
        )
        self.assertEqual(parse_problem(500, b'{"code":"oops"}').message, "Oops")
        for body in (b"", b"<html>", b'{"error":{"code":"invalid"}}', b'{"code":7}'):
            self.assertIsNone(parse_problem(400, body), body)


class Provenance(unittest.TestCase):
    def test_invisible_characters_by_path(self):
        value = {"a\u2066": ["ok", "x\u00ad\U000e0067"], "b": "\ufeff"}
        self.assertEqual(
            invisible_in(value),
            [
                {"path": "a? (its name)", "codePoints": ["U+2066"]},
                {"path": "a?[1]", "codePoints": ["U+00AD", "U+E0067"]},
                {"path": "b", "codePoints": ["U+FEFF"]},
            ],
        )
        self.assertEqual(
            untrusted("ada@example.com", "author-signed", "plain"),
            {"untrusted": {"from": "ada@example.com", "basis": "author-signed", "content": "plain"}},
        )

    def test_entries_unwrap_for_verification(self):
        message = {"v": 1, "from": "ada@example.com", "signature": "AA"}
        entry = {
            "cursor": 1,
            "id": "x",
            "message": message,
            "carrier": "https://a.example",
            "claims": [{"type": "t", "authoritative": True}],
            "signedClaims": {"claims": [{"type": "t"}], "signature": "AA"},
        }
        # The entry's claims, its server's unsigned judgement, stay behind.
        self.assertEqual(unwrap_entry(entry), (message, entry["signedClaims"]))
        self.assertEqual(unwrap_entry(present_entry(entry)), (message, entry["signedClaims"]))
        self.assertEqual(unwrap_entry({**entry, "signedClaims": None}), (message, None))
        self.assertEqual(unwrap_entry(message), (message, None))


class PureEd25519(unittest.TestCase):
    def test_sign_and_verify(self):
        seed = bytes(range(32))
        public = ed25519.public_key(seed)
        signature = ed25519.sign(seed, b"message")
        self.assertTrue(ed25519.verify(public, b"message", signature))
        self.assertFalse(ed25519.verify(public, b"messagf", signature))
        self.assertFalse(ed25519.verify(public, b"message", signature[:63]))
        self.assertFalse(ed25519.verify(public[:31], b"message", signature))

    def test_pem(self):
        key = SigningKey(bytes(range(32)), allow_pure_python_signing=True)
        again = SigningKey.from_pem(key.to_pem().replace("\n", "\\n"), allow_pure_python_signing=True)
        self.assertEqual(again.token, key.token)
        self.assertNotIn(key.to_pem().split("\n")[1], repr(key))
        with self.assertRaises(ValueError):
            SigningKey.from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")


def dns_answer(
    query_id: int, question: bytes, records: list[bytes], rcode: int = 0, flags: int = 0x8180
) -> bytes:
    header = struct.pack(">HHHHHH", query_id, flags | rcode, 1, len(records), 0, 0)
    return header + question + b"".join(records)


def rr(owner: bytes, rtype: int, data: bytes) -> bytes:
    return owner + struct.pack(">HHIH", rtype, 1, 60, len(data)) + data


QUESTION = dnsquery._question("_simon.example.com")
POINTER = b"\xc0\x0c"  # the question's name, at offset 12


class StubResolver(unittest.TestCase):
    def test_txt_records(self):
        txt = b"".join(bytes([len(s)]) + s for s in (b"v=simon1; server=https:", b"//simon.example.com"))
        records = [rr(POINTER, 16, txt), rr(POINTER, 16, b"\x03abc")]
        answer = dns_answer(7, QUESTION, records)
        self.assertEqual(
            dnsquery._txt_records(answer, QUESTION),
            [["v=simon1; server=https:", "//simon.example.com"], ["abc"]],
        )

    def test_a_cname_is_followed_and_strangers_are_not(self):
        target = b"\x04next\x07example\x03com\x00"
        records = [rr(POINTER, 5, target), rr(target, 16, b"\x02ok"), rr(b"\x05other\x00", 16, b"\x02no")]
        self.assertEqual(dnsquery._txt_records(dns_answer(7, QUESTION, records), QUESTION), [["ok"]])

    def test_absent_and_failed(self):
        self.assertEqual(dnsquery._txt_records(dns_answer(7, QUESTION, [], rcode=3), QUESTION), [])
        with self.assertRaises(LookupFailed):
            dnsquery._txt_records(dns_answer(7, QUESTION, [], rcode=2), QUESTION)

    def test_malformed_answers_are_failures(self):
        good = rr(POINTER, 16, b"\x02ok")
        for name, answer in [
            ("a record cut short", dns_answer(7, QUESTION, [good[:-1]])),
            ("a TXT string longer than its record", dns_answer(7, QUESTION, [rr(POINTER, 16, b"\x05ok")])),
            ("a pointer that points forward", dns_answer(7, QUESTION, [rr(b"\xc0\xff", 16, b"\x02ok")])),
            (
                "a pointer to itself",
                dns_answer(7, QUESTION, [rr(b"\xc0" + bytes([12 + len(QUESTION)]), 16, b"")]),
            ),
            ("a label of a reserved type", dns_answer(7, QUESTION, [rr(b"\x80", 16, b"")])),
            ("more answers than it holds", dns_answer(7, QUESTION, [good])[:-3]),
        ]:
            with self.subTest(name), self.assertRaises(LookupFailed):
                dnsquery._txt_records(answer, QUESTION)

    def test_only_an_answer_to_this_question(self):
        answer = dns_answer(7, QUESTION, [])
        self.assertTrue(dnsquery._answers(answer, 7, QUESTION))
        self.assertFalse(dnsquery._answers(answer, 8, QUESTION))
        self.assertFalse(dnsquery._answers(dns_answer(7, QUESTION, [], flags=0x0100), 7, QUESTION))
        other = dnsquery._question("_simon.example.org")
        self.assertFalse(dnsquery._answers(dns_answer(7, other, []), 7, QUESTION))
        self.assertFalse(dnsquery._answers(answer[:20], 7, QUESTION))

    def test_a_stray_datagram_is_ignored(self):
        """A reply with another id is dropped, and the real answer read after it."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))

            def nameserver():
                query, client = server.recvfrom(512)
                query_id = struct.unpack(">H", query[:2])[0]
                server.sendto(dns_answer(query_id ^ 1, QUESTION, [rr(POINTER, 16, b"\x05wrong")]), client)
                server.sendto(dns_answer(query_id, QUESTION, [rr(POINTER, 16, b"\x05right")]), client)

            threading.Thread(target=nameserver, daemon=True).start()
            port = server.getsockname()[1]
            answer = dnsquery._ask("127.0.0.1", QUESTION, time.monotonic() + 2, port)
        self.assertEqual(answer, [["right"]])

    def test_silence_is_a_failure(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            with self.assertRaises(OSError):
                dnsquery._ask("127.0.0.1", QUESTION, time.monotonic() + 0.2, server.getsockname()[1])


class Resolve(unittest.TestCase):
    def test_failures_are_temporary(self):
        def broken(name):
            raise LookupFailed("SERVFAIL")

        self.assertEqual(resolve("example.com", broken), Resolution("temporary"))
        self.assertEqual(
            resolve("example.com", lambda n: [], lambda u: (200, b'{"server":"https://a.example.com"}')).via,
            "well-known",
        )

    def test_ttls_reach_the_resolution(self):
        records = dnsquery.TxtRecords([["v=simon1; server=https://simon.example.com"]], 300_000)
        self.assertEqual(resolve("example.com", lambda n: records).ttl_ms, 300_000)
        answer = dns_answer(7, QUESTION, [rr(POINTER, 16, b"\x02ok")])
        self.assertEqual(dnsquery._txt_records(answer, QUESTION).ttl_ms, 60_000)
        well_known = (200, b'{"server":"https://a.example.com"}', 120_000)
        self.assertEqual(resolve("example.com", lambda n: [], lambda u: well_known).ttl_ms, 120_000)

    def test_http_freshness(self):
        from email.message import Message

        def headers(**fields):
            m = Message()
            for name, value in fields.items():
                m[name.replace("_", "-")] = value
            return m

        self.assertEqual(freshness_ms(headers(cache_control="public, max-age=300", age="100")), 200_000)
        self.assertEqual(freshness_ms(headers(cache_control="max-age=300, s-maxage=60")), 60_000)
        self.assertEqual(freshness_ms(headers(cache_control="no-store, max-age=300")), 0)
        expires = headers(date="Wed, 14 Oct 2026 21:00:00 GMT", expires="Wed, 14 Oct 2026 21:10:00 GMT")
        self.assertEqual(freshness_ms(expires), 600_000)
        self.assertIsNone(freshness_ms(headers()))

    def test_a_well_known_answer_longer_than_a_document_is_none(self):
        body = b'{"server":"https://simon.example.com"}' + b" " * 131_072
        self.assertEqual(well_known_outcome((200, body)), Resolution("not_found"))


class Files(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        patcher = mock.patch.dict(os.environ, {"SIMON_ALLOW_PURE_SIGNING": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_key_file_is_created_exclusively_mode_600(self):
        key = cli._create_key(self.home / "agent" / "key.pem")
        self.assertEqual(stat.S_IMODE((self.home / "agent" / "key.pem").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.home / "agent").stat().st_mode), 0o700)
        self.assertEqual(cli._create_key(self.home / "agent" / "key.pem").token, key.token)  # a race: read it

    def test_files_are_saved_mode_600(self):
        path = self.home / "address"
        path.write_text("old\n")
        path.chmod(0o644)
        cli._save(path, "ada@example.com")
        self.assertEqual(path.read_text(), "ada@example.com\n")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.home.iterdir()), ["address"])

    def test_pair_and_errors_on_the_command_line(self):
        out, err = io.StringIO(), io.StringIO()
        agent_home = self.home / "agent"
        with redirect_stdout(out), mock.patch.dict(os.environ, {"SIMON_WORKSPACE": str(self.home)}):
            status = cli.main(
                ["--home", str(agent_home), "pair", "--address", "Bob@Example.net", "--key", "principal.pem"]
            )
        self.assertEqual(status, 0)
        pairing = json.loads(out.getvalue())
        self.assertTrue(pairing["for"].startswith("simon-key:ed25519:"))
        self.assertTrue((self.home / "principal.pem").exists())
        with redirect_stderr(err):
            status = cli.main(["--home", str(agent_home), "sync"])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(err.getvalue())["error"]["code"], "no_key")




class WaitTransactionAndBudget(unittest.TestCase):
    def test_zero_reads_only_one_page_and_releases_the_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            agent = mock.Mock(address="ada@example.com", timeout=2)
            agent.sync.return_value = {"messages": [], "token": "opaque-1", "more": True}
            self.assertIsNone(wait_for_message(agent, home, timeout=0, interval=1))
            agent.sync.assert_called_once_with(None, 200, request_timeout=2)
            self.assertEqual(read_wait_state(home)["token"], "opaque-1")
            self.assertFalse((home / "wait.lock").exists())

    def test_overlapping_or_stale_unknown_wait_is_explicit_and_never_stolen(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            (home / "wait.lock").mkdir()
            (home / "wait.lock" / "owner.json").write_text(json.dumps({"pid": os.getpid()}))
            with self.assertRaises(SimonError) as caught:
                wait_for_message(mock.Mock(), home, timeout=0, interval=1)
            self.assertEqual(caught.exception.code, "concurrent_wait")
            self.assertTrue((home / "wait.lock" / "owner.json").exists())

    def test_positive_budget_limits_pages_and_preserves_checkpoint(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            now = [0.0]
            budgets = []
            def sync(token, limit, *, request_timeout):
                budgets.append(request_timeout)
                now[0] += 0.6
                return {"messages": [], "token": f"opaque-{len(budgets)}", "more": True}
            agent = mock.Mock(address="ada@example.com", timeout=30, sync=sync)
            self.assertIsNone(wait_for_message(agent, home, timeout=1, interval=1, clock=lambda: now[0]))
            self.assertEqual(budgets, [1.0, 0.4])
            self.assertEqual(read_wait_state(home)["token"], "opaque-2")
            self.assertFalse((home / "wait.lock").exists())

    def test_body_deadline_does_not_reset_on_each_slow_chunk(self):
        response = mock.Mock()
        response.read1.return_value = b"x"
        with mock.patch("simon.transport.time.monotonic", side_effect=[0.1, 0.5, 1.1]):
            with self.assertRaises(TimeoutError):
                _read(response, None, 1.0)
        self.assertEqual(response.read1.call_count, 2)




class BoundedHTTPWorker(unittest.TestCase):
    def process(self):
        process = mock.Mock(returncode=0, stdin=io.BytesIO(), stdout=io.BytesIO())
        process.poll.return_value = 0
        return process

    def test_worker_answer_and_spawn_failure_release_the_single_slot(self):
        process = self.process()
        answer = http_transport.Response("https://example.test", 200, {}, b"ok")
        process.communicate.return_value = (pickle.dumps((True, answer)), None)
        slots = mock.Mock()
        slots.acquire.return_value = True
        with mock.patch.object(http_transport, "_SLOTS", slots), mock.patch.object(http_transport, "_PENDING", []):
            with mock.patch.object(http_transport, "_SPAWN", return_value=process) as spawn:
                self.assertEqual(http_transport.fetch("GET", answer.url, timeout=1), answer)
                args, kwargs = spawn.call_args
                self.assertEqual(args[0][1:3], ["-I", "-c"])
                self.assertNotIn("PYTHONPATH", kwargs["env"])
                self.assertEqual(kwargs["cwd"], str(Path(http_transport.__file__).resolve().parent.parent))
            slots.release.assert_called_once()
            slots.reset_mock()
            with mock.patch.object(http_transport, "_SPAWN", side_effect=OSError("spawn failed")):
                with self.assertRaises(OSError):
                    http_transport.fetch("GET", answer.url, timeout=1)
            slots.release.assert_called_once()

    def test_timeout_terminates_then_kills_and_never_uses_unbounded_join(self):
        process = self.process()
        process.poll.return_value = None
        process.communicate.side_effect = [subprocess.TimeoutExpired("worker", 1), subprocess.TimeoutExpired("worker", 0.1), (b"", None)]
        slots = mock.Mock()
        slots.acquire.return_value = True
        with mock.patch.object(http_transport, "_SLOTS", slots), mock.patch.object(http_transport, "_PENDING", []), mock.patch.object(http_transport, "_SPAWN", return_value=process):
            with self.assertRaises(TimeoutError):
                http_transport.fetch("GET", "https://example.test", timeout=1)
            process.terminate.assert_called_once()
            process.kill.assert_called_once()
            self.assertTrue(all(call.kwargs["timeout"] >= 0 for call in process.communicate.call_args_list))
            slots.release.assert_called_once()

    def test_unreaped_killed_worker_keeps_its_slot_until_nonblocking_reap(self):
        process = self.process()
        process.poll.return_value = None
        process.communicate.side_effect = subprocess.TimeoutExpired("worker", 0.1)
        slots = mock.Mock()
        slots.acquire.return_value = True
        pending = []
        with mock.patch.object(http_transport, "_SLOTS", slots), mock.patch.object(http_transport, "_PENDING", pending), mock.patch.object(http_transport, "_SPAWN", return_value=process):
            with self.assertRaises(TimeoutError):
                http_transport.fetch("GET", "https://example.test", timeout=1)
            self.assertEqual(pending, [process])
            slots.release.assert_not_called()
            process.poll.return_value = -9
            http_transport._reap_finished()
            slots.release.assert_called_once()
            self.assertEqual(pending, [])




class RealHTTPWorkerRoundTrips(unittest.TestCase):
    """Definitions for later resource-authorized proof: real child process, loopback only, synthetic data."""
    def setUp(self):
        self.stopping = threading.Event()
        stop = self.stopping
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                try:
                    if self.path == "/slow-headers":
                        self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                        while not stop.wait(0.02):
                            self.wfile.write(b"x")
                            self.wfile.flush()
                        return
                    if self.path in ("/slow-framing", "/slow-body"):
                        self.send_response(200)
                        self.send_header("Transfer-Encoding", "chunked")
                        self.end_headers()
                        while not stop.wait(0.02):
                            self.wfile.write(b"1" if self.path == "/slow-framing" else b"1\r\nx\r\n")
                            self.wfile.flush()
                        return
                    status = 404 if self.path == "/missing" else 302 if self.path == "/redirect" else 200
                    self.send_response(status)
                    self.send_header("X-Synthetic", "worker-proof")
                    if status == 302:
                        self.send_header("Location", "/ok")
                    self.send_header("Content-Length", "8")
                    self.end_headers()
                    self.wfile.write(b"synthetic"[:8])
                except (BrokenPipeError, ConnectionResetError):
                    pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.thread.start()
        self.closed = False

    def tearDown(self):
        self.stopping.set()
        if not self.closed:
            self.server.shutdown()
            self.server.server_close()
        self.thread.join(timeout=1)
        self.assertFalse(self.thread.is_alive())
        http_transport._reap_finished()

    def test_real_child_preserves_status_headers_body_limit_and_does_not_redirect(self):
        for path, status in (("/ok", 200), ("/missing", 404), ("/redirect", 302)):
            with self.subTest(path=path):
                answer = http_transport.fetch("GET", self.origin + path, timeout=3, max_bytes=3)
                self.assertEqual((answer.status, answer.body, answer.headers.get("X-Synthetic")), (status, b"synt", "worker-proof"))
        self.assertEqual(answer.headers.get("Location"), "/ok")

    def test_real_child_connection_failure_preserves_oserror(self):
        self.server.shutdown()
        self.server.server_close()
        self.closed = True
        with self.assertRaises(OSError):
            http_transport.fetch("GET", self.origin + "/ok", timeout=2)

    def test_hostile_cwd_and_pythonpath_cannot_replace_the_trusted_worker_package(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "workspace-code-ran"
            malicious = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\nraise RuntimeError('workspace package imported')\n"
            (root / "simon.py").write_text(malicious)
            (root / "simon").mkdir()
            (root / "simon" / "__init__.py").write_text(malicious)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with mock.patch.dict(os.environ, {"PYTHONPATH": str(root)}):
                    answer = http_transport.fetch("GET", self.origin + "/ok", timeout=3)
            finally:
                os.chdir(previous)
            self.assertEqual(answer.status, 200)
            self.assertFalse(marker.exists(), "child imported untrusted workspace code")

    def test_real_child_deadline_bounds_slow_headers_body_and_chunk_framing_and_reaps(self):
        processes = []
        def spawn(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            processes.append(process)
            return process
        with mock.patch.object(http_transport, "_SPAWN", side_effect=spawn):
            for path in ("/slow-headers", "/slow-body", "/slow-framing"):
                with self.subTest(path=path):
                    started = time.monotonic()
                    with self.assertRaises(TimeoutError):
                        http_transport.fetch("GET", self.origin + path, timeout=0.5)
                    self.assertLess(time.monotonic() - started, 1.0)
        for process in processes:
            process.wait(timeout=1)
            self.assertIsNotNone(process.poll(), "timed-out HTTP worker survived cleanup")
        http_transport._reap_finished()


if __name__ == "__main__":
    unittest.main()
