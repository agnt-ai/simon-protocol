"""The actual SDK and CLI preserve an explicit history gap, including shared pending wait data.

HTTP is injected at the existing client.fetch seam; no subprocess/HTTP worker is needed for these cases.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from simon import cli
from simon.client import Agent
from simon.errors import SimonError
from simon.keys import SigningKey
from simon.messages import message_id, sign_message
from simon.transport import Response
from simon.wait import read_wait_state, save_wait_state, wait_file, wait_for_message

ORIGIN = "https://simon.migration.test"
ADDRESS = "reader@migration.test"
RESUME = "opaque:resume/+?=history-migration"
DETAILS = {"reason": "history_migration", "resumeToken": RESUME}


class MigrationTransport:
    def __init__(self, entry):
        self.entry = entry
        self.calls = []

    def fetch(self, method, url, body=None, headers=None, **options):
        requested = urlsplit(url)
        self.calls.append((method, requested.path, parse_qs(requested.query)))
        if method != "GET" or requested.path != "/simon/sync":
            raise AssertionError(f"unexpected network request: {method} {url}")
        since = parse_qs(requested.query).get("since")
        response_headers = Message()
        response_headers["content-type"] = "application/json" if since else "application/problem+json"
        if since is None:
            value = {"type": "about:blank", "title": "Token expired", "status": 410,
                     "code": "token_expired", "retryable": False,
                     "detail": "Retained sent history may be incomplete. Explicitly accept this gap.",
                     "details": DETAILS}
            return Response(url, 410, response_headers, json.dumps(value).encode())
        if since != [RESUME]:
            raise AssertionError(f"the caller changed the offered opaque token: {since!r}")
        value = {"messages": [self.entry], "signals": [], "marks": [], "removed": [],
                 "token": "opaque:after-retained-page", "more": False}
        return Response(url, 200, response_headers, json.dumps(value).encode())


class ExplicitMigrationGap(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey(bytes(range(32)), allow_pure_python_signing=True)
        author = SigningKey(bytes(reversed(range(32))), allow_pure_python_signing=True)
        message = sign_message({"v": 1, "from": "author@migration.test", "to": [ADDRESS],
                                "inReplyTo": None, "headers": {}, "sentAt": "2026-10-15T12:00:00Z",
                                "parts": [{"type": "text/plain", "data": "retained through migration"}]}, author)
        self.entry = {"id": message_id(message), "message": message, "carrier": ORIGIN,
                      "claims": [], "receivedAt": "2026-10-15T12:00:00Z"}
        self.transport = MigrationTransport(self.entry)
        self.agent = Agent(ORIGIN, self.key, ADDRESS)
        self.directory = tempfile.TemporaryDirectory(prefix="simon-gap-")
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name) / "home"
        self.home.mkdir()
        self.fetch_patch = mock.patch("simon.client.fetch", side_effect=self.transport.fetch)
        self.fetch_patch.start()
        self.addCleanup(self.fetch_patch.stop)

    def assert_gap(self, error):
        self.assertIsInstance(error, SimonError)
        self.assertEqual((error.status, error.code, error.retryable), (410, "token_expired", False))
        self.assertEqual(error.details, DETAILS)
        self.assertEqual(json.loads(json.dumps(error.to_json()))["error"]["details"], DETAILS)

    def test_sdk_surfaces_gap_once_then_explicit_since_reads_retained_history(self):
        with self.assertRaises(SimonError) as caught:
            self.agent.sync()
        self.assert_gap(caught.exception)
        self.assertEqual(len(self.transport.calls), 1, "the SDK did not automatically accept resumeToken")
        self.assertEqual(self.transport.calls[0][2], {})
        page = self.agent.sync(DETAILS["resumeToken"])
        self.assertEqual([e["id"] for e in page["messages"]], [self.entry["id"]])
        self.assertEqual(self.transport.calls[1][2], {"since": [RESUME]})
        with self.assertRaises(SimonError) as again:
            self.agent.sync()
        self.assert_gap(again.exception)
        self.assertEqual(len(self.transport.calls), 3, "initial requests remain explicit gap reports")

    def test_shared_wait_preserves_bytes_and_unmatched_buffer_on_gap(self):
        save_wait_state(self.home, {"token": None, "pending": [self.entry], "seen": ["e" * 64]})
        before = wait_file(self.home).read_bytes()
        with self.assertRaises(SimonError) as caught:
            wait_for_message(self.agent, self.home, sender="wanted@migration.test", timeout=60, interval=1,
                             sleep=lambda _: self.fail("a nonretryable gap must not sleep or retry"))
        self.assert_gap(caught.exception)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(wait_file(self.home).read_bytes(), before)
        self.assertFalse((self.home / "wait.lock").exists())
        buffered = wait_for_message(self.agent, self.home, timeout=0, interval=1)
        self.assertEqual(buffered.entry["id"], self.entry["id"])
        self.assertEqual(len(self.transport.calls), 1, "a buffered entry is shown without accepting the gap")
        self.assertIsNone(read_wait_state(self.home)["token"])

    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        environment = {"SIMON_HOME": str(self.home), "SIMON_WORKSPACE": self.directory.name,
                       "SIMON_PRIVATE_KEY": self.key.to_pem(), "SIMON_ADDRESS": ADDRESS,
                       "SIMON_SERVER": ORIGIN, "SIMON_ALLOW_PURE_SIGNING": "1"}
        with mock.patch.dict(os.environ, environment, clear=True), redirect_stdout(out), redirect_stderr(err):
            code = cli.main(args)
        return code, json.loads(out.getvalue()) if out.getvalue() else None, json.loads(err.getvalue()) if err.getvalue() else None

    def test_actual_cli_error_json_keeps_details_and_only_explicit_since_resumes(self):
        code, out, err = self.run_cli(["sync"])
        self.assertEqual((code, out), (1, None))
        self.assertEqual((err["error"]["status"], err["error"]["code"], err["error"]["retryable"]),
                         (410, "token_expired", False))
        self.assertEqual(err["error"]["details"], DETAILS)
        self.assertEqual(len(self.transport.calls), 1)
        code, out, err = self.run_cli(["sync", "--since", RESUME])
        self.assertEqual((code, err), (0, None))
        self.assertEqual([e["id"] for e in out["messages"]], [self.entry["id"]])
        self.assertEqual(self.transport.calls[1][2], {"since": [RESUME]})
        self.assertFalse(wait_file(self.home).exists(), "sync does not silently persist an acceptance for shared waits")

    def test_cli_wait_reports_gap_without_replacing_shared_pending_state(self):
        save_wait_state(self.home, {"token": None, "pending": [self.entry], "seen": []})
        before = wait_file(self.home).read_bytes()
        code, out, err = self.run_cli(["wait", "--from", "wanted@migration.test", "--timeout", "60", "--interval", "1"])
        self.assertEqual((code, out), (1, None))
        self.assertEqual(err["error"]["details"], DETAILS)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(wait_file(self.home).read_bytes(), before)
        self.assertFalse((self.home / "wait.lock").exists())


if __name__ == "__main__":
    unittest.main()
