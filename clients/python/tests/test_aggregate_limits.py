"""Cross-language exact aggregate boundaries and repeated-hash declarations."""
import base64
import unittest

from simon.canonical import canonical_bytes
from simon.errors import SimonError
from simon.limits import MINIMUM_LIMITS
from simon.messages import check_message


def file(size, key):
    return {"type": "application/octet-stream", "sha256": f"{key:064x}", "size": size}


def message(parts):
    return {"v": 1, "from": "ada@example.com", "to": [], "inReplyTo": None,
            "parts": parts, "headers": {}, "sentAt": "2026-10-01T00:00:00Z", "signature": "AAAA"}


def carry(parts):
    return {"type": "application/simon-message",
            "data": base64.b64encode(canonical_bytes(message(parts))).decode("ascii")}


class AggregateLimits(unittest.TestCase):
    def test_exact_large_bound_and_one_over(self):
        part_bytes = 2**48
        limits = {**MINIMUM_LIMITS, "partBytes": part_bytes}
        inner = [file(part_bytes, i + 1) for i in range(32)]
        check_message(message([carry(inner)]), limits)
        with self.assertRaises(SimonError) as caught:
            check_message(message([file(1, 33), carry(inner)]), limits)
        self.assertEqual((caught.exception.status, caught.exception.details["field"]), (400, "parts"))

    def test_repeated_hashes_must_agree(self):
        check_message(message([file(0, 1), carry([file(0, 1)])]))
        for left, right in [(0, 1), (1, 2)]:
            with self.subTest(left=left, right=right), self.assertRaises(SimonError) as caught:
                check_message(message([file(left, 1), carry([file(right, 1)])]))
            self.assertEqual((caught.exception.status, caught.exception.details["field"]), (400, "parts"))

    def test_maximum_safe_individual_sizes(self):
        part_bytes = 2**53 - 1
        limits = {**MINIMUM_LIMITS, "partBytes": part_bytes}
        check_message(message([carry([file(part_bytes, i + 1) for i in range(32)])]), limits)
