"""HMAC request signing between collector and SaaS (common/util.py): tampering and replay."""
import time
import unittest

from helpers import ROOT  # noqa: F401
from common.util import SIG_SKEW_S, sign, verify_sig

SECRET = "a" * 64
PATH = "/r/eu-west/v1/ingest"
BODY = b'[{"payload_id": "p1"}]'


class Signing(unittest.TestCase):
    def check(self, ts, body=BODY, path=PATH, method="POST", secret=SECRET):
        return verify_sig(SECRET, method, path, body, str(ts), sign(secret, "POST", PATH, BODY, str(ts)))

    def test_valid_signature_accepted(self):
        self.assertEqual(self.check(int(time.time())), (True, "ok"))

    def test_tampered_request_rejected(self):
        now = int(time.time())
        self.assertEqual(self.check(now, body=BODY + b" "), (False, "bad signature"))
        self.assertEqual(self.check(now, path="/r/us-east/v1/ingest"), (False, "bad signature"))
        self.assertEqual(self.check(now, method="GET"), (False, "bad signature"))
        self.assertEqual(self.check(now, secret="b" * 64), (False, "bad signature"))

    def test_replay_window(self):
        now = int(time.time())
        self.assertTrue(self.check(now - SIG_SKEW_S + 5)[0])                 # inside the 5-minute window
        self.assertFalse(self.check(now - SIG_SKEW_S - 5)[0])                # old request replayed
        self.assertFalse(self.check(now + SIG_SKEW_S + 5)[0])                # timestamp from the future
        self.assertIn("replay", self.check(now - SIG_SKEW_S - 5)[1])

    def test_bad_timestamp(self):
        self.assertEqual(verify_sig(SECRET, "POST", PATH, BODY, "yesterday", "x"), (False, "bad timestamp"))
        self.assertEqual(verify_sig(SECRET, "POST", PATH, BODY, None, "x"), (False, "bad timestamp"))


if __name__ == "__main__":
    unittest.main()
