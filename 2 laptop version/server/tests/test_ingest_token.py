"""The collector's loopback /ingest only accepts events carrying its bearer token."""
import http.server
import json
import threading
import unittest
import urllib.error
import urllib.request

from helpers import ROOT  # noqa: F401
from collector.collector import make_handler
from common.web import ingest_headers, token_ok


class FakeCollector:
    def __init__(self, token):
        self.cfg = {"ui_port": 0, "ingest_token": token}
        self.got = []

    def ingest(self, ev):
        self.got.append(ev)


class IngestToken(unittest.TestCase):
    def setUp(self):
        self.col = FakeCollector("s3cret-token")
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.col))
        self.col.cfg["ui_port"] = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.col.cfg['ui_port']}/ingest"

    def post(self, headers):
        req = urllib.request.Request(self.url, data=json.dumps([{"type": "log", "msg": "hi"}]).encode(),
                                     method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_right_token_accepted(self):
        self.assertEqual(self.post(ingest_headers("s3cret-token")), 202)
        self.assertEqual(len(self.col.got), 1)

    def test_missing_or_wrong_token_rejected(self):
        self.assertEqual(self.post(ingest_headers()), 401)
        self.assertEqual(self.post(ingest_headers("wrong")), 401)
        self.assertEqual(self.post({"Content-Type": "application/json", "Authorization": "s3cret-token"}), 401)
        self.assertEqual(self.col.got, [])

    def test_token_ok_rules(self):
        self.assertTrue(token_ok({}, None))                      # no token configured: open (old configs)
        self.assertTrue(token_ok({"Authorization": "Bearer t"}, "t"))
        self.assertFalse(token_ok({"Authorization": "Bearer t2"}, "t"))
        self.assertFalse(token_ok({}, "t"))


if __name__ == "__main__":
    unittest.main()
