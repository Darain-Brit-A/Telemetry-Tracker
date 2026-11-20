"""Collector egress hardening: redirects from the SaaS are refused, and log-template fingerprints
are keyed with the collector's salt (a plain hash would let the SaaS confirm a guessed template)."""
import hashlib
import http.server
import shutil
import tempfile
import threading
import unittest
import urllib.error

from helpers import ROOT  # noqa: F401
import collector.collector as colmod

HITS = []


class Redirector(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append(self.path)
        if self.path.startswith("/elsewhere"):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        self.send_response(302)
        self.send_header("Location", "/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def make_collector(test, salt="00"):
    tmp = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, tmp, True)
    old = colmod.DATA_DIR
    colmod.DATA_DIR = tmp
    test.addCleanup(setattr, colmod, "DATA_DIR", old)
    cfg = {"collector_id": "col-t", "secret": "s", "pseudonym_salt": salt, "site": "x", "tz": "UTC",
           "saas_url": "http://127.0.0.1:1", "ca_file": None, "ui_port": 0, "syslog_port": 0, "window_s": 1,
           "raw_retention_min": 60, "simulator_url": None, "hosts": {}, "auth_burst_threshold": 5}
    c = colmod.Collector(cfg)
    test.addCleanup(c.db.close)
    return c


class RedirectRefused(unittest.TestCase):
    def test_3xx_is_an_error_and_not_followed(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = make_collector(self)
        HITS.clear()
        with self.assertRaises(urllib.error.HTTPError) as cm:
            c._request("GET", f"http://127.0.0.1:{srv.server_address[1]}/v1/discover")
        self.assertEqual(cm.exception.code, 302)
        self.assertEqual(HITS, ["/v1/discover"])          # /elsewhere never requested


class KeyedFingerprint(unittest.TestCase):
    LINES = ("payment gateway timeout after 3000 ms", "payment gateway timeout after 4120 ms")

    def fingerprints(self, salt):
        c = make_collector(self, salt)
        for line in self.LINES:
            c._log("web-01", colmod.now_ms(), "ERROR", line)
        return {fp for _, _, fp in c.logs["web-01"]}       # deque of (ts, level, fingerprint)

    def test_fingerprint_depends_on_salt_and_is_not_plain_hash(self):
        plain = "fp-" + hashlib.sha256(colmod.template_of(self.LINES[0]).encode()).hexdigest()[:8]
        fpa, fpb = self.fingerprints("salt-a"), self.fingerprints("salt-b")
        self.assertEqual(len(fpa), 1)                 # same template -> same fingerprint within a collector
        self.assertNotEqual(fpa, fpb)                 # but different across salts
        self.assertNotIn(plain, fpa | fpb)


if __name__ == "__main__":
    unittest.main()
