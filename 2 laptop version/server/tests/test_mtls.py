"""Mutual TLS 1.3 settings shared by the SaaS and the collector (common/tlsserver.py).

A throwaway CA issues a server certificate and two client certificates. The server built with
server_context() must accept only TLS 1.3 clients that present a certificate from that CA, and
peer_fingerprint() must report exactly the fingerprint that setup_env.py enrols.
"""
import http.server
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from helpers import ROOT  # noqa: F401
from common.tlsserver import build_tls_server, client_context, fingerprint_file, peer_fingerprint, server_context
from setup_env import CLIENT_EXT, SERVER_EXT

SEEN = []


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN.append(peer_fingerprint(self.connection))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@unittest.skipUnless(shutil.which("openssl"), "openssl needed to create test certificates")
class MutualTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = cls.d = tempfile.mkdtemp()

        def run(*a):
            subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=d)

        def ext(name, text):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
            return name

        def issue(name, subj, extfile, ca="ca"):
            run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", subj)
            run("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.crt", "-CAkey", f"{ca}.key", "-CAcreateserial",
                "-out", f"{name}.crt", "-days", "1", "-extfile", extfile)

        for ca in ("ca", "other-ca"):
            run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{ca}.key", "-out", f"{ca}.crt",
                "-days", "1", "-subj", f"/CN=Test {ca}", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
        issue("server", "/CN=localhost", ext("server.ext", SERVER_EXT))
        cext = ext("client.ext", CLIENT_EXT)
        issue("col-a", "/CN=col-a", cext)
        issue("col-b", "/CN=col-b", cext)
        issue("rogue", "/CN=col-a", cext, ca="other-ca")     # right name, wrong CA

        def p(f):
            return os.path.join(d, f)
        cls.p = staticmethod(p)
        cls.srv = build_tls_server(("127.0.0.1", 0), Echo, server_context(p("server.crt"), p("server.key"), p("ca.crt")))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"https://localhost:{cls.srv.server_address[1]}/"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.d, True)

    def get(self, ctx):
        with urllib.request.urlopen(self.url, context=ctx, timeout=4) as r:
            return r.read()

    def client(self, name=None):
        p = self.p
        return client_context(p("ca.crt"), p(f"{name}.crt") if name else None, p(f"{name}.key") if name else None)

    def assertRejected(self, ctx):
        with self.assertRaises((urllib.error.URLError, ssl.SSLError, ConnectionError, OSError)):
            self.get(ctx)

    def test_enrolled_client_accepted_and_fingerprint_matches(self):
        SEEN.clear()
        self.assertEqual(self.get(self.client("col-a")), b"ok")
        self.assertEqual(SEEN, [fingerprint_file(self.p("col-a.crt"))])
        self.assertNotEqual(fingerprint_file(self.p("col-a.crt")), fingerprint_file(self.p("col-b.crt")))

    def test_client_without_certificate_rejected(self):
        self.assertRejected(self.client())

    def test_certificate_from_another_ca_rejected(self):
        self.assertRejected(self.client("rogue"))

    def test_tls12_client_rejected(self):
        ctx = self.client("col-a")
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.assertRejected(ctx)

    def test_client_refuses_server_outside_private_ca(self):
        ctx = client_context(self.p("other-ca.crt"), self.p("col-a.crt"), self.p("col-a.key"))
        self.assertRejected(ctx)


if __name__ == "__main__":
    unittest.main()
