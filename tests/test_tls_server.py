"""B1: a client that connects and never starts the TLS handshake must not block other clients."""
import http.server
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request

from helpers import ROOT  # noqa: F401
from common.tlsserver import build_tls_server


class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@unittest.skipUnless(shutil.which("openssl"), "openssl needed to create a test certificate")
class IdleClientDoesNotBlock(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                        "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self.srv = build_tls_server(("127.0.0.1", 0), Hello, ctx)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = f"https://127.0.0.1:{self.srv.server_address[1]}/"
        self.client = ssl.create_default_context()
        self.client.check_hostname = False
        self.client.verify_mode = ssl.CERT_NONE

    def get(self):
        t = time.time()
        with urllib.request.urlopen(self.url, context=self.client, timeout=4) as r:
            return r.read(), time.time() - t

    def test_idle_tcp_client(self):
        self.assertEqual(self.get()[0], b"ok")
        idle = socket.create_connection(self.srv.server_address)   # never sends a ClientHello
        self.addCleanup(idle.close)
        time.sleep(0.3)
        body, took = self.get()
        self.assertEqual(body, b"ok")
        self.assertLess(took, 1.0)


if __name__ == "__main__":
    unittest.main()
