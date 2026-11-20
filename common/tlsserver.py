"""TLS HTTP server used by the SaaS ingest endpoint.

The TLS handshake must not run inside accept(): the server has a single accept thread, so one
client that connects and never sends a ClientHello would block every other collector (bug B1).
Here the listening socket stays plain; each accepted connection gets its own thread, and the
handshake happens there with a timeout.

It also holds the TLS settings both tiers share, so the SaaS, the collector, the tools and the
tests cannot drift apart: TLS 1.3 only, and (when enabled) mutual TLS, where the SaaS requires a
client certificate issued by the private CA and pins its SHA-256 fingerprint per collector.
"""
import hashlib
import http.server
import ssl

HANDSHAKE_TIMEOUT_S = 10


class TLSThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256

    def __init__(self, addr, handler, ssl_context, handshake_timeout=HANDSHAKE_TIMEOUT_S):
        self.ssl_context = ssl_context
        self.handshake_timeout = handshake_timeout
        super().__init__(addr, handler)

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(self.handshake_timeout)
            request = self.ssl_context.wrap_socket(request, server_side=True)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)       # idle, slow or non-TLS client: drop only this one
            return
        super().process_request_thread(request, client_address)


def build_tls_server(addr, handler, ssl_context):
    return TLSThreadingHTTPServer(addr, handler, ssl_context)


def server_context(cert_file, key_file, client_ca_file=None):
    """TLS 1.3 server context; with `client_ca_file`, a client certificate from that CA is required."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_file, key_file)
    if client_ca_file:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=client_ca_file)
    return ctx


def client_context(ca_file, cert_file=None, key_file=None):
    """TLS 1.3 client context that trusts only the private CA (hostname checked) and, for mutual TLS,
    presents the collector's own certificate."""
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cert_file:
        ctx.load_cert_chain(cert_file, key_file)
    return ctx


def fingerprint_der(der):
    """Lowercase, colon-free SHA-256 of a DER certificate: the value enrolled in `cert_fingerprints`."""
    return hashlib.sha256(der).hexdigest()


def fingerprint_file(pem_path):
    with open(pem_path, encoding="ascii") as f:
        return fingerprint_der(ssl.PEM_cert_to_DER_cert(f.read()))


def peer_fingerprint(sock):
    """Fingerprint of the verified client certificate on an accepted connection, or None."""
    try:
        der = sock.getpeercert(binary_form=True)
    except (AttributeError, ValueError, ssl.SSLError):
        return None
    return fingerprint_der(der) if der else None
