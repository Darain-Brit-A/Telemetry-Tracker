"""TLS HTTP server used by the SaaS ingest endpoint.

The TLS handshake must not run inside accept(): the server has a single accept thread, so one
client that connects and never sends a ClientHello would block every other collector (bug B1).
Here the listening socket stays plain; each accepted connection gets its own thread, and the
handshake happens there with a timeout.
"""
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
