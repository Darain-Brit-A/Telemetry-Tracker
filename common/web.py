"""Browser-facing hardening shared by the SaaS dashboard and the collector console.

* Host check   - only answer requests addressed to localhost / 127.0.0.1 on our own port, which
                 defeats DNS-rebinding attacks against these loopback consoles.
* Origin check - state-changing requests must come from our own page (or a non-browser client).
* Headers      - strict Content-Security-Policy (no inline script), no framing, no sniffing,
                 no referrer leakage.
"""

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                                "frame-ancestors 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def allowed_hosts(port):
    return {f"localhost:{port}", f"127.0.0.1:{port}"}


def host_ok(headers, port):
    return (headers.get("Host") or "").lower() in allowed_hosts(port)


def origin_ok(headers, port):
    origin = headers.get("Origin")
    if origin is None:          # curl, scripts, same-origin GETs
        return True
    return origin.lower() in {f"http://{h}" for h in allowed_hosts(port)}
