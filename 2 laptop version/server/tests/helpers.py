"""Shared fixtures: an isolated SaaS app (temp stores, in-memory registry) and payload builders."""
import hashlib
import os
import sys
import tempfile
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from common.util import iso, now_ms  # noqa: E402
from setup_env import DEFAULT_THRESHOLDS, HEALTH_SETTINGS, REGIONS  # noqa: E402

SITE_HOSTS = {
    "col-a1": ("blr", [("s-web1", "web", "checkout-web"), ("s-web2", "web", "checkout-web"),
                       ("s-api1", "app", "checkout-api"), ("s-db1", "db", "orders-db")]),
    "col-a2": ("fra", [("s-web3", "web", "checkout-web"), ("s-api2", "app", "checkout-api")]),
    "col-b1": ("nyc", [("s-app9", "app", "billing-app")]),
}


def registry():
    salt = "00" * 16
    pw = hashlib.pbkdf2_hmac("sha256", b"pw", bytes.fromhex(salt), 120_000).hex()
    return {
        "regions": REGIONS, "tls": False, "dashboard_port": 0, "ingest_port": 0,
        "tenants": {
            "acme": {"name": "Acme", "region": "eu-west", "thresholds": {k: list(v) for k, v in DEFAULT_THRESHOLDS.items()},
                     "health": dict(HEALTH_SETTINGS),
                     "dependencies": {"checkout-web": ["checkout-api"], "checkout-api": ["orders-db"]}},
            "globex": {"name": "Globex", "region": "us-east", "thresholds": {k: list(v) for k, v in DEFAULT_THRESHOLDS.items()},
                       "health": dict(HEALTH_SETTINGS), "dependencies": {}},
        },
        "collectors": {"col-a1": {"tenant_id": "acme", "secret": "a1", "site": "blr"},
                       "col-a2": {"tenant_id": "acme", "secret": "a2", "site": "fra"},
                       "col-b1": {"tenant_id": "globex", "secret": "b1", "site": "nyc"}},
        "users": {"admin": {"tenant_id": "acme", "role": "admin", "salt": salt, "pw_hash": pw},
                  "viewer": {"tenant_id": "acme", "role": "viewer", "salt": salt, "pw_hash": pw}},
    }


def make_app(test=None):
    from saas.server import App
    tmp = tempfile.mkdtemp(prefix="aiops-test-")
    app = App(reg=registry(), data_dir=tmp)
    if test is not None:
        test.addCleanup(app.stores.close)
    return app


class Feeder:
    """Builds allow-listed payloads for a collector, one window per call."""

    def __init__(self, app, cid):
        self.app, self.cid, self.seq = app, cid, 0
        self.site, self.hosts = SITE_HOSTS[cid]
        self.tenant = app.reg["collectors"][cid]["tenant_id"]

    def payload(self, ts_ms, values, events=(), pid=None):
        """values: {source_id: {metric: value}}"""
        self.seq += 1
        meta = {h: (r, s) for h, r, s in self.hosts}
        metrics = [{"source_id": sid, "ts": iso(ts_ms), "name": k, "avg": v, "min": v, "max": v, "n": 1}
                   for sid, ms in values.items() for k, v in ms.items()]
        srcs = sorted(set(values) | {e["source_id"] for e in events})
        return {"schema": "aiops.meta/v1", "payload_id": pid or str(uuid.uuid4()), "collector_id": self.cid,
                "seq": self.seq, "kind": "metrics", "created_at": iso(), "policy_version": "2026.11-v1",
                "window": {"start": iso(ts_ms), "end": iso(ts_ms + 1000)},
                "sources": [{"source_id": s, "role": meta[s][0], "service": meta[s][1], "site": self.site, "tz": "UTC"}
                            for s in srcs],
                "metrics": metrics, "events": list(events)}

    def send(self, ts_ms, values, events=()):
        return self.app.ingest(self.cid, self.tenant, [self.payload(ts_ms, values, events)])


def normal(i, base=30.0, wobble=1.5):
    """Deterministic 'noisy' normal value for window i."""
    return base + ((i * 7919) % 11 - 5) / 5 * wobble


def series_start(n):
    return now_ms() - n * 1000
