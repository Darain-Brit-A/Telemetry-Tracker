"""B2: one bad payload must not take the rest of its batch down, or block the collector's queue."""
import io
import json
import shutil
import tempfile
import unittest
import urllib.error

from helpers import Feeder, make_app
from common.util import dumps, iso, now_ms, sha256_hex
import collector.collector as colmod


class SaasIsolatesBadPayloads(unittest.TestCase):
    def setUp(self):
        self.app = make_app(self)
        self.f = Feeder(self.app, "col-a1")

    def test_malformed_timestamp_rejected_alone(self):
        good = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        bad = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 31}})
        bad["metrics"][0]["ts"] = "not-a-timestamp"
        r = self.app.ingest("col-a1", "acme", [good, bad])
        self.assertEqual(r["accepted"], [good["payload_id"]])
        self.assertEqual([x["id"] for x in r["rejected"]], [bad["payload_id"]])
        self.assertIn("timestamp", r["rejected"][0]["reason"])

    def test_non_numeric_value_rejected_alone(self):
        good = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        bad = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 31}})
        bad["metrics"][0]["avg"] = "high"
        r = self.app.ingest("col-a1", "acme", [bad, good])
        self.assertEqual(r["accepted"], [good["payload_id"]])
        self.assertEqual(len(r["rejected"]), 1)

    def test_unexpected_processing_error_rolls_back_only_that_payload(self):
        real = self.app.engine.on_point

        def boom(t, sid, name, ts, value):
            if sid == "s-api1":
                raise RuntimeError("simulated engine bug")
            return real(t, sid, name, ts, value)
        self.app.engine.on_point = boom
        good = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        bad = self.f.payload(now_ms(), {"s-api1": {"cpu_pct": 30}})
        r = self.app.ingest("col-a1", "acme", [bad, good])
        self.assertEqual(r["accepted"], [good["payload_id"]])
        self.assertIn("processing error", r["rejected"][0]["reason"])
        st = self.app.stores.for_tenant("acme")
        self.assertIsNone(st.q1("SELECT 1 FROM payloads WHERE payload_id=?", (bad["payload_id"],)))
        self.assertIsNone(st.q1("SELECT 1 FROM metrics WHERE source_id='s-api1'"))
        self.assertIsNotNone(st.q1("SELECT 1 FROM payloads WHERE payload_id=?", (good["payload_id"],)))


class CollectorQueueKeepsMoving(unittest.TestCase):
    """A SaaS that answers HTTP 400 for any batch containing one particular payload."""

    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        old = colmod.DATA_DIR
        colmod.DATA_DIR = tmp
        self.addCleanup(setattr, colmod, "DATA_DIR", old)
        cfg = {"collector_id": "col-t", "secret": "s", "pseudonym_salt": "00", "site": "x", "tz": "UTC",
               "saas_url": "https://saas.invalid", "ca_file": None, "ui_port": 0, "syslog_port": 0, "window_s": 1,
               "raw_retention_min": 60, "simulator_url": None, "hosts": {}, "auth_burst_threshold": 5}
        self.c = colmod.Collector(cfg)
        self.addCleanup(self.c.db.close)
        self.c.ingest_base = "https://saas.invalid/r/eu-west"
        self.c._request = self.fake_saas
        self.requests = []

    def fake_saas(self, method, url, body=b""):
        items = json.loads(body)
        self.requests.append([p["seq"] for p in items])
        if any(p["seq"] == 2 for p in items):
            raise urllib.error.HTTPError(url, 400, "bad request", {}, io.BytesIO(b'{"error":"bad request"}'))
        return {"accepted": [p["payload_id"] for p in items], "duplicates": [], "rejected": [],
                "receipts": {p["payload_id"]: sha256_hex(dumps(p)) for p in items}}

    def stage(self, seq):
        p = {"schema": "aiops.meta/v1", "payload_id": f"00000000-0000-4000-8000-00000000000{seq}",
             "collector_id": "col-t", "seq": seq, "kind": "metrics", "created_at": iso(),
             "policy_version": "2026.11-v1", "window": {"start": iso(), "end": iso()},
             "sources": [], "metrics": [], "events": []}
        self.c.stage(p, seq)

    def status(self):
        return dict(self.c.q("SELECT seq, status FROM egress ORDER BY seq"))

    def test_bad_payload_is_isolated_and_the_rest_delivered(self):
        for seq in (1, 2, 3):
            self.stage(seq)
        for _ in range(8):
            try:
                self.c.send_once()
            except urllib.error.HTTPError:
                pass
        self.assertEqual(self.status(), {1: "delivered", 2: "rejected", 3: "delivered"})


if __name__ == "__main__":
    unittest.main()
