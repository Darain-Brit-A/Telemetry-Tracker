import json
import os
import unittest

from helpers import Feeder, make_app
from common.util import dumps, now_ms, sha256_hex


class Ingest(unittest.TestCase):
    def setUp(self):
        self.app = make_app(self)
        self.f = Feeder(self.app, "col-a1")

    def test_accept_returns_receipt_digest(self):
        p = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        r = self.app.ingest("col-a1", "acme", [p])
        self.assertEqual(r["accepted"], [p["payload_id"]])
        self.assertEqual(r["receipts"][p["payload_id"]], sha256_hex(dumps(p)))

    def test_identical_retry_is_idempotent(self):
        p = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        self.app.ingest("col-a1", "acme", [p])
        r = self.app.ingest("col-a1", "acme", [p])
        self.assertEqual(r["duplicates"], [p["payload_id"]])
        st = self.app.stores.for_tenant("acme")
        self.assertEqual(st.q1("SELECT COUNT(*) FROM payloads")[0], 1)
        self.assertEqual(st.q1("SELECT COUNT(*) FROM metrics")[0], 1)

    def test_same_id_different_body_is_a_conflict(self):
        p = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        self.app.ingest("col-a1", "acme", [p])
        tampered = json.loads(json.dumps(p))
        tampered["metrics"][0]["avg"] = 99
        r = self.app.ingest("col-a1", "acme", [tampered])
        self.assertEqual(r["accepted"] + r["duplicates"], [])
        self.assertEqual(r["rejected"][0]["code"], 409)
        st = self.app.stores.for_tenant("acme")
        self.assertEqual(st.q1("SELECT avg FROM metrics")[0], 30)   # original data untouched

    def test_collector_cannot_claim_another_identity(self):
        p = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        r = self.app.ingest("col-a2", "acme", [p])
        self.assertIn("does not match credential", r["rejected"][0]["reason"])

    def test_non_allow_listed_field_rejected_not_repaired(self):
        p = self.f.payload(now_ms(), {"s-db1": {"cpu_pct": 30}})
        p["raw_log"] = "something local"
        r = self.app.ingest("col-a1", "acme", [p])
        self.assertTrue(r["rejected"][0]["reason"].startswith("policy violation"))

    def test_dlp_rejects_secret_in_context(self):
        ev = {"source_id": "s-db1", "ts": "2026-11-20T09:00:00.000Z", "category": "log.error_burst",
              "severity": "low", "count": 1, "context": "password=hunter22"}
        p = self.f.payload(now_ms(), {}, events=[ev])
        r = self.app.ingest("col-a1", "acme", [p])
        self.assertIn("DLP", r["rejected"][0]["reason"])

    def test_residency_each_tenant_in_its_own_region_store(self):
        Feeder(self.app, "col-a1").send(now_ms(), {"s-db1": {"cpu_pct": 30}})
        Feeder(self.app, "col-b1").send(now_ms(), {"s-app9": {"cpu_pct": 30}})
        eu = self.app.stores.by_region["eu-west"]
        us = self.app.stores.by_region["us-east"]
        self.assertEqual({r[0] for r in eu.q("SELECT DISTINCT tenant_id FROM payloads")}, {"acme"})
        self.assertEqual({r[0] for r in us.q("SELECT DISTINCT tenant_id FROM payloads")}, {"globex"})
        self.assertTrue(os.path.basename(eu.db.execute("PRAGMA database_list").fetchone()[2]).endswith("eu-west.db"))

    def test_late_partial_window_is_merged_not_duplicated(self):
        ts = now_ms() - 5000
        self.f.send(ts, {"s-db1": {"cpu_pct": 20}})
        self.f.send(ts, {"s-db1": {"cpu_pct": 40}})        # late partial aggregate, same window
        st = self.app.stores.for_tenant("acme")
        avg, n = st.q1("SELECT avg, n FROM metrics")
        self.assertEqual((avg, n), (30, 2))


if __name__ == "__main__":
    unittest.main()
