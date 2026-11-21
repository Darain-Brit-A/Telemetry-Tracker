"""Site restrictions on the data allow-list: a customer can make it stricter for its own collector,
never wider, and the SaaS keeps accepting the smaller payloads under the unchanged shared policy."""
import json
import os
import shutil
import tempfile
import unittest

from helpers import ROOT  # noqa: F401
import collector.collector as colmod
from common.policy import load_policy, restricted_policy, restriction_error, validate_inbound
from common.util import now_ms


class Rules(unittest.TestCase):
    def setUp(self):
        self.base = load_policy()

    def test_only_tightens(self):
        metric = self.base["metric_names"][0]
        p = restricted_policy(self.base, {"metric_names": [metric, "made_up_metric"], "policy_version": ["x"]})
        self.assertNotIn(metric, p["metric_names"])
        self.assertNotIn("made_up_metric", p["metric_names"])       # an unknown name is ignored, never added
        self.assertEqual(p["policy_version"], self.base["policy_version"])
        self.assertEqual(len(p["metric_names"]), len(self.base["metric_names"]) - 1)

    def test_refuses_widening_and_required_fields(self):
        self.assertIn("widening", restriction_error(self.base, "metric_names", "made_up_metric"))
        self.assertIn("required", restriction_error(self.base, "event_fields", "severity"))
        self.assertIn("required", restriction_error(self.base, "source_fields", "source_id"))
        self.assertIsNotNone(restriction_error(self.base, "severities", "info"))
        self.assertIsNone(restriction_error(self.base, "metric_names", self.base["metric_names"][0]))


class OnCollector(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        old = colmod.DATA_DIR
        colmod.DATA_DIR = tmp
        self.addCleanup(setattr, colmod, "DATA_DIR", old)
        self.cfg_path = os.path.join(tmp, "col.json")
        cfg = {"collector_id": "col-t", "secret": "s", "pseudonym_salt": "00", "site": "Test", "tz": "UTC",
               "saas_url": "https://saas.invalid", "ca_file": None, "ui_port": 0, "syslog_port": 0, "window_s": 1,
               "raw_retention_min": 60, "simulator_url": None, "hosts": {}, "auth_burst_threshold": 5}
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        self.c = colmod.Collector(cfg)
        self.c.cfg_path = self.cfg_path
        self.addCleanup(self.c.db.close)

    def payload(self):
        self.c.ingest({"type": "metric", "host": "web-01", "role": "web", "service": "shop",
                       "ts": colmod.iso(now_ms() - 5000), "metrics": {"cpu_pct": 40.0, "mem_pct": 55.0}})
        wins = {s: self.c.windows.pop(s) for s in list(self.c.windows)}
        self.c.build_payload(wins, [], 1000)
        row = self.c.q("SELECT body, dropped FROM egress ORDER BY rowid DESC LIMIT 1")[0]
        return json.loads(row[0]), json.loads(row[1] or "[]")

    def test_withheld_metric_never_leaves_and_saas_still_accepts(self):
        before = self.c.config_hash
        self.assertIsNone(self.c.set_allowed("metric_names", "mem_pct", False))
        self.assertNotEqual(self.c.config_hash, before)                  # the heartbeat shows the change
        body, dropped = self.payload()
        self.assertNotIn("mem_pct", json.dumps(body))
        self.assertIn("cpu_pct", json.dumps(body))
        self.assertIn("metrics 'mem_pct' (not allow-listed)", dropped)
        self.assertEqual(validate_inbound(body, load_policy()), [])      # SaaS: unchanged policy, no rejection

    def test_persisted_audited_and_reversible(self):
        self.c.set_allowed("metric_names", "mem_pct", False)
        with open(self.cfg_path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["policy_restrictions"], {"metric_names": ["mem_pct"]})
        self.assertIn("withheld", self.c.q("SELECT detail FROM local_audit ORDER BY rowid DESC LIMIT 1")[0][0])
        items = {i["name"]: i for g in self.c.allow_list()["groups"] for i in g["items"]}
        self.assertFalse(items["mem_pct"]["allowed"])
        self.assertTrue(items["source_id"]["locked"])
        self.c.set_allowed("metric_names", "mem_pct", True)
        self.assertIn("mem_pct", self.c.policy["metric_names"])
        self.assertEqual(self.c.allow_list()["withheld"], 0)

    def test_lists_the_metrics_the_source_sends(self):
        self.c.ingest({"type": "metric", "host": "silk-board", "role": "air-monitor", "service": "Silk Board",
                       "ts": colmod.iso(now_ms() - 5000),
                       "metrics": {"pm25_ugm3": 91.0, "pm10_ugm3": 150.0, "no2_ugm3": 40.0}})
        self.c.set_allowed("metric_names", "cpu_pct", False)            # withheld items always stay visible
        metrics = self.c.allow_list()["groups"][0]
        self.assertEqual([i["name"] for i in metrics["items"]], ["cpu_pct", "pm25_ugm3", "pm10_ugm3", "no2_ugm3"])
        self.assertIn("mem_pct", metrics["other"])
        self.c.seen_metrics.clear()                                       # after a restart: from the raw store
        self.assertEqual(self.c.received_metrics(), {"pm25_ugm3", "pm10_ugm3", "no2_ugm3"})

    def test_cannot_widen_through_the_api(self):
        self.assertIsNotNone(self.c.set_allowed("metric_names", "gps_lat", True))
        self.assertIsNotNone(self.c.set_allowed("event_fields", "ts", False))
        self.assertNotIn("gps_lat", self.c.policy["metric_names"])
        self.assertIn("ts", self.c.policy["event_fields"])


if __name__ == "__main__":
    unittest.main()
