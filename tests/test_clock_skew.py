"""B3: future-dated or offset-less timestamps must not make a source silently disappear."""
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from helpers import Feeder, make_app
from common.util import iso, now_ms
import collector.collector as colmod


def make_collector(test, tz="UTC"):
    tmp = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, tmp, True)
    old = colmod.DATA_DIR
    colmod.DATA_DIR = tmp
    test.addCleanup(setattr, colmod, "DATA_DIR", old)
    cfg = {"collector_id": "col-t", "secret": "s", "pseudonym_salt": "00", "site": "x", "tz": tz,
           "saas_url": "https://saas.invalid", "ca_file": None, "ui_port": 0, "syslog_port": 0, "window_s": 1,
           "raw_retention_min": 60, "simulator_url": None, "hosts": {}, "auth_burst_threshold": 5}
    c = colmod.Collector(cfg)
    test.addCleanup(c.db.close)
    return c


class FutureTimestamps(unittest.TestCase):
    def test_future_event_is_restamped_and_flagged(self):
        c = make_collector(self)
        c.ingest({"type": "metric", "host": "dev-1", "ts": iso(now_ms() + 3600_000), "metrics": {"cpu_pct": 40}})
        self.assertTrue(c.windows, "the reading must be kept")
        self.assertLessEqual(max(c.windows), now_ms() + 1000, "window must be near now, not an hour ahead")
        skew = [e for e in c.pending_events if e["category"] == "source.clock_skew"]
        self.assertEqual(len(skew), 1)
        self.assertIn("ahead", skew[0]["context"])

    def test_small_jitter_is_left_alone(self):
        c = make_collector(self)
        c.ingest({"type": "metric", "host": "dev-1", "ts": iso(now_ms() + 2000), "metrics": {"cpu_pct": 40}})
        self.assertFalse([e for e in c.pending_events if e["category"] == "source.clock_skew"])

    def test_offsetless_timestamp_uses_collector_timezone(self):
        c = make_collector(self, tz="Asia/Kolkata")
        local = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%dT%H:%M:%S")
        c.ingest({"type": "metric", "host": "dev-2", "ts": local, "metrics": {"cpu_pct": 40}})
        self.assertLessEqual(abs(max(c.windows) - now_ms()), 3000)
        self.assertFalse([e for e in c.pending_events if e["category"] == "source.clock_skew"])


class SaasAcceptsSkewEvent(unittest.TestCase):
    def test_clock_skew_event_passes_allow_list_and_is_explained(self):
        app = make_app(self)
        ev = {"source_id": "s-web1", "ts": iso(), "category": "source.clock_skew", "severity": "low", "count": 3,
              "context": "source clock ahead by 3600s; 3 readings re-stamped with collector receive time"}
        r = Feeder(app, "col-a1").send(now_ms(), {}, events=[ev])
        self.assertEqual(r["rejected"], [])
        app.engine._incidents("acme")
        inc = app.stores.for_tenant("acme").rows("SELECT title FROM incidents WHERE tenant_id='acme'")
        self.assertTrue(inc and "clock" in inc[0]["title"].lower())


if __name__ == "__main__":
    unittest.main()
