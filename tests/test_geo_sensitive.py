"""Demo of a sensitive telemetry field: an air-quality monitor's exact GPS position travels in the raw event
to the collector, is kept and redacted locally, and never reaches the SaaS."""
import json
import shutil
import tempfile
import unittest

from helpers import ROOT  # noqa: F401
import collector.collector as colmod
from common.policy import dlp_scan, redact_text
from common.util import now_ms, parse_iso
from tools.openaq_poller import to_events

LAT, LON = 12.917348, 77.622813


class GeoLocation(unittest.TestCase):
    def test_redacted_and_flagged_by_outbound_scan(self):
        raw = json.dumps({"host": "silk-board", "location": {"latitude": LAT, "longitude": LON}})
        red, findings = redact_text(raw)
        self.assertEqual(findings.count("geo_location"), 2)
        self.assertNotIn(str(LAT), red)
        self.assertIn("[REDACTED:geo]", red)
        self.assertIn("geo_location", dlp_scan(raw))                    # would block an outbound payload
        self.assertEqual(redact_text('{"cpu_pct": 12.5, "pm25_ugm3": 91.0}')[1], [])   # ordinary values untouched

    def test_poller_attaches_position_to_raw_events(self):
        ts = parse_iso("2026-11-20T17:30:00Z")
        [ev] = to_events("silk-board", {"service": "Silk Board"}, {"pm25_ugm3": [(ts, 91.0)]},
                         {"latitude": LAT, "longitude": LON})
        self.assertEqual(ev["location"], {"latitude": LAT, "longitude": LON})
        self.assertNotIn("location", to_events("x", {}, {"pm25_ugm3": [(ts, 1.0)]})[0])

    def test_kept_on_collector_never_in_outbound_payload(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        old = colmod.DATA_DIR
        colmod.DATA_DIR = tmp
        self.addCleanup(setattr, colmod, "DATA_DIR", old)
        cfg = {"collector_id": "col-air", "secret": "s", "pseudonym_salt": "00", "site": "Bengaluru", "tz": "UTC",
               "saas_url": "https://saas.invalid", "ca_file": None, "ui_port": 0, "syslog_port": 0, "window_s": 1,
               "raw_retention_min": 60, "simulator_url": None, "hosts": {}, "auth_burst_threshold": 5}
        c = colmod.Collector(cfg)
        self.addCleanup(c.db.close)
        c.ingest({"type": "metric", "host": "silk-board", "role": "air-monitor", "service": "Silk Board",
                  "ts": colmod.iso(now_ms() - 5000), "metrics": {"pm25_ugm3": 91.0},
                  "location": {"latitude": LAT, "longitude": LON}})
        wins = {s: c.windows.pop(s) for s in list(c.windows)}
        c.build_payload(wins, [], 1000)                                  # what would be sent to the SaaS
        r = c.search(str(LAT))
        self.assertEqual(r["raw_matches_local"], 1)                       # kept locally
        self.assertEqual(r["egress_matches"], 0)                          # never in a payload
        body = c.q("SELECT body FROM egress")[0][0]
        self.assertIn("pm25_ugm3", body)                                  # the reading itself does go
        self.assertNotIn(str(LAT), body)
        self.assertNotIn("latitude", body)
        self.assertIn("geo_location", c.q("SELECT findings FROM raw_events")[0][0])


if __name__ == "__main__":
    unittest.main()
