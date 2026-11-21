"""B5: proof-panel searches must treat % and _ literally, or they report leaks that did not happen."""
import shutil
import tempfile
import unittest

from helpers import Feeder, make_app
from common.util import now_ms
import collector.collector as colmod


class SaasSearch(unittest.TestCase):
    def test_wildcards_are_literal(self):
        app = make_app(self)
        Feeder(app, "col-a1").send(now_ms(), {"s-db1": {"cpu_pct": 30}})      # payload bodies contain '_'
        self.assertGreater(app.search_metadata("acme", "cpu_pct")["payload_matches"], 0)   # real underscore
        # '%' never occurs in a payload; 'pay_oad_id' only matches 'payload_id' if '_' is a wildcard
        for term in ("%", "a%b", "pay_oad_id"):
            self.assertEqual(app.search_metadata("acme", term)["payload_matches"], 0, term)


class CollectorSearch(unittest.TestCase):
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

    def test_secret_found_locally_and_wildcards_literal(self):
        self.c.ingest({"type": "log", "host": "web-01", "level": "ERROR",
                       "message": "login failed password=Sup3rS3cret! for svc_app"})
        r = self.c.search("Sup3rS3cret")
        self.assertEqual((r["raw_matches_local"], r["egress_matches"]), (1, 0))
        self.assertEqual(self.c.search("_")["raw_matches_local"], 1)     # 'svc_app' really contains '_'
        self.assertEqual(self.c.search("%")["raw_matches_local"], 0)
        self.assertEqual(self.c.search("%")["egress_matches"], 0)


if __name__ == "__main__":
    unittest.main()
