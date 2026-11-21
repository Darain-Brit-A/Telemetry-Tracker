"""B6: a source that reports only bandwidth must count as fresh, not 'no data'."""
import unittest

from helpers import Feeder, make_app
from common.util import now_ms


class Freshness(unittest.TestCase):
    def test_bandwidth_only_source_is_fresh(self):
        app = make_app(self)
        f = Feeder(app, "col-a1")
        t0 = now_ms() - 10_000
        for i in range(10):
            f.send(t0 + i * 1000, {"s-web1": {"bw_in_mbps": 100 + i, "bw_out_mbps": 50}})
        app.engine.tick()
        state, reason = app.engine.health[("acme", "s-web1")]
        self.assertNotEqual(state, "Poor", reason)
        self.assertNotIn("no data", reason)
        stale = app.stores.for_tenant("acme").q1(
            "SELECT COUNT(*) FROM alerts WHERE akey='s-web1:data.stale' AND status='open'")[0]
        self.assertEqual(stale, 0)

    def test_silent_source_still_goes_stale(self):
        app = make_app(self)
        f = Feeder(app, "col-a1")
        old = now_ms() - 120_000
        for i in range(5):
            f.send(old + i * 1000, {"s-web1": {"bw_in_mbps": 100}})
        app.engine.tick()
        self.assertEqual(app.engine.health[("acme", "s-web1")][0], "Poor")


if __name__ == "__main__":
    unittest.main()
