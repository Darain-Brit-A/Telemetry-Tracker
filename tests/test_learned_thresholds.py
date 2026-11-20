"""Learned (ML) health limits: per-source limits from the baseline, with the manual Poor value kept as a
hard safety limit, and threshold alerts in learned mode only from that safety limit."""
import random
import unittest

from helpers import make_app
from common.util import now_ms

T, CPU = "acme", "cpu_pct"           # default cpu limits: Excellent < 60, Good < 80, Fair < 92, else Poor


class LearnedThresholds(unittest.TestCase):
    def setUp(self):
        random.seed(3)
        self.app = make_app(self)
        self.eng = self.app.engine
        self.t0 = now_ms() - 600_000

    def learned(self, on=True):
        self.app.reg["tenants"][T]["threshold_modes"] = {CPU: "learned" if on else "manual"}

    def feed(self, sid, values, start=0):
        for i, v in enumerate(values):
            self.eng.on_point(T, sid, CPU, self.t0 + (start + i) * 1000, v)
        return start + len(values)

    def level(self, sid, value):
        return self.eng.threshold_level(T, CPU, self.eng.series.get((T, sid, CPU)), value)

    def open_alerts(self, sid):
        st = self.app.stores.for_tenant(T)
        return {(r["signal"], r["kind"]) for r in st.rows(
            "SELECT signal, kind FROM alerts WHERE tenant_id=? AND source_id=? AND status='open'", (T, sid))}

    def steady(self, base, n=60):
        return [base + random.uniform(-1.5, 1.5) for _ in range(n)]

    def test_busy_but_normal_source_is_fair_manually_and_excellent_learned(self):
        # a database that always runs at ~88% CPU
        self.learned(False)
        self.feed("db", self.steady(88))
        self.assertEqual(self.level("db", 88)[0], 2)                   # manual: Fair
        self.assertIn((CPU, "threshold"), self.open_alerts("db"))      # and a standing threshold alert
        self.learned()
        lvl, alert, shown, mode = self.level("db", 88)
        self.assertEqual((lvl, alert, mode), (0, 0, "learned"))        # learned: normal for this source
        self.assertEqual(len(shown), 4)                                # 3 learned limits + safety limit
        self.assertLess(shown[0], shown[1])
        self.assertLess(shown[1], shown[2])

    def test_learned_limits_follow_each_source(self):
        self.learned()
        self.feed("web", self.steady(30))
        self.feed("db", self.steady(70))
        web, db = self.eng.series[(T, "web", CPU)].learned, self.eng.series[(T, "db", CPU)].learned
        self.assertLess(web[2], db[0])                                 # web's Poor line is below db's normal
        self.assertEqual(self.level("web", 70)[0], 3)                  # 70% is Poor for web ...
        self.assertEqual(self.level("db", 70)[0], 0)                   # ... and Excellent for db

    def test_deviation_graded_but_alerted_by_anomaly_detector_not_threshold(self):
        self.learned()
        n = self.feed("web", self.steady(30))
        self.feed("web", [72] * 6, n)                                  # well above web's baseline, below 92
        lvl, alert, _, _ = self.level("web", 72)
        self.assertEqual((lvl, alert), (3, 0))                         # health Poor, no threshold alert
        kinds = {k for s, k in self.open_alerts("web") if s == CPU}
        self.assertEqual(kinds, {"anomaly"})

    def test_safety_limit_always_applies(self):
        self.learned()
        n = self.feed("db", self.steady(88))
        self.assertEqual(self.level("db", 95)[:2], (3, 3))             # at/above Fair< (92): Poor + alert
        self.feed("db", [95, 95, 95], n)
        self.assertTrue(any(k in ("threshold", "anomaly+threshold") for s, k in self.open_alerts("db") if s == CPU))

    def test_manual_limits_until_baseline_exists(self):
        self.learned()
        self.feed("new", self.steady(88, n=5))
        lvl, alert, shown, mode = self.level("new", 88)
        self.assertEqual((lvl, alert, mode), (2, 2, "manual (learning baseline)"))
        self.assertEqual(shown, [60, 80, 92])

    def test_learned_is_the_default(self):
        self.app.reg["tenants"][T].pop("threshold_modes", None)
        self.feed("db", self.steady(88))
        self.assertEqual(self.level("db", 88)[3], "learned")
        self.assertNotIn((CPU, "threshold"), self.open_alerts("db"))

    def test_config_api_validates_modes(self):
        admin = {"username": "a", "role": "admin", "tenant_id": T}
        viewer = {"username": "v", "role": "viewer", "tenant_id": T}
        self.assertEqual(self.app.update_config(viewer, {"threshold_modes": {CPU: "learned"}})[0], 403)
        self.app.update_config(admin, {"threshold_modes": {CPU: "learned", "mem_pct": "bogus", "nope": "learned"}})
        modes = self.app.reg["tenants"][T]["threshold_modes"]
        self.assertEqual(modes, {CPU: "learned"})


if __name__ == "__main__":
    unittest.main()
