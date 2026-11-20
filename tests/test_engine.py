import json
import unittest

from helpers import Feeder, make_app, normal, series_start
from saas.aiops import MIN_BASELINE, PERSIST


def open_alerts(app, tenant="acme"):
    return app.stores.for_tenant(tenant).rows("SELECT * FROM alerts WHERE tenant_id=? AND status='open'", (tenant,))


def incidents(app, tenant="acme"):
    st = app.stores.for_tenant(tenant)
    app.engine._incidents(tenant)
    out = st.rows("SELECT * FROM incidents WHERE tenant_id=? AND status='open'", (tenant,))
    for i in out:
        i["analysis"] = json.loads(i["analysis"] or "{}")
    return out


class Detection(unittest.TestCase):
    def setUp(self):
        self.app = make_app(self)
        self.f = Feeder(self.app, "col-a1")
        self.t0 = series_start(120)

    def warm(self, n=60, **extra):
        for i in range(n):
            vals = {"s-db1": {"cpu_pct": normal(i)}}
            for sid, fn in extra.items():
                vals[sid] = fn(i)
            self.f.send(self.t0 + i * 1000, vals)
        return n

    def test_steady_noise_never_alerts(self):
        self.warm(90)
        self.assertEqual(open_alerts(self.app), [])

    def test_spike_needs_persistence_then_alerts_with_evidence(self):
        n = self.warm(60)
        for k in range(PERSIST - 1):
            self.f.send(self.t0 + (n + k) * 1000, {"s-db1": {"cpu_pct": 75}})
        self.assertEqual(open_alerts(self.app), [], "must not alert before the persistence filter is met")
        self.f.send(self.t0 + (n + PERSIST - 1) * 1000, {"s-db1": {"cpu_pct": 75}})
        a = open_alerts(self.app)
        self.assertEqual(len(a), 1)
        d = json.loads(a[0]["detail"])
        self.assertAlmostEqual(d["baseline"], 30, delta=2)
        self.assertGreater(d["z"], 4)

    def test_no_anomaly_alert_during_warm_up(self):
        warm = MIN_BASELINE - PERSIST - 1
        for i in range(warm):
            self.f.send(self.t0 + i * 1000, {"s-db1": {"cpu_pct": normal(i)}})
        for k in range(PERSIST):      # deviation arrives while the baseline is still unarmed
            self.f.send(self.t0 + (warm + k) * 1000, {"s-db1": {"cpu_pct": 70}})
        self.assertEqual(open_alerts(self.app), [])

    def test_sustained_fault_does_not_become_the_new_normal(self):
        n = self.warm(60)
        for k in range(40):
            self.f.send(self.t0 + (n + k) * 1000, {"s-db1": {"cpu_pct": 75}})
        a = open_alerts(self.app)
        self.assertEqual(len(a), 1)
        self.assertAlmostEqual(json.loads(a[0]["detail"])["baseline"], 30, delta=2)

    def test_poor_threshold_needs_two_windows_not_one_blip(self):
        n = self.warm(30)
        self.f.send(self.t0 + n * 1000, {"s-db1": {"cpu_pct": 96}})
        self.assertEqual(open_alerts(self.app), [], "a single 1 s blip must not page anyone")
        self.f.send(self.t0 + (n + 1) * 1000, {"s-db1": {"cpu_pct": 96}})
        a = open_alerts(self.app)
        self.assertEqual(a[0]["severity"], "critical")

    def test_late_point_does_not_move_detector(self):
        n = self.warm(40)
        self.f.send(self.t0 + 5 * 1000 + 300, {"s-db1": {"cpu_pct": 99}})     # very late, very high
        self.assertEqual(open_alerts(self.app), [])
        late = self.app.stores.for_tenant("acme").counters("acme").get("delivery", {}).get("late_points", 0)
        self.assertEqual(late, 1)
        self.assertGreater(n, 0)


class Correlation(unittest.TestCase):
    def setUp(self):
        self.app = make_app(self)
        self.a1 = Feeder(self.app, "col-a1")
        self.a2 = Feeder(self.app, "col-a2")
        self.t0 = series_start(140)

    def baseline(self, n=60):
        for i in range(n):
            self.a1.send(self.t0 + i * 1000, {"s-db1": {"cpu_pct": normal(i), "latency_ms": normal(i, 8, 1)},
                                              "s-web1": {"latency_ms": normal(i, 22, 1.5), "cpu_pct": normal(i, 32)},
                                              "s-api1": {"latency_ms": normal(i, 28, 1.5)}})
            self.a2.send(self.t0 + i * 1000, {"s-web3": {"latency_ms": normal(i, 22, 1.5)}})
        return n

    def test_cascade_is_one_incident_with_db_as_root(self):
        n = self.baseline()
        for k in range(10):
            t = self.t0 + (n + k) * 1000
            vals = {"s-db1": {"cpu_pct": 88, "latency_ms": normal(k, 8, 1)}}
            if k >= 4:   # dependents slow down a few seconds later
                vals["s-web1"] = {"latency_ms": 170, "cpu_pct": normal(k, 32)}
                vals["s-api1"] = {"latency_ms": 140}
            self.a1.send(t, vals)
        inc = incidents(self.app)
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["root_source"], "s-db1")
        self.assertIn("saturation", inc[0]["analysis"]["recommendation"]["title"].lower())
        self.assertEqual(inc[0]["analysis"]["recommendation"]["action"]["id"], "svc.scale_out")

    def test_same_service_on_another_site_is_not_merged(self):
        n = self.baseline()
        for k in range(6):
            self.a1.send(self.t0 + (n + k) * 1000, {"s-api1": {"latency_ms": 160}})
            self.a2.send(self.t0 + (n + k) * 1000, {"s-web3": {"latency_ms": 180}})
        self.assertEqual(len(incidents(self.app)), 2)

    def test_security_event_kept_apart_from_performance(self):
        n = self.baseline()
        ev = {"source_id": "s-db1", "ts": "2026-11-20T09:00:00.000Z", "category": "security.auth_failure_burst",
              "severity": "high", "count": 12, "context": "12 failed sshd logins in 60s, 5 distinct accounts"}
        for k in range(5):
            self.a1.send(self.t0 + (n + k) * 1000, {"s-db1": {"cpu_pct": 88}}, events=[ev] if k == 0 else ())
        titles = sorted(i["analysis"]["recommendation"]["title"] for i in incidents(self.app))
        self.assertEqual(len(titles), 2)
        self.assertTrue(any("Credential attack" in t for t in titles))

    def test_fleet_demand_is_low_severity_not_a_fault(self):
        for i in range(60):
            v = {"s-web1": {"cpu_pct": normal(i, 32), "bw_in_mbps": normal(i, 120, 5)},
                 "s-web2": {"cpu_pct": normal(i + 3, 32), "bw_in_mbps": normal(i + 3, 120, 5)}}
            self.a1.send(self.t0 + i * 1000, v)
            self.a2.send(self.t0 + i * 1000, {"s-web3": {"cpu_pct": normal(i + 5, 32), "bw_in_mbps": normal(i, 120, 5)}})
        for k in range(8):
            t = self.t0 + (60 + k) * 1000
            self.a1.send(t, {"s-web1": {"cpu_pct": 62, "bw_in_mbps": 290}, "s-web2": {"cpu_pct": 63, "bw_in_mbps": 295}})
            self.a2.send(t, {"s-web3": {"cpu_pct": 61, "bw_in_mbps": 288}})
        inc = incidents(self.app)
        self.assertTrue(inc)
        rec = inc[0]["analysis"]["recommendation"]
        self.assertIn("demand", rec["title"].lower())
        self.assertEqual(inc[0]["severity"], "low")


class RemediationPolicy(unittest.TestCase):
    def test_viewer_cannot_approve_and_irreversible_is_blocked(self):
        app = make_app(self)
        row = {"action": "svc.scale_out", "collector_id": "col-a1", "source_id": "s-db1"}
        viewer = app.engine.policy_check("acme", row, {"role": "viewer"})
        self.assertFalse(viewer["allowed"])
        manual = app.engine.policy_check("acme", dict(row, action="sec.rotate_credential"), {"role": "admin"})
        self.assertFalse(manual["allowed"])


if __name__ == "__main__":
    unittest.main()
