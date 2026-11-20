"""ML feature 2: deviation share per (source, signal), root vs symptoms, honest wording."""
import json
import unittest

from helpers import Feeder, make_app, normal, series_start
from saas.aiops import deviation_shares


def cascade(test):
    app = make_app(test)
    a1 = Feeder(app, "col-a1")
    t0 = series_start(140)
    for i in range(60):
        a1.send(t0 + i * 1000, {"s-db1": {"cpu_pct": normal(i), "latency_ms": normal(i, 8, 1)},
                                "s-web1": {"latency_ms": normal(i, 22, 1.5), "cpu_pct": normal(i, 32)},
                                "s-api1": {"latency_ms": normal(i, 28, 1.5)}})
    for k in range(10):
        vals = {"s-db1": {"cpu_pct": 88, "latency_ms": normal(k, 8, 1)}}
        if k >= 4:
            vals["s-web1"] = {"latency_ms": 170, "cpu_pct": normal(k, 32)}
            vals["s-api1"] = {"latency_ms": 140}
        a1.send(t0 + (60 + k) * 1000, vals)
    app.engine._incidents("acme")
    inc = app.stores.for_tenant("acme").rows("SELECT * FROM incidents WHERE tenant_id='acme' AND status='open'")[0]
    return json.loads(inc["analysis"])


class DeviationShares(unittest.TestCase):
    def test_shares_split_root_and_symptoms_and_sum_to_100(self):
        an = cascade(self)
        dev = an["recommendation"]["deviation"]
        self.assertTrue(dev["root"] and dev["symptoms"])
        self.assertTrue(all(r["source"] == "s-db1" for r in dev["root"]))
        self.assertTrue(all(r["source"] != "s-db1" for r in dev["symptoms"]))
        total = sum(r["share"] for r in dev["root"] + dev["symptoms"])
        self.assertAlmostEqual(total, 100.0, places=6)
        self.assertGreater(dev["composite_score"], 0)
        self.assertIn("share of total deviation", dev["note"])

    def test_wording_never_calls_a_symptom_the_cause(self):
        an = cascade(self)
        line = next(s for s in an["recommendation"]["reasoning"] if s.startswith("Deviation share"))
        self.assertIn("root is orders-db", line)
        self.assertIn("symptoms", line.lower())

    def test_worked_example_from_the_doc(self):
        sig = [{"source_id": "db", "service": "orders-db", "signal": "cpu_pct", "detail": {"z": 21.0}},
               {"source_id": "db", "service": "orders-db", "signal": "latency_ms", "detail": {"z": 6.6}},
               {"source_id": "db", "service": "orders-db", "signal": "mem_pct", "detail": {"z": 4.2}},
               {"source_id": "w1", "service": "checkout-web", "signal": "latency_ms", "detail": {"z": 25.2}},
               {"source_id": "w2", "service": "checkout-web", "signal": "latency_ms", "detail": {"z": 24.8}},
               {"source_id": "a1", "service": "checkout-api", "signal": "latency_ms", "detail": {"z": 17.2}},
               {"source_id": "a1", "service": "checkout-api", "signal": "security.auth_failure_burst", "detail": {}}]
        dev = deviation_shares(sig, "db")
        self.assertEqual(dev["composite_score"], 45.3)
        self.assertEqual([r["share"] for r in dev["root"]], [21.2, 6.7, 4.2])
        self.assertEqual([r["share"] for r in dev["symptoms"]], [25.5, 25.0, 17.4])   # largest-remainder rounding
        self.assertEqual([e["signal"] for e in dev["events"]], ["security.auth_failure_burst"])


if __name__ == "__main__":
    unittest.main()
