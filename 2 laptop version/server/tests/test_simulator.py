"""B12: 'Heal all' on one collector console must not end scenarios running on other collectors."""
import unittest

from helpers import ROOT  # noqa: F401
from simulator.stream import Stream


def stream():
    hosts = [["web-1", "web", "checkout-web"], ["db-1", "db", "orders-db"]]
    cfg = {"port": 0, "collectors": {
        cid: {"ingest": "http://127.0.0.1:1/ingest", "syslog_port": 1, "site": cid, "tz": "UTC", "tenant": t,
              "hosts": hosts} for cid, t in (("col-a", "acme"), ("col-b", "globex"))}}
    s = Stream(cfg)
    return s


class HealScope(unittest.TestCase):
    def test_heal_all_only_touches_its_own_collector(self):
        s = stream()
        self.addCleanup(s.udp.close)
        s.inject("cpu_spike", "col-a", "web-1")
        s.inject("cpu_spike", "col-b", "web-1")
        s.inject("heal", "col-a")
        self.assertEqual(s.host("col-a", "web-1").scn, {})
        self.assertIn("cpu_spike", s.host("col-b", "web-1").scn)

    def test_heal_one_host(self):
        s = stream()
        self.addCleanup(s.udp.close)
        s.inject("cpu_spike", "col-a", "web-1")
        s.inject("mem_leak", "col-a", "db-1")
        s.inject("heal", "col-a", "web-1")
        self.assertEqual(s.host("col-a", "web-1").scn, {})
        self.assertIn("mem_leak", s.host("col-a", "db-1").scn)


if __name__ == "__main__":
    unittest.main()
