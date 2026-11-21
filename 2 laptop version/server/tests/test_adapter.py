import unittest

from helpers import ROOT  # noqa: F401
from tools.stream_adapter import map_record, parse_ts


class Timestamps(unittest.TestCase):
    def test_formats(self):
        ms = 1763629200000   # 2025-11-20T09:00:00Z
        for v in ("2025-11-20T09:00:00Z", "2025-11-20T14:30:00+05:30", "2025-11-20 09:00:00", ms / 1000, ms,
                  str(ms), ms * 1000):
            self.assertEqual(parse_ts(v), ms, v)

    def test_offsetless_iso_uses_given_timezone(self):
        self.assertEqual(parse_ts("2025-11-20 14:30:00", "Asia/Kolkata"), 1763629200000)
        _, evs = map_record({"timestamp": "2025-11-20T14:30:00", "host": "h", "cpu": 1}, default_tz="Asia/Kolkata")
        self.assertEqual(evs[0]["ts"], "2025-11-20T09:00:00.000Z")


class Mapping(unittest.TestCase):
    def test_nested_metrics_logs_and_auth(self):
        _, evs = map_record({"at": "2025-11-20T09:00:00Z", "source": "gw-1", "zone": "Asia/Kolkata",
                             "metrics": {"cpu": 41, "memory": 55, "loss": 0.3, "connected": 1},
                             "message": "checkout ok"})
        m = next(e for e in evs if e["type"] == "metric")
        self.assertEqual(m["metrics"], {"cpu_pct": 41, "mem_pct": 55, "packet_loss_pct": 0.3, "reachable": 1})
        self.assertEqual(m["tz"], "Asia/Kolkata")
        self.assertTrue(any(e["type"] == "log" for e in evs))

    def test_name_value_pairs_and_availability_percent(self):
        _, evs = map_record({"event_time_utc": "2025-11-20T09:00:00Z", "hostname": "db-9",
                             "metric_name": "service_availability_percent", "metric_value": 99.95})
        self.assertEqual(evs[0]["metrics"], {"svc_up": 1.0})

    def test_flat_csv_style_with_ratio_and_strings(self):
        _, evs = map_record({"timestamp": "1763629200", "device": "edge-7", "cpu_ratio": "0.97", "link_up": "false",
                             "rtt_ms": "240"})
        self.assertEqual(evs[0]["metrics"], {"cpu_pct": 97.0, "reachable": 0.0, "latency_ms": 240.0})

    def test_auth_failure(self):
        _, evs = map_record({"time": 1763629200, "host": "api-1", "event_type": "login_failed", "username": "root",
                             "client_ip": "198.51.100.4"})
        a = evs[0]
        self.assertEqual((a["type"], a["result"], a["user"], a["src_ip"]), ("auth", "failure", "root", "198.51.100.4"))

    def test_explicit_mapping_overrides(self):
        _, evs = map_record({"t": "2025-11-20T09:00:00Z", "dev": {"name": "x1"}, "stats": {"proc": 77}},
                            mapping={"ts": "t", "host": "dev.name", "metrics": {"cpu_pct": "stats.proc"}})
        self.assertEqual((evs[0]["host"], evs[0]["metrics"]), ("x1", {"cpu_pct": 77.0}))


if __name__ == "__main__":
    unittest.main()
