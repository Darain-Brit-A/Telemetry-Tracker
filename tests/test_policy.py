import unittest

from helpers import ROOT  # noqa: F401  (sets sys.path)
from common.policy import dlp_scan, enforce, load_policy, pseudonymize, redact_text


class Redaction(unittest.TestCase):
    def test_password_and_url_credentials(self):
        out, f = redact_text("connect postgres://svc:Sup3r!@db:5432/x password=Sup3r! retry")
        self.assertNotIn("Sup3r", out)
        self.assertIn("url_creds", f)
        self.assertIn("kv_secret", f)

    def test_tokens_and_cloud_keys(self):
        out, f = redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl "
                             "key AKIAIOSFODNN7EXAMPLE sk_live_51HxQ9fAKExampleKey99")
        for secret in ("eyJhbGci", "AKIAIOSFODNN7EXAMPLE", "sk_live_51Hx"):
            self.assertNotIn(secret, out)
        self.assertTrue({"jwt", "aws_key", "api_key"} <= set(f))

    def test_pii(self):
        out, f = redact_text("user anna@example.com from 203.0.113.7")
        self.assertNotIn("anna@example.com", out)
        self.assertNotIn("203.0.113.7", out)
        self.assertEqual(sorted(set(f)), ["email", "ipv4"])

    def test_clean_line_untouched(self):
        line = "order 4411 committed in 12ms"
        self.assertEqual(redact_text(line), (line, []))


class AllowList(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()

    def test_unknown_fields_and_values_are_stripped(self):
        p = {"schema": "aiops.meta/v1", "payload_id": "x", "kind": "metrics", "raw_log": "secret!",
             "metrics": [{"source_id": "s", "ts": "t", "name": "cpu_pct", "avg": 1, "min": 1, "max": 1, "n": 1,
                          "hostname": "db-01"},
                         {"source_id": "s", "ts": "t", "name": "process_list", "avg": 1, "min": 1, "max": 1, "n": 1}],
             "events": [{"source_id": "s", "ts": "t", "category": "made.up", "severity": "high", "count": 1}],
             "sources": [{"source_id": "s", "role": "db", "ip": "10.0.0.1"}]}
        clean, dropped = enforce(p, self.policy)
        self.assertNotIn("raw_log", clean)
        self.assertEqual(len(clean["metrics"]), 1)
        self.assertNotIn("hostname", clean["metrics"][0])
        self.assertEqual(clean["events"], [])
        self.assertNotIn("ip", clean["sources"][0])
        self.assertTrue(any("raw_log" in d for d in dropped))

    def test_nested_objects_rejected(self):
        p = {"kind": "metrics", "sources": [], "events": [],
             "metrics": [{"source_id": {"host": "db-01"}, "ts": "t", "name": "cpu_pct", "avg": 1, "min": 1,
                          "max": 1, "n": 1}]}
        clean, _ = enforce(p, self.policy)
        self.assertNotIn("source_id", clean["metrics"][0])

    def test_heartbeat_stats_filtered(self):
        hb = {"kind": "heartbeat", "collector_id": "c", "stats": {"cpu_pct": 1, "hostname": "x", "buffer_depth": 0}}
        clean, dropped = enforce(hb, self.policy)
        self.assertEqual(set(clean["stats"]), {"cpu_pct", "buffer_depth"})
        self.assertIn("stats.hostname", dropped)


class Dlp(unittest.TestCase):
    def test_flags_raw_credentials(self):
        self.assertIn("kv_secret", dlp_scan('{"context":"password=hunter22"}'))
        self.assertIn("aws_key", dlp_scan('{"x":"AKIAIOSFODNN7EXAMPLE"}'))

    def test_ignores_placeholders_and_timestamps(self):
        self.assertEqual(dlp_scan('{"c":"password=[REDACTED:secret]","ts":"2026-11-20T09:00:00.000Z","n":1763611803123}'), [])

    def test_luhn_valid_card_flagged(self):
        self.assertIn("credit_card", dlp_scan('{"c":"4111 1111 1111 1111"}'))


class Pseudonyms(unittest.TestCase):
    def test_stable_and_salt_dependent(self):
        a = pseudonymize("salt1", "col/db-01")
        self.assertEqual(a, pseudonymize("salt1", "col/db-01"))
        self.assertNotEqual(a, pseudonymize("salt2", "col/db-01"))
        self.assertRegex(a, r"^src-[0-9a-f]{10}$")


if __name__ == "__main__":
    unittest.main()
