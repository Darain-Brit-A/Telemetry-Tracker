"""ML feature 1: entropy-assisted secret detection, checked against the acceptance criteria in
AIOPS_ML_FEATURES_MASTER.md. The corpora are generated deterministically (fixed seed) so every run and
every machine measures the same thing."""
import random
import string
import time
import unittest
import uuid

from helpers import ROOT  # noqa: F401
from common.policy import CREDENTIAL_TYPES, find_possible_secrets, redact_with_entropy

R = random.Random(20261120)
B62 = string.ascii_letters + string.digits
B64 = B62 + "+/"
HEX = "0123456789abcdef"
N = 2000


def rand(alphabet, n):
    return "".join(R.choice(alphabet) for _ in range(n))


ID_CORPUS = {
    "trace IDs": [f"trace {rand(HEX, 32)} handled in 12ms" for _ in range(N)],
    "git SHAs": [f"deployed commit {rand(HEX, 40)} to prod" for _ in range(N)],
    "request IDs": [f"request req_{rand(string.ascii_lowercase + string.digits, 20)} completed" for _ in range(N)],
    "pod names": [f"pod checkout-api-{rand(string.ascii_lowercase + string.digits, 9)}-{rand(string.ascii_lowercase + string.digits, 5)} restarted"
                  for _ in range(N)],
    "UUIDs": [f"order {uuid.UUID(int=R.getrandbits(128), version=4)} committed" for _ in range(N)],
    "IDs after common words": [f"processed request {R.choice(['with', 'using', 'for', 'from'])} trace "
                               f"{rand(HEX, R.choice([32, 40, 64]))}" for _ in range(N)],
    "sentences": [R.choice(["database connection timeout after retry", "checkout-api-service started on port 8080",
                            "user signed in from the mobile application", "cache hit ratio 0.93 over last minute",
                            "GET /api/cart/1234 200 34ms", "scheduled job nightly-report-generation finished"])
                  for _ in range(N)],
}


def mixed(alphabet, n):
    while True:
        tok = rand(alphabet, n)
        if any(c.islower() for c in tok) and any(c.isupper() for c in tok) and any(c.isdigit() for c in tok):
            return tok


SECRET_CORPUS = {
    "base62 keys 20-64": [(f"connected with {t}", t) for t in (mixed(B62, R.randint(20, 64)) for _ in range(N))],
    "base64 keys": [(f"cfg loaded {t}", t) for t in (mixed(B64, R.randint(24, 64)) for _ in range(N))],
    "AWS-style secret keys": [(f"aws {t}", t) for t in (mixed(B64, 40) for _ in range(N))],
    "GitHub-style tokens": [(f"push using ghp_{t}", "ghp_" + t) for t in (mixed(B62, 36) for _ in range(N))],
    "hex keys after a hint": [(f"{R.choice(['api key', 'token', 'secret', 'auth', 'key:'])} {t}", t)
                              for t in (rand(HEX, R.choice([28, 32, 40, 64])) for _ in range(N))],
}


class AcceptanceCriteria(unittest.TestCase):
    def test_false_positives_on_ordinary_ids(self):
        total_fp = total = 0
        for kind, lines in ID_CORPUS.items():
            fp = sum(1 for line in lines if find_possible_secrets(line)[1])
            total_fp += fp
            total += len(lines)
            self.assertLess(fp / len(lines), 0.02, f"{kind}: {fp}/{len(lines)} flagged")
        self.assertLess(total_fp / total, 0.01)

    def test_detection_on_secrets(self):
        found = total = 0
        for kind, cases in SECRET_CORPUS.items():
            hit = sum(1 for line, secret in cases if secret not in redact_with_entropy(line)[0])
            found += hit
            total += len(cases)
            self.assertGreaterEqual(hit / len(cases), 0.85, f"{kind}: {hit}/{len(cases)} caught")
        self.assertGreaterEqual(found / total, 0.90)

    def test_cost_per_line(self):
        lines = [line for v in ID_CORPUS.values() for line in v][:5000]
        t = time.perf_counter()
        for line in lines:
            redact_with_entropy(line)
        per_line_us = (time.perf_counter() - t) / len(lines) * 1e6
        self.assertLess(per_line_us, 200)       # target 50 us; generous here so slow CI machines do not flake


class Behaviour(unittest.TestCase):
    def test_doc_example_is_caught(self):
        out, n = find_possible_secrets("db_pool: acquired connection using 8f9b4c12d9e03fa57b21e84c90d2 at runtime")
        self.assertEqual(n, 1)
        self.assertIn("[REDACTED:possible_secret]", out)

    def test_never_a_confirmed_credential(self):
        self.assertNotIn("possible_secret", CREDENTIAL_TYPES)
        _, findings = redact_with_entropy("token aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW")
        self.assertIn("possible_secret", findings)

    def test_add_only_regex_redactions_kept(self):
        out, findings = redact_with_entropy("password=hunter22 and key aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW")
        self.assertNotIn("hunter22", out)
        self.assertIn("kv_secret", findings)

    def test_own_identifiers_skipped(self):
        for tok in ("src-7cf825bf88aa11bb22cc", "tpl-3fa9c1d2aabbccddeeff", "fp-1a2b3c4d5e6f7a8b9c0d"):
            self.assertEqual(find_possible_secrets(f"key {tok}")[1], 0, tok)


if __name__ == "__main__":
    unittest.main()


class SaasHandling(unittest.TestCase):
    def test_possible_secret_is_low_and_explained_as_heuristic(self):
        from helpers import Feeder, make_app
        from common.util import iso, now_ms
        app = make_app(self)
        ev = {"source_id": "s-web1", "ts": iso(), "category": "security.possible_secret", "severity": "low",
              "count": 3, "context": "3 token(s) in logs look like secrets (entropy heuristic, not confirmed)"}
        r = Feeder(app, "col-a1").send(now_ms(), {"s-web1": {"cpu_pct": 30}}, events=[ev])
        self.assertEqual(r["rejected"], [])
        app.engine.tick()
        self.assertEqual(app.engine.health[("acme", "s-web1")][0], "Good")
        title = app.stores.for_tenant("acme").rows("SELECT title FROM incidents")[0]["title"]
        self.assertIn("Possible secrets", title)
