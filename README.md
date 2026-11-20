# Secure AIOps Observability: two-tier, local-first, metadata-only

CICADA 2026 hackathon build. A **local collector** runs inside each customer environment. It keeps
raw logs, payloads, identities and secrets on site and sends only allow-listed metadata to a
**multi-tenant SaaS**. The SaaS turns that metadata into health states, correlated incidents and
explained, policy-gated remediation recommendations.

Pure Python 3 standard library: no third-party packages, no internet access needed. `openssl` is
used once, to create the demo CA.

| Doc | Purpose |
|---|---|
| [docs/PHASE1_PROBLEM_AND_IDEATION.md](docs/PHASE1_PROBLEM_AND_IDEATION.md) | Phase 1: problem, use cases, features and MVP, what stays local, 24-hour plan |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Phase 2: trust boundary, every hop, payload schema, security, AIOps, reliability, scaling |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Phase 4: live demo for every Section 8 scenario and answers to the Section 7 questions |
| [docs/VALIDATION_REPORT.md](docs/VALIDATION_REPORT.md) | Phase 3: end-to-end results from `tools/verify.py` (latency, zero loss, isolation, ...) |
| [docs/BENCHMARK.md](docs/BENCHMARK.md) | Measured detector precision, recall, false alarms and root-cause accuracy |
| [docs/LOADTEST.md](docs/LOADTEST.md) | Measured ingest throughput and latency at 25 / 100 / 200 collectors |

## Quick start

```powershell
python setup_env.py
```
```powershell
python run_all.py --fresh
```

Open:
* **SaaS dashboard**: http://localhost:8080. Sign in as `acme-admin` / `acme-admin-demo`
  (also `acme-viewer` / `acme-viewer-demo`, `globex-admin` / `globex-admin-demo`).
* **Collector consoles** (customer side): http://127.0.0.1:9101 (Acme, Bangalore DC),
  :9102 (Acme, Frankfurt cloud), :9103 (Globex, New York)

Wait about 30 s for baselines to arm, then inject scenarios from a collector console.

## Feeding the organizer stream

`tools/stream_adapter.py` maps an unknown format onto the collector's input. It accepts JSON-lines,
a JSON array or CSV, recognises the usual names for timestamps, hosts, metrics, logs and login
events (nested `metrics` objects, flat columns, or `metric_name` / `metric_value` pairs), converts
ISO, epoch-second, epoch-millisecond and ratio values, and replays at the original pace.

```powershell
python tools/stream_adapter.py organizer.ndjson --collector col-acme-dc1
```

Use `--dry-run` to see the mapped events first, `--mapping file.json` for field names it does not
guess, and `--speed 10` to replay faster. Unmapped fields still reach the collector, where they stay local.

## Testing

| Command | What it checks | Time |
|---|---|---|
| `python -m unittest discover -s tests -t tests` | 36 unit tests: redaction, allow-list, DLP, pseudonyms, ingest (idempotency, 409 conflicts, identity, residency), detection, correlation, root cause, demand vs fault, remediation policy, stream adapter | ~3 s |
| `python tools/benchmark.py` | Detector quality on labelled faults with extra noise and harmless blips | ~90 s |
| `python tools/loadtest.py` | Throughput, latency and loss at 25 / 100 / 200 collectors, isolated instance | ~75 s |
| `python tools/verify.py --spawn` | Starts the stack, runs every Section 8 scenario end to end, measures the Section 2 targets, stops the stack | ~10 min |

CI (`.github/workflows/ci.yml`) runs the unit tests on Linux and Windows and fails the build if
benchmark precision or recall drops below 85%.

## What runs

| Component | Path | Role |
|---|---|---|
| Collector (x3) | `collector/` | collect (HTTP JSON + syslog UDP), redact and pseudonymize, 1 s event-time aggregation, local analysis (auth bursts, secret findings, error templates, reachability), allow-list + DLP, persistent outbox, TLS + HMAC transport; egress proof panel, buffering, region discovery, simulated remediation executor |
| SaaS | `saas/` | regional ingest with auth, residency, strict allow-list, DLP, idempotency and conflict detection; AIOps engine (baselines, anomaly detection, peer analysis, correlation, root-cause ranking, playbook recommendations, four-state health, policy-checked actions); tenant-scoped dashboard |
| Simulator | `simulator/stream.py` | stand-in for the organizer stream: 11 hosts in 2 tenants and 3 sites/timezones, background logs and auth traffic, 12 injectable scenarios |
| Shared policy | `common/` | the egress allow-list both tiers enforce, secret/PII patterns, DLP scanner, HMAC pseudonyms, browser hardening |
| Tools | `tools/` | stream adapter, end-to-end verification, benchmark, load test |

Tenants: **Acme Retail** (data resides in `eu-west`, two collectors,
`checkout-web -> checkout-api -> orders-db / session-cache`) and **Globex Finance** (`us-east`,
one collector, `billing-app -> billing-db / edge-firewall`).

## Measured, not claimed

| Target (guide Section 2) | Required | Measured |
|---|---|---|
| Collection to dashboard, 95th percentile | 10 s | 2.6 s |
| Threshold breach to alert, 95th percentile | 15 s | 3.8 s |
| Collector offline detection | 60 s | 30.0 s |
| Backlog after outage | zero loss, zero duplicates | 482 sent, 482 stored, 0 gaps, drained in 0.6 s |

All 16 end-to-end checks pass (`docs/VALIDATION_REPORT.md`), including a stream in an unknown
format fed through the adapter.

| Quality and scale | Result |
|---|---|
| Detector precision / recall (60 labelled trials) | 95% / 96% |
| False alarms per host-hour of normal data | 0.5 |
| Root cause correct on cascading faults | 80% |
| Ingest capacity, single process | ~107 payloads/s (~3,900 points/s); 100 collectors fully served at p95 1.0 s, zero loss |

## Innovation highlights

* **Remediation without revealing the target.** The SaaS approves "block origins on
  `src-7cf825bf88`". Only the collector can resolve that pseudonym to a host and the attacking IPs.
* **Template fingerprints instead of log text.** Recurring errors are correlated with `fp-xxxxxxxx`
  hashes of the message *template*, so there is pattern intelligence with zero content.
* **Defence in depth on egress.** Payloads are built from aggregates, then allow-listed, then
  DLP-scanned. The SaaS re-validates, rejects instead of repairing, and refuses a reused payload ID
  with different content (409). The collector checks the digest in every acknowledgement.
* **Demand vs fault.** Peer comparison plus a traffic signal turns a fleet-wide usage spike into a
  low-severity "scale out" note instead of a page.
* **Measured confidence.** Every recommendation shows the detector's benchmarked precision and
  recall next to its rule-based confidence factors.
* **Provable delivery.** Contiguous sequence numbers, payload IDs and matching SHA-256 on both sides
  make "zero loss, zero duplicates" checkable by a judge.

## Security notes

* Collector to SaaS: TLS 1.2+ with a pinned private CA, HMAC-SHA256 request signatures, 300 s replay window.
* Dashboard and collector console: Host-header check (DNS rebinding), Origin check on writes,
  strict Content-Security-Policy (no inline script), no framing, no referrer.
* Dashboard login: PBKDF2-hashed passwords, HttpOnly SameSite session cookie, admin and viewer roles.

## Limitations and what production needs

* Telemetry in the demo is simulated. The inputs are real (HTTP JSON, syslog UDP, file replay
  through the adapter) but there is no SNMP poller or NetFlow parser.
* SQLite and a single process per tier with one lock. The load test shows the ceiling (~107
  payloads/s). Production would use regional Kafka, a time-series store and AIOps workers
  sharded by series (ARCHITECTURE section 8).
* The dashboard runs plain HTTP on localhost with local users. Production needs TLS, SSO/OIDC and finer RBAC.
* The collector console has no login. It only listens on 127.0.0.1 and refuses foreign Host and Origin headers.
* Collector secrets and the CA key live in config files. Production should enrol collectors with
  mTLS and short-lived certificates kept in an OS keystore or TPM.
* Baselines are rolling median/MAD without daily or weekly seasonality.
* Correlation and recommendations are rules over a declared dependency graph. They are explainable,
  but they will not find patterns nobody encoded. The rule-based confidence factors are a heuristic;
  only the benchmark figures are measured, and those come from our own simulator.
* Secret detection is regex-based.
* Remediation is simulation-only by design.
