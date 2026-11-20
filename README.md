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

## Live data: Bengaluru air quality (OpenAQ)

Besides the simulated tenants, the demo can monitor **real, live data**: six official air-quality monitors
in Bengaluru (CPCB / KSPCB: Silk Board, BTM Layout, Peenya, Jayanagar, Bapuji Nagar, Hebbal), read through
the [OpenAQ v3 API](https://docs.openaq.org/). Put your OpenAQ API key in `config/pollution.json`
(`{"api_key": "..."}`; `config/` is git-ignored) or in the `AIOPS_OPENAQ_API_KEY` environment variable, then
start the demo as usual. `run_all.py` starts `tools/openaq_poller.py` automatically when a key is present.

```powershell
python run_all.py --fresh
```

Sign in as `cityair-admin / cityair-admin-demo` (tenant "Bengaluru Air Quality", stored in region ap-south).
The readings take the same path as any telemetry: poller → collector `/ingest` (bearer token) → allow-list
and DLP → mutual TLS → SaaS → AI engine. Limits follow India's CPCB AQI bands (PM2.5 30 / 60 / 90, PM10
50 / 100 / 250, NO2 40 / 80 / 180 µg/m³; can be switched to Learned (ML) per metric), and incidents name the
CPCB category ("Air quality: PM10 Poor at Hebbal") with a regional-vs-local explanation. NO2 reported in ppb
is converted to µg/m³. Monitors publish every 15-60 minutes with a delay, so each card shows how old its
reading is; a monitor with nothing in the last 3 hours shows as no data rather than a stale value.
`python tools/openaq_poller.py --once` prints one round without sending anything.

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

## Statistical (ML) features

Three statistical methods described in [AIOPS_ML_FEATURES_MASTER.md](AIOPS_ML_FEATURES_MASTER.md), each measured
before it was kept:

| Feature | What it does | Measured |
|---|---|---|
| Entropy-assisted secret detection (collector) | Catches bare random tokens the regex patterns miss; add-only, never decides what leaves | 0 false positives on 14,000 ordinary IDs and lines; 95.5% of 10,000 secrets caught; 23.5 µs per line |
| Deviation share (SaaS) | Shows each signal's share of an incident's total deviation, root and symptoms drawn separately | Shares always add up to 100%; the root group is always the ranked root |
| Seasonal baseline (SaaS) | Compares each value with what is normal for that hour of the day once 3 days of history exist | Daily-peak false alarms in 20/20 trials without it, 1/20 with it; night spikes still caught 20/20 |
| Learned health limits (SaaS, optional per metric) | **Thresholds & audit → Limits: Learned (ML)**. Each source's Excellent / Good / Fair limits come from its own baseline (+2σ / +4σ / +8σ, seasonal when available) instead of one fixed number for all; the manual Fair value stays as a hard safety limit, and only it raises threshold alerts (deviations are alerted by the anomaly detector) | Unit-tested: a database always at 88% CPU is Fair with a standing alert under manual limits, Excellent under learned; 95% still Poor and alerted. Default stays Manual, so the benchmark is unchanged |

Seasonal demo with a 10-minute day (the evening peak stops alerting after 3 compressed days; then use the
collector console's **Night spike** button):

```powershell
python run_all.py --fresh --compressed-day 600
```

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
| Collection to dashboard, 95th percentile | 10 s | 2.4-2.6 s |
| Threshold breach to alert, 95th percentile | 15 s | 3.8 s |
| Collector offline detection | 60 s | 30-31 s |
| Backlog after outage | zero loss, zero duplicates | 481 sent, 481 stored, 0 gaps, drained in under 5 s |

All 17 end-to-end checks pass (`docs/VALIDATION_REPORT.md`), including a stream in an unknown
format fed through the adapter and an idle client holding a TLS connection.

| Quality and scale | Result |
|---|---|
| Detector precision / recall (60 labelled trials, 5 seeds) | 94-97% / 92-100% |
| False alarms per host-hour of normal data | 0.3-0.6 |
| Root cause correct on cascading faults | 90-100% |
| Ingest capacity, single process | about 90-107 payloads/s (3,300-3,900 points/s), varying with machine load between runs; 100 collectors at one payload/s each: ~94 accepted/s, zero errors, zero loss |

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

* Collector to SaaS: mutual TLS 1.3 (private CA; each collector's certificate pinned by fingerprint),
  plus HMAC-SHA256 request signatures with a 300 s replay window. Redirects are refused.
* Local producer to collector: loopback only, bearer token on `/ingest`. Log-template fingerprints and host
  pseudonyms are keyed with a per-collector salt. Details: [HOST_TO_SAAS_SECURITY.md](HOST_TO_SAAS_SECURITY.md).
* Dashboard and collector console: Host-header check (DNS rebinding), Origin check on writes,
  strict Content-Security-Policy (no inline script), no framing, no referrer.
* Dashboard login: PBKDF2-hashed passwords, HttpOnly SameSite session cookie, admin and viewer roles.

## Limitations and what production needs

* Telemetry in the demo is simulated. The inputs are real (HTTP JSON, syslog UDP, file replay
  through the adapter) but there is no SNMP poller or NetFlow parser.
* SQLite and a single process per tier with one lock. The load test shows the ceiling (about
  90-107 payloads/s on this laptop, varying with machine load). Production would use regional Kafka, a time-series store and AIOps workers
  sharded by series (ARCHITECTURE section 8).
* The dashboard runs plain HTTP on localhost with local users. Production needs TLS, SSO/OIDC and finer RBAC.
* The collector console has no login. It only listens on 127.0.0.1 and refuses foreign Host and Origin headers.
* Collector secrets, client keys and the demo CA live in config files (the CA key in its own
  `config/ca-private/` folder that the services never read). Production should issue short-lived
  certificates from a managed PKI and keep keys in an OS keystore or TPM.
* Baselines are rolling median/MAD with an hour-of-day seasonal profile; there is no weekly pattern.
* Correlation and recommendations are rules over a declared dependency graph. They are explainable,
  but they will not find patterns nobody encoded. The rule-based confidence factors are a heuristic;
  only the benchmark figures are measured, and those come from our own simulator.
* Secret detection is regex-based.
* Remediation is simulation-only by design.
