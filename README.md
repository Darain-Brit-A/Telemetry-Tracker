# Secure AIOps Observability: two-tier, local-first, metadata-only

CICADA 2026 hackathon build. A **local collector** runs inside each customer environment. It keeps
raw logs, payloads, identities and secrets on site and sends only allow-listed metadata to a
**multi-tenant SaaS**. The SaaS turns that metadata into health states, correlated incidents and
explained, policy-gated remediation recommendations.

Pure Python 3 standard library: no third-party packages, no internet access needed. `openssl` is
used once, to create the demo CA.

| Doc | Purpose |
|---|---|
| **[GUIDE.md](GUIDE.md)** | **Start here: the complete guide (run on one or two laptops, demo tour, how the AI works, security, testing, troubleshooting)** |
| [docs/PHASE1_PROBLEM_AND_IDEATION.md](docs/PHASE1_PROBLEM_AND_IDEATION.md) | Phase 1: problem, use cases, features and MVP, what stays local, 24-hour plan |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Phase 2: trust boundary, every hop, payload schema, security, AIOps, reliability, scaling |
| [docs/VIVA_SCRIPT.md](docs/VIVA_SCRIPT.md) | Viva preparation: what the project does, a speaking script per phase, likely questions with answers, demo order, numbers |
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

## Two laptops: collector on one, SaaS on the other

The collector and the SaaS can run on different machines on the same network; only the SaaS ingest port
(8443, mutual TLS 1.3 + HMAC) is exposed. Full guide: [docs/TWO_MACHINES.md](docs/TWO_MACHINES.md).

```powershell
# laptop A (SaaS): use its LAN IP, open TCP 8443 in the firewall (admin), export the collector, start
python setup_env.py --saas-host 192.168.1.20
python tools/export_collector.py col-acme-dc1
python run_all.py --exclude col-acme-dc1
# laptop B (collector): unpack the zip into the project folder, then
python run_all.py --collector col-acme-dc1
```

## Live data: air quality in four Indian cities (OpenAQ)

Besides the simulated tenants, the demo monitors **real, live data**: 16 official air-quality monitors (CPCB
and state pollution control boards) in **Bengaluru, Delhi, Mumbai and Chennai**, four per city, read through
the [OpenAQ v3 API](https://docs.openaq.org/). Each city has its own Tier-1 collector, as each site would in
a real deployment. Put your OpenAQ API key in `config/pollution.json` (`{"api_key": "..."}`; `config/` is
git-ignored) or in the `AIOPS_OPENAQ_API_KEY` environment variable, then start the demo as usual;
`run_all.py` starts `tools/openaq_poller.py` automatically when a key is present.

```powershell
python run_all.py --fresh
```

Sign in as `cityair-admin / cityair-admin-demo` (tenant "India Air Quality", stored in region ap-south).

* **History first.** At start the poller sends each monitor's last 4 days of hourly PM2.5, PM10 and NO2 at
  their real measurement times. The AI engine learns every monitor's own baseline (and, from 3 days of
  history, its normal level for each hour of the day) from them. Readings older than 3 hours only train the
  baselines; they never raise alerts.
* **Then live.** Every 2 minutes it fetches the latest readings and sends each new measurement once, at its
  real time. Official monitors publish every 15-60 minutes, usually 1-2 hours late, so cards show how old
  each reading is, and a monitor with nothing for 3 hours turns stale instead of repeating an old value.
* **Same secure path as all telemetry:** poller → collector `/ingest` (bearer token) → allow-list and DLP →
  mutual TLS → SaaS → AI engine.
* **Graphs.** Operations shows the current value of every monitor grouped by city and coloured by India's
  CPCB category, and a 4-day trend per city with the CPCB limits; PM2.5 / PM10 / NO2 can be switched.
  Each monitor's detail view charts 4 days with its learned limits drawn on.
* **Limits.** Learned (ML) by default with the CPCB Moderate limit (PM2.5 90, PM10 250, NO2 180 µg/m³) as the
  safety limit; switch any metric to Manual CPCB bands (PM2.5 30 / 60 / 90, PM10 50 / 100 / 250, NO2
  40 / 80 / 180) under Thresholds & audit. Incidents name the CPCB category and whether the cause looks
  regional (several monitors together) or local.

`python tools/openaq_poller.py --once` discovers the monitors and prints the history it would send, without
sending anything.

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
| Learned health limits (SaaS, **default**, Manual per metric optional) | **Thresholds & audit → Limits**. Each source's Excellent / Good / Fair limits come from its own baseline (+2σ / +4σ / +8σ, seasonal when available) instead of one fixed number for all; the manual Fair value stays as a hard safety limit, and only it raises threshold alerts (deviations are alerted by the anomaly detector) | Benchmark seed 7, 60 trials, learned vs manual: precision 95.3% vs 94.1%, false alarms 0.50 vs 0.64 per host-hour, recall 94% and detection delays identical. Unit-tested: a database always at 88% CPU is Fair with a standing alert under manual limits, Excellent under learned; 95% still Poor and alerted |

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
