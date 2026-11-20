# Secure AIOps Observability: two-tier, local-first, metadata-only

CICADA 2026 hackathon build. A **local collector** runs inside each customer environment. It keeps
raw logs, payloads, identities and secrets on site and sends only allow-listed metadata to a
**multi-tenant SaaS**. The SaaS turns that metadata into health states, correlated incidents and
explained, policy-gated remediation recommendations.

Pure Python 3 standard library: no third-party packages, no internet access needed. `openssl` is used once, to create the demo CA.

| Doc | Purpose |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Phase 2: trust boundary, every hop, payload schema, security, AIOps, reliability, scaling |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Phase 4: step-by-step live demo for every Section 8 scenario and answers to Section 7 questions |
| [docs/VALIDATION_REPORT.md](docs/VALIDATION_REPORT.md) | Phase 3: measured results from `tools/verify.py` (latency, zero loss, isolation, …) |

## Quick start

```powershell
python setup_env.py
```
```powershell
python run_all.py --fresh
```

Open:
* **SaaS dashboard**: http://localhost:8080. Sign in as `acme-admin` / `acme-admin-demo` (also `acme-viewer` / `acme-viewer-demo`, `globex-admin` / `globex-admin-demo`).
* **Collector consoles** (customer side): http://127.0.0.1:9101 (Acme, Bangalore DC), :9102 (Acme, Frankfurt cloud), :9103 (Globex, New York)

Wait about 40 s for baselines to arm, then inject scenarios from a collector console. To reproduce the measured results:

```powershell
python tools/verify.py
```

## What runs

| Component | Path | Role |
|---|---|---|
| Collector (×3) | `collector/collector.py` | collect (HTTP JSON + syslog UDP) → redact + pseudonymize → 2 s event-time aggregation → local analysis (auth bursts, secret findings, error templates, reachability) → allow-list + DLP → persistent outbox → TLS + HMAC transport; egress proof panel, buffering, region discovery, simulated remediation executor |
| SaaS | `saas/server.py`, `saas/aiops.py`, `saas/store.py` | regional ingest with auth, residency, strict allow-list, DLP, idempotency; AIOps engine (baselines, anomaly detection, peer analysis, correlation, root-cause ranking, playbook recommendations, four-state health, policy-checked actions); tenant-scoped dashboard |
| Simulator | `simulator/stream.py` | stand-in for the organizer stream: 11 hosts in 2 tenants and 3 sites/timezones, background logs and auth traffic, 12 injectable scenarios, `--replay file.jsonl` for a recorded/organizer stream |
| Shared policy | `common/data_policy.json`, `common/policy.py` | the single egress allow-list both tiers enforce; secret/PII patterns; DLP scanner; HMAC pseudonyms |
| Verification | `tools/verify.py` | runs every Section 8 scenario and measures the Section 2 targets |

Tenants: **Acme Retail** (data resides in `eu-west`, two collectors, `checkout-web → checkout-api → orders-db / session-cache`) and **Globex Finance** (`us-east`, one collector, `billing-app → billing-db / edge-firewall`).

## Phase 1: problem understanding & ideation

**Why raw telemetry stays local.** Raw logs carry credentials, personal data and payload content.
Shipping them to a shared platform widens the attack surface, creates a second copy that falls under
data-protection and residency rules, and makes the SaaS a high-value target. The SaaS only needs
*signals*: numbers, categories and counts. So the collector reduces data to signals before it
crosses the boundary, and the SaaS cannot leak what it never received.

**Use cases (all live in the demo):** infrastructure health (CPU, memory, disk, service checks) ·
network latency and packet loss per site · repeated failed logins / password spraying · credential leakage into logs ·
collector fleet health (online, last seen, version, config, resources, backlog).

**Prioritized features → minimum viable demo (✓ = built):**
1. ✓ Collector pipeline with redaction, allow-list and egress proof panel (MVP)
2. ✓ Authenticated TLS link, outbox buffering, idempotent replay (MVP)
3. ✓ Dashboard with four health states, stale-data handling, history (MVP)
4. ✓ Baseline anomaly detection + alerts with context (MVP)
5. ✓ Correlation into incidents + explained recommendations
6. ✓ Tenant isolation + regional residency, UTC/timezones, out-of-order handling
7. ✓ Policy-gated, approved, simulated remediation with rollback and two-sided audit

**Team split used in the 24 h plan:** collector & data protection · SaaS ingest, storage & reliability · AIOps engine · dashboard & demo/validation. The simulator came first so everyone built against the same stream.

## Innovation highlights

* **Remediation without revealing the target.** The SaaS approves "block origins on `src-7cf825bf88`". Only the collector can resolve that pseudonym to a host and the attacking IPs. Neither ever reaches the SaaS.
* **Template fingerprints instead of log text.** Recurring errors are correlated with `fp-xxxxxxxx` hashes of the message *template*, so there is pattern intelligence with zero content.
* **Defence in depth on egress.** Payloads are built from aggregates, then allow-listed, then DLP-scanned. A payload that still trips DLP is blocked and replaced with an empty marker, so the sequence numbers stay contiguous. The SaaS re-validates and *rejects* rather than repairs.
* **Demand vs fault.** Peer comparison plus a traffic signal turns a fleet-wide usage spike into a low-severity "scale out" note instead of a page.
* **Provable delivery.** Contiguous sequence numbers + payload IDs + matching SHA-256 on both sides make "zero loss, zero duplicates" checkable by a judge, not just asserted.

## Limitations (honest gaps) and what production needs

* Telemetry is simulated (same interfaces a real agent / SNMP / flow exporter would use). No SNMP poller or NetFlow parser is included; syslog and HTTP JSON inputs are real.
* SQLite and a single process per tier. Production would use regional Kafka plus a time-series store, with sharded AIOps workers (see ARCHITECTURE §8).
* The dashboard is plain HTTP on localhost with local users. Production needs TLS, SSO/OIDC and fine-grained RBAC.
* Collector secrets live in config files. Production should enrol with mTLS and short-lived certs stored in a TPM/OS keystore.
* Baselines are rolling median/MAD without seasonality. Weekly or diurnal patterns would need seasonal decomposition, and a cold start needs about 30 s of data.
* Correlation and recommendations are deterministic rules over a declared dependency graph. That keeps them explainable, but they won't find patterns nobody encoded. Topology discovery and learned correlations are future work.
* Secret detection is regex-based. Entropy scoring and custom per-customer patterns would cut misses and false positives.
* Remediation is simulation-only by design.
