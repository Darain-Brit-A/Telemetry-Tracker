# Head-to-head: this build vs `testsub-1`

Both were run side by side on 2026-11-20 and exercised in Chrome with the same scenarios (secret in
log, failed logins, correlated CPU + network fault, remediation), plus scripted probes against both
live APIs. "Mine" = this repository (Python). "testsub" = `testsub-1/` (Node.js, "Cicada").

## Test suites

| | Mine: `tools/verify.py` | testsub: `node --test` |
|---|---|---|
| Result | **15/15 pass** | **6/6 pass** |
| Runtime | ~8 min | 54 s |
| How it runs | against the running stack (`run_all.py`) | self-contained: spawns the app on temp ports with a temp data dir (CI-friendly) |
| Secret stays local / hashes match | ✓ (also checks AWS key, IPs, usernames absent in SaaS) | ✓ (also checks the hostname is absent) |
| Failed logins detected locally | ✓ | ✓ |
| CPU anomaly → explained recommendation | ✓ (z, baseline, confidence, action) | ✓ (deviation ≥ 3σ present) |
| Network latency incident | ✓ | – (not tested separately) |
| Several alerts → one incident **with root cause** | ✓ (orders-db ranked root across 4 sources) | partial (≥ 4 signals on one source; no root cause) |
| Remediation: policy, role, audit, rollback | ✓ (viewer → 403, collector executes) | state-machine order only |
| Offline detection ≤ 60 s | ✓ 30.3 s | ✓ 50.0 s |
| Outage replay: zero loss / zero duplicates | ✓ 160/160, seq gaps 0 | ✓ 26/26 IDs |
| Duplicate + out-of-order at volume (chaos) | ✓ 21 dups ignored, 3 out-of-order | single duplicate + single late event |
| Same ID, different body → conflict | ✗ **not handled** | ✓ 409 |
| Unknown field rejected at ingest | – | ✓ 422 |
| Tenant isolation / wrong region / forged credential | ✓ / ✓ 421 / ✓ 401 | ✓ / ✓ 401 / – |
| Normal usage spike not raised as a fault | ✓ | – (feature absent) |
| No false alarms at steady state | ✓ | – |
| NDJSON replay of an external stream | – | ✓ |
| Latency targets measured | ✓ dashboard p95, alert p95, ingest p95, offline | ✓ render p95, alert ≤ 15 s, offline |

## Features (observed live in Chrome + code review)

| Area | Mine | testsub | Edge |
|---|---|---|---|
| Topology | 3 collectors, 11 hosts, 2 tenants, 3 sites; dependency graph per tenant | 1 collector process, 5 sites, **1 synthetic host per site** | Mine |
| Inputs | HTTP JSON + **syslog UDP** + JSONL replay | HTTP JSON + NDJSON replay | Mine |
| Secret handling | regex redaction, raw-vs-redacted view, **secret-in-log finding sent as a signal**, DLP block of payloads | raw never enters the schema (no text fields); **no detection**, so SaaS never learns a secret leaked | Mine |
| Wire schema | allow-list strips, then DLP; SaaS re-validates and rejects | exact-key schema, regex-checked values, rejects unknown fields | testsub (stricter, simpler) |
| Collector auth | HMAC-SHA256 signature + ±300 s replay window, pinned CA | bearer token, pinned self-signed cert | Mine |
| Idempotency | payload-ID primary key, contiguous seq for gap proof | payload-ID + **digest conflict detection (409)**, ack must echo ID + digest | testsub |
| Atomicity | per-statement | raw + egress in one SQLite transaction; ingest atomic | testsub |
| Web hardening | session cookie; no CSP; **Host header not checked** | CSP, Origin + Host checks (DNS rebinding → 403) | testsub |
| Dashboard auth | always requires login (PBKDF2), admin/viewer roles | **demo mode: any tenant via `POST /api/session {"tenant":…}` with no credentials** (token mode exists) | Mine |
| Detection | median/MAD baseline from normal data only, 3-window persistence, peer + traffic analysis (demand vs fault) | trimmed-mean baseline of 24 samples, first sample over 3σ alerts immediately | Mine (fewer false alarms); testsub faster |
| Alert latency (live) | p95 6.9 s | p95 0.23 s | testsub |
| Dashboard latency (live) | p95 3.8–4.7 s | p95 1.5 s | testsub |
| Correlation | source / same-site dependency / shared-site network / collector / fleet role; security kept apart from performance | same site + source within 30 s only. **Observed: a login attack and an unrelated CPU + network fault merged into one "Authentication failures" incident** | Mine |
| Root cause | ranked (onset, upstream position, severity, evidence) | none | Mine |
| Recommendations | 12 playbook rules, reasoning path, confidence factors, why this action, alternatives, rollback | 3 fixed sentences chosen by category | Mine |
| Noise reduction | repeat alerts counted, not re-raised (228 suppressed in demo) | every sample over threshold inserts an alert row | Mine |
| Remediation | action catalog, 7 policy checks, RBAC, collector executes against a pseudonym, two-sided audit, rollback | Propose → Approve → Simulate → Rollback ledger; no action, target, policy or executor | Mine |
| Health | per source **and** per collector, stale → Fair, no data → Poor, reasons, history | per site, stale/offline, reasons, history | Mine (finer) |
| UI | functional, dense | polished, cleaner, seeded charts from the first second | testsub |
| Size | ~3,500 lines Python | ~1,830 lines JS | testsub (leaner) |

## Verdict

**For the hackathon rubric, this build is stronger.** Phases 3–4 weigh explainable AIOps,
correlation, live scenario response and remediation safeguards most heavily. Here testsub is
shallow: one host per site, category-level recommendations, no root cause, no noise reduction, and
remediation that is only a status ledger. In the live test it also merged two unrelated problems
into one incident. Its demo mode lets anyone open any tenant without credentials.

**testsub is better engineered in several places**, and these are worth porting:
1. Reject a reused payload ID with a different body (409) and verify the ack's digest on the collector.
2. Check the Host / Origin headers and add a Content-Security-Policy on both consoles.
3. A self-contained `verify` mode that spawns the stack on temp ports, so the suite runs in CI in about a minute.
4. Commit raw event + outbox row in one transaction.

Its lower latency comes from alerting on the first breaching sample. That is faster but more prone
to false alarms. Mine waits for 3 windows by design and still meets the 15 s target.
