# Three-way comparison: this build vs `testsub-1` vs `aegisops-demo`

> Note (2026-11-20, later the same day): the other projects were removed from this workspace after this comparison. They remain at github.com/Sherwin0095/testsub-1 and github.com/MishaelJulian/aegisops-demo. The scores describe the builds as they were when compared; this build has since added 409 conflict detection, ack digest checks, CSP and Host/Origin checks, an organizer-stream adapter, unit tests and CI, a measured detector benchmark and a load test.

All three were run live on 2026-11-20 and exercised in Chrome (secret in log, failed logins, CPU/network
fault, correlation, remediation), plus the same scripted probes against each API and each project's
own test suite. Scores follow the guide's four judging phases (10 / 25 / 35 / 30).

**Bias note:** "Mine" was built in this session, by the same assistant doing the scoring. Every claim
below is backed by a probe or an observation from the run, but weigh the self-score accordingly.

| | Mine (`./`) | testsub (`testsub-1/`) | AegisOps (`aegisops-demo/`) |
|---|---|---|---|
| Stack | Python stdlib only | Node 22 stdlib only | FastAPI + SQLAlchemy/Postgres + React/Vite + Docker |
| Size | ~3,500 lines | ~1,830 lines | ~8,500 lines + 18 docs, JSON-Schema contracts, CI |
| Setup | `python run_all.py` | `npm start` | `docker compose up` (or a venv + `npm ci` + 3 processes) |

## Tests (each project's own suite, run here)

| | Mine | testsub | AegisOps |
|---|---|---|---|
| Result | 15/15 | 6/6 | 27/27 (8 collector, 8 backend, 6 e2e/governance, 5 frontend) |
| Style | live system, ~8 min, writes a measured report | spawns app on temp ports, 54 s | unit + in-process e2e (TestClient), ~15 s, CI workflow |
| Measures real-time targets live | ✓ | ✓ | in-process only (ingest/alert ms, not end-to-end) |
| Unique coverage | fleet spike vs fault, cascade root cause, viewer 403, 421 region, forged HMAC, chaos dup/reorder | NDJSON replay, ID conflict 409, unknown field 422 | MAD cold-start / zero-MAD, policy-rejection path, ownership & secret-scan governance, frontend render |

## Measured in this session

| Probe | Mine | testsub | AegisOps |
|---|---|---|---|
| Offline detection (target ≤ 60 s) | **30.3 s** | 50.0 s | **~60 s** (58 s after stop, right at the limit) |
| Alert latency | 6.9 s p95 | **0.23 s** p95 | 0.54 s p95 (in-process) |
| Dashboard latency | 3.8–4.7 s p95 | **1.5 s** p95 | not measured live (3 s poll) |
| Outage replay | 160/160, gaps 0 | 26/26 | 36/36, drained 9 s after restart |
| Same ID, different body | silently "duplicate" ✗ | **409** ✓ | silently "duplicate" ✗ |
| Unknown field at ingest | rejected | 422 | 422 |
| Dashboard without credentials | 401 ✓ | **any tenant via demo session** ✗ | 401, but **both tenants' tokens are hard-coded in the JS bundle** ✗ |
| Host-header (DNS rebinding) check / CSP | ✗ / ✗ | ✓ / ✓ | ✗ / ✗ |
| Collector → SaaS transport | HTTPS + HMAC signature, batched | HTTPS + bearer, 1 envelope / 2 s | HTTP in dev (TLS via Caddy overlay) + token, **1 request per metric** |
| Steady state when nothing is injected | Excellent, 0 false alarms (tested) | Excellent | **Poor**: simulator loops fault fixtures, so it can't show a healthy baseline |

## Pros and cons

### Mine: 88 / 100 (P1 9 · P2 21 · P3 31 · P4 27)
**Pros**
- Deepest AIOps: robust baselines learned from normal data, 3-window persistence, peer + traffic test (usage spike ≠ fault), dependency-aware correlation, root-cause ranking, 12 playbooks with reasoning path, confidence factors, alternatives and rollback.
- Only build whose remediation is real end-to-end: 7 policy checks, RBAC (viewer 403), collector executes against a pseudonym, two-sided audit, working rollback.
- Detects secrets locally and reports a "secret found" signal; syslog input; DLP block on egress.
- Strongest global/reliability story: HMAC + replay window, regional residency with 421, contiguous seq gap proof, chaos mode, fastest offline detection.
- Broadest live validation (15 scenarios, measured report).

**Cons**
- No payload-ID conflict detection, no CSP / Host check, collector console unauthenticated (loopback only).
- Slowest alert and dashboard latency (by design, still within targets).
- Validation needs a running stack and ~8 min, with no unit tests or CI; UI is functional rather than polished.

### AegisOps: 75 / 100 (P1 9 · P2 21 · P3 25 · P4 20)
**Pros**
- Most "production-shaped" engineering: JSON-Schema contracts, OpenAPI snapshot, Postgres, Docker network isolation (collector can't reach the DB), CI, ownership and secret-scan governance, 18 docs.
- Best egress-proof screen: raw vs canonical bytes side by side, redacted keys listed, SHA-256 match badge.
- Clean incident explanation (evidence-score formula, uncertainty note), keeps security apart from infra incidents, strict Pydantic `extra='forbid'` schema.
- Largest automated suite (27), fast and CI-ready.

**Cons**
- Thin AIOps: 2 narrative templates, correlation = whole environment + 5-minute window, no root cause, no peer analysis, baseline history includes anomalous points.
- Remediation's "Policy Check PASS" is a hard-coded string, with a single click, no role check, no executor, and rollback as text only.
- Offline detection sits at the 60 s limit; dev transport is plain HTTP; one HTTP request per metric; no region residency enforcement (region is just a field).
- Operator tokens for both tenants ship in the frontend bundle; looping simulator keeps the fleet permanently Poor; heaviest to run (Docker/npm/pip).

### testsub: 71 / 100 (P1 7 · P2 19 · P3 28 · P4 17)
**Pros**
- Tightest core engineering for its size: exact-key wire schema, ID + digest conflict detection (409), ack must echo ID + hash, raw + outbox in one transaction, CSP + Host/Origin checks.
- Fastest live latencies; polished, calm UI with seeded charts; zero dependencies; fast self-contained test.
- NDJSON replay for the organizer stream, tested.

**Cons**
- One synthetic host per site, so correlation is site + source + 30 s. Observed live: a login attack and an unrelated CPU + network fault merged into one "Authentication failures" incident with a login-only recommendation.
- Recommendations are 3 fixed sentences; no root cause, no noise reduction (every sample writes an alert).
- Remediation is a status ledger only; no secret detection signal; demo mode opens any tenant without credentials; offline detection 50 s.

## Verdict

**Best overall for this hackathon: mine (88)**, because the guide weights Phases 3–4, and within
them explainable AIOps, correlation and remediation safeguards most heavily, and that is where the
other two are thinnest. **AegisOps (75)** is the best-engineered *project* (contracts, CI, Docker,
docs) and has the best egress-proof screen, but its intelligence and remediation are shallow and
offline detection is borderline. **testsub (71)** is the cleanest small codebase, with the best
idempotency and web hardening, but its correlation produced a wrong incident in the live test.

Worth borrowing into mine: testsub's 409 conflict check + CSP/Host check, and AegisOps' JSON-Schema
contracts, CI workflow and side-by-side egress view.
