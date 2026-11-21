# Phase 1: Problem Understanding and Ideation

CICADA 2026, Smart Observability track.
Project: TeleTracker — two-tier, local-first AIOps observability platform.

This document covers what the Phase 1 checkpoint asks for: our understanding of the problem, the
use cases we picked, the feature list and minimum demo, what stays local and what is sent, how
tenants are kept apart, and how we plan to finish inside 24 hours.

---

## 1. The problem in one paragraph

Companies want one place to watch their servers, networks, applications and security events. The
usual way to get that is to ship all the logs to a central platform. Those logs are full of things
that should never leave the building: passwords pasted into error messages, API tokens in request
headers, usernames and IP addresses in login records, customer data inside payloads. Once that data
sits on someone else's platform it is a second copy to protect, a compliance problem, and a target.
Our job is to give the customer a central, intelligent view of their whole estate **without** moving
that raw data out. The collector inside the customer network does the heavy lifting, and the
central SaaS only ever sees numbers, categories and counts.

## 2. Why raw data has to stay local

We looked at this from four sides.

| Concern | What goes wrong if raw logs are shipped | What we do instead |
|---|---|---|
| Security | One breach of the SaaS exposes every customer's secrets and logs | The SaaS never receives secrets, so there is nothing to steal |
| Compliance | Personal data crosses borders and lands in a third party's system | Personal data stays on site; only anonymous metadata moves |
| Data residency | A customer in the EU may not allow their data in a US region | Each tenant's metadata is stored only in the region they chose |
| Cost and noise | Gigabytes of logs per day, most of it never read | A few KB per collector per window: summaries, not text |

The SaaS does not need the raw text to do its job. To say "CPU on the orders database is 40%
above its normal level and the checkout service slowed down six seconds later", it needs the CPU
number, the latency number, a time and a stable identifier for the host. That is all it gets.

## 3. Who uses this and what they need

| User | Where they work | What they need |
|---|---|---|
| Customer IT / security team | Local collector console | See their raw data, prove what left, control retention |
| Operations engineer (customer) | SaaS dashboard, own tenant only | Health at a glance, incidents with reasons, suggested fixes |
| Approver / team lead | SaaS dashboard, admin role | Review and approve a proposed fix, roll it back |
| Platform provider | Ingest and storage | Run many tenants safely without being able to read their logs |

## 4. Use cases we chose

We kept the list short on purpose and picked the scenarios the judges will inject in the final round.

1. **Infrastructure health.** CPU, memory, disk and service availability per host, with four health
   states (Excellent, Good, Fair, Poor) and the reason for each state.
2. **Network latency and packet loss.** Spot a degraded site, show which hosts are affected and how
   it trends over time.
3. **Repeated failed logins.** Detect brute force and password spraying on the collector, and send a
   count and a pattern name, never the usernames or attacker IPs.
4. **Secret leaked into a log.** Catch credentials in raw log lines, redact them locally, and tell
   the SaaS only that it happened and what kind of credential it was.
5. **Collector fleet health.** Online or offline, last seen, version, config hash, CPU and memory of
   the collector, and how many payloads are waiting to be sent.
6. **Several alerts, one problem.** When a database slows down and the services that depend on it
   start timing out, show one incident with a likely root cause instead of six separate alerts.

## 5. Feature list and minimum viable demo

Features are ranked. Everything above the line is the minimum demo we commit to. Everything below
it is planned but can be cut if time runs short.

| # | Feature | Why it matters | Priority |
|---|---|---|---|
| 1 | Local collector: collect, redact, pseudonymize, aggregate | Core of the trust boundary | Must |
| 2 | Allow-list enforcement + egress proof panel (exact bytes and SHA-256 of every payload) | Mandatory in the guide | Must |
| 3 | Authenticated, encrypted link to a regional SaaS endpoint | Security requirement | Must |
| 4 | Local outbox: buffer during outages, replay with no loss and no duplicates | Reliability target | Must |
| 5 | Dashboard with four health states, stale-data handling and state history | Phase 3 requirement | Must |
| 6 | Baseline anomaly detection, not just fixed thresholds | Phase 3 and 4 | Must |
| 7 | Multi-tenant separation | Phase 1 and 2 | Must |
| | **Minimum viable demo line** | | |
| 8 | Correlate related alerts into incidents with a ranked root cause | Phase 4, weighted higher | Should |
| 9 | Explainable recommendations: signals, reasoning, confidence, why this action | Phase 4, weighted higher | Should |
| 10 | Regional ingest and data residency, UTC with source timezone, out-of-order handling | Global-ready bonus | Should |
| 11 | Simulated remediation with policy check, approval, audit and rollback | Bonus challenge | Should |
| 12 | Telling a normal traffic spike apart from a fault | False alarm control | Could |
| 13 | Chaos mode to show duplicate and out-of-order delivery live | Demo strength | Could |
| 14 | Real automated remediation | Out of scope for 24 hours | Won't |

**What the minimum demo looks like:** a raw log with a password goes into the collector. The
collector console shows the password locally and the redacted version next to it. The egress panel
shows the exact payload that left, which has no password in it. The SaaS dashboard shows the same
payload hash, a health state for every host, and an alert when CPU moves off its baseline. Cut the
link, and data piles up locally. Restore it, and every record arrives once.

## 6. What stays local, what is redacted, what is sent

This is the part judges ask about first, so we wrote it down field by field.

### 6.1 Stays on the collector, never transmitted

- Raw log lines, stack traces and request or response payloads
- Passwords, API keys, bearer tokens, JWTs, cloud access keys, private keys, connection strings
- Usernames and source IP addresses from login attempts
- Real hostnames (the SaaS sees an HMAC pseudonym instead; the key never leaves)
- Email addresses and card-like numbers found in logs
- The mapping from pseudonym back to hostname
- The local audit log and raw retention settings

### 6.2 Redaction examples

| Raw line on the collector | What the collector keeps for display | What leaves |
|---|---|---|
| `DB connection failed: postgres://svc_app:Sup3rS3cret!@db-01:5432/orders password=Sup3rS3cret!` | `postgres://[REDACTED:creds]@db-01:5432/orders password=[REDACTED:secret]` | Event `security.secret_in_log`, severity medium, count 1, types `url_creds, kv_secret` |
| `Authorization: Bearer eyJhbGciOi... api_key=sk_live_51Hx...` | `Authorization: Bearer [REDACTED:jwt] api_key=[REDACTED:secret]` | Event `security.secret_in_log`, severity high |
| `sshd: Failed password for invalid user admin from 203.0.113.7` (x20 in 60s) | Kept as is, local only | Event `security.auth_failure_burst`: "20 failed sshd logins in 60s, 8 distinct accounts, 2 distinct origins (pattern: password spraying)" |
| `user anna@example.com signed in` | `user [REDACTED:email] signed in` | Nothing. Routine info logs only feed counts |
| Metric sample from `db-01`: cpu 91.2 | Kept as is, local only | `src-bfcdbd862a`, `cpu_pct`, avg 91.2, min 88.0, max 94.1, n 2, window start time |

### 6.3 Sent to the SaaS (the allow-list)

Only these fields can appear in an outbound payload. Anything else is stripped on the collector and
rejected again by the SaaS.

| Group | Fields |
|---|---|
| Envelope | schema, payload_id, collector_id, seq, kind, created_at, window start/end, policy_version |
| Source tags | source_id (pseudonym), role, service, site, tz |
| Metrics | source_id, ts, name, avg, min, max, n for: cpu_pct, mem_pct, disk_pct, bw_in_mbps, bw_out_mbps, latency_ms, packet_loss_pct, reachable, svc_up |
| Events | source_id, ts, category, severity, count, context, fingerprint, from six fixed categories: auth failure burst, secret in log, error burst, recurring warning, unreachable, service down |
| Heartbeat | version, config hash, policy version, uptime, timezone, CPU, memory, buffer depth, sequence counters, error counts |

Two rules keep this honest:

1. The `context` sentence is generated by the collector from a template. It never contains raw text.
2. The `fingerprint` is a hash of the log *template* (numbers and IDs stripped out). It lets the SaaS
   say "this same error happened 30 times" without ever knowing what the error said.

As a last check, the collector scans the final bytes of every payload for credential patterns. If
anything slips through, the payload is blocked and never sent.

## 7. Metadata-only SaaS flow and tenant separation

```
CUSTOMER SITE (Tier 1)                         |  CENTRAL SAAS (Tier 2)
                                               |
 servers, apps,  --> LOCAL COLLECTOR           |
 network, auth        1 collect                |
 logs                 2 redact + pseudonymize  |
                      3 aggregate (1 s)        |
   raw store  <------ 4 analyse locally        |
   (stays here)       5 apply allow-list + DLP |
                      6 outbox (egress proof)  |
                           |                   |
                           |  HTTPS, signed per collector,
                           +--------------------->  regional ingest (eu-west / us-east)
                                               |      check signature, region, allow-list
                                               |      drop duplicates by payload ID
                                               |             |
                                               |      tenant store in that region only
                                               |             |
                                               |      AIOps: baseline, detect, correlate,
                                               |      recommend, health states
                                               |             |
                                               |      dashboard (login, own tenant only)
                    TRUST BOUNDARY ------------+
```

**Who can see what**

| Data | Customer IT (collector) | Customer ops (SaaS, own tenant) | Other tenants | Platform provider |
|---|---|---|---|---|
| Raw logs, secrets, usernames, IPs, hostnames | Yes | No | No | No |
| Pseudonym to hostname mapping | Yes | No | No | No |
| Metric summaries, event counts, health, incidents | Yes (what was sent) | Yes | No | Stored, not browsed |
| Approve a remediation | No | Admin role only | No | No |

**How tenants are kept apart**

- A collector's credential is bound to exactly one tenant. The SaaS takes the tenant from the
  credential, never from the payload, so a collector cannot write into someone else's data.
- Every row in the SaaS store carries the tenant ID, and every query filters on the tenant of the
  logged-in user.
- Each tenant's data lives only in the region it chose. A payload sent to the wrong region is refused.
- A dashboard user belongs to one tenant. Asking for another tenant's incident returns nothing.

## 8. Global concerns we are planning for from the start

- **Regions:** the collector asks the SaaS which regional endpoint it belongs to and sends only there.
- **Residency:** one store per region. No copying between regions without a policy decision.
- **Time zones:** every event carries a UTC timestamp plus the source's timezone (for example
  `Asia/Kolkata`), so the dashboard can show UTC, source time or the viewer's local time.
- **Late and out-of-order events:** stored by event time, not arrival time, so a delayed reading lands
  in the right place on the chart.
- **Retries:** every payload has a unique ID, so resending after an outage never creates duplicates.

## 9. Plan for simulated telemetry

The organizers will provide a shared stream. Until we have it, and so we can rehearse every judge
scenario, we will build our own simulator that feeds the collector through the same inputs a real
source would use.

- **Inputs used:** HTTP JSON (metrics, app logs, auth records) and syslog over UDP (sshd login lines).
- **Fleet:** 2 tenants, 3 sites in 3 time zones, 11 hosts with roles (web, app, db, cache, network)
  and a service dependency map (web calls api, api calls db and cache).
- **Normal behaviour:** slow waves plus random noise on every metric, routine log lines and
  occasional successful logins, so baselines have something real to learn.
- **Injectable scenarios** (one click each, same every time):
  secret in log, failed logins, CPU spike, memory leak, disk filling, service down, site latency and
  packet loss, cascading database saturation, legitimate fleet-wide load spike, source goes silent,
  out-of-order events, heal all.
- **Organizer stream:** a replay mode reads a JSON-lines file and feeds it in with the original
  timing. When the official stream arrives we only write a small mapping from its fields to ours.

## 10. Can we finish this in 24 hours?

Yes, if we stay disciplined about scope. The plan keeps the minimum demo safe first and only then
adds the scoring features.

### Team roles

Replace Member A to D with your names.

| Member | Owns | Hands over to others |
|---|---|---|
| A: Collector and data protection | Collection inputs, redaction, pseudonyms, allow-list, DLP, outbox, egress panel | Payload format, local API |
| B: SaaS ingest and reliability | Auth, TLS, regional ingest, dedupe, storage, outage and replay, heartbeat and offline detection | Stored data model, delivery counters |
| C: AIOps | Baselines, anomaly detection, correlation, root cause, recommendations, health states, remediation policy | Incident and health data |
| D: Dashboard, simulator and demo | Simulator and scenarios, SaaS dashboard, collector console, validation script, demo script | Final run-through |

The payload schema is agreed in the first hour so all four can work in parallel against it.

### Timeline

| Hours | Goal | Done when |
|---|---|---|
| 0 to 2 | Agree schema and allow-list, set up repo, certificates and keys, simulator skeleton | A fake payload travels end to end |
| 2 to 8 | Collector pipeline, signed TLS ingest, storage, first dashboard page | Minimum demo works, ugly but real |
| 8 to 12 | Outbox and replay, health states, stale handling, baseline detection | Outage test passes with zero loss |
| 12 to 16 | Correlation, root cause, recommendations, remediation flow | Cascade scenario shows one incident with a reason |
| 16 to 20 | Regions and residency, chaos mode, peer comparison, polish both consoles | All Section 8 scenarios run |
| 20 to 22 | Validation script, measure latency targets, fix what fails | Measured report generated |
| 22 to 24 | Rehearse the demo, prepare answers, write limitations | Two clean run-throughs |

### Risks and what we do about them

| Risk | Impact | Mitigation |
|---|---|---|
| Organizer stream format differs from ours | Demo breaks on the day | Keep a mapping layer and replay mode; test the stream the moment it arrives |
| AIOps takes longer than planned | Phase 4 marks drop | Thresholds and baselines first, correlation second, recommendations third; each step is demoable on its own |
| TLS or certificate trouble on judge machines | Link fails | Generate a private CA at setup; keep one-command setup |
| Too many false alarms on noisy data | Judges lose trust | Require the deviation to persist, learn baselines only from normal data, compare peers |
| Running out of time | Unfinished features | Minimum demo line is fixed; anything below it can be dropped without breaking the rest |

## 11. How we will know we succeeded

These are the guide's targets, and we will measure them from timestamps rather than claim them.

| Measure | Target | How we measure |
|---|---|---|
| Collection to dashboard | Within 10 s at the 95th percentile | Event time vs the time the dashboard shows it |
| Threshold breach to alert | Within 15 s | Injection time vs alert creation time |
| Collector offline detection | Within 60 s of last heartbeat | Last heartbeat vs the moment the status turns Poor |
| Backlog after outage | All records delivered, zero loss, zero duplicates | IDs sent by the collector vs IDs stored by the SaaS |
| Secrets | Never present on the SaaS side | Search the SaaS store for the injected secret |

## 12. Questions for the organizers

1. What is the format and delivery method of the shared telemetry stream (file, HTTP, syslog, Kafka)?
2. Will the injected scenarios arrive through the stream, or do we trigger them ourselves?
3. Are the latency targets in Section 2 final?
4. Is a self-signed private CA acceptable for TLS in the demo environment?
5. Will judges inspect the code during Phase 3, or only the running system?
