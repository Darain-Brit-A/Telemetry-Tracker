# Architecture & technical design (Phase 2)

## 1. Two tiers and the trust boundary

```
 CUSTOMER ENVIRONMENT (Tier 1)                                   │  CENTRAL SAAS (Tier 2, multi-tenant)
                                                                 │
 sources ──HTTP JSON :91xx/ingest──┐                             │
 (servers, apps, network,          │   LOCAL COLLECTOR           │   regional ingest /r/<region>/v1/*
  security)  ──syslog UDP :514x──┐ │   ┌────────────────────┐    │   ┌──────────────────────────────┐
                                 ▼ ▼   │ 1 collect          │    │   │ authenticate (HMAC, skew)    │
                                       │ 2 redact (secrets, │    │   │ residency check (421)        │
   raw store (SQLite, retention) ◄─────┤   PII) + pseudonym │    │   │ allow-list + DLP (reject)    │
   raw logs, auth users/IPs, secrets   │ 3 aggregate (2s    │    │   │ idempotent insert (payload_id)│
   NEVER leave                         │   event-time win.) │    │   │ event-time merge             │
                                       │ 4 analyze locally  │    │   └──────────────┬───────────────┘
                                       │   auth bursts,     │    │                  ▼
                                       │   secret findings, │    │   region DB  (eu-west | us-east)
                                       │   error templates  │    │   tenant_id on every row
                                       │ 5 data policy:     │    │                  ▼
                                       │   allow-list + DLP │    │   AIOps engine: baselines → detect →
                                       │ 6 outbox (egress   │    │   correlate → recommend → health
                                       │   proof, buffer)   │    │                  ▼
                                       └─────────┬──────────┘    │   dashboard :8080 (session, tenant-scoped)
                                                 │ TLS 1.2+ (private CA pinned), HMAC-signed,
                                                 └─────────────────────────────────►  metadata only
                                                 ◄──── commands (approved, simulated) ─────
```

Every network hop:

| Hop | Transport | Auth | Content |
|---|---|---|---|
| source → collector | HTTP JSON on 127.0.0.1, syslog UDP | local only (bind 127.0.0.1) | raw events |
| collector → SaaS `/v1/discover` | HTTPS, CA-pinned | HMAC-SHA256 over ts+method+path+sha256(body) | none |
| collector → SaaS `/r/<region>/v1/ingest` | HTTPS | HMAC, ±300 s replay window | allow-listed metadata batches |
| collector → SaaS `/v1/heartbeat` | HTTPS | HMAC | collector health (allow-listed) |
| collector ← SaaS `/v1/commands` | HTTPS (collector pulls; no inbound port) | HMAC | approved action + pseudonymous target |
| operator → dashboard | HTTP on localhost (TLS + SSO in production) | PBKDF2 password, HttpOnly session | tenant metadata |

## 2. What leaves, what stays

| Stays local (collector only) | Leaves (allow-listed, `common/data_policy.json`) |
|---|---|
| raw log lines, payloads, stack traces | metric aggregates per 2 s window: `avg,min,max,n` for 9 named metrics |
| secrets (passwords, tokens, keys, JWTs, connection strings) | event `category` + `severity` + `count` from a fixed list of 6 categories |
| usernames, source IPs of auth attempts | `context`: a collector-generated template sentence (never raw text) |
| hostnames (→ HMAC pseudonym `src-xxxxxxxxxx`, key never leaves) | `fingerprint`: hash of a log *template* (e.g. `fp-1a2b3c4d`) |
| pseudonym map, local audit, raw retention | source `role`, `service`, `site`, `tz` tags |
| | heartbeat: version, config hash, policy version, buffer depth, CPU/RSS |

Enforcement happens three times: the collector builds payloads only from aggregates and templates,
then `enforce()` strips any non-allow-listed field, then `dlp_scan()` scans the serialized bytes and
**blocks** the payload if a credential pattern survived. The SaaS runs the same allow-list again and
**rejects** (does not repair) anything outside it, plus its own DLP scan.

## 3. Payload schema (`aiops.meta/v1`)

```json
{
  "schema": "aiops.meta/v1",
  "payload_id": "6c0f…-uuid4",          // idempotency key
  "collector_id": "col-acme-dc1",        // must match the HMAC credential
  "seq": 412,                            // contiguous per collector -> gap detection
  "kind": "metrics",
  "created_at": "2026-11-20T09:08:37.272Z",
  "policy_version": "2026.11-v1",
  "window": {"start": "…Z", "end": "…Z"},
  "sources": [{"source_id": "src-bfcdbd862a", "role": "db", "service": "orders-db", "site": "blr-dc1", "tz": "Asia/Kolkata"}],
  "metrics": [{"source_id": "src-bfcdbd862a", "ts": "…Z", "name": "cpu_pct", "avg": 91.2, "min": 88.0, "max": 94.1, "n": 2}],
  "events":  [{"source_id": "src-…", "ts": "…Z", "category": "security.auth_failure_burst", "severity": "high",
               "count": 12, "context": "12 failed sshd logins in 60s, 5 distinct accounts, 2 distinct origins (pattern: password spraying)"}]
}
```

All timestamps are UTC ISO-8601 with milliseconds; each source also carries its IANA timezone so the
dashboard can render UTC, source-local or viewer-local time.

## 4. Reliability: outage, retry, idempotency, ordering

* **Outbox first**: a payload is written to the collector's SQLite outbox *before* sending. That row
  is the egress proof record and the buffer, and it survives collector restarts.
* **Sender**: in seq order, up to 100 payloads per request, exponential backoff capped at 4 s so the
  backlog drains within seconds of reconnect.
* **Ack**: the SaaS returns `accepted`, `duplicates` and `rejected`; both accepted and duplicate IDs
  are marked delivered. At-least-once delivery + idempotent insert = effectively exactly-once.
* **Gap proof**: `seq` is contiguous per collector, so the SaaS computes missing sequence numbers. The
  reliability tab compares collector-created / collector-acked / SaaS-stored counts.
* **Out-of-order**: metrics are keyed `(tenant, source, metric, event_ts)`. A late partial aggregate
  for an already-stored window is *merged* (weighted average, min/max). The online detector ignores
  points older than the newest it has seen, so late data cannot corrupt a baseline.
* **Heartbeats are not buffered**: they are point-in-time. The SaaS marks a collector Poor after 30 s
  of silence (target ≤ 60 s), and its sources go stale (Fair) and then no-data (Poor), never "last good value".
* **Chaos mode** (collector UI) deliberately re-sends delivered payloads and holds others back, to show
  live that the SaaS dedupes and orders correctly.

## 5. Security controls

* Collector authentication: per-collector 256-bit secret, HMAC-SHA256 request signatures, ±300 s
  timestamp window, constant-time compare. The tenant comes from the credential, never from the payload.
* Transport: TLS ≥ 1.2 with a private CA pinned in the collector (hostname verified, strict X.509).
* Collector UI and raw ingest bind to 127.0.0.1 only. The collector initiates all connections (no inbound port).
* Local retention: raw events are purged after a configurable number of minutes (UI-adjustable, audited);
  delivered outbox rows are kept 24 h.
* Auditable transfers: every payload's exact bytes, SHA-256, size, allow-list removals, DLP result,
  attempts and delivery time are kept in the egress log. The SaaS stores the hash of what it received.
* Remediation: pull-based, policy-checked, human-approved, simulation-only, reversible, audited on both tiers.

## 6. AIOps approach

| Stage | Implementation |
|---|---|
| Baseline | per (tenant, source, metric): rolling median + MAD over the last 90 *normal* windows (≥ 15 before arming); anomalous points are excluded so a sustained fault cannot become the new normal |
| Detect | robust z = (x − median) / max(1.4826·MAD, metric floor); open when z ≥ 4 for 3 consecutive windows (persistence filter), clear after 3 normal windows; static thresholds as a backstop (Poor = immediate) |
| Normal spike vs anomaly | peer comparison: if ≥ 60 % of same-role peers deviate together **and** inbound traffic rises, the incident is classified *demand* (severity low, recommend scale-out); peers together without traffic = suspected fleet-wide change; alone = isolated fault |
| Correlate | an alert joins an open incident if it relates to an **active** alert there: same source, service dependency at the same site, network signals at a shared site, same collector, or same demand signal on the same role. Repeats of an open alert key are counted, not re-raised |
| Root cause | score = 0.3·earliest onset + 0.4·upstream-of-other-affected-services + 0.2·severity + 0.1·signal count |
| Recommend | ordered playbook rules over the signal set (collector loss, credential attack, secret exposure, service down, demand, saturation propagating via dependencies, network path, memory leak, disk, generic deviation, error burst, telemetry gap), each with likely cause, chosen action, why that action, alternatives, rollback, confidence factors and reasoning path |
| Act (future, simulated) | catalog of actions with risk / reversibility; policy check (role, catalog, reversible, single target, collector online, cooldown, simulation mode); approval; collector resolves the pseudonym locally and executes in simulation; rollback; audit on both tiers |

## 7. Health model (product states)

| State | Source conditions (configurable) | Collector conditions |
|---|---|---|
| Excellent | all metrics below the first threshold, no active anomaly | heartbeat fresh, no backlog |
| Good | minor threshold band or medium anomaly | late heartbeat, small backlog, recent transport error |
| Fair | elevated band, high-severity anomaly, high security event, **stale data > 10 s** | backlog > 20 payloads, collector CPU > 80 % |
| Poor | critical band, unreachable / service down, critical security event, **no data > 30 s** | **offline > 30 s** |

Every state change is written to the health history with UTC time, previous state and the reason text shown to the operator.

## 8. Scalability path

| Prototype | Production |
|---|---|
| SQLite per region | Kafka/Redpanda per region → ClickHouse/Timescale for metrics, Postgres for incidents, partitioned by tenant |
| one SaaS process | stateless ingest pods behind a regional LB; AIOps workers sharded by `hash(tenant, source)` (the detector is per-series, so it partitions cleanly) |
| in-memory baselines | baselines checkpointed to a state store (rebuilt from the last 5 min on restart today) |
| collector polling for commands | long-poll / gRPC stream; mTLS per collector with short-lived certs from enrolment |
| config file registry | control-plane DB with tenant → region pinning; replication between regions only via an explicit policy record |

Payloads are about 1–4 KB per 2 s window for 4 hosts, so one collector sends about 1 KB/s. 10 000
collectors would send about 10 MB/s per region, well within a single Kafka partition set.
