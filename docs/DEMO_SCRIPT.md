# Live demo script (Phase 4)

Setup: `python run_all.py --fresh`. Put the **collector console** (http://127.0.0.1:9101) and the
**SaaS dashboard** (http://localhost:8080, `acme-admin`) side by side. Wait about 40 s for baselines.

The judges' key question has three parts, and each is answered live:
* **What exactly does the collector send?** Egress proof panel → click a payload → identical SHA-256 on SaaS "Received metadata".
* **Does sensitive data stay local?** Type the secret into "Prove it stayed local" on the collector (found locally, 0 outbound) and into "Search SaaS store" (0).
* **How does metadata become an action?** Open the incident → signals → reasoning path → action → policy → approve → collector executes (simulated) → rollback.

## Section 8 scenarios

| # | Scenario | Do this | Show this |
|---|---|---|---|
| 1 | Raw log contains a secret | Collector: target `web-01` → **Secret in raw log** | Collector raw view: password, bearer token, API key, AWS key highlighted red on the left, `[REDACTED:…]` on the right. Egress panel: newest payload has only a `security.secret_in_log` event with a count and the credential *types*. SaaS: incident "Credential exposed in checkout-web logs" → manual rotation runbook. Search `Sup3rS3cret!` on both sides. |
| 2 | Collector loses SaaS | Collector: **Simulate SaaS outage** | Collector: link "disconnected - buffering locally", buffer depth climbs, payloads stay `pending`. SaaS: collector → Poor about 30 s after the last heartbeat; its sources go Fair (stale), then Poor (no data), never showing old values as current. Click **Restore**: the backlog drains in a few seconds. Performance tab: sequence gaps 0, no duplicates; offline detection measured. |
| 3 | Repeated failed logins | Collector: target `api-01` → **Repeated failed logins** | Collector "Local security findings": accounts and attacker IPs (local only). SaaS: "Credential attack against checkout-api" with counts, distinct-account count and pattern (spraying vs brute force). No usernames or IPs anywhere on SaaS. Recommendation: temporary block, executed by the collector, which alone knows the IPs. |
| 4 | Network latency rises | Console :9102 → **Site latency + loss** | SaaS: one incident "Network path degradation at fra-cloud": every affected source, severity, latency vs baseline with z-score, packet loss; Fleet tab charts show the trend with the alert window shaded. |
| 5 | CPU or memory deviates | Target `db-01` → **CPU off baseline** (or **Memory leak**) | Incident lists the CPU value vs the median ± spread baseline, z-score, onset, peer check ("0/0 peers deviate → isolated, not a usage spike"), confidence factors, and the safe read-only "capture process snapshot" action. The memory leak shows trend %/min → rolling restart. |
| 6 | Several alerts, one incident | :9101 → **Cascading DB saturation** | DB CPU rises first, then web and api latency about 6 s later. One incident with ≥ 5 alerts; correlation reasons ("service dependency checkout-web -> orders-db at blr-dc1"); root-cause ranking puts orders-db first; "Resource saturation on orders-db propagating to dependents" → scale out the *root*, with a stated reason why restarting the dependents was rejected. |
| 7 | Duplicate / out-of-order delivery | :9102 → **Chaos** on + **Out-of-order events**, wait 20 s, chaos off | Performance tab: duplicates ignored and out-of-order payloads counted, late points merged by event time, sequence gaps 0; charts stay smooth. Received tab marks "arrived out of order". |
| 8 | Remediation proposed | In any incident with an automatable action | Policy checklist (role, catalog, reversible, single target, collector online, cooldown, simulation). Sign in as `acme-viewer`: the approve button is disabled, and the API returns 403. As admin: **Approve & run** → collector audit shows `[SIMULATED] … on db-01 (src-…)` → status executed → **Roll back** → rolled_back. All of it is in the audit log on both tiers. |
| + | Normal usage spike (false-alarm control) | **Legit fleet-wide load spike** | All web hosts rise together with inbound traffic → "Legitimate demand increase across the fleet (not a fault)", severity low, scale-out. |
| + | Global-ready | Thresholds & audit tab, Times selector | Residency statement (eu-west); times toggle UTC / source TZ (Asia/Kolkata, Europe/Berlin) / viewer; `globex-admin` sees only Globex, served from the us-east store. |

## Answers to the Section 7 judge questions

**Exactly what data leaves the local environment, and what stays?** Only fields listed in
`common/data_policy.json`: per-window metric aggregates for 9 metric names, events from 6 categories
with severity, count, a generated context sentence and a template fingerprint, source tags
(pseudonymous ID, role, service, site, tz) and collector heartbeat stats. Raw lines, payloads,
usernames, IPs, hostnames and secrets stay in the collector's local store, which has a retention limit.

**How does the collector decide which fields may be sent?** Payloads are assembled only from
aggregates and templates, then `enforce()` keeps only allow-listed keys and values (unknown metric
names or categories are dropped and listed on the egress panel). The SaaS runs the same allow-list
and rejects violations.

**How do you prevent secrets or raw content from leaking by accident?** Raw text is never copied into
a payload. Context strings are generated from templates. As a last line, the serialized payload is
DLP-scanned and blocked if a credential pattern appears. The SaaS DLP-scans again on ingest.

**How are collectors authenticated and data encrypted?** TLS ≥ 1.2 with a pinned private CA and
hostname verification; every request is HMAC-SHA256 signed with a per-collector secret plus a
timestamp (±300 s anti-replay). The tenant is derived from the credential.

**Can you open the egress proof panel and show the last payload?** Yes: collector console, egress
panel, top row. The SaaS "Received metadata" tab shows the same SHA-256.

**Real anomaly vs normal usage spike?** Robust baselines learned only from normal data, a
persistence filter (3 consecutive windows), and peer comparison. If most same-role peers rise
together *with* inbound traffic, it is classified as demand (low severity, scale-out). If one host
deviates alone, it is a fault.

**How do you correlate alerts into one incident?** An alert joins an incident if it relates to an
active alert there: same source, a service dependency at the same site, network signals at a shared
site, same collector, or the same demand signal on the same role. Repeats are counted, not re-raised.
Root cause is ranked by onset, upstream position, severity and evidence.

**Why does the platform recommend this action?** Each incident shows the contributing signals with
value, baseline, z and onset; a numbered reasoning path; confidence with the factors that raised it;
the chosen action with "why this action", alternatives considered and the rollback plan.

**What safeguards are needed before automated remediation?** An action catalog with risk and
reversibility; a policy check (role, reversible, single target, collector online, cooldown); human
approval; execution only by the collector, against a pseudonymous target, in simulation here; a
rollback path; audit on both tiers. Irreversible actions (e.g. credential rotation) stay manual.

**What happens when SaaS is unreachable?** The collector keeps collecting and aggregating, persists
every payload to its outbox, retries with capped backoff, and replays in sequence order on reconnect.
The SaaS marks it offline within 30 s and its sources stale, not healthy.

**How do you avoid losing or duplicating metadata after reconnect?** At-least-once delivery with UUID
payload IDs as a primary key (identical retries are acknowledged and ignored), contiguous
per-collector sequence numbers for gap detection, and event-time merge of metric points. A reused
ID with *different* content is rejected with 409 and audited, and the collector only marks a payload
delivered when the SaaS echoes the SHA-256 of the exact bytes it sent.

**How would you scale?** Measured first: one process handles about 90-107 payloads/s (3,300-3,900
points/s, depending on machine load), which is roughly 100 collectors with zero loss (`tools/loadtest.py`, docs/LOADTEST.md).
Beyond that, partition by region, then tenant, then source: stateless ingest behind regional load
balancers, Kafka per region, a time-series store, and AIOps workers sharded by series (the detector
is per series). See ARCHITECTURE §8.

**Where does the confidence percentage come from?** Two parts, both shown on screen. The rule-based
factors (pattern base, corroborating signals, deviation strength, persistence, dependency position)
are a transparent heuristic. Next to them is the measured detector quality from 60 labelled trials
with extra noise and 800+ harmless blips, repeated on 5 seeds: precision 94-97%, recall 92-100%,
0.3-0.6 false alarms per host-hour
(`tools/benchmark.py`, docs/BENCHMARK.md). We say plainly that the benchmark uses our own simulator.

**Will it work with our stream?** `tools/stream_adapter.py` maps unknown field names, nested or
flat metrics, name/value pairs, ISO or epoch timestamps and ratio values onto the collector input,
and replays at the original pace. The end-to-end verification feeds it a foreign-format file
(epoch-ms `timestamp`, `device`, `cpu_ratio`, string booleans, an unseen host) and checks that the
fault is detected and explained and that the hostname never reaches the SaaS.

**Is the dashboard secure?** Login with PBKDF2 hashes, HttpOnly SameSite cookies, admin and viewer
roles, Host-header allow-list against DNS rebinding, Origin checks on writes, and a strict
Content-Security-Policy with no inline script. It is still plain HTTP on localhost; production would
add TLS and SSO.

**Regions, residency, UTC, out-of-order?** Collectors discover their tenant's regional endpoint. The
SaaS refuses other regions with 421, and each region has its own store. All timestamps are UTC with
the source IANA timezone. Data is ordered and merged by event time; late points never move a baseline backwards.
