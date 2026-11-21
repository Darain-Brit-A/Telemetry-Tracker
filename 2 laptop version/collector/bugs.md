# Bugs

Last updated 2026-11-21. **12 open, 9 fixed.**

Every bug marked **Reproduced** was triggered on the running system or in a test, and the result is
quoted. **Code reading** means the cause is visible in the code but the bug was not triggered, usually
because it needs hours of uptime or a crash at an exact moment. File and line references describe the
code at the time of writing.

Each open bug has its own plan below. [plan.md](plan.md) puts them in order with effort estimates.
Rules for every fix: write a test that fails first, fix, run all tests, one bug per commit, then mark
it fixed here with the commit hash.

## Open bugs

| ID | Severity | Bug | How found | Phase |
|---|---|---|---|---|
| B4 | High | Drops are never detected, only rises (dead service, traffic collapse) | Reproduced | 2 |
| B7 | Medium | No brute-force protection on dashboard login | Reproduced | 2 |
| B8 | Medium | SaaS stores grow without limit (no retention on any table) | Reproduced | 3 |
| B10 | Medium | A remediation command can get stuck in "dispatched" forever | Code reading | 2 |
| B11 | Medium | Any logged-in user can skew the dashboard latency SLO | Code reading | 2 |
| B18 | Medium | Adapter mis-maps `name` / `value` fields, and no percentage is range-checked | Reproduced | 2 |
| B9 | Low | Collector sequence numbers restart after 24 h without telemetry plus a restart | Code reading | 2 |
| B21 | Low | A rejected payload's readings stay in the engine's memory | Reproduced | 3 |
| B13 | Low | Collector CPU in heartbeats is measured over the wrong interval | Code reading | 3 |
| B14 | Low | Memory grows without limit in several in-process caches | Code reading | 3 |
| B15 | Low | SaaS forgets per-collector sequence state on restart | Code reading | 3 |
| B17 | Low | An acknowledgement digest mismatch is retried forever with no escalation | Code reading | 3 |

---

### B4. Drops are never detected (High)

**Where:** `saas/aiops.py`, `on_point()`: `if z is not None and z >= Z_OPEN:` checks only the upward
direction.

**Evidence:** unit harness on the real engine, 60 s of normal data, then 20 s with inbound traffic at
0 Mbps (was ~120) and CPU at 2% (was ~40%): **0 alerts**.

**Impact:** a crashed process, a traffic black hole or a dead uplink often shows up as numbers falling.
Unless the collector's reachability or service probe also fails, the platform stays green.

**Plan:** give each metric a direction. CPU, memory, disk, latency and loss alert on rises; inbound and
outbound traffic alert on rises and drops; CPU also alerts on a sustained collapse to near zero. Use
the same robust z-score with the sign flipped and the same persistence filter. Add a playbook rule
"traffic collapse / service stopped serving", and `traffic_drop` / `cpu_collapse` scenarios to the
simulator and the benchmark.
**Test:** traffic 120 to 0 Mbps for 10 s raises one alert with a "drop" explanation; the benchmark
range across five seeds must not get worse than precision 94% / recall 92%.

### B20. Timezone handling depends on an optional package (Medium) - FIXED, see the fixed table

**Where:** `common/util.py`, `_zone()` uses `zoneinfo`, which on Windows has no system timezone
database (`zoneinfo.TZPATH` is empty) and only works if the third-party `tzdata` package is installed.
`_zone()` then falls back to UTC without saying so. Introduced by the B3 fix.

**Evidence:** this machine has `tzdata` installed, which is why every test passed. With it hidden:
`14:30` in `Asia/Kolkata` without an offset was read as `1763649000000` instead of `1763629200000`, i.e.
5.5 hours off, with no warning.

**Impact:** on a stock Windows Python, the B3 fix for offset-less timestamps does nothing, and readings
from such a source show up as clock skew instead of being read correctly. The README promises no
third-party packages. The Windows CI jobs are likely to fail two tests
(`test_offsetless_timestamp_uses_collector_timezone` and the adapter timezone test).

**Plan:** stop depending on a timezone database for the common case. Record a fixed UTC offset per
collector at setup (`utc_offset_min` in the collector config, computed from the IANA name with a
small built-in table for the zones in use) and use it for offset-less timestamps; use `zoneinfo` only
when it is actually available, to get daylight-saving changes right. Log a clear warning once when
a zone cannot be resolved instead of silently using UTC.
**Test:** with `zoneinfo` blocked (the same trick used to reproduce it), `14:30` IST still parses to
`09:00Z`; an unknown zone logs a warning.

### B7. No brute-force protection on login (Medium)

**Where:** `saas/server.py`, `/api/login`. A failed login sleeps 0.5 s in its own request thread,
which slows one attacker thread but not parallel ones.

**Evidence:** 40 wrong-password attempts in parallel finished in 0.75 s (all 401), about 50 guesses
per second from one machine.

**Plan:** count failed logins per username and per client IP. After 5 failures lock for 30 s, doubling
with each further failure, capped at 15 minutes, and return 429 while locked. Write each lockout to the
audit log. Keep the constant-time password check.
**Test:** 6 wrong passwords then the right one gets 429 until the lock expires; 40 parallel attempts
get at most 5 guesses through.

### B8. SaaS storage grows without limit (Medium)

**Where:** nothing in `saas/` ever deletes from `payloads`, `metrics`, `latency`, `events` or
`health_history`. Payload bodies are stored in full.

**Evidence:** after 43 minutes with two collectors, the eu-west store held 2,097 payloads, 55,029
metric rows and 1,895 latency rows, 16.2 MB, roughly 0.5 GB per day for that region.

**Impact:** the disk fills on a long-running demo or pilot, and queries over these tables (overview,
reliability counts, SLO stats) slow down as history grows. The overview poll takes 17-20 ms and
returns 144 KB today.

**Plan:** an hourly retention job in the engine loop, with per-tenant settings: drop payload bodies
after 24 h but keep ID, sequence and SHA-256 for the delivery proof; keep metrics 7 days, latency
samples 24 h, events and health history 30 days; run an incremental vacuum. Show the settings on the
Thresholds tab.
**Test:** rows with old timestamps are deleted by the job, and delivery reconciliation still reports
0 gaps afterwards.

### B10. Remediation commands can get stuck (Medium)

**Where:** `saas/server.py` marks a command `dispatched` when the collector fetches it;
`collector/collector.py`, `execute()`, posts the result once and ignores a failed POST.

**What happens:** if the collector crashes after fetching but before reporting, or the result POST
fails, the action stays `dispatched` forever. There is no timeout, no retry and no way to re-run it.

**Plan:** record `dispatched_ms`; if no result arrives within 60 s, put the command back to `approved`
(up to 3 attempts), then mark it `failed` with a retry button. The collector remembers command IDs it
has executed so a retried command is not run twice, and retries posting the result until it is
acknowledged.
**Test:** the collector fetches a command and "crashes" before reporting; after 60 s the command is
dispatched again and executes exactly once.

### B11. Dashboard latency SLO can be skewed by any user (Medium)

**Where:** `saas/server.py`, `/api/render-ack` accepts `event_ts_ms` and `render_ms` from the browser
and records the difference.

**What happens:** any logged-in user, including a viewer, can post invented values and move the
reported p95 either way; a browser clock that is off also distorts it.

**Plan:** make the server-side number authoritative: record server send time minus event time when an
overview response first includes a point. Keep the browser acknowledgement only as an extra sample,
and accept it only if the event timestamp is one the server actually sent to that session and the
render time is within 2 s of the server's clock.
**Test:** a fabricated render-ack does not change the reported p95; the server-side p95 is reported
even with no browser open.

### B18. Adapter mis-maps `name` / `value`, and no percentage is range-checked (Medium)

**Where:** `tools/stream_adapter.py`, `extract_metrics()`, takes a metric name from `metric_name`,
`metric` **or** `name` and pairs it with `value`. Neither the collector nor the SaaS value checks
reject percentages above 100.

**Evidence:** `--dry-run` on `{"name": "memory", "value": 512, "unit": "MB"}` gives `{"mem_pct": 512.0}`,
and that value would pass every later check and show as a critical fault.

**Plan:** use `name` as a metric name only when it is paired with `metric_value` or a mapping file says
so; read a `unit` field and refuse percentage metrics whose unit is not a percentage. Add range checks
(0-100 for percentage metrics, 0/1 for `reachable` and `svc_up`, non-negative elsewhere) in the
collector before aggregation and in the SaaS value validation added for B2.
**Test:** the record above produces no `mem_pct`; `{"metric_name": "cpu", "metric_value": 42}` still
maps; a payload with `cpu_pct` 512 is rejected by the SaaS with a clear reason.

### B9. Collector sequence numbers can restart (Low)

**Where:** `collector/collector.py` starts the counter from `MAX(seq)` in the outbox at startup;
retention deletes delivered rows older than 24 hours.

**What happens:** if a collector runs for more than 24 hours **without any telemetry**, every numbered
outbox row ages out (heartbeat rows have no sequence number). If it is then restarted, numbering starts
again at 1, so the SaaS flags new payloads as out of order and computes a wrong gap count. Deleting
the collector's data directory has the same effect. (Originally reported as "idle or stopped" and
Medium; stopping is safe because the counter is read before retention runs. Corrected to Low.)

**Plan:** keep the counter in a `state` table in the collector's database, updated in the same
transaction as the outbox insert, and never let retention delete the newest delivered row.
**Test:** delete all delivered rows, restart the collector, send one payload; its sequence continues
from the old value and the SaaS reports 0 gaps.

### B21. A rejected payload's readings stay in the engine's memory (Low)

**Where:** `saas/server.py`, `_store_one()` runs inside a savepoint (B2 fix), but `Engine.on_point()`
updates in-memory state (`latest`, detector series, open-alert keys) as it goes, and a rollback does
not undo that.

**Evidence:** a payload whose processing raised after its CPU reading was handled: the payload was
rejected and the database held 0 rows for the source, but the engine still reported CPU 77% as that
source's latest value.

**Impact:** only after an unexpected processing error. The dashboard can then show a value that was
never stored, and the reading can enter a baseline.

**Plan:** validate and compute everything for a payload first, then apply the in-memory changes only
after the savepoint commits; or snapshot the touched series and restore them on rollback. The first
is simpler: collect the points, write them, and call `on_point` after `RELEASE`.
**Test:** the reproduction above leaves `engine.latest` without the rejected reading.

### B13. Collector CPU in heartbeats measured over the wrong interval (Low)

**Where:** `collector/collector.py`, `self_stats()` resets the CPU sample every time it runs; both the
console (every second) and the heartbeat (every 5 s) call it.

**What happens:** while a console is open, the heartbeat reports CPU over the last ~1 s instead of 5 s,
so the fleet view shows a noisier number.

**Plan:** separate CPU samplers for the heartbeat and the console.
**Test:** heartbeat CPU stays the same whether or not the console is polling.

### B14. Unbounded in-memory caches (Low)

**Where:** `saas/aiops.py` (`series`, `latest`, `cls`, `health`), `saas/server.py` (`SESSIONS`), and the
chaos-mode `held` dict in `collector/collector.py`.

**What happens:** entries are added for every source, alert, session and held payload and never
removed. Fine for a demo; memory only grows over a long run.

**Plan:** evict detector series and latest values not updated for an hour; drop classification entries
when their alert resolves; sweep expired sessions on each login; drop `held` entries once delivered.
**Test:** after a source has been silent for over an hour (simulated clock), its entries are gone.

### B15. SaaS forgets sequence state on restart (Low)

**Where:** `saas/server.py`, `self.max_seq = {}` lives in memory only.

**What happens:** after a SaaS restart, the first payloads from each collector are never flagged as out
of order even when they are, so the counter undercounts.

**Plan:** load `MAX(seq)` per collector from the payloads table at startup.
**Test:** restart the app object and send an older sequence number; it is flagged out of order.

### B17. Digest mismatch retried forever (Low)

**Where:** `collector/collector.py`, `send_once()`: on an acknowledgement digest mismatch the payload
stays pending and is resent.

**What happens:** if the digests ever disagree permanently (for example a serialisation change after an
upgrade), the payload loops forever and only a counter shows it.

**Plan:** after 5 mismatches, mark the payload `ack_mismatch`, stop resending, report it in heartbeat
stats and the local audit, and show it on the collector console and the fleet view.
**Test:** against a stub that always returns a wrong digest, the payload stops looping after 5 tries
and is reported.

---

## Fixed bugs

| ID | Severity | Bug | Fixed in | Proof |
|---|---|---|---|---|
| B1 | Critical | One idle TCP connection to the TLS port froze all collector ingest | `bd9bb4e` | Handshake moved to the connection thread with a timeout. Before: requests timed out after 6 s while an idle client was connected; after: answered in 0.01 s. `tests/test_tls_server.py` and a `verify.py` check |
| B2 | High | One malformed payload failed its whole batch, and the collector retried it forever | `6509154`, `e5c20d3` | Value validation, a savepoint per payload, and the collector isolates a refused payload. Before: the valid payload in the batch was lost; after: stored, with the bad one rejected alone. The follow-up restored throughput (93.7 payloads/s, same as before the fix). `tests/test_poison_batch.py` |
| B3 | High | Future-dated events never reached the SaaS | `45287cd` | Readings more than 5 s ahead are re-stamped and raise a "Clock skew" incident; offset-less timestamps use the site's timezone (but see B20). Before: the host was invisible; after: visible, with an explanation. `tests/test_clock_skew.py` |
| B5 | Medium | Proof-panel search treated `%` and `_` as wildcards and could report false leaks | `e29210e` | Terms escaped. Before: `%` gave 988 false outbound matches; after: 0. (Originally rated High with wrong `_` evidence; corrected.) `tests/test_search.py` |
| B6 | Medium | A source reporting only bandwidth showed as Poor, "no data" | `4b0ff76` | Freshness counts every metric. Before: Poor; after: Excellent, no stale alert. `tests/test_freshness.py` |
| B12 | Low | "Heal all" on one console healed every tenant's simulated faults | `ccdf2ee` | Heal is scoped to the requesting collector. `tests/test_simulator.py` |
| B16 | Low | Validation report printed "render-ack p95 0.00s" with no samples | `c372be4` | Now says "not measured (no browser open)". `tests/test_verify_report.py` |
| B19 | Medium | About 1 in 9,000 payloads was blocked by DLP because its UUID looked like a card number | `20e1a84` | Found by the end-to-end run (16/17). UUIDs are masked before scanning; real card numbers are still caught. Before: one lost window and a sequence gap; after: 17/17. Tests in `tests/test_policy.py` |
| B20 | Medium | Offset-less timestamps were read as UTC on Python without a timezone database (stock Windows); this also failed the Windows CI jobs | this commit | `common/util.py` falls back to a built-in table with EU/US daylight-saving rules for the zones in use (checked hour by hour against the real database for 2025-2027) and warns once for an unknown zone. The whole suite passes with `zoneinfo` blocked. `tests/test_timezone_fallback.py` |
