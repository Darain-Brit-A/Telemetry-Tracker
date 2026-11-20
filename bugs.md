# Known bugs

Found on 2026-11-20 by reading the code and then trying to break the running stack (`python run_all.py`).
Every bug marked **Reproduced** was triggered on the live system and the result is quoted. Bugs marked
**Code reading** were not triggered, usually because they need hours of uptime or a crash at a precise
moment, but the cause is visible in the lines given.

The fix plan is in [plan.md](plan.md).

## Summary

| ID | Severity | Bug | How found | Status |
|---|---|---|---|---|
| B1 | Critical | One idle TCP connection to the TLS port freezes all collector ingest | Reproduced | Fixed |
| B2 | High | One malformed payload makes the whole batch fail, and the collector retries it forever | Reproduced | Fixed |
| B3 | High | Events with a future timestamp never reach the SaaS (device clock or timezone skew) | Reproduced | Open |
| B4 | High | Drops are never detected, only rises (dead service, traffic collapse) | Reproduced | Open |
| B5 | Medium | Search on both proof panels treats `_` and `%` as wildcards and can report false leaks | Reproduced | Fixed |
| B6 | Medium | A source that reports only bandwidth is shown as Poor, "no data" | Reproduced | Open |
| B7 | Medium | No brute-force protection on dashboard login | Reproduced | Open |
| B8 | Medium | SaaS stores grow without limit (no retention on any table) | Reproduced | Open |
| B9 | Medium | Collector sequence numbers restart after a long idle period, corrupting gap detection | Code reading | Open |
| B10 | Medium | A remediation command can get stuck in "dispatched" forever | Code reading | Open |
| B11 | Medium | Any logged-in user can skew the dashboard latency SLO | Code reading | Open |
| B12 | Low | "Heal all" on one collector console heals every tenant's simulated faults | Code reading | Open |
| B13 | Low | Collector CPU in heartbeats is measured over the wrong interval | Code reading | Open |
| B14 | Low | Memory grows without limit in several in-process caches | Code reading | Open |
| B15 | Low | SaaS forgets per-collector sequence state on restart | Code reading | Open |
| B16 | Low | Validation report prints "render-ack p95 0.00s" when there were no samples | Code reading | Open |
| B17 | Low | An acknowledgement digest mismatch is retried forever with no escalation | Code reading | Open |
| B18 | Low | Stream adapter can map a record's `name` / `value` fields as a metric by mistake | Code reading | Open |

---

## B1. One idle TCP connection freezes all collector ingest (Critical)

**Where:** `saas/server.py:547`, `ingest.socket = ctx.wrap_socket(ingest.socket, server_side=True)`

**What happens:** the listening socket is wrapped in TLS, so the TLS handshake runs inside `accept()`
on the server's single accept thread. A client that opens a TCP connection and never sends a
ClientHello blocks that thread. No other collector can connect until the idle client goes away.

**Reproduced:**
```
normal request:                              HTTP 401 in 0.01s
while one idle TCP client is connected:      FAILED after 6.0s (URLError)
after it disconnects:                        HTTP 401 in 0.01s
```

**Impact:** anyone who can reach port 8443 can stop all telemetry with one socket, no credentials
needed. In a demo, a stuck health checker or port scanner would make every collector look offline.
The same server also has no socket timeouts, so slow clients pin threads indefinitely.

**Status: fixed** (commit "Fix B1"). The listening socket stays plain and each connection does its
TLS handshake in its own thread with a 10 s timeout (`common/tlsserver.py`). All handlers now have a
30 s socket timeout. Test: `tests/test_tls_server.py` failed with "handshake operation timed out"
before the change and passes after it; `verify.py` has a regression check. Live re-run of the
reproduction: `HTTP 401 in 0.01s` while an idle client is connected.

## B2. One malformed payload poisons the whole batch (High)

**Where:** `saas/server.py`, `App.ingest` runs the batch in one transaction; the handler turns any
`KeyError` / `ValueError` into HTTP 400 for the entire request (`saas/server.py:387`). The collector
treats a 400 as a transport failure and resends the same batch (`collector/collector.py`, `sender_loop`).

**Reproduced:** a signed batch of one valid payload and one payload whose metric timestamp is
`"not-a-timestamp"`:
```
batch [valid, malformed] -> HTTP 400 "bad request: Invalid isoformat string: 'not-a-timestamp'"
valid payload stored? False
```

**Impact:** the valid payload is lost along with the bad one. Because the collector sends its outbox in
sequence order, the bad payload sits at the head of the queue and is retried forever, so nothing behind
it is ever delivered. Any unexpected exception during processing (not only bad input) has the same
effect. The allow-list check does not catch this because it validates field names, not value formats.

**Status: fixed** (commit "Fix B2"). The SaaS validates value formats (timestamps, finite numbers,
counts) as well as field names, and processes each payload inside its own SQLite savepoint, so an
unexpected error rolls back and rejects only that payload. The collector marks rejected payloads and
moves on; if a whole batch is refused with a 4xx it resends one payload at a time and rejects only
the bad one. Tests: `tests/test_poison_batch.py` (4 tests, all failed before the change). Live
re-run: the valid payload was accepted and stored, the malformed one rejected with
"metrics[0].ts is not an ISO-8601 timestamp".

## B3. Future-dated events never reach the SaaS (High)

**Where:** `collector/collector.py:220` (`_metric`) buckets events by their own timestamp with no sanity
check, and `flush_loop` only flushes a window once wall-clock time has passed its end.
`common/util.py:29` (`parse_iso`) also treats a timestamp without an offset as UTC.

**Reproduced:** 15 readings for host `future-1` stamped one hour ahead:
```
future-1: sent 15 readings -> NOT VISIBLE ON SAAS AT ALL
```

**Impact:** a device whose clock runs ahead, or that sends local time without an offset (for example
IST written as if it were UTC, 5.5 hours ahead), is silently invisible for hours. Nothing tells the
operator why. This is likely with an unfamiliar organizer stream.

## B4. Drops are never detected (High)

**Where:** `saas/aiops.py:201`, `if z is not None and z >= Z_OPEN:` checks only the upward direction.

**Reproduced** (unit harness, real engine): 60 s of normal data, then 20 s with inbound traffic at
0 Mbps (was ~120) and CPU at 2% (was ~40%):
```
alerts raised: 0
```

**Impact:** a crashed process, a traffic black hole or a dead uplink often shows up as numbers
*falling*. Unless the collector's reachability or service probe also fails, the platform stays green.

## B5. Proof-panel search can report false leaks (Medium)

**Where:** `collector/collector.py:638-639` and `saas/server.py:474-475` build `LIKE '%term%'`
without escaping `%` and `_`.

**Reproduced:**
```
collector search '%' : raw_matches_local 4491, egress_matches 988
```
No payload contains a `%`, so all 988 outbound matches are false. `_` matches any single character, so
`pay_oad_id` matched `payload_id`.

**Correction (found while fixing):** the original report also quoted `'_' -> 988 egress matches` as
evidence. That was wrong: every payload genuinely contains underscores (`payload_id`, `cpu_pct`), so
most of those matches were real. Severity lowered from High to Medium: a false positive needs a `%`
in the search term, or an `_` standing in for a character that differs.

**Impact:** "Prove it stayed local" and "Search SaaS store" are the panels judges use to check for
leaks. A false "found in outbound payloads" reads as a data-protection failure on stage.

**Status: fixed** (commit "Fix B5"). Both searches escape `\`, `%` and `_` (`common.util.like_contains`)
and use `LIKE ? ESCAPE '\'`. Tests: `tests/test_search.py` failed before and passes now. Same data,
old query vs fixed query: `%` 1 -> 0, `pay_oad_id` 1 -> 0, `cpu_pct` 1 -> 1. Live re-run after
restart: `%` -> 0 outbound matches, `payload_id` -> 11 (real).

## B6. Bandwidth-only sources show as "no data" (Medium)

**Where:** `saas/aiops.py:454`. Freshness is computed only from the threshold metrics (CPU, memory,
disk, latency, loss) plus `reachable` / `svc_up`.

**Reproduced:** 15 readings of only `bw_in_mbps` / `bw_out_mbps` for host `bw-only-1`:
```
bw-only-1 -> ('Poor', 'no data - last value NOT shown as current')
```

**Impact:** network devices or flow exporters that only report traffic are permanently Poor and also
raise a stale-data alert, which is a false alarm. The same applies to any organizer source whose
fields map only to bandwidth.

## B7. No brute-force protection on login (Medium)

**Where:** `saas/server.py:490`. A failed login sleeps 0.5 s in its own request thread, which slows
one attacker thread but not parallel ones.

**Reproduced:** 40 wrong-password attempts in parallel finished in 0.75 s (all 401).

**Impact:** about 50 password guesses per second from one machine. There is no per-account or per-IP
lockout and no logging of repeated failures.

## B8. SaaS storage grows without limit (Medium)

**Where:** no retention anywhere in `saas/` (there is no `DELETE` on `payloads`, `metrics`, `latency`,
`events` or `health_history`). Payload bodies are stored in full.

**Reproduced:** after 43 minutes with two collectors, the eu-west store held 2,097 payloads, 55,029
metric rows and 1,895 latency rows, 16.2 MB, roughly 0.5 GB per day per region.

**Impact:** the disk fills on a long-running demo or pilot, and queries over these tables (overview,
reliability counts, SLO stats) slow down as history grows. The dashboard overview takes 17-20 ms and
returns 144 KB per poll today; that cost rises with the payload count.

## B9. Collector sequence numbers can restart (Medium)

**Where:** `collector/collector.py:120` starts the counter from `MAX(seq)` in the outbox, and
`collector/collector.py:554` deletes delivered rows older than 24 hours.

**What happens:** if a collector is idle or stopped for more than 24 hours, retention can delete every
outbox row. On restart `MAX(seq)` is empty and numbering starts again at 1. The SaaS still holds the
old sequence numbers, so it flags new payloads as out of order and computes a nonsense gap count
(`max_seq - count`).

**Impact:** the "zero loss, provable by sequence numbers" claim breaks after a long outage, which is
exactly when it matters.

## B10. Remediation commands can get stuck (Medium)

**Where:** `saas/server.py:183` marks a command `dispatched` when the collector fetches it;
`collector/collector.py:519-544` executes it and posts the result once.

**What happens:** if the collector crashes after fetching but before reporting, or the result POST
fails, the action stays `dispatched` forever. There is no timeout, no retry and no way to re-run it
from the dashboard.

## B11. Dashboard latency SLO can be skewed by any user (Medium)

**Where:** `saas/server.py:506`, `/api/render-ack` accepts `event_ts_ms` and `render_ms` from the
browser and records the difference.

**What happens:** any logged-in user (including a viewer) can post fabricated values and push the
reported p95 up or down. A browser clock that is off also distorts it. The guide asks for measured
numbers, so the measurement should not depend on client-supplied timestamps.

## B12. "Heal all" heals every tenant (Low, demo only)

**Where:** `simulator/stream.py:203`. With no target host, heal clears the faults of every host on
every collector.

**What happens:** pressing "Heal all" on the Globex console also ends a scenario running for Acme.
This only affects the simulator, but it can wreck a live demo that runs two scenarios at once.

## B13. Collector CPU in heartbeats measured over the wrong interval (Low)

**Where:** `collector/collector.py:497`. `self_stats()` resets the CPU sample every time it runs, and
both the console (every second) and the heartbeat (every 5 s) call it.

**What happens:** while a console is open, the heartbeat reports CPU over the last ~1 s instead of the
last 5 s, so the fleet view shows a noisier, partly misleading number.

## B14. Unbounded in-memory caches (Low)

**Where:** `saas/aiops.py:108-114` (`series`, `latest`, `cls`, `health`), `saas/server.py:493`
(`SESSIONS`), and the chaos-mode `held` dict in `collector/collector.py:456`.

**What happens:** entries are added for every source, alert, session and held payload and never removed.
That is fine for a demo, but over a long run with many sources or logins memory only grows.

## B15. SaaS forgets sequence state on restart (Low)

**Where:** `saas/server.py:52`, `self.max_seq = {}` lives in memory only.

**What happens:** after a SaaS restart, the first payloads from each collector are never flagged as out
of order even when they are, so the out-of-order counter undercounts.

## B16. Misleading "0.00s" in the validation report (Low)

**Where:** `tools/verify.py:410` prints `browser render-ack p95 0.00s (n=0)` when no browser was open.

**What happens:** the report looks as if a real render latency of zero was measured. It should say
"not measured" when n is 0.

## B17. Digest mismatch retried forever (Low)

**Where:** `collector/collector.py:421`. On an acknowledgement digest mismatch the payload stays pending
and is resent.

**What happens:** if the digests ever disagree permanently (for example a serialisation difference
after an upgrade), the payload loops forever. Nothing escalates, apart from a counter.

## B18. Adapter can mis-map `name` / `value` fields (Low)

**Where:** `tools/stream_adapter.py:143` looks for a metric name in `metric_name`, `metric` **or**
`name`, then pairs it with `value`.

**What happens:** in many formats `name` is just a label, not a metric name. A record such as
`{"name": "memory", "value": 512, "unit": "MB"}` is read as memory at 512%, which immediately looks
like a critical fault. The fallback to `name` is too loose, and units are ignored.
