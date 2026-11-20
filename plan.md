# Bug fix plan

How we will remove every bug listed in [bugs.md](bugs.md). The order is set by what could hurt us
most in front of judges, not by how easy a fix is.

## Rules for every fix

1. **Test first.** Write a test that fails because of the bug (unit test in `tests/`, or a check in
   `tools/verify.py` when the bug only shows up end to end). Commit nothing until it fails for the
   right reason.
2. **Fix, then run everything.** Unit tests (`python -m unittest discover -s tests -t tests`) must
   pass. For changes to detection or ingest, also run `tools/benchmark.py` and `tools/loadtest.py`
   and compare with the numbers in `docs/`.
3. **One bug, one commit.** Message starts with the bug ID, for example
   `Fix B1: do the TLS handshake in the request thread`. Update the bug's entry in `bugs.md` to
   **Fixed in `<commit>`** in the same commit.
4. **Re-run the full check at the end of each phase:** `python tools/verify.py --spawn` must stay
   16/16, plus any new checks added by the fixes.

## Phase 1: before the next demo (about half a day)

These are the bugs a judge or a stray tool could trigger live, or that would make the proof panels lie.

| Order | Bug | Fix | Test that proves it | Effort |
|---|---|---|---|---|
| 1 | **B1** idle connection freezes ingest | Stop wrapping the listening socket. Accept plain sockets, then do the TLS handshake inside the per-request thread with a 10 s socket timeout. Set a 30 s timeout on all handler sockets (ingest, dashboard, collector console) to stop slow clients pinning threads. | Integration test: open a raw TCP connection to 8443 and leave it idle, then send a signed request. It must succeed in under 1 s. Add the same check to `verify.py`. | 1 h |
| 2 | **B2** one bad payload poisons the batch | SaaS: wrap each payload in a `SAVEPOINT` so a failure rolls back only that payload, which is then returned in `rejected` with the reason. Extend `validate_inbound` to check value formats (ISO timestamps, numeric ranges, known units), not only field names. Collector: a rejected payload is marked `rejected` and the queue moves on; a 4xx for a whole batch makes the collector resend that batch one payload at a time to find the bad one. | Unit test: batch `[valid, malformed-ts]` stores the valid one and rejects the other. Collector test: a rejected payload at the head of the queue does not block later ones. | 2 h |
| 3 | **B5** search reports false leaks | Escape `\`, `%` and `_` in the search term and use `LIKE ? ESCAPE '\'` in both search endpoints. | Unit test: searching `_` and `%` returns 0 outbound matches on a clean store; searching a real injected secret still finds it locally. | 20 min |
| 4 | **B3** future-dated events vanish | Collector: if an event is more than 5 s in the future, keep the raw record but stamp the aggregate with the receive time, count it, and raise a local finding. Send an allow-listed `source.clock_skew` event (count and skew in seconds only) so the SaaS can show "source clock ahead by 5.5 h". Treat timestamps without an offset as the collector's configured timezone, not UTC. | Unit test: an event 1 h ahead appears on the SaaS within one window and a clock-skew event is raised. Unit test: a naive IST timestamp is converted correctly. | 1.5 h |
| 5 | **B6** bandwidth-only source shows "no data" | Track freshness per source from every metric it reports, not only the threshold metrics. | Unit test: a source sending only `bw_in_mbps` stays Excellent and raises no stale alert. | 30 min |
| 6 | **B12** "Heal all" heals every tenant | When no host is given, heal only the hosts of the collector that sent the request. | Unit test on the simulator: heal on one collector leaves another collector's scenario active. | 15 min |
| 7 | **B16** "0.00s" with no samples | Print "not measured (no browser open)" when n is 0. | Run `verify.py` without a browser and read the report. | 10 min |

## Phase 2: correctness and security (about one day)

| Order | Bug | Fix | Test that proves it | Effort |
|---|---|---|---|---|
| 8 | **B4** drops never detected | Give each metric a direction: CPU, memory, disk, latency and loss alert on rises; inbound and outbound traffic alert on both rises and drops; CPU also alerts on a sustained collapse to near zero. Use the same robust z-score with the sign flipped and the same persistence filter. Add a playbook rule for "traffic collapse / service stopped serving". Add `traffic_drop` and `cpu_collapse` scenarios to the simulator and the benchmark. | Unit test: traffic 120 to 0 Mbps for 10 s raises one alert with a "drop" explanation. Benchmark: precision and recall stay at or above the current 95% / 96% with the new scenarios included. | 3 h |
| 9 | **B9** sequence numbers can restart | Store the sequence counter in a `state` table in the collector's local database, updated in the same transaction as the outbox insert. Retention never deletes the newest delivered row. | Test: delete all delivered rows, restart the collector, send one payload; its sequence number continues from the old value and the SaaS reports 0 gaps. | 1 h |
| 10 | **B10** commands stuck in "dispatched" | Add a lease: record `dispatched_ms`; if no result arrives within 60 s, put the command back to `approved` (up to 3 attempts), then mark it `failed` and show a retry button. The collector remembers command IDs it has already executed, so a retried command is not run twice, and it retries posting the result until acknowledged. | Test: the collector fetches a command and "crashes" before reporting; after 60 s the command is re-dispatched and executes exactly once. | 2 h |
| 11 | **B7** no brute-force protection | Count failed logins per username and per client IP. After 5 failures, lock for 30 s, doubling with each further failure, capped at 15 minutes. Write each lockout to the audit log. Keep the constant-time password check. | Test: 6 wrong passwords in a row, then the right one, gets 429 until the lock expires; 40 parallel attempts cannot get more than 5 guesses through. | 1.5 h |
| 12 | **B11** latency SLO can be skewed | Make the server-side number authoritative: when the overview response first includes a point, record server send time minus event time. Keep the browser acknowledgement only as an extra sample, and accept it only if the event timestamp is one the server actually sent to that session and the render time is within 2 s of the server's clock. | Test: posting a fabricated render-ack does not change the reported p95; the server-side p95 is reported even with no browser open. | 1.5 h |

## Phase 3: long-running hygiene (about half a day)

| Order | Bug | Fix | Test that proves it | Effort |
|---|---|---|---|---|
| 13 | **B8** storage grows without limit | Add an hourly retention job to the engine loop, with per-tenant settings: drop payload bodies after 24 h but keep ID, sequence and SHA-256 for the delivery proof; keep metrics 7 days, latency samples 24 h, events and health history 30 days. Run incremental vacuum afterwards. Show the settings on the Thresholds tab. | Test: insert rows with old timestamps, run the job, check what is deleted and that delivery reconciliation still shows 0 gaps. | 2 h |
| 14 | **B14** unbounded caches | Evict detector series and latest values not updated for 1 hour; remove classification entries when their alert resolves; sweep expired sessions on each login; remove chaos `held` entries once a payload is delivered. | Test: after a source goes silent for over an hour (simulated clock), its cache entries are gone. | 1 h |
| 15 | **B15** SaaS forgets sequence state | On startup, load `MAX(seq)` per collector from the payloads table. | Test: restart the app object and send an older sequence number; it is flagged out of order. | 15 min |
| 16 | **B13** wrong CPU interval | Keep separate CPU samplers for the heartbeat and the console. | Test: heartbeat CPU stays stable whether or not the console is polling. | 20 min |
| 17 | **B17** digest mismatch loops forever | After 5 mismatches, mark the payload `ack_mismatch`, stop resending it, report it in the heartbeat stats and the local audit, and show it on the collector console and the fleet view. | Test: a SaaS stub that always returns a wrong digest; after 5 tries the payload stops looping and the collector reports it. | 45 min |
| 18 | **B18** loose `name` / `value` mapping | Use the `name` field as a metric name only when it is paired with a `metric_value` field or the mapping file says so. Read a `unit` field when present and refuse percentage metrics with a non-percentage unit. | Unit test: `{"name": "memory", "value": 512, "unit": "MB"}` produces no `mem_pct`; `{"metric_name": "cpu", "metric_value": 42}` still maps. | 30 min |

## After all phases

- Re-run and commit the benchmark, the load test and the full verification so `docs/BENCHMARK.md`,
  `docs/LOADTEST.md` and `docs/VALIDATION_REPORT.md` reflect the fixed code.
- Update the README limitations section: remove the ones these fixes close, keep the ones that remain
  (plain HTTP dashboard, collector console without login, secrets in config files, single process).
- Push the branch and open a pull request into `main`; CI must be green before merging.

## Total effort

Roughly two working days: half a day for Phase 1, one day for Phase 2, half a day for Phase 3. If time
runs out before the event, Phase 1 alone removes everything a judge could trigger during the demo.
