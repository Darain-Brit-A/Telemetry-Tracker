# Bug fix plan

The order in which we fix the open bugs in [bugs.md](bugs.md). Each bug's fix and test are described
in its entry there; this file sets the order and the effort.

## Rules for every fix

1. **Test first.** Write a test that fails because of the bug (unit test in `tests/`, or a check in
   `tools/verify.py` when the bug only shows up end to end). Do not commit until it fails for the
   right reason.
2. **Fix, then run everything.** `python -m unittest discover -s tests -t tests` must pass. For changes to
   detection or ingest, also run `tools/benchmark.py` on several seeds and `tools/loadtest.py`, and
   compare A/B against the previous commit, interleaving the runs so machine load affects both
   equally.
3. **One bug, one commit.** The message starts with the bug ID, for example `Fix B20: ...`. Move the bug
   to the "Fixed" table in `bugs.md` with its commit hash.
4. **End of each phase:** `python tools/verify.py --spawn` must pass every check. Add a check when a fix
   is only visible end to end.

## Phase 1: demo blockers (done)

B1, B2, B5, B3, B6, B12 and B16 are fixed, plus B19, which the end-to-end run found afterwards. The
verification passes 17/17. Commits are listed in the "Fixed bugs" table in `bugs.md`.

## Phase 2: correctness and security (about one day)

| Order | Bug | Why in this position | Effort |
|---|---|---|---|
| 1 | **B20** timezone falls back to UTC without `tzdata` | Introduced by the B3 fix, and the Windows CI jobs are likely to fail on it as soon as the pull request opens | 1 h |
| 2 | **B4** drops are never detected | The biggest remaining detection gap; a dead service can stay green | 3 h |
| 3 | **B18** loose `name` / `value` mapping, no range checks | An organizer stream with a `name` field could raise false critical alerts on stage | 45 min |
| 4 | **B10** commands stuck in "dispatched" | The remediation demo could hang with no way to recover | 2 h |
| 5 | **B7** no login lockout | Judges ask about authentication; cheap to fix | 1.5 h |
| 6 | **B11** latency SLO can be skewed | The performance numbers must not depend on client-supplied timestamps | 1.5 h |
| 7 | **B9** sequence numbers can restart | Narrow trigger, but it undermines the zero-loss evidence | 1 h |

After B4, re-run the benchmark on five seeds and update `docs/BENCHMARK.md` and every doc that quotes
its ranges.

## Phase 3: long-running hygiene (about half a day)

| Order | Bug | Why | Effort |
|---|---|---|---|
| 8 | **B8** no retention | The disk fills on a long pilot and queries slow down | 2 h |
| 9 | **B21** rejected payload stays in engine memory | Shows values that were never stored, after an unexpected error | 1 h |
| 10 | **B14** unbounded caches | Memory growth over long runs | 1 h |
| 11 | **B15** sequence state lost on SaaS restart | Undercounted out-of-order payloads | 15 min |
| 12 | **B13** wrong CPU interval in heartbeats | Noisy fleet view | 20 min |
| 13 | **B17** digest mismatch loops forever | Silent stuck payload in a rare case | 45 min |

## After all phases

- Re-run and commit the benchmark (five seeds), the load test and the full verification, so
  `docs/BENCHMARK.md`, `docs/LOADTEST.md` and `docs/VALIDATION_REPORT.md` match the fixed code.
- Update the README limitations: remove the ones the fixes close, keep the ones that remain (plain HTTP
  dashboard, collector console without login, secrets in config files, single process).
- Open a pull request into `main`; CI must be green before merging.

## Total remaining effort

About one and a half working days: one day for Phase 2, half a day for Phase 3. If time is short before
the event, do B20, B4 and B18 first: together they remove the CI failure and the two problems most
likely to show up in a live demo.
