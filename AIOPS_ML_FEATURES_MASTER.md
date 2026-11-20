# ML and statistical features: proposal

> **Project:** End-to-end, secure AIOps observability (CICADA 2026, TechForcz x Atria Institute of Technology)
> **Repository:** `Telemetry-Tracker`
> **Status:** proposal, **not implemented yet**. Nothing below is in the code until its checklist is done.
> **Revision 2:** revised from the first draft after testing its rules against real data. What changed and
> why is listed at the end.

## Summary

Three additions, each aimed at a judging criterion, each small enough to build in a few hours, and each
required to prove itself with measurements before it ships.

| # | Feature | Where | Technique | Problem it solves | Judging phase |
|---|---|---|---|---|---|
| 1 | Entropy-assisted secret detection | Collector (`common/policy.py`) | Normalised Shannon entropy plus character-class and shape rules | Secrets with no keyword in front of them (`8f9b4c12...`) slip past the regex patterns | Phase 1 and 3: local data protection |
| 2 | Deviation share per signal | SaaS (`saas/aiops.py`, `recommend()`) | Robust z-scores combined into an L2 score, shares split into root and symptoms | Shows how much each signal deviated, without confusing symptoms with the cause | Phase 4: explainable AIOps |
| 3 | Seasonal baseline | SaaS (`saas/aiops.py`, `on_point()`) | Hour-of-day profile, existing median/MAD detector run on the residual | A daily peak is not an anomaly; a quiet-hours jump is | Phase 2 and 3: baselines beyond thresholds |

All three use only the Python standard library (`math`, `re`, `collections`, `statistics`).

**On wording:** these are statistical methods, not trained machine-learning models. Present them that way.
Judges respect "a measured statistical rule we can explain" more than "ML" that turns out to be a
threshold.

## Rules every feature follows

1. **A model may decide what to look at, never what leaves the collector.** The allow-list and DLP gate in
   `common/policy.py` keep the final say. These features can add redactions and explanations; they can
   never cause a field to be sent.
2. **Measured, not claimed.** Each feature has acceptance criteria below. It ships only when they pass,
   and the numbers go into the docs from the actual run.
3. **Explainable.** Every decision can be traced to the inputs that caused it and shown on screen.
4. **No regressions.** The unit tests, `tools/benchmark.py` (five seeds) and `tools/verify.py --spawn` must
   still pass.

---

## Feature 1: entropy-assisted secret detection

### The problem

The regex patterns catch secrets with a recognisable shape or a keyword (`password=`, `AKIA...`, `Bearer`).
They miss a bare random token:

```
[INFO] db_pool: acquired connection using 8f9b4c12d9e03fa57b21e84c90d2 at runtime
```

### Why a plain entropy threshold does not work

Shannon entropy measures how random a string looks:

$$H(S) = -\sum_{c} P(c)\,\log_2 P(c)$$

The first draft redacted any token of 16+ characters with digits and letters and $H \ge 3.65$ bits per
character. Tested on ordinary identifiers, that rule flagged:

| Ordinary identifier | Flagged as a secret |
|---|---|
| W3C trace IDs (32 hex) | 42% |
| Git commit SHAs (40 hex) | 69% |
| Request IDs (`req_` + 20 letters/digits) | 99% |
| Kubernetes pod names (`checkout-api-7d4b9c8f6-x2kqz`) | 100% |

Each hit would also have raised a `security.secret_in_log` alert, which means an alert storm on any real
system. It also missed a real random 32-hex key. The reason: hex strings can never exceed 4.0 bits per
character, so a fixed threshold near 3.65 lands in the middle of normal hex IDs.

### The design

Score each candidate token on three things, and redact only when all agree:

1. **Normalised entropy.** Divide $H$ by the maximum possible for the token's alphabet ($\log_2 16 = 4$ for
   hex, about 5.95 for base62, 6 for base64). A value close to 1 means "as random as this alphabet allows".
   Threshold: at least 0.85.
2. **Shape.** Length 20 or more; a mix of upper case, lower case and digits (base62/base64), or hex only
   when it appears next to a hint word (see 3).
3. **Context.** Known identifier shapes are skipped: UUIDs, 32/40/64-character hex IDs (trace IDs, SHAs,
   digests), our own `src-` / `col-` / `fp-` / `tpl-` prefixes, `word-word-hash` pod and container
   names, and tokens inside a field named like an ID (`trace_id`, `request_id`, `commit`, `pod`). A hex
   token is only treated as a secret when a hint word (`key`, `secret`, `token`, `auth`, `credential`,
   `using`, `with`) appears within the three tokens before it.

What happens on a hit:

- the token is replaced with `[REDACTED:possible_secret]` in the redacted view (the raw line stays in the
  local store, as today);
- it is recorded as a local finding;
- it is **not** treated as a confirmed credential. The collector sends one rate-limited
  `security.possible_secret` summary per source per minute (count only), instead of one alert per line.

Nothing about egress changes: log text never leaves the collector, with or without this feature. The
gain is a cleaner local redacted view and an early warning that secrets are being logged.

### Sketch

```python
HINTS = {"key", "secret", "token", "auth", "credential", "using", "with"}
ID_SHAPES = [UUID_RX, re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$"),
             re.compile(r"^(src|col|fp|tpl)-"), re.compile(r"^[a-z]+(-[a-z]+)*-[a-z0-9]{5,10}(-[a-z0-9]{5})?$")]

def normalised_entropy(tok):
    alphabet = 16 if re.fullmatch(r"[0-9a-fA-F]+", tok) else 64
    return shannon_entropy(tok) / math.log2(min(alphabet, len(tok)))

def possible_secret(tok, prev_tokens):
    if len(tok) < 20 or any(rx.search(tok) for rx in ID_SHAPES):
        return False
    is_hex = re.fullmatch(r"[0-9a-fA-F]+", tok) is not None
    mixed = re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok) and re.search(r"[0-9]", tok)
    hinted = any(p.lower().strip(":=") in HINTS for p in prev_tokens[-3:])
    return normalised_entropy(tok) >= 0.85 and (mixed or (is_hex and hinted))
```

### What we drop from the first draft

`segregate_telemetry()` is **not** implemented. It sent every short, plain string field to the SaaS, so
`{"user": "alice", "host": "db-01"}` would have gone out as-is, bypassing the allow-list. Today payloads are
built only from aggregates, and that must not change. If the team wants help with unknown incoming fields,
the safe version is a *local* classifier inside `tools/stream_adapter.py` that labels each field as metric,
label, identifier or free text to suggest a mapping. It never sends anything.

### Acceptance criteria

Two fixture files in `tests/fixtures/`:
- **IDs corpus** (must not be flagged): 2,000 each of trace IDs, SHAs, request IDs, pod names, UUIDs,
  plus normal log sentences;
- **Secrets corpus** (must be flagged): random base62/base64 keys of 20-64 characters, GitHub- and
  Slack-style tokens, AWS-style secret keys, and hex keys preceded by a hint word.

| Measure | Target |
|---|---|
| False positives on the IDs corpus | below 1% overall, and below 2% for each ID type |
| Detection on the secrets corpus | 90% or more |
| Effect on the existing tests and DLP | none |
| Cost per log line | under 50 µs, measured |

---

## Feature 2: deviation share per signal

### The problem

An incident has several signals. Operators want to know how far each one moved, and judges ask "which
signals contributed?" (Phase 4, the highest-weighted criterion).

### The method

For each signal $i$ in the incident, use the robust z-score the engine already computes:

$$z_i = \left|\frac{x_i - \mathrm{median}_i}{\max(1.4826\cdot\mathrm{MAD}_i,\ \mathrm{floor}_i)}\right|$$

Composite deviation score (how far the incident is from normal overall):

$$S = \|\vec z\|_2 = \sqrt{\textstyle\sum_i z_i^2}$$

Share of each signal:

$$w_i = \frac{z_i}{\sum_j z_j}\times 100\%$$

### What changes from the first draft

The first draft added z-scores per *metric name* across all sources. In a cascade the symptoms are the
largest deviations, so it reported, for the real orders-db incident, "latency 74%, CPU 21%" while the root
cause was orders-db CPU. That reads as a contradiction.

Three fixes:

1. Compute shares per **(source, signal)**, not per metric name.
2. Show the **root group** (signals on the ranked root source) separately from **symptoms**.
3. Label it honestly: **"share of total deviation"**. Size of deviation is not cause; the root is chosen by
   onset time and position in the dependency graph, and the text says so.

Event signals (auth bursts, secrets, stale data) have no z-score. They are listed separately instead of
being given an arbitrary weight.

### Worked example (the orders-db cascade scenario, values as shown on the dashboard)

| Group | Source | Signal | z | Share of total deviation |
|---|---|---|---|---|
| Root | orders-db | CPU | 21.0 | 21.2% |
| Root | orders-db | latency | 6.6 | 6.7% |
| Root | orders-db | memory | 4.2 | 4.2% |
| Symptom | checkout-web, host A | latency | 25.2 | 25.5% |
| Symptom | checkout-web, host B | latency | 24.8 | 25.1% |
| Symptom | checkout-api | latency | 17.2 | 17.4% |

Composite score $S = 45.3$. The reasoning line reads:

> "Symptoms carry 68% of the total deviation (latency on checkout-web and checkout-api). The root is
> orders-db (32%, led by CPU at z = 21.0) because it deviated first and the slowed services depend on it."

### Output added to the recommendation

```json
"deviation": {
  "composite_score": 45.3,
  "root": [{"source": "src-bfcdbd862a", "signal": "cpu_pct", "z": 21.0, "share": 21.2}, "..."],
  "symptoms": [{"source": "src-...", "signal": "latency_ms", "z": 25.2, "share": 25.5}, "..."],
  "events": [],
  "note": "share of total deviation; root chosen by onset and dependency position"
}
```

The dashboard shows it as a small bar chart under "Why it was flagged", root bars in one colour and
symptom bars in another.

### Acceptance criteria

| Measure | Target |
|---|---|
| Shares add up to 100% (z-scored signals only) | always |
| The root group is always the ranked root source | always |
| The text never calls a symptom the cause | checked by a unit test on the cascade scenario |
| Effect on detection | none (explanation only) |

---

## Feature 3: seasonal baseline

### The problem

Real traffic has daily patterns. A CPU level that is normal at the evening peak can be abnormal at 3 a.m.
The current baseline (median and MAD over the last 180 normal windows) only knows the last few minutes.

### Why a fast EWMA does not solve it

The first draft proposed $S_t = 0.15\,x_t + 0.85\,S_{t-1}$. Two problems:

- In the draft's code the EWMA was computed but never used for detection, so it changed nothing.
- If it were used, a smoothing factor of 0.15 catches up with a new level in about 4 seconds (half-life
  4.3 windows). A slow fault, such as a memory leak or creeping latency, would become "normal" before it
  was ever flagged. That is the opposite of what we want.

### The design

Learn what is normal *for this hour of the day*, then run the existing detector on the difference:

1. For each series, keep a 24-slot profile: the median value seen in each hour of the day (UTC, or the
   source's local hour from its timezone), updated only from windows that were not anomalous.
2. Once a slot has enough history (at least 3 days' worth of samples for that hour), compute the
   **residual** $r_t = x_t - \mathrm{profile}[\text{hour}(t)]$.
3. Run the existing median/MAD detector, persistence filter and thresholds on the residual instead of the
   raw value. Until a slot has enough history, behaviour is exactly as today.
4. The explanation says which baseline was used: "CPU 71% vs 38% expected at 03:00 (seasonal), z = 9.4".

A slow EWMA ($\alpha = 0.01$, half-life about 69 windows) may be shown as a **trend line** in explanations
("rising 4% per minute"), never as the baseline.

### Demonstrating it in a 24-hour event

A real weekly pattern cannot be shown in a day. The simulator gets a **compressed day**: a 24-slot daily
curve played back over 10 minutes, with the profile's "hour" mapped to simulated time. The demo then shows
the evening peak raising no alert, and the same CPU level at simulated 3 a.m. raising one.

### Acceptance criteria

New benchmark scenarios: `daily_peak` (a normal daily rise that must not alert) and `night_spike` (the same
level at a quiet hour, which must alert).

| Measure | Target |
|---|---|
| False alarms on `daily_peak` | none |
| Detection of `night_spike` | 90% or more |
| Existing scenarios (including `mem_leak`) | precision and recall stay within today's range |
| Before enough history | identical to current behaviour |

---

## Implementation plan

| Step | Work | Depends on | Effort |
|---|---|---|---|
| 1 | Feature 2: deviation shares, root vs symptom split, dashboard bar chart, unit test on the cascade | none | 1.5 h |
| 2 | Feature 1: candidate scoring, ID-shape and context rules, fixture corpora, rate-limited summary event (allow-list gets `security.possible_secret`) | none | 2.5 h |
| 3 | Feature 3: hour-of-day profiles, residual detection, compressed-day simulator mode, two benchmark scenarios | B4 from `bugs.md` (two-sided detection) is recommended first | 3 h |
| 4 | Re-run the unit tests, the benchmark on five seeds and `verify.py --spawn`; put the measured numbers into this document and the README | 1-3 | 1 h |

One feature per commit, each with its tests, following the rules in `plan.md`.

---

## Judge questions and honest answers

**"How do you catch secrets without a keyword like `password`?"**
"Regex patterns catch the known shapes. For the rest, the collector scores each long token on how random
it is for its alphabet, its character mix and its context, and skips known ID formats. On our test corpus
it flags [measured]% of secrets with [measured]% false positives on normal IDs. It can only add
redactions: log text never leaves the collector either way."

**"Which signals contributed, and why scale orders-db and not checkout-api?"**
"The breakdown shows each signal's share of the total deviation. Checkout's latency moved the most, but
it is a symptom: orders-db deviated first and checkout depends on it, so fixing orders-db removes the
cause. The chart shows root and symptoms separately for that reason."

**"How do you tell a normal daily peak from a real anomaly?"**
"Two ways. Peer comparison: if similar hosts rise together with traffic, it is demand. And once there is
enough history, a seasonal baseline: we compare each value with what is normal for that hour. In the demo
we use a compressed day to show it."

**"Is this machine learning?"**
"These are statistical methods: robust z-scores, entropy scoring, seasonal profiles. We chose them because
every decision can be explained and measured."

---

## Changes from the first draft

| First draft | Revision 2 | Why |
|---|---|---|
| Said "implementation" and "59 tests OK" | Marked as a proposal with acceptance criteria | None of the code or tests were in the repository; the repo had 57 tests |
| Entropy threshold 3.65 bits/char | Normalised entropy plus shape and context rules | The threshold flagged 42-100% of normal IDs and missed a real random hex key |
| Entropy hits counted as confirmed credentials | Separate `possible_secret`, rate-limited summary | Avoids one security alert per log line |
| `segregate_telemetry()` routes fields to the SaaS | Dropped; optional local field classifier in the adapter only | It would have sent usernames and hostnames past the allow-list |
| Attribution per metric name | Per source and signal, root vs symptoms, labelled "share of deviation" | The draft reported "latency 74%" when the root cause was CPU |
| Fast EWMA (α = 0.15) as the baseline | Hour-of-day seasonal profile; slow EWMA only as a trend line | The fast EWMA was unused in the draft, and if used it would absorb slow faults in seconds |
| Entropy table: "database connection timeout" 2.91, "checkout-api-service" 3.15 bits/char | Removed | Actual values are 3.53 and 3.65 |
| Example output with packet loss and an "Incident #4 Reasoning tab" | Worked example from the real incident | The example did not match what the system produces |
| Called "ML" throughout | Called statistical methods | It is more accurate, and judges ask |
