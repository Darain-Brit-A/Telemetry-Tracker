# Viva script: Secure AIOps Observability

A speaking script for every phase, the questions judges are likely to ask with short, honest answers, a
live demo order, and a numbers cheat sheet. Lines in quotes are meant to be said more or less as written;
adapt them to your own words. Replace Member A to D with your names (roles as in the Phase 1 plan:
A collector and data protection, B SaaS ingest and reliability, C AIOps, D dashboard and demo).

---

## 0. The 30-second pitch (anyone, first thing)

> "Companies want one place to watch their servers, networks and security events, but their logs are full
> of passwords, tokens, usernames and customer data that should never leave the building. We built a
> two-tier AIOps platform where a collector inside the customer's network keeps all raw data local and
> sends only allow-listed numbers and counts to a multi-tenant SaaS. The SaaS learns what is normal for
> every source, detects anomalies, groups alerts into incidents, names the likely root cause and
> recommends a safe, approved action. And it works on real, live data: 16 official air-quality monitors in
> four Indian cities."

## 1. What our project does (2 minutes)

**Member D:**

> "There are two tiers. Tier 1 is the collector. It runs at each customer site and receives raw telemetry:
> metrics, application logs, login records, syslog, and live air-quality readings. It stores the raw data
> locally, redacts secrets, turns host names into keyed pseudonyms and log lines into pattern
> fingerprints, and builds small metadata payloads from an allow-list. Every payload is scanned for
> secrets once more before it leaves.
>
> Tier 2 is the SaaS. It receives those payloads over mutual TLS 1.3, with every request signed, stores
> each tenant's data in its own region, and runs the AI engine: it learns a baseline for every source,
> scores each new reading, ignores one-off blips, groups related alerts into one incident, ranks the root
> cause, and recommends an action that a human must approve. The dashboard shows health, incidents,
> live charts, the exact metadata received, measured performance, and the audit log."

Three demo tenants:

| Tenant | Data | Shows |
|---|---|---|
| Acme Retail | simulated servers at two sites | incidents, root cause, remediation, outage recovery |
| Globex Finance | simulated servers in New York | tenant isolation, a second region (US) |
| India Air Quality | real air-quality monitors via OpenAQ, 4 cities | real data, learned limits, a sensitive field that stays local |

---

## 2. Phase 1: problem and ideation

**Member A** (2 to 3 minutes):

> "Shipping raw logs to a central platform creates a second copy of every secret, a compliance problem and
> a target. We looked at it from four sides: security, compliance, data residency and cost. The SaaS does
> not need raw text to do its job. To say 'CPU on the orders database is far above normal and checkout
> slowed down six seconds later' it needs a number, a time and a stable identifier. That is all it gets.
>
> Our users are the operations engineer at the customer, who needs to know what is wrong and what to do;
> the security analyst, who needs to know about attacks without seeing usernames; and the provider, who
> runs one SaaS for many customers without ever holding their secrets.
>
> We decided field by field what stays local, what is redacted and what is sent, before writing code."

**What stays local (say this clearly; judges ask it first):** raw log lines and payloads; passwords, API
keys, tokens, JWTs, cloud keys, private keys, connection strings; usernames and IP addresses from login
attempts; real host names and the map back from pseudonyms; email addresses and card numbers; the local
audit log; and for the air feed, each monitor's exact GPS position and our API key.

**What is sent:** allow-listed metric aggregates (average, min, max, count per 1-second window), event
categories with severity and counts, pseudonymous source IDs, and collector heartbeats.

**Likely Phase 1 questions**

| Question | Answer |
|---|---|
| Why not just encrypt the logs and send them? | The SaaS would still have to decrypt them to analyse them, so a SaaS breach would still expose them. Not sending them at all is the only way the SaaS cannot leak them. |
| What use cases did you pick? | Detecting a deviating server, a network problem at a site, a cascading failure with a root cause, brute-force logins, secrets in logs, a collector going offline, and telling real faults from normal demand spikes. |
| How did you plan to finish in 24 hours? | Four owners working in parallel against a payload schema agreed in the first hour; a fixed minimum demo line; anything below it could be dropped. |
| How do you know you succeeded? | Every target in the guide is measured from timestamps, not claimed: see Phase 3. |

---

## 3. Phase 2: architecture and design

**Member B** (3 minutes). Open `docs/ARCHITECTURE.md` or the architecture diagram.

> "The trust boundary is the customer's network edge. Everything raw stays inside it. Only one connection
> crosses it: the collector calls the SaaS over HTTPS. There is no inbound port at the customer; the
> collector even pulls approved remediation commands instead of receiving them.
>
> That connection is mutual TLS 1.3: the collector trusts only our private certificate authority and
> checks the server's name, and the SaaS requires the collector's own client certificate and pins its
> fingerprint to that collector. On top, every request is signed with HMAC-SHA256 using a per-collector
> secret and a timestamp, so it cannot be altered or replayed after five minutes.
>
> Inside the SaaS, the tenant comes from the collector's enrolment, never from the payload. Each tenant
> lives in one region: a payload sent to the wrong region is refused with status 421 and never stored.
> Payloads are idempotent: the same payload ID is stored once, a reused ID with different content is
> rejected, and the collector only marks a payload delivered when the SaaS echoes the SHA-256 of the exact
> bytes it sent."

**Member C** on the AI design (2 minutes):

> "For each source and metric we keep a rolling median and median absolute deviation, which ignore
> outliers, and with three days of history the normal level for each hour of the day. Every reading gets a
> z-score; an anomaly needs three unusual readings in a row and clears after five normal ones. Alerts that
> start close together on related services become one incident, the root cause is ranked by onset time,
> position in the dependency graph, severity and evidence, and the recommendation comes with its
> reasoning, confidence, alternatives and rollback plan. Health limits are learned per source by default,
> with a fixed safety limit that always applies."

**Likely Phase 2 questions**

| Question | Answer |
|---|---|
| How does the collector decide what may be sent? | Payloads are built only from aggregates and templates, then filtered against the allow-list in `common/data_policy.json`. Unknown fields are dropped and shown on the egress proof panel. The SaaS applies the same allow-list again. |
| Can the customer change the allow-list? | Only to make it stricter. The collector console lists every allowed item as a ticked box; unticking one stops it leaving the site from the next payload, and the change is audited. Adding a field is refused at the site: the SaaS would reject it, so it needs a new policy version agreed on both sides. |
| What if a developer accidentally puts raw text in a payload? | The serialized payload is scanned for secrets (rules plus an entropy check) right before sending, and blocked if anything is found. The SaaS scans again on arrival. |
| What if a collector's secret is stolen? | It is useless without that collector's private key (mutual TLS), and vice versa. You disable the collector in the registry and re-enrol it. |
| How are tenants kept apart? | Tenant derived from the credential, per-tenant queries, per-region stores; the validation run shows Globex requesting Acme incident IDs gets nothing. |
| What happens when the SaaS is down? | The collector keeps collecting, stores every payload in a local outbox (SQLite, survives restarts), retries with backoff and replays in order. Zero loss, zero duplicates, measured. |
| How would it scale? | Measured on one laptop process: tens of payloads per second per core with zero loss. Production: stateless ingest pods behind a queue per region, AI workers sharded by source, a time-series store. The detector works per series, so it partitions cleanly. |

---

## 4. Phase 3: implementation and validation

**Member D** (2 to 3 minutes):

> "Everything is pure Python standard library: no third-party packages. We did not want to claim targets,
> so we measured them. `tools/verify.py` starts the whole system and runs 18 end-to-end checks against it:
> latency targets, a secret in a log, brute-force logins, anomaly detection, an organiser-format stream with
> unknown field names, network degradation, correlation and root cause, remediation with approval and
> rollback, collector offline detection, a SaaS outage with zero loss, duplicate and out-of-order delivery,
> mutual TLS, tenant isolation and normal demand spikes. All 18 pass. There are also 117 unit tests, and a
> detector benchmark with labelled faults that runs in CI on Linux and Windows for every push."

**Member C** on measured AI quality:

> "On 60 labelled trials the detector has 95.3% precision and 94% recall, 0.5 false alarms per host-hour,
> picks the right root cause 90% of the time, and detects a fault in a median of 3 seconds. Learned limits
> beat fixed limits on false alarms: 0.50 versus 0.64 per host-hour, with the same recall. The seasonal
> baseline removes daily-peak false alarms (1 in 20 trials instead of 20 in 20) while still catching
> spikes at unusual hours in 20 of 20. Entropy-based secret detection catches 95.5% of 10,000 secrets with
> zero false positives on 14,000 normal IDs."

**Be honest about limits** (judges respect this):

> "We keep a public bug list. 12 issues are open, the biggest being that the detector only catches rises,
> not drops, such as traffic collapsing to zero. Data at rest is not encrypted by the application; that is
> left to encrypted disks. The air-quality data is real but arrives one to two hours late, because that is
> when the government publishes it."

**Likely Phase 3 questions**

| Question | Answer |
|---|---|
| Is it really AI? | It is statistical machine learning: models learned from each source's own data (robust baselines, seasonal profiles, entropy), plus explainable correlation and ranking. We chose explainability and measured accuracy over a black box, and every number is reproducible with `tools/benchmark.py`. |
| Why not deep learning? | No labelled training data from customers (it stays local by design), it must run on modest hardware, and operators need to see why something was flagged. Our methods learn per source from a few minutes of data and explain every decision. |
| What is simulated and what is real? | The server tenants (Acme, Globex) are simulated with realistic faults. The air-quality tenant is real, live data from official monitors via OpenAQ. The pipeline, security, storage and AI are the same for both. |
| How do you know there is no data loss? | The collector numbers every payload; the SaaS stores payload IDs. After an outage we compare IDs sent with IDs stored: equal, and no gaps in the sequence. |
| How did you test security? | The validation run checks a forged signature (401), another collector's certificate (401), no certificate and TLS 1.2 (refused at TLS), the wrong region (421), and that injected secrets, attacker IPs and usernames never appear in the SaaS store. |

---

## 5. Phase 4: live demo (10 minutes)

**Before the viva:** `python run_all.py --fresh`, wait 40 seconds. Open three tabs: the dashboard
(http://localhost:8080, signed in as `acme-admin` / `acme-admin-demo`), the Acme collector console
(http://127.0.0.1:9101) and the Bengaluru air collector console (http://127.0.0.1:9104). The air feed
needs internet; the rest does not.

| # | Click | Say |
|---|---|---|
| 1 | Dashboard, Operations | "This is Acme's health: four summary cards, live charts per source and site, incidents, the health map. Everything here is metadata." |
| 2 | Console :9101, *Secret in raw log* | "A password just appeared in an application log on the customer side." |
| 3 | Dashboard | "The SaaS got a security event saying a credential was found and redacted, but not the password." |
| 4 | Console, search `Sup3rS3cret!` (the injected password) with *Prove it stayed local* | "Found in the local raw store, zero matches in outbound payloads." |
| 5 | Dashboard, Received metadata, search `Sup3rS3cret!` | "Zero matches in the SaaS store. That is the core promise, proven live." |
| 6 | Console, *Repeated failed logins* | "Brute force detected locally: the SaaS learns the count of accounts and origins, never the usernames or the attacker's IP." |
| 7 | Console, *Cascading DB saturation*; open the incident | "Several alerts on several sources became one incident. The database is ranked root cause because its anomaly started first and the others depend on it. Here is the reasoning, the confidence and the share of deviation per signal." |
| 8 | Approve the action as admin | "Actions are policy-checked, need approval, run only through the collector, are audited and can be rolled back. A viewer cannot approve." |
| 9 | Console, *Fleet-wide load spike* | "Not every spike is a fault: all web servers rising together with traffic is classified as demand, low severity." |
| 10 | Console, *Simulate SaaS outage* for 20 s, then restore; Performance & reliability | "The collector buffered every payload and replayed it: no gaps, no duplicates." |
| 11 | Sign in as `cityair-admin` | "Now real data: 16 official monitors in four cities. Delhi's evening pollution peaks, colour-coded by India's CPCB categories." |
| 12 | Console :9104, raw events; then search a latitude | "Each monitor's exact GPS position is treated as sensitive. It is highlighted here, redacted on the right, and searching it on the SaaS finds zero matches, while all the readings are there." |
| 13 | (optional) Console :9101, *Data allow-list*, untick `mem_pct`; open the newest metrics payload | "The customer decides what leaves, but only in one direction. Memory is now removed before the payload is hashed; the egress proof says so, the SaaS still accepts it, and the change is in the audit log. Tick it again to restore." |
| 14 | (optional) Thresholds & audit | "Limits are learned per source by default; a safety limit always applies; every change is audited." |

**If something goes wrong:** say what happened and move on. If the internet is down, skip steps 11 and 12;
everything else is local. If a scenario does not show, click *Heal all* and run it again after 20 seconds.

**Optional, two laptops:** with the collector running on a second laptop (`start_server.bat` here,
`start_collector.bat` there), show the header line "Tier 1: ... on another machine" and the *Connected from* column under Fleet & sources.

---

## 6. Hard questions and honest answers

| Question | Answer |
|---|---|
| What is the weakest part of your system? | Drops are not detected yet (bug B4), there is no login lockout on the dashboard (B7), and storage has no retention limit (B8). All are written up with a fix plan in `bugs.md`. |
| Could the SaaS operator still learn something sensitive? | Only what is allow-listed: numbers, categories and counts, plus service and site labels the customer approved. Host names are keyed pseudonyms whose key never leaves the collector. |
| What if the collector itself is compromised? | Then raw data at that site is exposed, as it would be on any host. The design limits the blast radius: one site, never the central store. |
| Why should we trust your numbers? | Every number is produced by a script in the repository and can be re-run: `tools/verify.py --spawn`, `tools/benchmark.py`, `tools/loadtest.py`, and the unit tests. |
| What would you build next? | Detecting drops, login lockout, data retention, a managed certificate authority with short-lived certificates, and a queue-based ingest for scale. |
| Why Python and no packages? | It runs anywhere with one command and no installation, which matters for a collector deployed at many customer sites, and every security-relevant line is ours to review. |

---

## 7. Numbers cheat sheet

| What | Number |
|---|---|
| End-to-end validation | 18 of 18 checks pass |
| Unit tests | 117 pass (CI on Linux and Windows) |
| Alert latency | p95 3.8 s (target 15 s) |
| Collection to dashboard | p95 about 2.4 s (target 10 s) |
| Collector offline detection | about 30 s (target 60 s) |
| SaaS outage | zero loss, zero duplicates |
| Detector (60 labelled trials) | precision 95.3%, recall 94%, 0.50 false alarms per host-hour, root cause 90%, median detection 3 s |
| Learned vs fixed limits | 0.50 vs 0.64 false alarms per host-hour, same recall |
| Seasonal baseline | daily-peak false alarms 1/20 (20/20 without), night spikes caught 20/20 |
| Secret detection (entropy) | 95.5% of 10,000 secrets, 0 false positives on 14,000 normal IDs |
| Live data | 16 monitors, 4 cities, 4 days of history, CPCB categories |
| Security | mutual TLS 1.3, pinned client certificates, HMAC-SHA256 with 5-minute replay window, allow-list and DLP on both tiers, 3 regions |

## 8. Checklist before you walk in

- [ ] `python run_all.py --fresh` started at least 2 minutes before (baselines and air history loaded)
- [ ] Three tabs open and signed in (dashboard, :9101, :9104); know the logins (`acme-admin`, `acme-viewer`, `cityair-admin`, all with `-demo` passwords)
- [ ] Each member has rehearsed their section and can answer their phase's questions
- [ ] Everyone can say the 30-second pitch and the "what stays local" list from memory
- [ ] Laptop charger, internet for the air feed, and a fallback plan if it is offline
- [ ] `docs/VALIDATION_REPORT.md` and `docs/BENCHMARK.md` ready to show as evidence
