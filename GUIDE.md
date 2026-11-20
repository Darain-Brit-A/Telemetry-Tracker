# Complete guide: Secure AIOps Observability

Everything in one place: what the system is, how to run it on one laptop or two, what to show, how the AI
works, how it is secured, how to prove it works, and what to do when something goes wrong.

---

## Contents

1. [What this is](#1-what-this-is)
2. [What you need](#2-what-you-need)
3. [Run everything on one laptop](#3-run-everything-on-one-laptop)
4. [Tour of the dashboard](#4-tour-of-the-dashboard)
5. [Collector console and demo scenarios](#5-collector-console-and-demo-scenarios)
6. [Live air-quality data (real, OpenAQ)](#6-live-air-quality-data-real-openaq)
7. [How the AI / ML works](#7-how-the-ai--ml-works)
8. [Health limits: Learned (ML) or Manual](#8-health-limits-learned-ml-or-manual)
9. [Security: what protects what](#9-security-what-protects-what)
10. [Run Tier 1 and Tier 2 on two laptops](#10-run-tier-1-and-tier-2-on-two-laptops)
11. [Feed your own data](#11-feed-your-own-data)
12. [Prove it works: tests, validation, benchmark, load test](#12-prove-it-works)
13. [Suggested 10-minute demo](#13-suggested-10-minute-demo)
14. [Command cheat sheet](#14-command-cheat-sheet)
15. [Troubleshooting](#15-troubleshooting)
16. [Where things are](#16-where-things-are)

---

## 1. What this is

A **two-tier, local-first, metadata-only** observability and AIOps platform.

* **Tier 1, the collector**, runs inside each customer site. It receives raw telemetry (metrics, logs,
  login records, syslog), keeps the raw data **on site**, and sends only **allow-listed metadata** upward:
  numbers, counts, pseudonymous IDs and log-template fingerprints. Secrets in logs are redacted and the
  outgoing payload is scanned again before it leaves.
* **Tier 2, the SaaS**, is multi-tenant. It stores each tenant's metadata in its own region, runs the
  **AI engine** (learned baselines, anomaly detection, correlation, root cause, recommendations) and shows
  everything on a web **dashboard** with role-based access.

```
 Customer site (Tier 1)                                   SaaS (Tier 2)
 ┌───────────────────────────────────┐                    ┌─────────────────────────────────────┐
 │ sources: servers, apps, syslog,   │                    │ ingest  :8443  (mutual TLS 1.3+HMAC)│
 │ air-quality monitors (OpenAQ)     │                    │   allow-list + DLP check again      │
 │        │ loopback only, token     │                    │   per-region SQLite (EU / US / APAC)│
 │        ▼                          │  metadata only     │ AI engine: baselines, anomalies,    │
 │ collector: keeps raw data locally,├───────────────────▶│   incidents, root cause, actions    │
 │ redacts secrets, pseudonymises    │  mutual TLS 1.3    │ dashboard :8080 (login, roles, CSP) │
 │ hosts, allow-list + DLP, outbox   │  + HMAC signatures │                                     │
 └───────────────────────────────────┘                    └─────────────────────────────────────┘
```

Three demo tenants come with it:

| Tenant | Data | Collectors | Region |
|---|---|---|---|
| Acme Retail | simulated servers (checkout web, API, database, cache) | `col-acme-dc1` (Bengaluru DC), `col-acme-cloud` (Frankfurt cloud) | eu-west |
| Globex Finance | simulated servers (billing app, DB, firewall) | `col-globex-nyc` (New York) | us-east |
| India Air Quality | **real, live** air-quality monitors (16, in 4 cities) via OpenAQ | `col-air-blr`, `col-air-del`, `col-air-bom`, `col-air-maa` | ap-south |

Pure Python standard library: no packages to install. `openssl` is used once to create the private
certificate authority.

---

## 2. What you need

* **Python 3.12 or newer** (python.org; tick "Add Python to PATH").
* **openssl** on the SaaS machine. Git for Windows includes it; check with `openssl version`.
  Without it the demo still runs, but without TLS.
* **Git**, to get the code.
* Optional: an **OpenAQ API key** (free at openaq.org) for the live air-quality tenant.

Get the code:

```powershell
git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
```
```powershell
cd Telemetry-Tracker
```

---

## 3. Run everything on one laptop

```powershell
python run_all.py --fresh
```

The first run creates everything automatically (certificates, secrets, tenants, users); `--fresh` wipes
stored data so you start clean. Stop with **Ctrl+C**.

It starts the SaaS, the collectors, the simulator, and (if an OpenAQ key is configured, see section 6)
the live air-quality feed. Wait about **40 seconds** for the baselines to arm.

| Open | Address |
|---|---|
| SaaS dashboard | http://localhost:8080 |
| Collector consoles (customer side) | http://127.0.0.1:9101 (Acme Bengaluru), :9102 (Acme Frankfurt), :9103 (Globex New York), :9104 to :9107 (air: Bengaluru, Delhi, Mumbai, Chennai) |

Demo logins (local demo values, also printed at start):

| User | Password | Sees |
|---|---|---|
| `acme-admin` | `acme-admin-demo` | Acme Retail, can approve actions and change settings |
| `acme-viewer` | `acme-viewer-demo` | Acme Retail, read-only (approvals are refused) |
| `globex-admin` | `globex-admin-demo` | Globex Finance only |
| `cityair-admin` | `cityair-admin-demo` | India Air Quality (live) |
| `cityair-viewer` | `cityair-viewer-demo` | India Air Quality, read-only |

A user never sees another tenant's data; try it by signing in as `globex-admin`.

---

## 4. Tour of the dashboard

| Tab | What it shows | What to point out |
|---|---|---|
| **Operations** | Overall health, open incidents, health counts, noise reduction; **monitoring charts**; incidents with root cause and recommendation; health map; open alerts; health transitions | Click an incident: contributing signals, deviation share per signal (root vs symptoms), reasoning, confidence, the recommended action and Approve / Reject (policy-gated, audited, with rollback) |
| **Fleet & sources** | Every collector (online, version, buffer, sequence gaps) and every source with its latest values and a sparkline | Click a source: detail charts with axes, alert periods shaded, and that source's **learned limits** drawn on |
| **Received metadata (egress proof)** | The exact payloads the SaaS received, and a search box | Search for a raw value (e.g. a secret or attacker IP from the collector's raw store): **0 matches** in the SaaS |
| **Performance & reliability** | Measured latencies (collection → dashboard, alert latency, offline detection), delivery counters, benchmark results | Targets: alert ≤ 15 s, dashboard ≤ 10 s, offline ≤ 60 s |
| **Thresholds & audit** | Health limits per metric (**Learned (ML)** or **Manual**), freshness settings, dependency graph, data residency, audit log | Every change is audited; viewers cannot change anything |

**Monitoring charts** (top of Operations):

* Server tenants: the chosen metric (CPU, latency, memory, packet loss) per source and per site, last 30 min,
  with the safety limit dashed.
* Air tenant: the current value of every monitor grouped by city and coloured by India's CPCB category,
  and a 4-day trend per city with the CPCB limits. Switch PM2.5 / PM10 / NO2 with the selector.

**Times**: the selector in the header switches between UTC, the source's time zone and your local time.

---

## 5. Collector console and demo scenarios

Each collector has a console on its own machine (http://127.0.0.1:9101 and up). It shows what stays
local: the raw event store, the outbox (every payload with its digest and what the data policy dropped),
local findings, the audit log, and **"Prove it stayed local"** search.

Buttons (inject a scenario, then watch the SaaS dashboard):

| Button | What happens | What the SaaS should show |
|---|---|---|
| Secret in raw log | a log line with a password | `security.secret_in_log` summary; the secret itself only in the local raw store |
| Repeated failed logins | sshd brute-force pattern | "Repeated failed logins" alert; usernames and attacker IP never leave |
| CPU off baseline | CPU jumps on one host | anomaly alert in a few seconds, explained against the learned baseline |
| Memory leak | memory climbs steadily | memory anomaly with a rising trend |
| Site latency + loss | network degradation at a site | one incident for the whole site, "network path degradation" |
| Cascading DB saturation | database saturates, dependants slow down | one incident, root cause = the database, symptoms ranked below |
| Disk filling | disk usage climbs | disk alert, clean-up action suggested |
| Service down | health check fails | critical alert, restart suggested |
| Legit fleet-wide load spike | every host busier at once | low-severity "legitimate demand increase", not a fault |
| Source goes silent | a host stops reporting | "no data" shown honestly; the old value is **not** shown as current |
| Out-of-order events | late and shuffled events | placed by event time, no false alarms |
| Night spike (seasonal demo) | a peak at an unusual hour | alert "vs N% expected for this hour (seasonal)" once 3 days of history exist |
| Heal all | ends the scenarios at that site | alerts resolve |
| Simulate SaaS outage | collector cannot reach the SaaS | payloads buffer in the outbox, then drain: zero loss, zero duplicates |
| Chaos | duplicate and out-of-order delivery | duplicates ignored, order restored |

---

## 6. Live air-quality data (real, OpenAQ)

Sixteen official monitors (CPCB and state pollution control boards), four each in **Bengaluru, Delhi,
Mumbai and Chennai**, read through the OpenAQ v3 API.

**Turn it on:** put your key in `config/pollution.json` (git-ignored; never commit a key):

```json
{"api_key": "your-openaq-key"}
```

or set the `AIOPS_OPENAQ_API_KEY` environment variable. `run_all.py` then starts the poller by itself.

**What it does:**

1. At start it sends each monitor's **last 4 days of hourly PM2.5, PM10 and NO2** at their real times. The
   AI engine learns each monitor's normal level from them (and its normal level for each hour of the day,
   from 3 days of history). Readings older than 3 hours only train; they never raise alerts.
2. Every 2 minutes it fetches the latest readings and sends each new measurement once.
3. Data takes the normal secure path: poller → collector `/ingest` (token) → allow-list and DLP → mutual
   TLS → SaaS → AI engine.

**Be aware:** official monitors publish every 15-60 minutes, usually 1-2 hours late. Each card shows how
old its reading is; a monitor with nothing for 3 hours turns stale instead of repeating an old value.

Check the feed without sending anything:

```powershell
python tools/openaq_poller.py --once
```

---

## 7. How the AI / ML works

1. **Learns what is normal, per source and metric.** It keeps a rolling history and computes the
   **median** (typical value) and the **MAD**, median absolute deviation (how much values usually vary).
   Both ignore outliers, so one wild reading barely moves them.
2. **Learns the daily rhythm.** With 3 days of history it learns what is normal **for each hour of the day**,
   so an evening peak is expected while the same value at 4 a.m. stands out.
3. **Scores every reading.** z = (reading − normal) ÷ typical spread. z = 4 means four times further from
   normal than usual.
4. **Ignores blips.** An anomaly opens only after **3 unusual readings in a row** and closes after 5 normal
   ones.
5. **Groups and explains.** Alerts that start close together, on the same site or on services that depend on
   each other, become **one incident**. Sources are ranked as root cause or symptom, each signal's
   **deviation share** is shown, and a recommendation names a likely cause and a policy-gated action.
6. **Spots secrets statistically.** Besides regular-expression rules, the collector flags long random-looking
   tokens by **Shannon entropy** after a hint word like "key" or "token" (only adds redactions; never decides
   what leaves).

Measured, not claimed (see `docs/BENCHMARK.md`, `AIOPS_ML_FEATURES_MASTER.md`):

| What | Result |
|---|---|
| Detector, 60 labelled trials (seed 7), learned limits | precision 95.3%, recall 94%, 0.50 false alarms per host-hour, root cause correct 90%, median detection 3 s |
| Seasonal baseline | daily-peak false alarms in 1 of 20 trials (20 of 20 without it); night spikes caught 20 of 20 |
| Entropy secret detection | 95.5% of 10,000 secrets caught, 0 false positives on 14,000 normal IDs and lines |

---

## 8. Health limits: Learned (ML) or Manual

Each metric has a mode under **Thresholds & audit → Limits**. **Learned (ML) is the default.**

| | Learned (ML) | Manual |
|---|---|---|
| Excellent / Good / Fair limits | per source: its baseline + 2σ / 4σ / 8σ (seasonal when available) | the same three numbers for every source |
| Example | a database that always runs at 88% CPU is Excellent; a web server that normally sits at 30% is Poor at 70% | 88% CPU is Fair for everyone, with a standing alert |
| Threshold alerts | only from the **safety limit** (the manual Fair value); deviations are alerted by the anomaly detector | from all three limits |
| Before a baseline exists | the manual limits apply | |

The **safety limit** keeps learned limits honest: at or above it a source is Poor and alerts, whatever its
history. For air quality it is the CPCB Moderate limit (PM2.5 90, PM10 250, NO2 180 µg/m³), so chronically
polluted air is never called "normal".

Switch a metric: pick Manual or Learned in its row, then **Save thresholds** (admins only; audited).

---

## 9. Security: what protects what

| Path | Protection |
|---|---|
| Source → collector | loopback only (`127.0.0.1`); bearer token on `/ingest`; Host and Origin checks on the console |
| Inside the collector | raw data stays local; allow-listed fields only; hosts pseudonymised with a keyed HMAC; log lines reduced to keyed template fingerprints; secrets redacted (rules + entropy); every payload DLP-scanned before it leaves |
| Collector → SaaS | **mutual TLS 1.3**: the collector trusts only the private CA and checks the server name; the SaaS requires the collector's own client certificate and pins its SHA-256 fingerprint to that collector. Every request is also **HMAC-SHA256 signed** with a per-collector secret and a 5-minute replay window. Redirects are refused |
| Inside the SaaS | tenant from the enrolment, never from the payload; data residency (a request to the wrong region is refused with 421); allow-list and DLP checked again; idempotent storage (`payload_id`); receipts with the SHA-256 of what was stored |
| Dashboard | loopback; PBKDF2-hashed passwords; admin / viewer roles; strict Content-Security-Policy; Host and Origin checks; every change audited |

Not built in (deployment work): encryption of stored data at rest, certificate revocation lists, and a
managed PKI on a separate machine. Details: `HOST_TO_SAAS_SECURITY.md`.

---

## 10. Run Tier 1 and Tier 2 on two laptops

**Laptop A** runs the SaaS (Tier 2). **Laptop B** runs the collectors (Tier 1). Only port 8443 on laptop A
is opened, protected by mutual TLS and signatures. Both laptops must be on the **same network**, set to
**Private**, with clocks within 5 minutes of each other.

### Laptop A (SaaS)

1. Get the code (section 2) and find laptop A's Wi-Fi address:

   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like '*Wi*Fi*' | Select-Object IPAddress
   ```

   Below, replace `192.168.1.20` with that address.

2. Point the setup at it (re-issues only the server certificate; collector certificates stay valid):

   ```powershell
   python setup_env.py --saas-host 192.168.1.20
   ```

3. Settings → Network & internet → Wi-Fi → your network → **Network profile type: Private**. Then, in
   **PowerShell as Administrator**, allow the port:

   ```powershell
   New-NetFirewallRule -DisplayName "AIOps SaaS ingest 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -Profile Private
   ```

4. Export all collectors as one bundle (written to the git-ignored `export` folder):

   ```powershell
   python tools/export_collector.py col-acme-dc1 col-acme-cloud col-globex-nyc col-air-blr col-air-del col-air-bom col-air-maa --out export
   ```

5. Copy `export\collectors-7.zip` (and `config\pollution.json` for the live air data) to a USB stick.
   The zip holds the collectors' secrets and private keys: treat it like a password.

6. Start only the SaaS, then open http://localhost:8080:

   ```powershell
   python run_all.py --saas-only
   ```

### Laptop B (collectors)

1. Join the same network (Private). Install Python 3.12+ and Git, then get the code (section 2).
2. Check laptop A is reachable; it must print `True`:

   ```powershell
   Test-NetConnection 192.168.1.20 -Port 8443 -InformationLevel Quiet
   ```

3. Unpack the bundle into the project folder (change `E:` to your USB drive):

   ```powershell
   Expand-Archive E:\collectors-7.zip -DestinationPath .
   ```
   ```powershell
   Copy-Item E:\pollution.json config\pollution.json
   ```

4. Start all of Tier 1:

   ```powershell
   python run_all.py --collector col-acme-dc1 --collector col-acme-cloud --collector col-globex-nyc --collector col-air-blr --collector col-air-del --collector col-air-bom --collector col-air-maa
   ```

5. Delete the zip and `pollution.json` from the USB stick.

### Check

* Laptop A's dashboard: every tenant's collectors **Online / Excellent** under Fleet & sources, with data.
* Laptop B: each collector console (http://127.0.0.1:9101 to 9107) shows "delivered" climbing with no
  send errors.

You can also move only some collectors: export just those, start laptop A with
`python run_all.py --exclude <id>` (repeat for each), and laptop B with `--collector <id>`.

**Afterwards:** remove the firewall rule (as Administrator) and switch laptop A back to single-machine mode:

```powershell
Remove-NetFirewallRule -DisplayName "AIOps SaaS ingest 8443"
```
```powershell
python setup_env.py --saas-host local
```

More detail and a troubleshooting table: `docs/TWO_MACHINES.md`.

---

## 11. Feed your own data

Any program on the collector's machine can post JSON events to its `/ingest` with the collector's token
(`ingest_token` in `config/collectors/<id>.json`):

```json
[{"type": "metric", "host": "web-01", "ts": "2026-11-20T10:00:00Z", "metrics": {"cpu_pct": 42.0}},
 {"type": "log", "host": "web-01", "level": "ERROR", "message": "payment gateway timeout"},
 {"type": "auth", "host": "web-01", "user": "alice", "src_ip": "10.0.0.5", "result": "failure"}]
```

For files in another format (JSON lines, JSON or CSV with other field names, epoch timestamps, ratios
instead of percentages), use the adapter; it maps fields and replays at the original pace:

```powershell
python tools/stream_adapter.py my-data.jsonl --collector col-acme-dc1
```

Options: `--mapping map.json` (explicit field mapping), `--speed 10` (faster replay), `--keep-ts`,
`--tz Asia/Kolkata` (time zone for timestamps without one), `--dry-run` (print instead of sending).
Syslog can be sent over UDP to the collector's syslog port (5141 and up), from the same machine only.

---

## 12. Prove it works

| Check | Command | Current result |
|---|---|---|
| Unit tests | `python -m unittest discover -s tests -t tests` | 109 tests, all pass |
| End-to-end validation on the running system (18 checks: latency targets, zero loss through an outage, duplicates, tenant isolation, mutual TLS, secrets never leaving, remediation policy, ...) | `python tools/verify.py --spawn` | 18 of 18 pass, report in `docs/VALIDATION_REPORT.md` |
| Detector benchmark (labelled faults, precision / recall) | `python tools/benchmark.py --trials 60 --seed 7` | see section 7; `--threshold-mode manual` to compare |
| Seasonal benchmark | `python tools/benchmark.py --seasonal --trials 20 --seed 1` | see section 7 |
| Load test over mutual TLS | `python tools/loadtest.py --collectors 25 100 200 --seconds 20` | 0 errors and 0 lost at every level; throughput depends on the laptop (`docs/LOADTEST.md`) |

Run `verify.py --spawn` with nothing else running (it starts its own stack on the usual ports). GitHub runs
the unit tests and a benchmark gate on Linux and Windows for every push (`.github/workflows/ci.yml`).

---

## 13. Suggested 10-minute demo

1. **Start** (`python run_all.py --fresh`), sign in as `acme-admin`; show the overview and charts (1 min).
2. **Local-first**: on console :9101 click *Secret in raw log* and *Repeated failed logins*; show the SaaS
   alerts, then search the secret / attacker IP on *Received metadata*: 0 matches. Search the same value
   on the console's *Prove it stayed local*: found locally (2 min).
3. **AI**: click *Cascading DB saturation*; open the incident: one incident, database ranked root cause,
   deviation shares, reasoning, confidence. Approve the action as admin; show that `acme-viewer` is refused
   (2 min).
4. **Not every spike is a fault**: *Legit fleet-wide load spike* → low severity, "legitimate demand" (1 min).
5. **Reliability**: *Simulate SaaS outage* for 20 s, switch off; show zero loss and no duplicates under
   *Performance & reliability* (1 min).
6. **Real data**: sign in as `cityair-admin`; show the city comparison, Delhi's trend, a monitor's learned
   limits, and an "Air quality" incident with its CPCB category (2 min).
7. **Two tiers for real** (optional): run the collectors on a second laptop (section 10) (1 min).

---

## 14. Command cheat sheet

| Task | Command |
|---|---|
| Start everything (clean) | `python run_all.py --fresh` |
| Start only the SaaS | `python run_all.py --saas-only` |
| Start everything except some collectors | `python run_all.py --exclude col-acme-dc1` |
| Start only some collectors (other laptop) | `python run_all.py --collector col-acme-dc1` |
| Re-create config (keeps secrets) | `python setup_env.py` |
| Re-create everything, new secrets and certificates | `python setup_env.py --force` |
| Accept collectors from other machines | `python setup_env.py --saas-host <IP or name>` |
| Back to one machine | `python setup_env.py --saas-host local` |
| Export collectors for another machine | `python tools/export_collector.py <id> [<id> ...] --out export` |
| Seasonal demo with a 10-minute day | `python run_all.py --fresh --compressed-day 600` |
| Check the OpenAQ feed | `python tools/openaq_poller.py --once` |
| Replay your own data | `python tools/stream_adapter.py <file> --collector <id>` |
| Unit tests / validation | `python -m unittest discover -s tests -t tests` / `python tools/verify.py --spawn` |

---

## 15. Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| "Address already in use" / a component exits at start | an earlier run is still running | close the other window, or stop leftover Python processes, then start again |
| Dashboard shows "no data" / everything Fair at first | baselines are still learning | wait about 40 s after start |
| No live air tenant data | no OpenAQ key | create `config/pollution.json` (section 6) |
| Air cards say "stale" | the official monitor has not published for hours | normal for some monitors; it recovers when they publish |
| Laptop B: `Test-NetConnection` prints `False` | firewall rule missing, different network, network set to Public, or the hotspot isolates devices | section 10 step A3; same Wi-Fi; set it to Private; try a normal router |
| Laptop B: certificate error mentioning an IP | laptop A's address changed | on A: `setup_env.py --saas-host <new IP>`, export again |
| Laptop B: `401 client certificate not enrolled` | the bundle came from an older setup | export again on laptop A |
| `401 timestamp outside allowed skew` | clocks more than 5 minutes apart | sync the time on both machines |
| `openssl not found` | openssl not on PATH | install Git for Windows or OpenSSL; without it the demo runs without TLS |
| Wrong times shown | time-zone mode | use the **Times** selector (UTC / source / local) |

---

## 16. Where things are

| Path | What |
|---|---|
| `run_all.py` | starts the whole demo or parts of it (section 14) |
| `setup_env.py` | creates the CA and certificates, tenants, collectors, users, secrets |
| `collector/collector.py`, `collector/ui.html` | Tier 1 collector and its console |
| `saas/server.py`, `saas/aiops.py`, `saas/store.py`, `saas/static/` | Tier 2: API, AI engine, per-region storage, dashboard |
| `common/` | shared code: data policy and DLP (`policy.py`, `data_policy.json`), TLS (`tlsserver.py`), web hardening (`web.py`), signing and time (`util.py`) |
| `simulator/stream.py` | simulated telemetry and the demo scenarios |
| `tools/` | `openaq_poller.py` (live air data), `export_collector.py`, `stream_adapter.py`, `verify.py`, `benchmark.py`, `loadtest.py` |
| `tests/` | unit tests |
| `config/` (git-ignored) | generated secrets, certificates, registry, collector configs, your OpenAQ key |
| `data/` (git-ignored) | stored data of the SaaS and the collectors |
| `export/` (git-ignored) | exported collector bundles |
| `docs/` | architecture, demo script, validation report, benchmark, load test, two-machine guide |
| `HOST_TO_SAAS_SECURITY.md`, `AIOPS_ML_FEATURES_MASTER.md` | security design and ML features in depth |
