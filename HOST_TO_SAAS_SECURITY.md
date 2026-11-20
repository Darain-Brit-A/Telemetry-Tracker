# Securing Telemetry-Tracker from host to SaaS

This document describes what the code in this repository **actually does** to protect telemetry on its way
from a customer host to the SaaS, what it does not do yet, and what a real deployment would add. Every
"implemented" claim below names the file that implements it.

In short: collectors talk to the SaaS over **TLS (1.2 or newer) pinned to a private CA**, every request is
**signed with a per-collector HMAC-SHA256 key** bound to one tenant, and only **allow-listed metadata** ever
leaves the host. Raw logs stay on the customer's machine.

## What no cipher can fix

The SaaS has to read the metadata it receives in order to calculate health and incidents, so a compromised
SaaS process could read that metadata. A compromised customer host could read events before anything is
filtered or encrypted. Encryption protects the path between the two, not the endpoints.

For any value that even the SaaS operator must never see, compute the result on the collector and keep the
original on the customer's host. That is the design here: the collector sends counts, rates and template
fingerprints, and keeps usernames, IP addresses and raw log lines local.

## What each part of the path protects

| Path | Implemented protection | Who can read the data |
| --- | --- | --- |
| Host process to local collector | The collector listens on **loopback only** (`127.0.0.1`): HTTP `/ingest` for JSON events and UDP for syslog. The HTTP console rejects foreign `Host` headers (DNS rebinding) and cross-site writes (`Origin` check). `collector/collector.py` | The producer and the collector see raw events. There is **no token** on the local `/ingest`; it relies on the host's OS isolation, so keep both processes on the same machine. |
| Inside the collector | Raw events are stored locally (`data/`). Before anything is sent, events are reduced to allow-listed fields (`common/data_policy.json`), host names become keyed pseudonyms (HMAC-SHA256 with a per-collector salt), log lines become template fingerprints, secrets are redacted (regex rules plus the entropy check), and every outgoing payload gets a DLP scan. If the scan finds anything, the payload's metrics, events and sources are emptied and only that empty marker is sent, so sequence numbers stay continuous. `common/policy.py`, `collector/collector.py` | Raw events and the pseudonym salt stay on the host. Service and site labels that the policy allows are visible to the SaaS. |
| Collector to SaaS | HTTPS to the ingest port. The collector trusts **only the private CA** in its `ca_file` and checks the server's hostname (`ssl.create_default_context(cafile=...)`). The server requires **TLS 1.2 or newer** (`saas/server.py`). Every request carries `X-Collector-Id`, `X-Timestamp` and `X-Signature`: an HMAC-SHA256 over the timestamp, method, path and SHA-256 of the body, using a 256-bit secret unique to that collector. `common/util.py` | Network observers see connection timing, sizes and endpoints, but not content. The SaaS can read the permitted metadata. |
| Inside the SaaS | Rejects unknown collectors and bad signatures; rejects timestamps more than **5 minutes** off (replay window). The collector's tenant comes from its enrolment, not from the payload. Data residency: a request for the wrong region gets `421` with the correct region. The payload is checked again against the allow-list and DLP scan, de-duplicated by `payload_id` (a reused ID with a different body gets `409`), and acknowledged with a SHA-256 digest of the stored bytes. The collector keeps the payload in its outbox until the digest matches. `saas/server.py` | The ingest service and the tenant's authorised users, within their roles. SQLite files, journals and backups are **not encrypted** by the application. |
| SaaS dashboard | Loopback only (`127.0.0.1:8080`), PBKDF2-SHA256 password hashes (120,000 rounds), per-tenant roles, strict Content-Security-Policy, `Host` and `Origin` checks. `saas/server.py`, `common/web.py` | Authorised tenant users. |

TLS encrypts and authenticates each session. With the ephemeral key exchange that modern TLS uses, stealing
the server's certificate key later does not by itself reveal past traffic ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)).
Filtering on the host also limits what a later SaaS compromise could expose.

## Run the secured localhost demo

```powershell
python setup_env.py
python run_all.py
```

`setup_env.py` uses `openssl` to create a private CA and a server certificate for `localhost` / `127.0.0.1`,
and enrols each collector with its own random HMAC secret and pseudonym salt. If `openssl` is not on the
`PATH`, it prints a warning and the demo runs **without TLS** (HMAC signing still applies).

Open the dashboard at [localhost:8080](http://localhost:8080). The demo intentionally shows raw local
telemetry in the collector consoles and uses published demo accounts; it is not a production configuration.

## Not implemented yet

These are reasonable next steps, but **none of them is in the code today**:

| Gap | Why it matters | What it would take |
| --- | --- | --- |
| TLS 1.3 only | Removes older cipher suites and renegotiation | One line: `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` in `saas/server.py`, plus a test |
| Mutual TLS (client certificates) | Collector identity would no longer depend only on a shared HMAC secret; a stolen secret alone could not be used without the private key | `setup_env.py` issues a `clientAuth` certificate per collector; the server sets `CERT_REQUIRED` and maps the certificate fingerprint to the enrolled collector |
| Token on the local `/ingest` | Another local user or process could currently feed events to the collector | A random token in the producer's and collector's environment, checked on every local request |
| Redirect refusal | The collector uses `urllib`, which follows redirects (TLS and the pinned CA still apply to the target) | A custom redirect handler that refuses all 3xx responses |
| Keyed log-template fingerprints | Template fingerprints are a plain SHA-256 prefix, so someone who guesses a template can confirm it | Use the pseudonym salt (HMAC) for fingerprints too |
| Encryption at rest | SQLite files, journals and backups are plain files | Encrypted disks or volumes on both tiers |
| CA key separation | In the demo, the CA private key sits in `config/certs/` next to the certificates | Keep the CA key in a managed PKI outside both tiers |

## Deploying for real (guidance)

1. **Certificates.** Replace the demo CA with your managed PKI. Give the SaaS a certificate whose subject
   alternative name matches its ingest DNS name, keep the CA signing key outside both tiers, and restrict
   each private key file to its service account.
2. **Secrets.** Each collector's HMAC `secret` and `pseudonym_salt` are generated by `setup_env.py`.
   Keep them in the collector's secret store, never in source control. To rotate a secret, run
   `setup_env.py --force` (or replace it in the registry and the collector config) and restart both.
3. **Storage.** Put collector and SaaS data directories, SQLite journals and backups on encrypted storage,
   restrict access to the required identities, and choose retention periods for raw events and metadata.
4. **Exposure.** The ingest and dashboard listeners bind to `127.0.0.1`. To expose ingest, put it behind
   a TLS-terminating or pass-through load balancer with connection limits; keep the dashboard behind
   authenticated operator access.
5. **Incident response.** For a suspected stolen collector secret, remove that collector from the registry
   and restart the SaaS; its requests then fail with `401` while its payloads wait in the outbox. Re-enrol
   it with a new secret after investigating the host.

## Evidence from this repository

| Check | How to run it | Result |
| --- | --- | --- |
| Unit tests (signing, policy, DLP, entropy secret detection, TLS server, idempotency) | `python -m unittest discover -s tests -t tests` | 72 tests, all pass |
| End-to-end validation, including a forged signature (`401`), wrong region (`421`), tenant isolation and a raw secret in a log | `python tools/verify.py --spawn` | 17 of 17 checks pass (`docs/VALIDATION_REPORT.md`) |

No automated test checks the 5-minute replay window yet; the check exists in `common/util.py` (`verify_sig`).
| Load over real TLS and HMAC | `python tools/loadtest.py --collectors 25 100 200 --seconds 20` | 100 collectors: 93.7 payloads/s, 0 errors, 0 lost (`docs/LOADTEST.md`) |

These checks run local processes with synthetic telemetry. Production network configuration, disk
encryption, backup permissions and an independent security review remain deployment work.

## Long-term confidentiality

If recorded traffic must stay confidential for many years, plan to require a hybrid post-quantum TLS key
exchange (for example `X25519MLKEM768`) on both endpoints once the Python and OpenSSL versions in use
support it. The repository does not do this today. Keep an inventory of TLS runtimes, certificates and data
retention periods so algorithms and keys can be replaced over the system's lifetime.
