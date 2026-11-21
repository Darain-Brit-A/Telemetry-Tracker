# Securing TeleTracker from host to SaaS

This document describes what the code in this repository **actually does** to protect telemetry on its way
from a customer host to the SaaS, what it still does not do, and what a real deployment would add. Every
"implemented" claim below names the file that implements it.

In short: collectors talk to the SaaS over **TLS 1.3 with mutual certificate authentication**, each
collector's certificate is **pinned by fingerprint** to that collector, every request is also **signed with
a per-collector HMAC-SHA256 key** bound to one tenant, and only **allow-listed metadata** ever leaves the
host. Raw logs stay on the customer's machine.

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
| Host process to local collector | The collector listens on **loopback only** (`127.0.0.1`): HTTP `/ingest` for JSON events and UDP for syslog. `/ingest` requires `Authorization: Bearer <token>` with the collector's own random token, compared in constant time; without it the answer is `401`. The console rejects foreign `Host` headers (DNS rebinding) and cross-site writes (`Origin` check). `collector/collector.py`, `common/web.py` | The producer and the collector see raw events. The token stops other local processes from feeding fake events over HTTP. **Syslog over UDP has no authentication** (the protocol has none); it is reachable only from the same machine. |
| Inside the collector | Raw events are stored locally (`data/`). Before anything is sent, events are reduced to allow-listed fields (`common/data_policy.json`), host names become keyed pseudonyms and log lines become keyed template fingerprints (both HMAC-SHA256 with a per-collector salt, so the SaaS cannot confirm a guess by hashing it), secrets are redacted (regex rules plus the entropy check), and every outgoing payload gets a DLP scan. If the scan finds anything, the payload's metrics, events and sources are emptied and only that empty marker is sent, so sequence numbers stay continuous. `common/policy.py`, `collector/collector.py` | Raw events and the salt stay on the host. Service and site labels that the policy allows are visible to the SaaS. |
| Collector to SaaS | **TLS 1.3 only**, both directions. The collector trusts only the private CA and checks the server's hostname, and presents **its own client certificate** (`clientAuth`, issued by the same CA). It **refuses redirects**: any 3xx is an error, so metadata only goes to the configured origin. Every request also carries `X-Collector-Id`, `X-Timestamp` and `X-Signature`: an HMAC-SHA256 over the timestamp, method, path and SHA-256 of the body, with a 256-bit secret unique to that collector. `common/tlsserver.py`, `collector/collector.py`, `common/util.py` | Network observers see connection timing, sizes and endpoints, but not content. The SaaS can read the permitted metadata. |
| Inside the SaaS | The TLS layer accepts only clients with a certificate from the private CA. The SaaS then checks that the certificate's SHA-256 fingerprint is in the `cert_fingerprints` enrolled for **the collector the request claims to be**, so one collector's certificate cannot be used to speak for another. It rejects disabled collectors, bad signatures and timestamps more than **5 minutes** off (replay window). The tenant comes from the enrolment, not the payload. Data residency: a request for the wrong region gets `421` with the correct region. The payload is checked again against the allow-list and DLP scan, de-duplicated by `payload_id` (a reused ID with a different body gets `409`), and acknowledged with a SHA-256 digest of the stored bytes; the collector keeps the payload in its outbox until the digest matches. `saas/server.py` | The ingest service and the tenant's authorised users, within their roles. SQLite files, journals and backups are **not encrypted** by the application. |
| SaaS dashboard | Loopback only (`127.0.0.1:8080`), PBKDF2-SHA256 password hashes (120,000 rounds), per-tenant roles, strict Content-Security-Policy, `Host` and `Origin` checks. `saas/server.py`, `common/web.py` | Authorised tenant users. |

A stolen HMAC secret alone is no longer enough to send data as a collector: the attacker would also need that
collector's private key. A stolen certificate alone is not enough either: the request must also carry a
valid signature.

TLS encrypts and authenticates each session. With the ephemeral key exchange TLS 1.3 always uses, stealing
the server's certificate key later does not by itself reveal past traffic ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)).
Filtering on the host also limits what a later SaaS compromise could expose.

## Run the secured localhost demo

```powershell
python setup_env.py
python run_all.py
```

`setup_env.py` uses `openssl` to create:

| What | Where | Read by |
| --- | --- | --- |
| Private CA certificate | `config/certs/ca.crt` | SaaS and collectors |
| SaaS server certificate and key (`serverAuth`, `localhost` / `127.0.0.1`) | `config/certs/server.*` | SaaS |
| One client certificate and key per collector (`clientAuth`, CN = collector ID) | `config/certs/collectors/<id>.*` | that collector |
| CA signing key | `config/ca-private/` (or `AIOPS_CA_KEY_DIR`) | `setup_env.py` only |

It enrols each collector in `config/registry.json` with its HMAC secret and certificate fingerprint, and gives
each collector a pseudonym salt and an `/ingest` token (shared with the simulator, its local producer).
Re-running keeps existing secrets and certificates and adds anything missing; `run_all.py` re-runs it
automatically for configs created by an older setup. Everything under `config/` is git-ignored. If `openssl`
is not on the `PATH`, the demo runs **without TLS** (HMAC signing and the `/ingest` token still apply).

Open the dashboard at [localhost:8080](http://localhost:8080). The demo intentionally shows raw local
telemetry in the collector consoles and uses published demo accounts; it is not a production configuration.

## Still not implemented

| Gap | Why it matters | What it would take |
| --- | --- | --- |
| Encryption at rest | SQLite files, journals and backups are plain files | Encrypted disks or volumes on both tiers (deployment, not application code) |
| Certificate revocation lists | A compromised certificate is blocked by removing its fingerprint or disabling the collector, not by CRL or OCSP | CRL checking (`VERIFY_CRL_CHECK_LEAF`) against the PKI's list |
| CA on a separate machine | The demo CA key is in its own folder that the services never read, but still on the same machine | A managed PKI that issues certificates on request |
| Authenticated syslog | UDP syslog cannot carry a token | Accept syslog only over TCP with TLS, or turn the UDP listener off where it is not needed |
| Post-quantum key exchange | Traffic recorded today could be decrypted by a future quantum computer | See "Long-term confidentiality" below |

## Deploying for real (guidance)

1. **Certificates.** Replace the demo CA with your managed PKI. Issue the SaaS a `serverAuth` certificate
   whose subject alternative name matches its ingest DNS name, and each collector a short-lived `clientAuth`
   certificate whose key is generated on the collector. Keep the CA signing key on neither tier, and restrict
   each private key file to its service account.
2. **Enrolment.** In the registry, give each collector `cert_fingerprints`: the lowercase, colon-free SHA-256
   of its DER certificate (`common/tlsserver.py`, `fingerprint_file`). In its config set `ca_file`,
   `client_cert` and `client_key`.
3. **Secrets.** Keep each collector's HMAC `secret`, `pseudonym_salt` and `ingest_token` in its secret store,
   never in source control. The `ingest_token` is shared only with the authorised local producer.
4. **Rotation.** Add the new certificate's fingerprint next to the old one and restart the SaaS; install the
   new certificate on the collector and restart it; then remove the old fingerprint and restart the SaaS.
   To rotate an HMAC secret, replace it in the registry and the collector config (or `setup_env.py --force`
   in the demo) and restart both.
5. **Storage.** Put collector and SaaS data directories, SQLite journals and backups on encrypted storage,
   restrict access to the required identities, and choose retention periods for raw events and metadata.
6. **Exposure.** The ingest and dashboard listeners bind to `127.0.0.1`. To expose ingest, put it behind a
   load balancer that **passes TLS through** (terminating TLS there would hide the client certificate from
   the SaaS) with connection limits; keep the dashboard behind authenticated operator access.
7. **Incident response.** For a suspected stolen collector key or secret, set `"disabled": true` on that
   collector in the registry (or remove its fingerprint) and restart the SaaS. Its requests then fail with
   `401` while its payloads wait in the outbox. Re-enrol it with a new certificate and secret after
   investigating the host. The SaaS reads registry changes at startup.

## Evidence from this repository

| Check | How to run it | Result |
| --- | --- | --- |
| Unit tests: mutual TLS (enrolled client accepted, no certificate / other CA / TLS 1.2 rejected, server outside the private CA refused), request signing (tampering, 5-minute replay window), `/ingest` token, redirect refusal, keyed fingerprints, policy, DLP, entropy secret detection | `python -m unittest discover -s tests -t tests` | 86 tests, all pass |
| End-to-end validation on the running stack, including: acme's signed request with acme's certificate accepted, without a certificate rejected at TLS, with globex's certificate `401`, from a TLS 1.2 client rejected; forged signature `401`; wrong region `421`; tenant isolation; a raw secret in a log never reaching the SaaS | `python tools/verify.py --spawn` | **18 of 18** checks pass (`docs/VALIDATION_REPORT.md`) |
| Load over mutual TLS 1.3 and HMAC | `python tools/loadtest.py --collectors 25 100 200 --seconds 20` | 0 errors and 0 lost at 25, 100 and 200 collectors. Throughput is the same as before mutual TLS when both are run back to back (`docs/LOADTEST.md`) |

These checks run local processes with synthetic telemetry. Production network configuration, disk
encryption, backup permissions and an independent security review remain deployment work.

## Long-term confidentiality

If recorded traffic must stay confidential for many years, plan to require a hybrid post-quantum TLS key
exchange (for example `X25519MLKEM768`) on both endpoints once the Python and OpenSSL versions in use
support it. The repository does not do this today. Keep an inventory of TLS runtimes, certificates and data
retention periods so algorithms and keys can be replaced over the system's lifetime.
