# Securing Telemetry-Tracker from host to SaaS

Telemetry-Tracker now requires **TLS 1.3 with mutual certificate authentication** for collector-to-SaaS traffic. Each collector verifies the SaaS hostname and certificate before sending telemetry. The SaaS uses the collector's verified certificate to identify its tenant and permitted region.

The SaaS decrypts the approved metadata to calculate health and incidents. A compromised SaaS process could read that metadata. A compromised customer host could read events before encryption. No cipher can guarantee 100% or lifelong security across those endpoints. For any value that even the SaaS operator must never see, compute the result on the collector and keep the original on the customer's host. For example, send the failed-login count and the number of distinct accounts. Keep the usernames and IP addresses local.

## What each part of the path protects

| Path | Implemented protection | Who can read the data |
| --- | --- | --- |
| Host process to local collector | In deployed mode the collector accepts authenticated JSON on loopback. The raw-data console, UDP input and simulated command polling are disabled. | The producer and collector see raw events. Local HTTP relies on the host's OS isolation. Keep both processes on the same machine. |
| Collector to SaaS | A direct TLS 1.3 connection goes to the configured HTTPS origin. Discovery selects a region on that origin. The client rejects redirects and destinations outside the origin. Ingest requires a trusted and enrolled client certificate. | Network observers can see connection timing, sizes and endpoints. The authenticated endpoints can read the permitted metadata. |
| Inside the collector | The collector aggregates metrics, assigns keyed identifiers to hosts and log templates, builds events from allowed fields and checks outgoing metric batches for recognizable secrets immediately before sending. | Raw events and the key for generating those identifiers stay local. Service and site labels explicitly configured for export are visible to the SaaS. |
| Inside the SaaS | Ingest checks the payload policy and region, enforces collector ownership of existing sources and deduplicates retries. A failed authentication leaves queued metric batches pending. | The ingest service and authorized tenant users can access the metadata their roles allow. SQLite files, journals and backups require separate storage protection. |

TLS negotiates authenticated encryption for each session. With a full ephemeral key exchange, stealing the server's certificate key later does not by itself reveal past session traffic. The application disables TLS session tickets at ingress. Filtering at the host also reduces what a later SaaS compromise could expose. [TLS 1.3 specification](https://www.rfc-editor.org/info/rfc9846/)

## Run the secured localhost demo

From the repository root on the tested Windows machine, run the following in PowerShell. Port 18443 worked in the load test. Windows denied the bind on the default port 8443 during validation.

```powershell
$env:AIOPS_INGEST_PORT = "18443"
py -3.13 setup_env.py
py -3.13 run_all.py
```

Open the demo dashboard at [localhost:8080](http://localhost:8080). Demo setup creates a local certificate authority and separate collector certificates. The demo intentionally enables local inspection of raw telemetry and uses published demo accounts. Use the deployment settings below for customer data.

## Deploy a real collector

1. **Provision identities.** Generate a private key on each collector and issue a short-lived certificate with the `clientAuth` purpose through your managed PKI. Give the SaaS listener a `serverAuth` certificate whose subject alternative name matches its ingest DNS name. Keep the CA signing key outside both application tiers. This implementation loads PEM keys from files, so restrict each private key to its service account.
2. **Configure the SaaS.** Set `ingest_bind`, `ingest_port` and `ingest_origin` in the registry. For example, the origin could be `https://ingest.example.com:8443`. Under `AIOPS_CERT_DIR`, install the server chain as `server.crt`, its key as `server.key`, and the trusted client CA bundle as `ca.crt`. Enroll each collector under its tenant with a `cert_fingerprints` list containing the lowercase, colon-free SHA-256 digest of its DER leaf certificate. Set `demo` to `false`. For ingest-only service, omit `dashboard_port`. Keep any enabled dashboard on loopback behind authenticated operator access. A load balancer on the ingest path must pass TLS through to the listener.
3. **Configure the host.** Set the collector's `saas_url`, `ca_file`, `client_cert`, `client_key`, unique random `pseudonym_salt`, and `demo: false`. Give the collector and its authorized local producer the same randomly generated `AIOPS_LOCAL_INGEST_TOKEN` through their secret environments. The producer sends `Authorization: Bearer <token>` to the loopback `/ingest` endpoint. Review any site and service labels before approving their export.
4. **Protect retained data.** Place the collector and SaaS data directories, SQLite journals and backups on encrypted storage. Restrict filesystem and backup access to the required identities. Choose retention periods for raw events and SaaS metadata, and verify deletion and backup expiry. Transport encryption ends when the receiving service decrypts a batch.
5. **Start the services separately.** Start `python saas/server.py` on the SaaS machine and `python collector/collector.py --config <collector-config.json>` on the customer machine. Feed a synthetic event, verify its receipt and tenant assignment, and confirm the raw test value is absent from the exported payload. Monitor certificate expiry, outbox depth, disk space, rejected payloads and delivery latency. Protect a network-accessible ingress with connection limits and traffic controls sized for the deployment.

**Rotation and incident response.** Enroll a replacement fingerprint alongside the existing one and restart the SaaS. Install the new key and certificate on the collector, restart it, and verify delivery. Then remove the old fingerprint and restart ingress. For suspected theft, disable the affected collector in the registry and restart ingress immediately. Revoke the certificate through the issuing PKI and investigate the host before re-enrollment. The running service reads registry changes at startup.

## Evidence from the workspace

All **63 automated tests passed** on Windows with Python 3.13. The final run completed in 8.137 seconds.

| Check | Observed result |
| --- | --- |
| Certificate and transport enforcement | Live localhost tests negotiated TLS 1.3 and rejected a missing client certificate, an unenrolled certificate, a wrong server hostname and a TLS 1.2 client. |
| Tenant isolation and recovery | The tests rejected delivery to the wrong region and writes to another collector's existing source. Disabling a collector left a metric batch queued. After re-enabling it, the batch arrived and replay produced one stored payload. |
| Disclosure of a synthetic secret | The deployed-mode test submitted a raw log containing a synthetic password. It found the password locally. The SaaS received the security event, and its payload contained zero matches for the password, raw hostname or source-supplied service label. |
| Load over mTLS | In separate 10-second localhost runs, 25 collectors submitted 250 payloads and 100 collectors submitted 852. Every submitted payload was accepted and stored once. The 100-collector run measured 71.1 payloads/s and 3.01 s p95 request latency. Use deployment hardware and real traffic distributions for a capacity commitment. |

Run these commands to repeat the suite and load checks.

```powershell
py -3.13 -m unittest discover -s tests -t tests
py -3.13 tools/loadtest.py --collectors 25 100 --seconds 10 --no-write
```

These checks exercised local processes and synthetic telemetry. The longer demo verification also observed zero SaaS matches for its synthetic secret and attacker IP. Its final result was unconfirmed after the interruption. Production network configuration, disk encryption, backup permissions and an independent security assessment remain deployment work.

## Long-term confidentiality

If recorded traffic must stay confidential for many years, require and verify a hybrid TLS key exchange such as `X25519MLKEM768` on both deployed endpoints. The repository currently enforces TLS 1.3 and certificate authentication. Its tests do not require or demonstrate negotiation of that hybrid group. Maintain an inventory of TLS runtimes, certificates and data retention periods so algorithms and keys can be replaced during the system's lifetime. [IETF hybrid TLS key exchange](https://datatracker.ietf.org/doc/html/rfc10024) · [NIST guidance on cryptographic agility](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final)
