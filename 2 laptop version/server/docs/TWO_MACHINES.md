# Running the collector and the SaaS on two laptops

The two tiers are separate programs that only talk over one HTTPS connection, so they can run on different
machines: **laptop A** runs the SaaS (dashboard, database, AI engine), **laptop B** runs a collector (and
the data source it watches). Raw data never leaves laptop B; only allow-listed metadata crosses the network,
over mutual TLS 1.3 with every request HMAC-signed.

```
 Laptop B (customer site)                              Laptop A (SaaS)
 ┌──────────────────────────────┐                      ┌───────────────────────────────┐
 │ simulator / OpenAQ / syslog  │                      │ dashboard  http://localhost:8080│
 │        │ 127.0.0.1 only       │  mutual TLS 1.3      │ ingest     https://<A-IP>:8443  │
 │        ▼                      │  + HMAC, metadata    │ AI engine · SQLite per region   │
 │ collector col-acme-dc1 ───────┼─────────────────────▶│ (only port 8443 is on the LAN)  │
 │ console http://127.0.0.1:9101│                      └───────────────────────────────┘
 └──────────────────────────────┘
```

Tested: a separate copy of the code holding only an exported bundle delivered every payload to the SaaS
through the laptop's Wi-Fi address, and the SaaS dashboard showed the collector Excellent with no sequence gaps.

## What you need

* Both laptops on the same network (same Wi-Fi or LAN), Python 3.12+ on both, `openssl` on laptop A.
* The project code on both (e.g. `git clone`, same branch / version).
* Clocks within 5 minutes of each other (Windows syncs automatically; request signatures expire after 5 min).

## Laptop A: the SaaS

1. **Find laptop A's address** on the shared network:

   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like '*Wi*Fi*' | Select-Object IPAddress
   ```

   Say it is `192.168.1.20`. (A DNS name such as `saas-laptop.local` works too, if laptop B resolves it.)

2. **Point the setup at that address.** This re-issues only the SaaS server certificate so it is valid for
   that address (the CA and every collector certificate stay as they are), makes the ingest port listen on
   the network, and writes the address into every collector config:

   ```powershell
   python setup_env.py --saas-host 192.168.1.20
   ```

   The setting sticks; `python setup_env.py --saas-host local` switches back to single-laptop mode.

3. **Allow inbound TCP 8443** through Windows Defender Firewall (PowerShell **as Administrator**, Private
   network profile only):

   ```powershell
   New-NetFirewallRule -DisplayName "AIOps SaaS ingest 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -Profile Private
   ```

   Make sure the Wi-Fi network is set to *Private* in Windows settings. Remove the rule when you are done:
   `Remove-NetFirewallRule -DisplayName "AIOps SaaS ingest 8443"`.

4. **Export the collector** that will run on laptop B:

   ```powershell
   python tools/export_collector.py col-acme-dc1
   ```

   This writes `collector-col-acme-dc1.zip` with only that collector's config, its client certificate and
   key, the CA certificate, its simulator config and a README. It does **not** contain the registry, the CA
   private key, other collectors' secrets or your OpenAQ key. It **does** contain this collector's secret
   and private key: copy it like a password (USB stick, `scp`), and delete it after unpacking.

   **Whole Tier 1 on laptop B:** list every collector; you get one zip and one start command:

   ```powershell
   python tools/export_collector.py col-acme-dc1 col-acme-cloud col-globex-nyc col-air-blr col-air-del col-air-bom col-air-maa
   ```

   then start only the SaaS on laptop A with `python run_all.py --saas-only`, and on laptop B
   `python run_all.py --collector col-acme-dc1 --collector col-acme-cloud ...` (the README in the zip has the
   exact line). For the air-quality collectors, also copy `config/pollution.json` (your OpenAQ key) to laptop B
   yourself; it is deliberately not in the bundle.

5. **Start the SaaS without that collector:**

   ```powershell
   python run_all.py --exclude col-acme-dc1
   ```

   (`--saas-only` starts the SaaS alone; repeat `--exclude` for several remote collectors.)

## Laptop B: the collector

1. Get the code, then **unpack the zip into the project folder** so that
   `config/collectors/col-acme-dc1.json` exists.
2. **Check the SaaS is reachable:**

   ```powershell
   Test-NetConnection 192.168.1.20 -Port 8443
   ```

   `TcpTestSucceeded : True` is what you want; `False` is almost always the firewall rule or a different
   network.
3. **Start the collector and its data source:**

   ```powershell
   python run_all.py --collector col-acme-dc1
   ```

   That starts `collector/collector.py --config col-acme-dc1` plus the simulator for its hosts (or, for an
   air-quality collector such as `col-air-del`, the OpenAQ poller, which needs `config/pollution.json` with
   your OpenAQ key on laptop B). Laptop B never runs setup and has no registry.
4. Open the collector console on laptop B at `http://127.0.0.1:9101`: "delivered" should climb with no
   send errors. On laptop A's dashboard (`acme-admin`) the collector shows **Online / Excellent** within
   seconds, with its hosts under Fleet & sources.

## How it works (what changed in the code)

| Piece | Single laptop | Two laptops |
|---|---|---|
| SaaS ingest listener | `127.0.0.1:8443` | `0.0.0.0:8443` (registry `ingest_bind`), still mutual TLS + HMAC |
| Address collectors use | `https://127.0.0.1:8443` | `https://<A-IP>:8443` (registry `ingest_public_host`, collector `saas_url`) |
| Region discovery | returns `127.0.0.1` URLs | returns `<A-IP>` URLs |
| SaaS server certificate | valid for localhost, 127.0.0.1 | also valid for `<A-IP>` (re-issued by the same CA) |
| Collector cert paths | relative to `config/` | same, so the unpacked bundle works anywhere |
| Dashboard, collector consoles, simulator | loopback | loopback (never exposed) |

Environment overrides for special cases: `AIOPS_INGEST_BIND` (e.g. bind only one interface) and
`AIOPS_PUBLIC_HOST` (e.g. behind NAT) on laptop A.

## Troubleshooting

| Symptom on laptop B | Cause | Fix |
|---|---|---|
| `TcpTestSucceeded : False`, collector "connection refused / timed out" | firewall on A, or not on the same network | step A3; same Wi-Fi; Wi-Fi profile *Private* |
| `CERTIFICATE_VERIFY_FAILED ... IP address mismatch` | A's certificate does not include the address B uses | on A: `setup_env.py --saas-host <that exact address>`, export again |
| `401 client certificate not enrolled` | bundle from an older setup (`--force` re-issued certificates) | export the bundle again |
| `401 timestamp outside allowed skew` | clocks more than 5 min apart | sync time on both laptops |
| Collector online but no hosts | the data source is not running | use `run_all.py --collector <id>` (it starts the simulator / poller) |
| A's address changed (new Wi-Fi, DHCP) | collectors still use the old address | re-run step A2 with the new address and re-export, or give A a fixed IP / DNS name |
