"""One-time environment setup.

* creates a private CA and a TLS certificate for the SaaS ingest endpoint (openssl)
* issues each collector its own client certificate (mutual TLS) and enrols its SHA-256 fingerprint
* enrols collectors (per-collector HMAC secret, bound to one tenant, and a token for the local /ingest)
* writes the SaaS registry (tenants, residency regions, users) and collector configs

Re-running keeps existing secrets unless --force is given.
"""
import argparse
import hashlib
import ipaddress
import os
import secrets
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common.tlsserver import fingerprint_file  # noqa: E402
from common.util import CERT_DIR, CONFIG_DIR, DATA_DIR, load_json, save_json  # noqa: E402

REGIONS = {"eu-west": "Frankfurt (EU)", "us-east": "Virginia (US)", "ap-south": "Mumbai (APAC)"}

TENANTS = {
    "acme": {
        "name": "Acme Retail",
        "region": "eu-west",
        "dependencies": {"checkout-web": ["checkout-api"], "checkout-api": ["orders-db", "session-cache"]},
        "collectors": {
            "col-acme-dc1": {"site": "blr-dc1", "tz": "Asia/Kolkata", "ui_port": 9101, "syslog_port": 5141,
                              "hosts": [["web-01", "web", "checkout-web"], ["web-02", "web", "checkout-web"],
                                        ["api-01", "app", "checkout-api"], ["db-01", "db", "orders-db"]]},
            "col-acme-cloud": {"site": "fra-cloud", "tz": "Europe/Berlin", "ui_port": 9102, "syslog_port": 5142,
                                "hosts": [["web-03", "web", "checkout-web"], ["api-02", "app", "checkout-api"],
                                          ["cache-01", "cache", "session-cache"]]},
        },
    },
    "globex": {
        "name": "Globex Finance",
        "region": "us-east",
        "dependencies": {"billing-app": ["billing-db", "edge-firewall"]},
        "collectors": {
            "col-globex-nyc": {"site": "nyc-dc", "tz": "America/New_York", "ui_port": 9103, "syslog_port": 5143,
                                "hosts": [["app-01", "app", "billing-app"], ["app-02", "app", "billing-app"],
                                          ["db-01", "db", "billing-db"], ["fw-01", "network", "edge-firewall"]]},
        },
    },
    # Real, live data: official air-quality monitors (CPCB and state boards) in four Indian cities, read through
    # the OpenAQ v3 API by tools/openaq_poller.py. Not simulated. One collector per city, as one per site in a
    # real deployment; region ap-south keeps Indian data in the Mumbai store.
    "cityair": {
        "name": "India Air Quality (live, OpenAQ)",
        "region": "ap-south",
        "dependencies": {},
        "live": "openaq",
        "collectors": {cid: {"site": site, "tz": "Asia/Kolkata", "ui_port": port, "syslog_port": port - 3960,
                             "simulated": False,
                             # host, role, service (shown as the monitor's name), OpenAQ location id
                             "hosts": [[h, "air-monitor", name, loc] for h, name, loc in monitors]}
                       for cid, site, port, monitors in (
            ("col-air-blr", "Bengaluru", 9104, [("silk-board", "Silk Board", 6975), ("btm-layout", "BTM Layout", 5548),
                                                ("peenya", "Peenya", 5607), ("hebbal", "Hebbal", 6984)]),
            ("col-air-del", "Delhi", 9105, [("rk-puram", "R K Puram", 17), ("punjabi-bagh", "Punjabi Bagh", 50),
                                            ("sirifort", "Sirifort", 5586), ("mandir-marg", "Mandir Marg", 6358)]),
            ("col-air-bom", "Mumbai", 9106, [("powai", "Powai", 6956), ("mulund-west", "Mulund West", 12040),
                                             ("worli", "Worli", 3409323), ("colaba", "Colaba", 6927)]),
            ("col-air-maa", "Chennai", 9107, [("royapuram", "Royapuram", 11578), ("perungudi", "Perungudi", 12046),
                                              ("kodungaiyur", "Kodungaiyur", 11579), ("arumbakkam", "Arumbakkam", 11581)]),
        )},
    },
}

USERS = [  # demo-only credentials (also listed in README)
    ("acme-admin", "acme-admin-demo", "acme", "admin"),
    ("acme-viewer", "acme-viewer-demo", "acme", "viewer"),
    ("globex-admin", "globex-admin-demo", "globex", "admin"),
    ("cityair-admin", "cityair-admin-demo", "cityair", "admin"),
    ("cityair-viewer", "cityair-viewer-demo", "cityair", "viewer"),
]

DEFAULT_THRESHOLDS = {
    # metric: [excellent_below, good_below, fair_below]  (>= last -> Poor)
    "cpu_pct": [60, 80, 92],
    "mem_pct": [70, 85, 95],
    "disk_pct": [75, 85, 95],
    "latency_ms": [60, 120, 300],
    "packet_loss_pct": [0.5, 2, 5],
}
# Air-quality limits from India's CPCB National AQI bands (micrograms per cubic metre):
# Excellent = Good, Good = Satisfactory, Fair = Moderate, Poor = Poor or worse
AIR_THRESHOLDS = {
    "pm25_ugm3": [30, 60, 90],
    "pm10_ugm3": [50, 100, 250],
    "no2_ugm3": [40, 80, 180],
}
HEALTH_SETTINGS = {"stale_after_s": 10, "no_data_after_s": 30, "collector_offline_after_s": 30}
# official monitors publish every 15-60 minutes, typically 1-2 hours late: stale after 3 h, no data after 6 h
AIR_HEALTH_SETTINGS = {"stale_after_s": 10800, "no_data_after_s": 21600, "collector_offline_after_s": 30}

SETUP_VERSION = 4          # bump when setup adds something existing configs need (run_all re-runs setup)
SAAS_DASH_PORT = 8080
SAAS_INGEST_PORT = 8443
SIM_PORT = 9000


def pbkdf2(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()


def server_san(saas_host=None):
    """Names the SaaS certificate is valid for: always localhost, plus the SaaS machine's IP or DNS name
    when collectors on other machines connect to it (setup_env.py --saas-host)."""
    names = ["DNS:localhost", "IP:127.0.0.1"]
    if saas_host and saas_host not in ("localhost", "127.0.0.1"):
        try:
            ipaddress.ip_address(saas_host)
            names.append(f"IP:{saas_host}")
        except ValueError:
            names.append(f"DNS:{saas_host}")
    return ",".join(names)


def server_ext(saas_host=None):
    return (f"subjectAltName={server_san(saas_host)}\nbasicConstraints=CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")


SERVER_EXT = server_ext()
CLIENT_EXT = ("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
CLIENT_DIR = os.path.join(CERT_DIR, "collectors")
# The CA signing key is only needed here, to issue certificates. It is kept out of config/certs, which
# the SaaS and collectors read; in a real deployment it lives in a managed PKI on neither tier.
CA_KEY_DIR = os.environ.get("AIOPS_CA_KEY_DIR", os.path.join(CONFIG_DIR, "ca-private"))


def client_cert_paths(cid):
    return os.path.join(CLIENT_DIR, f"{cid}.crt"), os.path.join(CLIENT_DIR, f"{cid}.key")


def make_certs(force, collector_ids, saas_host=None):
    """Returns (tls, mtls). Existing certificates are kept unless `force`; missing client
    certificates are issued from the existing CA, and the server certificate is re-issued (same CA, so
    collector certificates stay valid) when the SaaS host name / IP it must cover changes."""
    os.makedirs(CLIENT_DIR, exist_ok=True)
    os.makedirs(CA_KEY_DIR, exist_ok=True)
    ca_crt, ca_key = os.path.join(CERT_DIR, "ca.crt"), os.path.join(CA_KEY_DIR, "ca.key")
    ca_srl = os.path.join(CA_KEY_DIR, "ca.srl")
    for name in ("ca.key", "ca.srl"):          # older setups kept these next to the certificates
        old = os.path.join(CERT_DIR, name)
        if os.path.exists(old):
            new = os.path.join(CA_KEY_DIR, name)
            if os.path.exists(new):
                os.remove(old)
            else:
                shutil.move(old, new)
                print(f"   moved {name} out of config/certs into {os.path.relpath(CA_KEY_DIR, CONFIG_DIR)}/")
    if os.path.exists(os.path.join(CERT_DIR, "server.csr")):
        os.remove(os.path.join(CERT_DIR, "server.csr"))
    have_ca = os.path.exists(ca_crt) and not force
    missing = [c for c in collector_ids if force or not os.path.exists(client_cert_paths(c)[0])]
    san_file = os.path.join(CERT_DIR, "server_san.txt")
    want_san = server_san(saas_host)
    have_san = open(san_file).read().strip() if os.path.exists(san_file) else server_san()
    if have_ca and not missing and have_san == want_san:
        return True, True
    openssl = shutil.which("openssl")
    if not openssl:
        if have_ca:
            print("!! openssl not found - collectors without a client certificate; mutual TLS disabled.")
            return True, False
        print("!! openssl not found - SaaS ingest will run WITHOUT TLS (demo fallback).")
        return False, False

    def run(*args):
        subprocess.run([openssl, *args], check=True, cwd=CERT_DIR, capture_output=True)

    def ext_file(name, text):
        path = os.path.join(CERT_DIR, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    if not have_ca:
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", "ca.crt",
            "-days", "365", "-subj", "/CN=TeleTracker Demo Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
    if not have_ca or have_san != want_san:
        if not os.path.exists(ca_key):
            print("!! CA private key not found - cannot re-issue the server certificate for the new SaaS host")
            return True, False
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr",
            "-subj", "/CN=localhost")
        run("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", ca_key, "-CAserial", ca_srl,
            "-CAcreateserial", "-out", "server.crt", "-days", "365",
            "-extfile", ext_file("san.ext", server_ext(saas_host)))
        os.remove(os.path.join(CERT_DIR, "server.csr"))
        with open(san_file, "w") as f:
            f.write(want_san)
        print(f"   TLS: {'private CA + ' if not have_ca else ''}server certificate for {want_san} in config/certs")
    if not os.path.exists(ca_key):
        print("!! CA private key not found - cannot issue client certificates; mutual TLS disabled.")
        return True, False
    client_ext = ext_file("client.ext", CLIENT_EXT)
    for cid in missing:
        crt, key = client_cert_paths(cid)
        csr = os.path.join(CLIENT_DIR, f"{cid}.csr")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", f"/CN={cid}")
        run("x509", "-req", "-in", csr, "-CA", "ca.crt", "-CAkey", ca_key, "-CAserial", ca_srl,
            "-CAcreateserial", "-out", crt, "-days", "365", "-extfile", client_ext)
        os.remove(csr)
    if missing:
        print(f"   mTLS: {len(missing)} collector client certificate(s) issued in config/certs/collectors")
    return True, True


def rel(path):
    """Path relative to the config folder when it is inside it (portable collector configs)."""
    r = os.path.relpath(path, CONFIG_DIR)
    return path if r.startswith("..") else r.replace(os.sep, "/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="regenerate secrets and certificates")
    ap.add_argument("--saas-host", metavar="IP_OR_NAME",
                    help="run collectors on other machines: the SaaS machine's LAN IP or DNS name (e.g. "
                         "192.168.1.20). The ingest port then listens on the network and the server certificate "
                         "covers this name. Kept on later runs; 'local' switches back to this machine only.")
    args = ap.parse_args()
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    reg_path = os.path.join(CONFIG_DIR, "registry.json")
    old = {} if args.force else (load_json(reg_path, {}) or {})
    saas_host = args.saas_host if args.saas_host is not None else old.get("ingest_public_host", "127.0.0.1")
    if saas_host in ("local", "localhost"):
        saas_host = "127.0.0.1"
    remote = saas_host != "127.0.0.1"

    collector_ids = [cid for t in TENANTS.values() for cid in t["collectors"]]
    tls, mtls = make_certs(args.force, collector_ids, saas_host if remote else None)
    scheme = "https" if tls else "http"
    url_host = f"[{saas_host}]" if ":" in saas_host else saas_host
    ingest_base = f"{scheme}://{url_host}:{SAAS_INGEST_PORT}"
    old_secrets = {cid: c["secret"] for cid, c in old.get("collectors", {}).items()}

    registry = {"regions": REGIONS, "tenants": {}, "collectors": {}, "users": {}, "tls": tls, "mtls": mtls, "setup_version": SETUP_VERSION,
                "dashboard_port": SAAS_DASH_PORT, "ingest_port": SAAS_INGEST_PORT,
                # collectors on other machines: ingest listens on all interfaces (mTLS + HMAC still required)
                "ingest_bind": "0.0.0.0" if remote else "127.0.0.1", "ingest_public_host": saas_host}
    sim = {"port": SIM_PORT, "collectors": {}}

    for tid, t in TENANTS.items():
        thresholds = dict(AIR_THRESHOLDS if t.get("live") else DEFAULT_THRESHOLDS)
        # Learned (ML) limits by default for every metric; a choice saved in the dashboard survives re-runs
        old_modes = (old.get("tenants", {}).get(tid) or {}).get("threshold_modes") or {}
        registry["tenants"][tid] = {"name": t["name"], "region": t["region"], "dependencies": t["dependencies"],
                                    "thresholds": thresholds,
                                    "threshold_modes": {m: old_modes.get(m, "learned") for m in thresholds},
                                    "health": dict(AIR_HEALTH_SETTINGS if t.get("live") else HEALTH_SETTINGS)}
        if t.get("live"):
            # readings older than 3 h (the backfill) only train the baselines; they never raise alerts
            registry["tenants"][tid]["history_after_s"] = 10800
        for cid, c in t["collectors"].items():
            secret = old_secrets.get(cid) or secrets.token_hex(32)
            registry["collectors"][cid] = {"tenant_id": tid, "secret": secret, "site": c["site"]}
            crt, key = client_cert_paths(cid)
            if mtls:
                # rotation: add the new fingerprint next to the old one, restart, then remove the old
                registry["collectors"][cid]["cert_fingerprints"] = [fingerprint_file(crt)]
            col_cfg_path = os.path.join(CONFIG_DIR, "collectors", f"{cid}.json")
            old_col = (load_json(col_cfg_path, {}) or {}) if not args.force else {}
            # shared with the authorised local producer (here: the simulator); sent as a bearer token
            token = old_col.get("ingest_token") or secrets.token_urlsafe(32)
            save_json(col_cfg_path, {
                "collector_id": cid,
                "secret": secret,
                "pseudonym_salt": old_col.get("pseudonym_salt") or secrets.token_hex(16),
                "ingest_token": token,
                "site": c["site"],
                "tz": c["tz"],
                "saas_url": ingest_base,          # global entry point; region discovered at startup
                # relative to the config folder, so an exported collector bundle works on another machine
                "ca_file": rel(os.path.join(CERT_DIR, "ca.crt")) if tls else None,
                "client_cert": rel(crt) if mtls else None,
                "client_key": rel(key) if mtls else None,
                "ui_port": c["ui_port"],
                "syslog_port": c["syslog_port"],
                "window_s": 1,
                "raw_retention_min": 60,
                "simulator_url": f"http://127.0.0.1:{SIM_PORT}",
                "hosts": {h[0]: {"role": h[1], "service": h[2]} for h in c["hosts"]},
                "auth_burst_threshold": 5,
                **({"openaq_locations": {h[0]: h[3] for h in c["hosts"]}} if t.get("live") == "openaq" else {}),
            })
            if c.get("simulated") is False:
                continue                     # live sources feed this collector, not the simulator
            sim["collectors"][cid] = {"ingest": f"http://127.0.0.1:{c['ui_port']}/ingest", "ingest_token": token,
                                      "syslog_port": c["syslog_port"], "site": c["site"], "tz": c["tz"],
                                      "tenant": tid, "hosts": c["hosts"]}

    for user, pw, tid, role in USERS:
        salt = secrets.token_hex(16)
        registry["users"][user] = {"tenant_id": tid, "role": role, "salt": salt, "pw_hash": pbkdf2(pw, salt)}

    save_json(reg_path, registry)
    save_json(os.path.join(CONFIG_DIR, "simulator.json"), sim)
    print(f"   Registry: {len(registry['tenants'])} tenants, {len(registry['collectors'])} collectors, "
          f"{len(registry['users'])} users -> config/registry.json")
    if remote:
        print(f"   Collectors on other machines connect to {ingest_base} (ingest listens on all interfaces).")
        print("   Export a collector for another laptop: python tools/export_collector.py <collector-id>")
    print("Setup complete.")


if __name__ == "__main__":
    main()
