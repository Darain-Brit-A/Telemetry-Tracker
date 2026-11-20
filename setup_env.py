"""One-time environment setup.

* creates a private CA and a TLS certificate for the SaaS ingest endpoint (openssl)
* issues each collector its own client certificate (mutual TLS) and enrols its SHA-256 fingerprint
* enrols collectors (per-collector HMAC secret, bound to one tenant, and a token for the local /ingest)
* writes the SaaS registry (tenants, residency regions, users) and collector configs

Re-running keeps existing secrets unless --force is given.
"""
import argparse
import hashlib
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
}

USERS = [  # demo-only credentials (also listed in README)
    ("acme-admin", "acme-admin-demo", "acme", "admin"),
    ("acme-viewer", "acme-viewer-demo", "acme", "viewer"),
    ("globex-admin", "globex-admin-demo", "globex", "admin"),
]

DEFAULT_THRESHOLDS = {
    # metric: [excellent_below, good_below, fair_below]  (>= last -> Poor)
    "cpu_pct": [60, 80, 92],
    "mem_pct": [70, 85, 95],
    "disk_pct": [75, 85, 95],
    "latency_ms": [60, 120, 300],
    "packet_loss_pct": [0.5, 2, 5],
}
HEALTH_SETTINGS = {"stale_after_s": 10, "no_data_after_s": 30, "collector_offline_after_s": 30}

SETUP_VERSION = 2          # bump when setup adds something existing configs need (run_all re-runs setup)
SAAS_DASH_PORT = 8080
SAAS_INGEST_PORT = 8443
SIM_PORT = 9000


def pbkdf2(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()


SERVER_EXT = ("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
              "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
CLIENT_EXT = ("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
CLIENT_DIR = os.path.join(CERT_DIR, "collectors")


def client_cert_paths(cid):
    return os.path.join(CLIENT_DIR, f"{cid}.crt"), os.path.join(CLIENT_DIR, f"{cid}.key")


def make_certs(force, collector_ids):
    """Returns (tls, mtls). Existing certificates are kept unless `force`; missing client
    certificates are issued from the existing CA."""
    os.makedirs(CLIENT_DIR, exist_ok=True)
    ca_crt, ca_key = os.path.join(CERT_DIR, "ca.crt"), os.path.join(CERT_DIR, "ca.key")
    have_ca = os.path.exists(ca_crt) and not force
    missing = [c for c in collector_ids if force or not os.path.exists(client_cert_paths(c)[0])]
    if have_ca and not missing:
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
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
            "-days", "365", "-subj", "/CN=AIOps Demo Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr",
            "-subj", "/CN=localhost")
        run("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", ca_key, "-CAcreateserial",
            "-out", "server.crt", "-days", "365", "-extfile", ext_file("san.ext", SERVER_EXT))
        print("   TLS: private CA + server certificate created in config/certs")
    if not os.path.exists(ca_key):
        print("!! CA private key not found - cannot issue client certificates; mutual TLS disabled.")
        return True, False
    client_ext = ext_file("client.ext", CLIENT_EXT)
    for cid in missing:
        crt, key = client_cert_paths(cid)
        csr = os.path.join(CLIENT_DIR, f"{cid}.csr")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", f"/CN={cid}")
        run("x509", "-req", "-in", csr, "-CA", "ca.crt", "-CAkey", ca_key, "-CAcreateserial",
            "-out", crt, "-days", "365", "-extfile", client_ext)
        os.remove(csr)
    print(f"   mTLS: {len(missing)} collector client certificate(s) issued in config/certs/collectors")
    return True, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="regenerate secrets and certificates")
    args = ap.parse_args()
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    collector_ids = [cid for t in TENANTS.values() for cid in t["collectors"]]
    tls, mtls = make_certs(args.force, collector_ids)
    scheme = "https" if tls else "http"
    ingest_base = f"{scheme}://127.0.0.1:{SAAS_INGEST_PORT}"

    reg_path = os.path.join(CONFIG_DIR, "registry.json")
    old = {} if args.force else (load_json(reg_path, {}) or {})
    old_secrets = {cid: c["secret"] for cid, c in old.get("collectors", {}).items()}

    registry = {"regions": REGIONS, "tenants": {}, "collectors": {}, "users": {}, "tls": tls, "mtls": mtls, "setup_version": SETUP_VERSION,
                "dashboard_port": SAAS_DASH_PORT, "ingest_port": SAAS_INGEST_PORT}
    sim = {"port": SIM_PORT, "collectors": {}}

    for tid, t in TENANTS.items():
        registry["tenants"][tid] = {"name": t["name"], "region": t["region"], "dependencies": t["dependencies"],
                                    "thresholds": DEFAULT_THRESHOLDS, "health": HEALTH_SETTINGS}
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
                "ca_file": os.path.join(CERT_DIR, "ca.crt") if tls else None,
                "client_cert": crt if mtls else None,
                "client_key": key if mtls else None,
                "ui_port": c["ui_port"],
                "syslog_port": c["syslog_port"],
                "window_s": 1,
                "raw_retention_min": 60,
                "simulator_url": f"http://127.0.0.1:{SIM_PORT}",
                "hosts": {h: {"role": r, "service": s} for h, r, s in c["hosts"]},
                "auth_burst_threshold": 5,
            })
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
    print("Setup complete.")


if __name__ == "__main__":
    main()
