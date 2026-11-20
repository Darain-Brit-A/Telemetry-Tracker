"""Package one collector so it can run on another machine (two-laptop / multi-site deployments).

    python tools/export_collector.py col-acme-dc1                  # -> collector-col-acme-dc1.zip
    python tools/export_collector.py col-air-del --out D:/usb/

Run it on the SaaS machine after `python setup_env.py --saas-host <SaaS IP or name>`. The zip holds only
what that collector needs:

    config/collectors/<id>.json            its identity: HMAC secret, pseudonym salt, /ingest token, SaaS URL
    config/certs/ca.crt                    the private CA, to verify the SaaS certificate
    config/certs/collectors/<id>.crt/.key  its own mutual-TLS client certificate and private key
    config/simulator.json                  the simulator config for this collector only (simulated sites)
    COLLECTOR-README.txt                   the steps for the other machine

It never contains the SaaS registry, the CA private key, other collectors' secrets, or the OpenAQ API key.
The zip DOES contain this collector's secret and private key: move it like a password (USB stick, scp),
and delete it after unpacking. If it leaks, re-issue: delete the collector's certificate, re-run
setup_env.py --force (or disable the collector in the registry) and export again.
"""
import argparse
import json
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.util import CONFIG_DIR, load_json  # noqa: E402

README = """Collector {cid} ({site}) - run on this machine
=================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/{cid}.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP {port}):
       Test-NetConnection {host} -Port {port}

4. Start the collector and its local data source:
       python run_all.py --collector {cid}
   (that starts collector/collector.py --config {cid} plus {feeder})

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:{ui_port} on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("collector", help="collector id, e.g. col-acme-dc1")
    ap.add_argument("--out", default=".", help="folder or .zip path for the bundle (default: current folder)")
    args = ap.parse_args()
    cid = args.collector
    cfg = load_json(os.path.join(CONFIG_DIR, "collectors", f"{cid}.json"))
    if not cfg:
        sys.exit(f"unknown collector {cid} (run setup_env.py first)")
    if "127.0.0.1" in (cfg.get("saas_url") or "") or "localhost" in (cfg.get("saas_url") or ""):
        print(f"!! {cid} points at {cfg.get('saas_url')}, which only works on this machine.\n"
              f"   Run: python setup_env.py --saas-host <this machine's LAN IP>   and export again.")
        sys.exit(1)
    files = {}
    for key in ("ca_file", "client_cert", "client_key"):
        p = cfg.get(key)
        if not p:
            continue
        if os.path.isabs(p):
            rel = os.path.relpath(p, CONFIG_DIR).replace(os.sep, "/")
            if rel.startswith(".."):
                sys.exit(f"{key} {p} is outside the config folder; re-run setup_env.py")
            cfg[key] = rel
        files[f"config/{cfg[key]}"] = os.path.join(CONFIG_DIR, cfg[key])
    for name, path in files.items():
        if not os.path.exists(path):
            sys.exit(f"missing {path} - run setup_env.py")
    sim = load_json(os.path.join(CONFIG_DIR, "simulator.json"), {}) or {}
    sim_one = None
    if cid in sim.get("collectors", {}):
        sim_one = dict(sim, collectors={cid: sim["collectors"][cid]})
    host = cfg["saas_url"].split("://", 1)[1].rsplit(":", 1)[0].strip("[]")
    port = cfg["saas_url"].rsplit(":", 1)[1]
    out = args.out
    if not out.endswith(".zip"):
        os.makedirs(out, exist_ok=True)
        out = os.path.join(out, f"collector-{cid}.zip")
    feeder = "the simulator for its hosts" if sim_one else (
        "the OpenAQ poller (needs config/pollution.json with your OpenAQ key)" if cfg.get("openaq_locations")
        else "nothing else: point your own sources at its /ingest")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"config/collectors/{cid}.json", json.dumps(cfg, indent=2))
        for name, path in files.items():
            z.write(path, name)
        if sim_one:
            z.writestr("config/simulator.json", json.dumps(sim_one, indent=2))
        z.writestr("COLLECTOR-README.txt", README.format(cid=cid, site=cfg.get("site"), host=host, port=port,
                                                         ui_port=cfg.get("ui_port"), feeder=feeder))
    print(f"wrote {out}  ({cid} -> {cfg['saas_url']})")
    print("   contains this collector's secret and private key: move it like a password, delete after unpacking")


if __name__ == "__main__":
    main()
