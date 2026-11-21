"""Start the whole demo: SaaS (Tier 2), three collectors (Tier 1) and the telemetry simulator.

    python run_all.py            # start (runs setup on first use)
    python run_all.py --fresh    # wipe stored data first (keeps certs/secrets)

Two machines (see docs/TWO_MACHINES.md):
    python run_all.py --saas-only                 # SaaS machine: only the SaaS
    python run_all.py --exclude col-acme-dc1      # SaaS machine: everything except collectors run elsewhere
    python run_all.py --collector col-acme-dc1    # collector machine: that collector + its data source

Ctrl+C stops everything. Individual components can be restarted on their own, e.g.
    python saas/server.py
    python collector/collector.py --config col-acme-dc1
    python simulator/stream.py
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def pump(name, proc):
    for line in iter(proc.stdout.readline, b""):
        sys.stdout.write(f"{name:<16}| {line.decode(errors='replace')}")
        sys.stdout.flush()


def read_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fresh", action="store_true", help="delete stored SaaS/collector data before starting")
    ap.add_argument("--compressed-day", type=float, metavar="SECONDS",
                    help="seasonal-baseline demo: a simulated day lasts this many seconds (e.g. 600)")
    ap.add_argument("--seasonal-min-days", type=int, metavar="N",
                    help="days of history before the seasonal baseline is used (default 3)")
    ap.add_argument("--saas-only", action="store_true", help="start only the SaaS (collectors run elsewhere)")
    ap.add_argument("--collector", action="append", metavar="ID",
                    help="start only this collector (repeatable) plus its data source; no SaaS, no setup. "
                         "Use on a collector machine after unpacking its bundle")
    ap.add_argument("--exclude", action="append", metavar="ID",
                    help="start everything except this collector (repeatable), e.g. because it runs on another machine")
    args = ap.parse_args()
    if args.compressed_day:
        os.environ["AIOPS_DAY_S"] = str(args.compressed_day)          # read by the SaaS engine and the simulator
    if args.seasonal_min_days:
        os.environ["AIOPS_SEASONAL_MIN_DAYS"] = str(args.seasonal_min_days)
    collector_mode = bool(args.collector)
    reg_path = os.path.join(ROOT, "config", "registry.json")
    reg = {}
    if os.path.exists(reg_path):
        with open(reg_path, encoding="utf-8") as f:
            reg = json.load(f)
    from setup_env import SETUP_VERSION
    if not collector_mode and reg.get("setup_version", 0) < SETUP_VERSION:
        # first run, or a config from an older setup: setup keeps existing secrets and adds what is missing.
        # A collector-only machine has no registry and never runs setup (its bundle is its whole config).
        subprocess.run([PY, os.path.join(ROOT, "setup_env.py")], check=True)
    if args.fresh:
        shutil.rmtree(os.path.join(ROOT, "data"), ignore_errors=True)
        print("data/ wiped")
    cdir = os.path.join(ROOT, "config", "collectors")
    all_cols = sorted(f[:-5] for f in os.listdir(cdir) if f.endswith(".json")) if os.path.isdir(cdir) else []
    if collector_mode:
        missing = [c for c in args.collector if c not in all_cols]
        if missing:
            sys.exit(f"no config for {', '.join(missing)} - unpack its bundle (tools/export_collector.py) here first")
        cols = sorted(args.collector)
    elif args.saas_only:
        cols = []
    else:
        cols = [c for c in all_cols if c not in (args.exclude or [])]
    plan = [] if collector_mode else [("saas", [PY, "-u", os.path.join(ROOT, "saas", "server.py")])]
    plan += [(c, [PY, "-u", os.path.join(ROOT, "collector", "collector.py"), "--config", c]) for c in cols]
    sim_cols = set(read_json(os.path.join(ROOT, "config", "simulator.json")).get("collectors") or {})
    simulated = [c for c in cols if c in sim_cols]
    if simulated:
        plan += [("simulator", [PY, "-u", os.path.join(ROOT, "simulator", "stream.py"), "--collectors", ",".join(simulated)])]
    # live air-quality feed (real data, OpenAQ) when an API key is configured; see tools/openaq_poller.py
    air = []
    for c in cols:
        with open(os.path.join(cdir, f"{c}.json"), encoding="utf-8") as f:
            if json.load(f).get("openaq_locations"):
                air.append(c)
    if air and (os.environ.get("AIOPS_OPENAQ_API_KEY") or os.path.exists(os.path.join(ROOT, "config", "pollution.json"))):
        plan += [("openaq", [PY, "-u", os.path.join(ROOT, "tools", "openaq_poller.py"), "--collectors", ",".join(air)])]
    procs = []
    for name, cmd in plan:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        procs.append((name, p))
        threading.Thread(target=pump, args=(name, p), daemon=True).start()
        time.sleep(0.8 if name == "saas" else 0.3)
    if collector_mode:
        for c in cols:
            with open(os.path.join(cdir, f"{c}.json"), encoding="utf-8") as f:
                cc = json.load(f)
            print(f"\n  Collector {c} ({cc.get('site')}) -> SaaS {cc.get('saas_url')}   console http://127.0.0.1:{cc.get('ui_port')}")
        if air and not any(n == "openaq" for n, _ in plan):
            print("  !! live air collector without an OpenAQ key: create config/pollution.json on this machine")
    else:
        print("\n  SaaS dashboard : http://localhost:8080   (acme-admin / acme-admin-demo, globex-admin / globex-admin-demo)")
        if reg.get("ingest_public_host", "127.0.0.1") != "127.0.0.1":
            print(f"  SaaS ingest    : https://{reg['ingest_public_host']}:{reg.get('ingest_port', 8443)}  (collectors on other machines)")
        if cols:
            print(f"  Collectors here: {', '.join(cols)}" + (f"   (elsewhere: {', '.join(args.exclude)})" if args.exclude else ""))
        if any(n == "openaq" for n, _ in plan):
            print("  Live air data  : cityair-admin / cityair-admin-demo  (16 monitors in Bengaluru, Delhi, Mumbai, Chennai via OpenAQ)")
        elif air:
            print("  Live air data  : off (set AIOPS_OPENAQ_API_KEY or create config/pollution.json)")
    print("  Baselines need ~40s of telemetry before anomaly detection is armed.  Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
            for name, p in procs:
                if p.poll() is not None:
                    print(f"!! {name} exited with code {p.returncode}")
                    procs.remove((name, p))
                    break
    except KeyboardInterrupt:
        pass
    finally:
        for _, p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
