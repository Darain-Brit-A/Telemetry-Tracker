"""Start the whole demo: SaaS (Tier 2), three collectors (Tier 1) and the telemetry simulator.

    python run_all.py            # start (runs setup on first use)
    python run_all.py --fresh    # wipe stored data first (keeps certs/secrets)

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fresh", action="store_true", help="delete stored SaaS/collector data before starting")
    ap.add_argument("--compressed-day", type=float, metavar="SECONDS",
                    help="seasonal-baseline demo: a simulated day lasts this many seconds (e.g. 600)")
    ap.add_argument("--seasonal-min-days", type=int, metavar="N",
                    help="days of history before the seasonal baseline is used (default 3)")
    args = ap.parse_args()
    if args.compressed_day:
        os.environ["AIOPS_DAY_S"] = str(args.compressed_day)          # read by the SaaS engine and the simulator
    if args.seasonal_min_days:
        os.environ["AIOPS_SEASONAL_MIN_DAYS"] = str(args.seasonal_min_days)
    reg_path = os.path.join(ROOT, "config", "registry.json")
    reg = {}
    if os.path.exists(reg_path):
        with open(reg_path, encoding="utf-8") as f:
            reg = json.load(f)
    if not reg or "mtls" not in reg:
        # first run, or a config from before mutual TLS: setup keeps existing secrets and adds the rest
        subprocess.run([PY, os.path.join(ROOT, "setup_env.py")], check=True)
    if args.fresh:
        shutil.rmtree(os.path.join(ROOT, "data"), ignore_errors=True)
        print("data/ wiped")
    cols = sorted(f[:-5] for f in os.listdir(os.path.join(ROOT, "config", "collectors")) if f.endswith(".json"))
    plan = [("saas", [PY, "-u", os.path.join(ROOT, "saas", "server.py")])]
    plan += [(c, [PY, "-u", os.path.join(ROOT, "collector", "collector.py"), "--config", c]) for c in cols]
    plan += [("simulator", [PY, "-u", os.path.join(ROOT, "simulator", "stream.py")])]
    procs = []
    for name, cmd in plan:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        procs.append((name, p))
        threading.Thread(target=pump, args=(name, p), daemon=True).start()
        time.sleep(0.8 if name == "saas" else 0.3)
    print("\n  SaaS dashboard : http://localhost:8080   (acme-admin / acme-admin-demo, globex-admin / globex-admin-demo)")
    print("  Collector UIs  : http://127.0.0.1:9101 (acme dc1)  :9102 (acme cloud)  :9103 (globex nyc)")
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
