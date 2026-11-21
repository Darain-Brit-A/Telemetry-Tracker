"""TeleTracker two-laptop mode with the fewest possible steps: this machine is the SaaS (Tier 2), another laptop runs
the collectors (Tier 1) and sends to it over the network.

    python tools/two_laptop.py package     # on the server, once: builds ..\\collector and ..\\collector.zip
    python tools/two_laptop.py server      # on the server: start Tier 2 (start_server.bat does this)
    python tools/two_laptop.py collector   # on the other laptop: find the server, start Tier 1
                                           # (start_collector.bat in the collector folder does this)

No IP addresses to type. Each time the server starts it looks up its current network address, makes sure
its TLS certificate covers it (re-issued by the same private CA when it changes, so the collector's
certificates stay valid) and answers discovery requests on UDP 8442. The collector broadcasts a discovery
request, takes the server address from the reply and connects. Discovery is only a hint: the collector
still verifies the server's certificate against the private CA before sending anything, so a fake reply
leads nowhere. If discovery is blocked on the network, the collector asks for the address shown in the
server window.
"""
import argparse
import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.util import CONFIG_DIR, load_json, save_json  # noqa: E402

PY = sys.executable
DISCOVERY_PORT = 8442
INGEST_PORT = 8443
ASK, ANSWER = b"AIOPS-DISCOVER?", b"AIOPS-HERE "
PACKAGE_MARK = ".aiops-collector-package"

START_COLLECTOR_BAT = r"""@echo off
title TeleTracker Tier 1 (collector)
cd /d "%~dp0"
python tools\two_laptop.py collector
pause
"""

COLLECTOR_README = """TeleTracker Tier 1 - collector laptop
=====================================

1. Install Python 3.12 or newer from python.org (tick "Add Python to PATH").
2. Connect this laptop to the SAME Wi-Fi / hotspot as the server laptop.
3. Make sure the server laptop shows "TIER 2 READY" (start_server.bat on the server).
4. Double-click start_collector.bat in this folder.

It finds the server by itself, then starts {n} collectors: live air quality from the OpenAQ API
(Bengaluru, Delhi, Mumbai, Chennai) and the simulated servers. Close the window to stop.

This folder contains the collectors' secrets, private keys and the OpenAQ API key: do not share it.
"""


def lan_ip():
    """This machine's address on the network that leads to the internet / other laptops."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))           # no packet is sent; picks the outgoing interface
        ip = s.getsockname()[0]
    except OSError:
        ip = None
    finally:
        s.close()
    if not ip or ip.startswith("127."):
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = "127.0.0.1"
    return ip


def run_setup(ip):
    subprocess.run([PY, os.path.join(ROOT, "setup_env.py"), "--saas-host", ip], cwd=ROOT, check=True)


def collector_ids():
    return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(CONFIG_DIR, "collectors", "*.json")))


# ------------------------------------------------------------------ server side
def discovery_responder(ip, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", DISCOVERY_PORT))
    sock.settimeout(1.0)
    reply = ANSWER + json.dumps({"host": ip, "port": INGEST_PORT}).encode()
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(256)
        except socket.timeout:
            continue
        except OSError:
            continue
        if data.startswith(ASK):
            sock.sendto(reply, addr)
            print(f"[discovery] collector laptop {addr[0]} asked for the server -> {ip}:{INGEST_PORT}", flush=True)


def server(args):
    ip = args.host or lan_ip()
    if ip.startswith("127."):
        sys.exit("No network address found: connect this laptop to Wi-Fi / the hotspot first.")
    run_setup(ip)
    stop = threading.Event()
    threading.Thread(target=discovery_responder, args=(ip, stop), daemon=True).start()
    line = "=" * 64
    print(f"\n{line}\n  TeleTracker TIER 2 READY on this laptop\n  collectors send to : https://{ip}:{INGEST_PORT}\n"
          f"  dashboard          : http://localhost:8080   (acme-admin / acme-admin-demo,\n"
          f"                       cityair-admin / cityair-admin-demo)\n"
          f"  other laptop       : double-click start_collector.bat\n{line}\n", flush=True)
    cmd = [PY, os.path.join(ROOT, "run_all.py"), "--saas-only"] + (["--fresh"] if args.fresh else [])
    try:
        subprocess.run(cmd, cwd=ROOT)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()


def package(args):
    """Build the ready-to-copy collector folder (..\\collector) and collector.zip next to this folder."""
    ip = args.host or lan_ip()
    run_setup(ip)
    ids = collector_ids()
    parent = os.path.dirname(ROOT)
    dest = os.path.join(parent, "collector")
    if os.path.exists(dest):
        if not os.path.exists(os.path.join(dest, PACKAGE_MARK)):
            sys.exit(f"{dest} exists and is not a collector package; move it away first")
        shutil.rmtree(dest)
    os.makedirs(dest)
    # code: every tracked file except tests (the collector laptop does not need git)
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    for rel in files:
        if rel.startswith("tests/") or rel.startswith(".github/"):
            continue
        os.makedirs(os.path.dirname(os.path.join(dest, rel)) or dest, exist_ok=True)
        shutil.copy2(os.path.join(ROOT, rel), os.path.join(dest, rel))
    # identity: the exported bundle for all collectors, unpacked
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([PY, os.path.join(ROOT, "tools", "export_collector.py"), *ids, "--out", tmp],
                       cwd=ROOT, check=True, capture_output=True)
        with zipfile.ZipFile(glob.glob(os.path.join(tmp, "*.zip"))[0]) as z:
            z.extractall(dest)
    key = os.path.join(CONFIG_DIR, "pollution.json")
    if os.path.exists(key):
        shutil.copy2(key, os.path.join(dest, "config", "pollution.json"))
    with open(os.path.join(dest, "start_collector.bat"), "w", newline="\r\n") as f:
        f.write(START_COLLECTOR_BAT)
    with open(os.path.join(dest, "README.txt"), "w", newline="\r\n") as f:
        f.write(COLLECTOR_README.format(n=len(ids)))
    with open(os.path.join(dest, PACKAGE_MARK), "w") as f:
        f.write("collector package built by tools/two_laptop.py package\n")
    zpath = os.path.join(parent, "collector.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for base, _, names in os.walk(dest):
            for n in names:
                full = os.path.join(base, n)
                z.write(full, os.path.join("collector", os.path.relpath(full, dest)))
    print(f"\ncollector folder : {dest}\ncollector.zip    : {zpath}\n"
          f"  {len(ids)} collectors ({', '.join(ids)})\n"
          f"  OpenAQ key       : {'included' if os.path.exists(key) else 'NOT included (no config/pollution.json here)'}\n"
          f"Copy collector.zip to the other laptop, unzip it, double-click start_collector.bat.")


# ------------------------------------------------------------------ collector side
def discover(timeout=2.0, tries=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    try:
        for _ in range(tries):
            try:
                sock.sendto(ASK, ("255.255.255.255", DISCOVERY_PORT))
                while True:
                    data, addr = sock.recvfrom(512)
                    if data.startswith(ANSWER):
                        info = json.loads(data[len(ANSWER):])
                        return info["host"], int(info.get("port", INGEST_PORT))
            except (socket.timeout, OSError, ValueError, KeyError):
                continue
    finally:
        sock.close()
    return None


def reachable(host, port, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def point_collectors_at(host, port):
    url = f"https://{host}:{port}"
    for cid in collector_ids():
        path = os.path.join(CONFIG_DIR, "collectors", f"{cid}.json")
        cfg = load_json(path)
        if cfg.get("saas_url") != url:
            cfg["saas_url"] = url
            save_json(path, cfg)
    return url


def collector(args):
    ids = collector_ids()
    if not ids:
        sys.exit("No collector configuration here: unzip collector.zip from the server laptop and run this inside it.")
    current = (load_json(os.path.join(CONFIG_DIR, "collectors", f"{ids[0]}.json")) or {}).get("saas_url", "")
    print("Looking for the server laptop on the network ...", flush=True)
    found = (args.host, INGEST_PORT) if args.host else discover()
    if found:
        host, port = found
        print(f"Found the server at {host}:{port}")
    else:
        host, port = current.split("://", 1)[-1].rsplit(":", 1)[0].strip("[]"), INGEST_PORT
        print(f"No answer to discovery; trying the last known server {host}:{port}")
    if not reachable(host, port):
        print(f"\nCannot reach {host}:{port}. Check that:\n  - the server laptop shows 'TIER 2 READY'\n"
              "  - both laptops are on the same Wi-Fi / hotspot\n"
              "  - the server laptop's firewall allows Python (see README in the '2 laptop version' folder)")
        typed = input("Server address shown in the server window (or Enter to quit): ").strip()
        if not typed:
            sys.exit(1)
        host = typed.split("://", 1)[-1].split(":")[0]
        if not reachable(host, port):
            sys.exit(f"Still cannot reach {host}:{port}.")
    url = point_collectors_at(host, port)
    print(f"\nTeleTracker TIER 1 starting: {len(ids)} collectors -> {url}\n", flush=True)
    cmd = [PY, os.path.join(ROOT, "run_all.py")] + [x for cid in ids for x in ("--collector", cid)]
    try:
        subprocess.run(cmd, cwd=ROOT)
    except KeyboardInterrupt:
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("server", "collector", "package"))
    ap.add_argument("--host", help="override the detected / discovered server address")
    ap.add_argument("--fresh", action="store_true", help="server: start with empty data")
    args = ap.parse_args()
    {"server": server, "collector": collector, "package": package}[args.mode](args)


if __name__ == "__main__":
    main()
