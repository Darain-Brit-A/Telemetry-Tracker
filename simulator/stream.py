"""Simulated telemetry stream (stand-in for the organizer-provided stream).

Feeds every collector through its *real* local inputs:
  * HTTP JSON  -> POST http://127.0.0.1:<ui_port>/ingest   (metrics, app logs, auth records)
  * Syslog UDP -> 127.0.0.1:<syslog_port>                    (sshd auth lines, app syslog)

Control API (port 9000) for injecting live scenarios identically every time:
  POST /scenario {"name": ..., "collector": ..., "host": ... | null, "duration": s}
  POST /heal     {"collector": ..., "host": ..., "action": ...}
  GET  /scenarios  -> injection log with UTC timestamps (used to measure detection latency)

--replay FILE.jsonl replays a recorded/organizer stream instead: one JSON event per line with a
"collector" field; timestamps are re-based to now unless --keep-ts is given.
"""
import argparse
import http.server
import json
import math
import os
import random
import socket
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.util import CONFIG_DIR, iso, load_json, now_ms, parse_iso  # noqa: E402
from common.web import ingest_headers  # noqa: E402

PROFILES = {  # role -> baseline
    "web": dict(cpu=32, mem=48, disk=41, bw=120, lat=22),
    "app": dict(cpu=38, mem=55, disk=37, bw=80, lat=28),
    "db": dict(cpu=30, mem=62, disk=58, bw=60, lat=8),
    "cache": dict(cpu=18, mem=66, disk=22, bw=90, lat=3),
    "network": dict(cpu=14, mem=35, disk=12, bw=300, lat=4),
}
SITE_WIDE = {"latency_rise", "db_saturation", "fleet_load", "out_of_order", "heal"}
USERS = ["admin", "root", "oracle", "jdoe", "backup", "test", "svc_deploy", "postgres"]
ATTACK_IPS = ["203.0.113.7", "198.51.100.23"]
LOCK = threading.Lock()
INJECTIONS = []
# Compressed day for the seasonal-baseline demo (ML feature 3): with AIOPS_DAY_S=600 a "day" lasts 10 minutes
# and web/app/db hosts get a normal evening peak. Unset: no daily curve, exactly the old behaviour.
DAY_S = float(os.environ["AIOPS_DAY_S"]) if os.environ.get("AIOPS_DAY_S") else None
DAILY_PEAK = 28.0       # extra CPU % at the evening peak


def daily_peak_factor(now, day_s):
    """0..1 shape of the evening peak: ramps up 16-18 h, full 18-20 h, down 20-22 h (local "hour")."""
    hour = (now % day_s) / day_s * 24
    if hour < 16 or hour >= 22:
        return 0.0
    if hour < 18:
        return (1 - math.cos((hour - 16) / 2 * math.pi)) / 2
    if hour < 20:
        return 1.0
    return (1 + math.cos((hour - 20) / 2 * math.pi)) / 2


class Host:
    def __init__(self, cid, name, role, service, tenant):
        self.cid, self.name, self.role, self.service, self.tenant = cid, name, role, service, tenant
        p = PROFILES.get(role, PROFILES["app"])
        self.base = {k: v * random.uniform(0.9, 1.1) for k, v in p.items()}
        self.phase = random.uniform(0, 6.28)
        self.scn = {}     # name -> {start, until, root}
        self.day_s = DAY_S if role in ("web", "app", "db") else None

    def active(self, name, now):
        s = self.scn.get(name)
        if s and now > s["until"]:
            self.scn.pop(name, None)
            return None
        return s

    def metrics(self, now):
        b = self.base
        cpu = b["cpu"] + 5 * math.sin(now / 95 + self.phase) + random.gauss(0, 2.2)
        mem = b["mem"] + random.gauss(0, 0.7)
        disk = b["disk"] + random.gauss(0, 0.15)
        bw = b["bw"] * (1 + 0.08 * math.sin(now / 80 + self.phase)) + random.gauss(0, b["bw"] * 0.05)
        lat = b["lat"] * (1 + 0.05 * math.sin(now / 60)) + random.gauss(0, max(1, b["lat"] * 0.08))
        loss = max(0.0, random.gauss(0.05, 0.04))
        reach, up = 1, 1
        if self.day_s:
            cpu += DAILY_PEAK * daily_peak_factor(now, self.day_s)
        for name in list(self.scn):
            s = self.active(name, now)
            if not s:
                continue
            el = now - s["start"]
            ramp = min(1.0, el / 4)
            if name == "cpu_spike":
                cpu += 55 * ramp
            elif name == "mem_leak":
                mem += min(0.45 * el, 97 - b["mem"])
            elif name == "disk_fill":
                disk += min(0.6 * el, 97 - b["disk"])
            elif name == "service_down":
                up = 0
            elif name == "latency_rise":
                lat += (140 + random.gauss(0, 12)) * ramp
                loss += 3.2 * ramp + random.gauss(0, 0.3)
            elif name == "db_saturation":
                if self.role == "db":
                    cpu += 58 * ramp
                    mem += 9 * ramp
                    lat += 40 * ramp
                elif el > 6:   # dependents feel it a few seconds later
                    lat += (110 if self.role == "app" else 150) * min(1.0, (el - 6) / 4)
            elif name == "fleet_load":
                cpu += 30 * ramp
                bw += 170 * ramp
                lat += 8 * ramp
            elif name == "night_spike":
                cpu += DAILY_PEAK * ramp      # the evening-peak level, but at whatever hour it is now
        clamp = lambda v, lo=0, hi=100: max(lo, min(hi, v))  # noqa: E731
        return {"cpu_pct": round(clamp(cpu), 2), "mem_pct": round(clamp(mem), 2), "disk_pct": round(clamp(disk), 2),
                "bw_in_mbps": round(max(0, bw), 1), "bw_out_mbps": round(max(0, bw * 0.6), 1),
                "latency_ms": round(max(0.5, lat), 1), "packet_loss_pct": round(clamp(loss), 2),
                "reachable": reach, "svc_up": up}


class Stream:
    def __init__(self, cfg):
        self.cfg = cfg
        self.hosts = {}
        for cid, c in cfg["collectors"].items():
            self.hosts[cid] = [Host(cid, h, r, s, c["tenant"]) for h, r, s in c["hosts"]]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.queue = {cid: [] for cid in cfg["collectors"]}
        self.silent = {}

    def host(self, cid, name):
        return next((h for h in self.hosts.get(cid, []) if h.name == name), None)

    def emit(self, cid, ev):
        with LOCK:
            self.queue[cid].append(ev)

    def syslog(self, cid, host, app, msg, pri=38):
        line = f"<{pri}>1 {iso()} {host} {app}[{random.randint(1000, 9999)}]: {msg}"
        self.udp.sendto(line.encode(), ("127.0.0.1", self.cfg["collectors"][cid]["syslog_port"]))

    def base_event(self, h):
        c = self.cfg["collectors"][h.cid]
        return {"host": h.name, "ts": iso(), "tz": c["tz"], "role": h.role, "service": h.service}

    # ------------------------------------------------------------------ background traffic
    def tick(self):
        now = time.time()
        for cid, hosts in self.hosts.items():
            for h in hosts:
                if self.silent.get((cid, h.name), 0) > now:
                    continue
                self.emit(cid, dict(self.base_event(h), type="metric", metrics=h.metrics(now)))
                r = random.random()
                if r < 0.30:
                    self.emit(cid, dict(self.base_event(h), type="log", level="INFO",
                                        message=random.choice([
                                            f"GET /api/cart/{random.randint(1000, 9999)} 200 {random.randint(8, 60)}ms",
                                            f"order {random.randint(10 ** 6, 10 ** 7)} committed in {random.randint(3, 30)}ms",
                                            f"cache hit ratio {random.uniform(0.8, 0.99):.2f}",
                                            f"user {random.choice(['anna', 'li', 'omar'])}@example.com signed in"])))
                elif r < 0.33:
                    self.emit(cid, dict(self.base_event(h), type="log", level="WARN",
                                        message=f"slow query took {random.randint(500, 900)}ms on table orders"))
                elif r < 0.34:
                    self.syslog(cid, h.name, "sshd", f"Accepted publickey for deploy from 10.0.{random.randint(0, 9)}.5 port "
                                f"{random.randint(30000, 60000)} ssh2", pri=86)
            self.scenario_tick(cid, now)

    def scenario_tick(self, cid, now):
        for h in self.hosts[cid]:
            s = h.active("failed_logins", now)
            if s:
                for _ in range(2):
                    user = random.choice(USERS)
                    ip = random.choice(ATTACK_IPS)
                    self.syslog(cid, h.name, "sshd", f"Failed password for invalid user {user} from {ip} port "
                                f"{random.randint(30000, 60000)} ssh2", pri=84)
                if random.random() < 0.5:
                    self.emit(cid, dict(self.base_event(h), type="auth", user=random.choice(USERS),
                                        src_ip=random.choice(ATTACK_IPS), result="failure", method="https-login"))
            s = h.active("error_burst", now)
            if s:
                for _ in range(3):
                    self.emit(cid, dict(self.base_event(h), type="log", level="ERROR",
                                        message=f"payment gateway timeout after {random.randint(3000, 5000)}ms "
                                                f"(order {random.randint(10 ** 6, 10 ** 7)})"))

    def flush(self):
        for cid, c in self.cfg["collectors"].items():
            with LOCK:
                batch, self.queue[cid] = self.queue[cid], []
            if not batch:
                continue
            try:
                req = urllib.request.Request(c["ingest"], data=json.dumps(batch).encode(), method="POST",
                                             headers=ingest_headers(c.get("ingest_token")))
                urllib.request.urlopen(req, timeout=2).read()
            except Exception:
                pass   # collector down: the source simply loses its sink, like a real device would

    def run(self):
        while True:
            t0 = time.time()
            self.tick()
            self.flush()
            time.sleep(max(0.0, 1.0 - (time.time() - t0)))

    # ------------------------------------------------------------------ scenarios
    def inject(self, name, cid, host=None, duration=None):
        now = time.time()
        hosts = self.hosts.get(cid)
        if hosts is None:
            return {"error": f"unknown collector {cid}"}
        target = self.host(cid, host) if host else None
        dur = duration or {"failed_logins": 25, "secret_in_log": 0, "mem_leak": 150, "disk_fill": 120,
                           "source_silent": 60, "night_spike": 60}.get(name, 120)
        info = {"name": name, "collector": cid, "host": host, "injected_at": iso(), "ms": now_ms()}
        if name == "heal":
            # only this collector's hosts: "Heal all" on one console must not end another tenant's
            # scenario (bug B12)
            scope = [target] if target else hosts
            for h in scope:
                h.scn.clear()
                self.silent.pop((cid, h.name), None)
        elif name == "secret_in_log":
            h = target or random.choice(hosts)
            info["host"] = h.name
            self.emit(cid, dict(self.base_event(h), type="log", level="ERROR",
                                message="DB connection failed: postgres://svc_app:Sup3rS3cret!@db-01:5432/orders "
                                        "password=Sup3rS3cret! retrying"))
            self.emit(cid, dict(self.base_event(h), type="log", level="WARN",
                                message="outbound call headers: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMifQ."
                                        "c2lnbmF0dXJlLXNlY3JldA api_key=sk_live_51HxQ9fAKExampleKey99"))
            self.syslog(cid, h.name, "deploy", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET=wJalrXUtnFEMI", pri=28)
        elif name == "source_silent":
            h = target or random.choice(hosts)
            info["host"] = h.name
            self.silent[(cid, h.name)] = now + dur
        elif name == "out_of_order":
            evs = []
            for _ in range(24):
                h = random.choice(hosts)
                ts = now_ms() - random.randint(3000, 15000)
                evs.append(dict(self.base_event(h), ts=iso(ts), type="metric", metrics=h.metrics(time.time())))
            random.shuffle(evs)
            for e in evs:
                self.emit(cid, e)
            info["events"] = len(evs)
        elif name in ("latency_rise", "db_saturation"):
            root = target
            if name == "db_saturation":
                root = next((h for h in hosts if h.role == "db"), hosts[0])
            for h in hosts:
                h.scn[name] = {"start": now, "until": now + dur, "root": root.name if root else None}
            info["host"] = root.name if root else None
        elif name == "fleet_load":
            tenant = hosts[0].tenant
            for hs in self.hosts.values():
                for h in hs:
                    if h.tenant == tenant and h.role == "web":
                        h.scn[name] = {"start": now, "until": now + dur, "root": None}
        else:
            h = target or random.choice(hosts)
            info["host"] = h.name
            h.scn[name] = {"start": now, "until": now + dur, "root": h.name}
        INJECTIONS.append(info)
        print(f"[sim] inject {name} on {cid}/{info.get('host') or 'site'} at {info['injected_at']}", flush=True)
        return info

    def heal(self, cid, host, action):
        now = time.time()
        for h in self.hosts.get(cid, []):
            for name, s in list(h.scn.items()):
                if h.name == host or s.get("root") == host or (action == "net.failover_uplink" and name == "latency_rise"):
                    h.scn.pop(name, None)
        if action == "svc.scale_out":   # extra capacity: fleet load spread thinner
            for hs in self.hosts.values():
                for h in hs:
                    if "fleet_load" in h.scn:
                        h.scn.pop("fleet_load")
        INJECTIONS.append({"name": f"remediated:{action}", "collector": cid, "host": host, "injected_at": iso(),
                           "ms": now_ms()})
        return {"ok": True, "healed_at": iso(now * 1000)}


def control(stream, port):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, code, obj):
            d = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(d)))
            self.end_headers()
            self.wfile.write(d)

        def do_GET(self):
            if self.path.startswith("/scenarios"):
                return self.reply(200, {"injections": INJECTIONS[-200:]})
            self.reply(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/scenario":
                r = stream.inject(data.get("name"), data.get("collector"), data.get("host"), data.get("duration"))
                return self.reply(400 if "error" in r else 200, r)
            if self.path == "/heal":
                return self.reply(200, stream.heal(data.get("collector"), data.get("host"), data.get("action")))
            self.reply(404, {"error": "not found"})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def replay(cfg, path, keep_ts):
    with open(path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    if not events:
        return
    t0 = parse_iso(events[0]["ts"])
    start = now_ms()
    for ev in events:
        offset = parse_iso(ev["ts"]) - t0
        wait = (start + offset - now_ms()) / 1000
        if wait > 0:
            time.sleep(wait)
        cid = ev.pop("collector")
        if not keep_ts:
            ev["ts"] = iso()
        req = urllib.request.Request(cfg["collectors"][cid]["ingest"], data=json.dumps([ev]).encode(), method="POST",
                                     headers=ingest_headers(cfg["collectors"][cid].get("ingest_token")))
        try:
            urllib.request.urlopen(req, timeout=2).read()
        except Exception as e:
            print(f"[sim] replay send failed: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--replay", help="replay a JSONL stream instead of generating one")
    ap.add_argument("--keep-ts", action="store_true")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--collectors", help="comma-separated collector ids to feed (default: all in the config)")
    args = ap.parse_args()
    random.seed(args.seed)
    cfg = load_json(os.path.join(CONFIG_DIR, "simulator.json"))
    if not cfg:
        sys.exit("config/simulator.json missing - run setup_env.py")
    if args.collectors:
        keep = set(args.collectors.split(","))
        cfg["collectors"] = {c: v for c, v in cfg["collectors"].items() if c in keep}
    if args.replay:
        replay(cfg, args.replay, args.keep_ts)
        return
    s = Stream(cfg)
    control(s, cfg["port"])
    print(f"[sim] streaming to {len(cfg['collectors'])} collectors; control http://127.0.0.1:{cfg['port']}", flush=True)
    s.run()


if __name__ == "__main__":
    main()
