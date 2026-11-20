"""Live air-quality feed: official monitors read through the OpenAQ v3 API, fed into a Tier-1 collector.

    python tools/openaq_poller.py                 # uses config/collectors/col-air-blr.json
    python tools/openaq_poller.py --once          # fetch and print one round, send nothing

The API key comes from the AIOPS_OPENAQ_API_KEY environment variable or from config/pollution.json
({"api_key": "..."}); config/ is git-ignored, so the key never lands in the repository.

Every --poll seconds the poller asks OpenAQ for each monitor's latest readings (one request per monitor,
well inside the free plan's 60 requests per minute). It keeps, per pollutant, the newest reading that is
at most --max-age hours old (some monitors carry sensors that stopped years ago), converts it to
micrograms per cubic metre, and every --emit seconds posts the latest known values to the collector's
loopback /ingest as metric events, together with `aq_age_min` (minutes since the monitor measured).
Monitors report every 15-60 minutes with a delay, so the age is shown rather than hidden; a monitor with
nothing recent is not emitted at all and shows as "no data" on the dashboard.
"""
import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.util import CONFIG_DIR, iso, load_json, now_ms, parse_iso  # noqa: E402
from common.web import ingest_headers  # noqa: E402

API = "https://api.openaq.org/v3"
METRIC_FOR = {"pm25": "pm25_ugm3", "pm10": "pm10_ugm3", "no2": "no2_ugm3"}
# ppb -> micrograms per cubic metre at 25 °C and 1 atm (molar mass / 24.45)
PPB_TO_UGM3 = {"no2": 46.0055 / 24.45}


def api_key():
    key = os.environ.get("AIOPS_OPENAQ_API_KEY") or (load_json(os.path.join(CONFIG_DIR, "pollution.json"), {}) or {}).get("api_key")
    return (key or "").strip() or None


def to_ugm3(parameter, value, units):
    """Convert a reading to micrograms per cubic metre; None if the unit is not understood."""
    u = (units or "").lower().replace("µ", "u").replace("μ", "u").replace("³", "3")
    if u in ("ug/m3", "ugm3"):
        return value
    if u == "ppb" and parameter in PPB_TO_UGM3:
        return value * PPB_TO_UGM3[parameter]
    if u == "ppm" and parameter in PPB_TO_UGM3:
        return value * 1000 * PPB_TO_UGM3[parameter]
    return None


def pick_latest(latest, sensors, now, max_age_h):
    """From /locations/{id}/latest results and the location's sensor list, the newest reading per metric.

    Returns {metric: (value_ugm3, measured_ms)}; readings older than max_age_h, negative, or in an
    unknown unit are dropped."""
    out = {}
    for r in latest:
        sensor = sensors.get(r.get("sensorsId"))
        if not sensor:
            continue
        parameter, units = sensor
        metric = METRIC_FOR.get(parameter)
        value = r.get("value")
        when = ((r.get("datetime") or {}).get("utc"))
        if not metric or not isinstance(value, (int, float)) or value < 0 or not when:
            continue
        ts = parse_iso(when)
        if now - ts > max_age_h * 3_600_000:
            continue
        v = to_ugm3(parameter, float(value), units)
        if v is None:
            continue
        if metric not in out or ts > out[metric][1]:
            out[metric] = (round(v, 1), ts)
    return out


class Poller:
    def __init__(self, cfg, key, poll_s=120, emit_s=5, max_age_h=3, out=print):
        self.cfg, self.key, self.poll_s, self.emit_s, self.max_age_h, self.out = cfg, key, poll_s, emit_s, max_age_h, out
        self.locations = cfg["openaq_locations"]               # host -> OpenAQ location id
        self.sensors = {}                                       # location id -> {sensor id: (parameter, units)}
        self.readings = {}                                      # host -> {metric: (value, measured_ms)}
        self.lock = threading.Lock()
        self.ingest = f"http://127.0.0.1:{cfg['ui_port']}/ingest"

    def get(self, path):
        req = urllib.request.Request(API + path, headers={"X-API-Key": self.key, "Accept": "application/json",
                                                          "User-Agent": "aiops-observability/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())

    def refresh(self):
        now = now_ms()
        for host, loc in self.locations.items():
            try:
                if loc not in self.sensors:
                    res = self.get(f"/locations/{loc}")["results"][0]
                    self.sensors[loc] = {s["id"]: (s["parameter"]["name"], s["parameter"]["units"]) for s in res["sensors"]}
                got = pick_latest(self.get(f"/locations/{loc}/latest")["results"], self.sensors[loc], now, self.max_age_h)
            except urllib.error.HTTPError as e:
                self.out(f"[openaq] {host}: HTTP {e.code} {'(rate limited, will retry)' if e.code == 429 else ''}")
                if e.code in (401, 403):
                    raise SystemExit("[openaq] API key rejected - check AIOPS_OPENAQ_API_KEY or config/pollution.json")
                continue
            except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError) as e:
                self.out(f"[openaq] {host}: {type(e).__name__}: {str(e)[:80]}")
                continue
            with self.lock:
                if got:
                    self.readings[host] = got
                else:
                    self.readings.pop(host, None)
            if got:
                newest = max(ts for _, ts in got.values())
                vals = ", ".join(f"{m.split('_')[0]}={v}" for m, (v, _) in sorted(got.items()))
                self.out(f"[openaq] {host}: {vals} (measured {iso(newest)[:16]}Z, {(now - newest) // 60000} min ago)")
            else:
                self.out(f"[openaq] {host}: no reading in the last {self.max_age_h} h - shown as no data")

    def events(self):
        now = now_ms()
        evs = []
        with self.lock:
            for host, got in self.readings.items():
                metrics = {m: v for m, (v, _) in got.items()}
                metrics["aq_age_min"] = round((now - max(ts for _, ts in got.values())) / 60000, 1)
                h = self.cfg["hosts"].get(host, {})
                evs.append({"type": "metric", "host": host, "role": h.get("role", "air-monitor"),
                            "service": h.get("service", host), "ts": iso(now), "metrics": metrics})
        return evs

    def emit(self):
        evs = self.events()
        if not evs:
            return 0
        req = urllib.request.Request(self.ingest, data=json.dumps(evs).encode(), method="POST",
                                     headers=ingest_headers(self.cfg.get("ingest_token")))
        try:
            urllib.request.urlopen(req, timeout=3).read()
        except (urllib.error.URLError, OSError) as e:
            self.out(f"[openaq] collector not reachable: {e}")
            return 0
        return len(evs)

    def run(self):
        last_poll = 0.0
        while True:
            if time.time() - last_poll >= self.poll_s:
                last_poll = time.time()
                self.refresh()
            self.emit()
            time.sleep(self.emit_s)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--collector", default="col-air-blr")
    ap.add_argument("--poll", type=int, default=120, help="seconds between OpenAQ requests per monitor (default 120)")
    ap.add_argument("--emit", type=int, default=5, help="seconds between sends to the collector (default 5)")
    ap.add_argument("--max-age", type=float, default=3, help="ignore readings older than this many hours (default 3)")
    ap.add_argument("--once", action="store_true", help="fetch one round, print it, send nothing")
    args = ap.parse_args()
    key = api_key()
    if not key:
        sys.exit("[openaq] no API key: set AIOPS_OPENAQ_API_KEY or create config/pollution.json")
    cfg = load_json(os.path.join(CONFIG_DIR, "collectors", f"{args.collector}.json"))
    if not cfg or "openaq_locations" not in cfg:
        sys.exit(f"[openaq] collector {args.collector} has no openaq_locations (run setup_env.py)")
    p = Poller(cfg, key, args.poll, args.emit, args.max_age)
    print(f"[openaq] {len(p.locations)} monitors -> {p.ingest} (poll {args.poll}s, emit {args.emit}s)", flush=True)
    if args.once:
        p.refresh()
        print(json.dumps(p.events(), indent=1))
        return
    p.run()


if __name__ == "__main__":
    main()
