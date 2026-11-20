"""Live air-quality feed: official monitors read through the OpenAQ v3 API, fed into Tier-1 collectors.

    python tools/openaq_poller.py            # every collector config that has "openaq_locations"
    python tools/openaq_poller.py --once     # discover + latest readings, print them, send nothing

The API key comes from the AIOPS_OPENAQ_API_KEY environment variable or from config/pollution.json
({"api_key": "..."}); config/ is git-ignored, so the key never lands in the repository.

How it works
* Discovery: for each monitor, the location's sensor list and its latest readings decide which sensor is
  live for each pollutant (some monitors also carry sensors that stopped years ago).
* History: the last --history-days of hourly averages per pollutant are sent first, at their real
  measurement times. The SaaS uses them only to learn each monitor's baseline and hour-of-day profile
  (points older than 3 hours never raise alerts), and the dashboard draws them as trends.
* Live: every --poll seconds the latest readings are fetched and each new measurement is sent once, at its
  real measurement time. Official monitors publish every 15-60 minutes with a delay; the dashboard shows
  how old each reading is, and a monitor with nothing recent turns stale / no data instead of repeating
  an old value.
* Requests are paced to stay inside the free plan (60 per minute).
"""
import argparse
import glob
import json
import os
import sys
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
MIN_INTERVAL_S = 1.1           # <= 55 requests per minute


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


def active_sensors(latest, sensors, now, max_age_h):
    """The live sensor per tracked pollutant: {metric: (sensor_id, value_ugm3, measured_ms)}.

    `latest` are /locations/{id}/latest results, `sensors` maps sensor id -> (parameter, units).
    For each pollutant the newest reading wins; readings older than max_age_h, negative, or in an unknown
    unit are ignored."""
    out = {}
    for r in latest:
        sensor = sensors.get(r.get("sensorsId"))
        if not sensor:
            continue
        parameter, units = sensor
        metric = METRIC_FOR.get(parameter)
        value = r.get("value")
        when = (r.get("datetime") or {}).get("utc")
        if not metric or not isinstance(value, (int, float)) or value < 0 or not when:
            continue
        ts = parse_iso(when)
        if now - ts > max_age_h * 3_600_000:
            continue
        v = to_ugm3(parameter, float(value), units)
        if v is None:
            continue
        if metric not in out or ts > out[metric][2]:
            out[metric] = (r["sensorsId"], round(v, 1), ts)
    return out


def hourly_points(results, parameter, units):
    """/sensors/{id}/hours results -> [(measured_ms, value_ugm3)], timestamped at the end of each hour."""
    pts = []
    for r in results:
        value = r.get("value")
        when = (((r.get("period") or {}).get("datetimeTo")) or {}).get("utc")
        if not isinstance(value, (int, float)) or value < 0 or not when:
            continue
        v = to_ugm3(parameter, float(value), units)
        if v is not None:
            pts.append((parse_iso(when), round(v, 1)))
    return sorted(pts)


def to_events(host, meta, points_by_metric):
    """{metric: [(ts, value)]} -> metric events, one per timestamp, in time order."""
    by_ts = {}
    for metric, pts in points_by_metric.items():
        for ts, v in pts:
            by_ts.setdefault(ts, {})[metric] = v
    return [{"type": "metric", "host": host, "role": meta.get("role", "air-monitor"),
             "service": meta.get("service", host), "ts": iso(ts), "metrics": m} for ts, m in sorted(by_ts.items())]


class Monitor:
    def __init__(self, host, location_id, cfg):
        self.host, self.location_id, self.cfg = host, location_id, cfg
        self.meta = cfg["hosts"].get(host, {})
        self.sensors = {}          # sensor id -> (parameter, units)
        self.active = {}           # metric -> sensor id
        self.last_sent = {}        # metric -> newest measurement time sent


class Poller:
    def __init__(self, configs, key, poll_s=120, history_days=4, max_age_h=6, out=print):
        self.key, self.poll_s, self.history_days, self.max_age_h, self.out = key, poll_s, history_days, max_age_h, out
        self.monitors = [Monitor(h, loc, cfg) for cfg in configs for h, loc in cfg["openaq_locations"].items()]
        self._last_request = 0.0

    def get(self, path):
        wait = MIN_INTERVAL_S - (time.time() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.time()
        req = urllib.request.Request(API + path, headers={"X-API-Key": self.key, "Accept": "application/json",
                                                          "User-Agent": "aiops-observability/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise SystemExit("[openaq] API key rejected - check AIOPS_OPENAQ_API_KEY or config/pollution.json")
            if e.code == 429:
                self.out("[openaq] rate limited - waiting 30 s")
                time.sleep(30)
            raise

    def send(self, m, events):
        """Post events to the monitor's own collector in chunks; True if all were accepted."""
        url = f"http://127.0.0.1:{m.cfg['ui_port']}/ingest"
        for i in range(0, len(events), 400):
            req = urllib.request.Request(url, data=json.dumps(events[i:i + 400]).encode(), method="POST",
                                         headers=ingest_headers(m.cfg.get("ingest_token")))
            try:
                urllib.request.urlopen(req, timeout=10).read()
            except (urllib.error.URLError, OSError) as e:
                self.out(f"[openaq] {m.host}: collector not reachable ({e})")
                return False
        return True

    def discover(self, m):
        loc = self.get(f"/locations/{m.location_id}")["results"][0]
        m.sensors = {s["id"]: (s["parameter"]["name"], s["parameter"]["units"]) for s in loc["sensors"]}
        latest = self.get(f"/locations/{m.location_id}/latest")["results"]
        act = active_sensors(latest, m.sensors, now_ms(), 24)
        m.active = {metric: sid for metric, (sid, _, _) in act.items()}
        return latest

    def backfill(self, m, latest, dry_run=False):
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - self.history_days * 86400))
        pts = {}
        for metric, sid in m.active.items():
            parameter, units = m.sensors[sid]
            res = self.get(f"/sensors/{sid}/hours?datetime_from={since}&limit=1000")["results"]
            pts[metric] = hourly_points(res, parameter, units)
        # the 15-minute latest readings are newer than the last complete hour
        for metric, (sid, v, ts) in active_sensors(latest, m.sensors, now_ms(), self.max_age_h).items():
            if sid == m.active.get(metric) and (not pts.get(metric) or ts > pts[metric][-1][0]):
                pts.setdefault(metric, []).append((ts, v))
        events = to_events(m.host, m.meta, pts)
        if dry_run or self.send(m, events):
            for metric, p in pts.items():
                if p:
                    m.last_sent[metric] = p[-1][0]
        return events

    def poll(self, m):
        latest = self.get(f"/locations/{m.location_id}/latest")["results"]
        fresh = {}
        for metric, (sid, v, ts) in active_sensors(latest, m.sensors, now_ms(), self.max_age_h).items():
            if sid == m.active.get(metric) and ts > m.last_sent.get(metric, 0):
                fresh[metric] = [(ts, v)]
        events = to_events(m.host, m.meta, fresh)
        if events and self.send(m, events):
            for metric, p in fresh.items():
                m.last_sent[metric] = p[-1][0]
            vals = ", ".join(f"{k.split('_')[0]}={p[-1][1]}" for k, p in sorted(fresh.items()))
            self.out(f"[openaq] {m.host}: new reading {vals} (measured {iso(max(p[-1][0] for p in fresh.values()))[11:16]}Z)")

    def start(self, dry_run=False):
        for m in self.monitors:
            try:
                latest = self.discover(m)
                events = self.backfill(m, latest, dry_run)
                newest = max(m.last_sent.values()) if m.last_sent else None
                self.out(f"[openaq] {m.cfg['site']}/{m.host}: {len(events)} hourly points over {self.history_days} days "
                         f"({', '.join(sorted(k.split('_')[0] for k in m.active)) or 'no live sensors'})"
                         + (f", newest {iso(newest)[:16]}Z" if newest else ""))
            except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError) as e:
                self.out(f"[openaq] {m.host}: discovery failed ({type(e).__name__}: {str(e)[:80]}) - will retry")

    def run(self):
        self.start()
        while True:
            t0 = time.time()
            for m in self.monitors:
                try:
                    if not m.active:
                        latest = self.discover(m)
                        self.backfill(m, latest)
                    else:
                        self.poll(m)
                except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError) as e:
                    self.out(f"[openaq] {m.host}: {type(e).__name__}: {str(e)[:80]}")
            time.sleep(max(5.0, self.poll_s - (time.time() - t0)))


def air_configs():
    out = []
    for path in sorted(glob.glob(os.path.join(CONFIG_DIR, "collectors", "*.json"))):
        cfg = load_json(path)
        if cfg and cfg.get("openaq_locations"):
            out.append(cfg)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--poll", type=int, default=120, help="seconds between rounds of latest readings (default 120)")
    ap.add_argument("--history-days", type=int, default=4, help="days of hourly history sent at start (default 4)")
    ap.add_argument("--once", action="store_true", help="discover and print one round, send nothing")
    args = ap.parse_args()
    key = api_key()
    if not key:
        sys.exit("[openaq] no API key: set AIOPS_OPENAQ_API_KEY or create config/pollution.json")
    configs = air_configs()
    if not configs:
        sys.exit("[openaq] no collector with openaq_locations (run setup_env.py)")
    p = Poller(configs, key, args.poll, args.history_days)
    print(f"[openaq] {len(p.monitors)} monitors in {len(configs)} cities "
          f"({', '.join(c['site'] for c in configs)}); history {args.history_days} days, poll {args.poll}s", flush=True)
    if args.once:
        p.start(dry_run=True)
        return
    p.run()


if __name__ == "__main__":
    main()
