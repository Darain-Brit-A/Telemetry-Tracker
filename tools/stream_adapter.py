"""Organizer-stream adapter: map an unknown telemetry format onto the collector's input.

The judging guide says every team gets the same organizer-provided stream, but not its format. This
adapter reads JSON-lines, a JSON array or CSV, recognises the usual field names for timestamps,
hosts, metrics, logs and login events, converts units and timestamp styles, and feeds the result
to the collector's local /ingest endpoint at the original pace.

    python tools/stream_adapter.py organizer.ndjson --collector col-acme-dc1
    python tools/stream_adapter.py data.csv --collector col-acme-dc1 --speed 10
    python tools/stream_adapter.py feed.json --mapping my_mapping.json --dry-run

Anything it cannot map is still delivered to the collector as raw local data (where it stays);
only recognised metrics can ever leave as metadata.
"""
import argparse
import csv
import io
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.util import CONFIG_DIR, _zone, iso, load_json, now_ms  # noqa: E402

TS_KEYS = ["ts", "timestamp", "time", "@timestamp", "at", "event_time", "eventTime", "event_time_utc", "datetime",
           "date"]
HOST_KEYS = ["host", "hostname", "source", "source_host", "device", "node", "instance", "server", "source_id"]
TZ_KEYS = ["tz", "zone", "timezone", "source_timezone"]
MSG_KEYS = ["message", "msg", "log", "raw_log", "line", "text"]
LEVEL_KEYS = ["level", "severity", "log_level", "lvl"]
USER_KEYS = ["user", "username", "actor", "account", "principal"]
IP_KEYS = ["src_ip", "source_ip", "ip", "address", "ip_address", "client_ip", "remote_addr"]
KIND_KEYS = ["kind", "type", "event_type", "event", "category"]
AUTH_FAIL = {"auth_failure", "login_failed", "failed_login", "authentication_failure", "auth_fail", "login_failure",
             "failed_password"}
AUTH_OK = {"auth_success", "login_success", "login", "authentication_success"}

# our metric -> accepted aliases (lower-case, compared after stripping separators)
METRIC_ALIASES = {
    "cpu_pct": ["cpu", "cpu_pct", "cpu_percent", "cpu_usage", "cpu_usage_percent", "cpu_util", "cpu_utilization"],
    "mem_pct": ["mem", "memory", "mem_pct", "memory_percent", "memory_usage_percent", "mem_used_pct",
                "memory_utilization", "ram"],
    "disk_pct": ["disk", "disk_pct", "disk_percent", "disk_usage_percent", "disk_used_pct", "disk_utilization"],
    "latency_ms": ["latency", "latency_ms", "rtt", "rtt_ms", "network_latency_ms", "ping_ms", "response_time_ms"],
    "packet_loss_pct": ["loss", "packet_loss", "packet_loss_pct", "packet_loss_percent",
                        "network_packet_loss_percent", "pkt_loss"],
    "bw_in_mbps": ["bandwidth", "bw_in", "bw_in_mbps", "rx_mbps", "network_bandwidth_mbps", "bandwidth_in",
                   "throughput_in", "inbound_mbps"],
    "bw_out_mbps": ["bw_out", "bw_out_mbps", "tx_mbps", "bandwidth_out", "throughput_out", "outbound_mbps"],
    "reachable": ["reachable", "connected", "up", "connectivity", "network_connectivity_status", "link_up"],
    "svc_up": ["svc_up", "available", "service_up", "service_availability", "service_availability_percent",
               "availability"],
}


def _norm(k):
    return "".join(ch for ch in str(k).lower() if ch.isalnum())


ALIAS_TO_METRIC = {_norm(a): m for m, aliases in METRIC_ALIASES.items() for a in aliases}


def _first(rec, keys):
    lower = {k.lower(): k for k in rec}
    for k in keys:
        if k.lower() in lower:
            v = rec[lower[k.lower()]]
            if v not in (None, ""):
                return v
    return None


def _num(v):
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip().rstrip("%")
        if s.lower() in ("true", "up", "yes", "ok", "online"):
            return 1.0
        if s.lower() in ("false", "down", "no", "offline"):
            return 0.0
        try:
            return float(s)
        except ValueError:
            return None
    return None


def parse_ts(v, default_tz=None):
    """ISO-8601 (any offset), epoch seconds, or epoch milliseconds -> epoch ms (UTC). An ISO timestamp
    without an offset is read in `default_tz` (IANA name) when given, otherwise UTC."""
    if v is None:
        return None
    n = _num(v) if not (isinstance(v, str) and ("-" in v[1:] or "T" in v)) else None
    if n is not None:
        if n > 1e14:          # microseconds
            return int(n / 1000)
        if n > 1e11:          # milliseconds
            return int(n)
        return int(n * 1000)  # seconds
    s = str(v).strip().replace("Z", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_zone(default_tz) if default_tz else timezone.utc)
    return int(dt.timestamp() * 1000)


def _convert(metric, key, value):
    if value is None:
        return None
    if metric in ("cpu_pct", "mem_pct", "disk_pct", "packet_loss_pct") and \
            ("ratio" in key.lower() or "fraction" in key.lower()) and value <= 1.0:
        return value * 100
    if metric in ("reachable", "svc_up"):
        return 1.0 if value >= (99.0 if value > 1 else 0.5) else 0.0   # 99.9 % availability -> up
    if metric == "latency_ms" and key.lower().endswith(("_s", "seconds")):
        return value * 1000
    return value


def extract_metrics(rec, mapping=None):
    out = {}
    mapping = mapping or {}
    for our, theirs in (mapping.get("metrics") or {}).items():
        v = _dig(rec, theirs)
        if v is not None and _num(v) is not None:
            out[our] = _convert(our, theirs, _num(v))
    nested = rec.get("metrics") if isinstance(rec.get("metrics"), dict) else {}
    for src in (nested, rec):
        for k, v in src.items():
            nk = _norm(k)
            m = ALIAS_TO_METRIC.get(nk) or ALIAS_TO_METRIC.get(nk.removesuffix("ratio").removesuffix("fraction"))
            if m and m not in out and _num(v) is not None and not isinstance(v, dict):
                out[m] = _convert(m, k, _num(v))
    # name/value pair style: {"metric_name": "cpu_usage_percent", "metric_value": 91}
    name = _first(rec, ["metric_name", "metric", "name"])
    val = _first(rec, ["metric_value", "value"])
    if isinstance(name, str) and _num(val) is not None:
        m = ALIAS_TO_METRIC.get(_norm(name))
        if m:
            out[m] = _convert(m, name, _num(val))
    return {k: round(v, 4) for k, v in out.items() if v is not None}


def _dig(rec, path):
    cur = rec
    for part in str(path).split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def map_record(rec, mapping=None, default_tz="UTC"):
    """Return a list of native collector events (metric / auth / log) for one foreign record."""
    mapping = mapping or {}
    ts_raw = _dig(rec, mapping["ts"]) if mapping.get("ts") else _first(rec, TS_KEYS)
    tz = _first(rec, TZ_KEYS) or default_tz
    ts = parse_ts(ts_raw, tz) if ts_raw is not None else now_ms()
    host = _dig(rec, mapping["host"]) if mapping.get("host") else _first(rec, HOST_KEYS)
    host = str(host or "unknown-source")[:64]
    base = {"host": host, "ts": iso(ts), "tz": tz}
    for k in ("role", "service"):
        if rec.get(k):
            base[k] = str(rec[k])[:64]
    events = []
    metrics = extract_metrics(rec, mapping)
    if metrics:
        events.append(dict(base, type="metric", metrics=metrics))
    kind = str(_first(rec, KIND_KEYS) or "").lower()
    result = str(rec.get("result") or rec.get("outcome") or "").lower()
    if kind in AUTH_FAIL or kind in AUTH_OK or (kind in ("auth", "login", "authentication") and result):
        ok = kind in AUTH_OK or result in ("success", "ok", "accepted")
        events.append(dict(base, type="auth", user=str(_first(rec, USER_KEYS) or "?"),
                           src_ip=str(_first(rec, IP_KEYS) or "?"), result="success" if ok else "failure",
                           method=str(rec.get("method") or "unknown")))
    msg = _first(rec, MSG_KEYS)
    if msg:
        events.append(dict(base, type="log", level=str(_first(rec, LEVEL_KEYS) or "INFO").upper(), message=str(msg)))
    return ts, events


def read_records(path):
    text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8-sig").read()
    stripped = text.lstrip()
    if path.lower().endswith(".csv"):
        return list(csv.DictReader(io.StringIO(text)))
    if stripped.startswith("["):
        return json.loads(stripped)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def run(records, ingest_url, mapping=None, rebase=True, speed=1.0, dry_run=False, default_tz="UTC", out=print):
    mapped = []
    for rec in records:
        if isinstance(rec, dict):
            mapped.append(map_record(rec, mapping, default_tz))
    mapped.sort(key=lambda x: x[0])
    if not mapped:
        return {"records": 0}
    stats = {"records": len(records), "metric": 0, "auth": 0, "log": 0, "batches": 0}
    t0 = mapped[0][0]
    shift = (now_ms() - t0) if rebase else 0
    start = time.time()
    batch, batch_due = [], None
    for ts, evs in mapped:
        due = (ts - t0) / 1000 / max(speed, 1e-6)
        for e in evs:
            stats[e["type"]] += 1
            if shift:
                e["ts"] = iso(parse_ts(e["ts"]) + shift + int((due - (ts - t0) / 1000) * 1000))
        if batch and due - batch_due > 0.2:
            _send(ingest_url, batch, start, batch_due, dry_run, stats, out)
            batch = []
        if not batch:
            batch_due = due
        batch.extend(evs)
    if batch:
        _send(ingest_url, batch, start, batch_due, dry_run, stats, out)
    return stats


def _send(url, batch, start, due, dry_run, stats, out):
    wait = start + due - time.time()
    if wait > 0 and not dry_run:
        time.sleep(wait)
    stats["batches"] += 1
    if dry_run:
        out(json.dumps(batch))
        return
    req = urllib.request.Request(url, data=json.dumps(batch).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="file (.ndjson/.jsonl/.json/.csv) or - for stdin")
    ap.add_argument("--collector", default="col-acme-dc1", help="collector id to feed (default col-acme-dc1)")
    ap.add_argument("--mapping", help="optional JSON mapping: {\"ts\": \"a.b\", \"host\": \"x\", \"metrics\": {\"cpu_pct\": \"m.cpu\"}}")
    ap.add_argument("--keep-ts", action="store_true", help="keep original timestamps instead of re-basing to now")
    ap.add_argument("--speed", type=float, default=1.0, help="replay speed factor (1 = original pace)")
    ap.add_argument("--tz", default="UTC", help="timezone to assume when records carry none")
    ap.add_argument("--dry-run", action="store_true", help="print the mapped events instead of sending them")
    args = ap.parse_args()
    cfg = load_json(os.path.join(CONFIG_DIR, "collectors", f"{args.collector}.json"))
    if not cfg and not args.dry_run:
        sys.exit(f"unknown collector {args.collector} (run setup_env.py)")
    url = f"http://127.0.0.1:{cfg['ui_port']}/ingest" if cfg else ""
    mapping = load_json(args.mapping) if args.mapping else None
    stats = run(read_records(args.input), url, mapping, rebase=not args.keep_ts, speed=args.speed,
                dry_run=args.dry_run, default_tz=args.tz)
    print(json.dumps(stats), file=sys.stderr)


if __name__ == "__main__":
    main()
