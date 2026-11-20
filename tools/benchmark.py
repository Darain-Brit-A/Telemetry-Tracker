"""Offline benchmark of the AIOps engine on labelled scenarios.

Feeds the real SaaS engine (same code path as live ingest) with simulated telemetry in which the
faults are known, then measures:

* recall            - share of injected faults that raised an alert on the right source + metric
* precision         - share of alerts that correspond to an injected fault
* false alarms      - alerts per host-hour of fault-free telemetry
* detection delay   - windows from fault start to alert
* root-cause hit    - cascading DB faults where the DB was ranked as root cause

Runs in well under a minute, needs no running stack, and writes saas/benchmark.json (shown in
every recommendation's confidence factors) plus docs/BENCHMARK.md.

    python tools/benchmark.py --trials 60 --seed 1
"""
import argparse
import json
import os
import random
import shutil
import statistics
import sys
import tempfile
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.util import iso, now_ms  # noqa: E402
from saas.server import App  # noqa: E402
from setup_env import DEFAULT_THRESHOLDS, HEALTH_SETTINGS, REGIONS  # noqa: E402
from simulator.stream import Host  # noqa: E402

HOSTS = [("web-1", "web", "checkout-web"), ("web-2", "web", "checkout-web"),
         ("api-1", "app", "checkout-api"), ("db-1", "db", "orders-db")]
SCENARIOS = {  # name -> (affected hosts selector, metrics that should alert)
    "none": (lambda hs: [], set()),
    "cpu_spike": (lambda hs: [random.choice(hs)], {"cpu_pct"}),
    "mem_leak": (lambda hs: [random.choice(hs)], {"mem_pct"}),
    "disk_fill": (lambda hs: [random.choice(hs)], {"disk_pct"}),
    "latency_rise": (lambda hs: list(hs), {"latency_ms", "packet_loss_pct"}),
    "db_saturation": (lambda hs: list(hs), {"cpu_pct", "latency_ms", "mem_pct"}),
}
WARM, FAULT, RECOVER = 150, 60, 60
NOISE_EXTRA = 1.6   # widen the simulator's noise so the benchmark is harder than the live demo
MAGNITUDES = [0.3, 0.5, 0.75, 1.0]   # fraction of the full fault strength; small faults may be missed
BLIP_RATE = 1 / 60  # chance per host per window of a harmless 1-2 window spike that must NOT alert


def registry():
    return {"regions": REGIONS, "tls": False, "dashboard_port": 0, "ingest_port": 0, "users": {},
            "tenants": {"bench": {"name": "Bench", "region": "eu-west",
                                  "thresholds": {k: list(v) for k, v in DEFAULT_THRESHOLDS.items()},
                                  "health": dict(HEALTH_SETTINGS),
                                  "dependencies": {"checkout-web": ["checkout-api"], "checkout-api": ["orders-db"]}}},
            "collectors": {"col-bench": {"tenant_id": "bench", "secret": "x", "site": "lab"}}}


def trial(name, seed):
    random.seed(seed)
    tmp = tempfile.mkdtemp(prefix="aiops-bench-")
    app = App(reg=registry(), data_dir=tmp)
    try:
        hosts = [Host("col-bench", h, r, s, "bench") for h, r, s in HOSTS]
        sel, expected = SCENARIOS[name]
        affected = {h.name for h in sel(hosts)}
        total = WARM + FAULT + RECOVER
        t0_ms = now_ms() - total * 1000
        f_start = t0_ms + WARM * 1000
        mag = random.choice(MAGNITUDES) if name != "none" else 0
        blips = {}   # host -> (metric, windows left, size)
        blip_count = 0
        for i in range(total):
            t = (t0_ms + i * 1000) / 1000
            if i == WARM and name != "none":
                root = next((h.name for h in hosts if h.role == "db"), None) if name == "db_saturation" else None
                for h in hosts:
                    if h.name in affected or name in ("latency_rise", "db_saturation"):
                        h.scn[name] = {"start": t, "until": t + FAULT, "root": root}
            metrics, sources = [], []
            for h in hosts:
                state = random.getstate()
                m = h.metrics(t)
                if h.scn and mag < 1.0:            # scale the fault: normal + mag * (fault - normal)
                    random.setstate(state)
                    saved, h.scn = h.scn, {}
                    m0 = h.metrics(t)
                    h.scn = saved
                    m = {k: m0[k] + mag * (m[k] - m0[k]) for k in m}
                if h.name not in blips and random.random() < BLIP_RATE and not (WARM <= i < WARM + FAULT + 10):
                    blips[h.name] = (random.choice(["cpu_pct", "latency_ms"]), random.randint(1, 2),
                                     random.uniform(25, 45) if random.random() < 0.5 else random.uniform(60, 120))
                    blip_count += 1
                if h.name in blips:
                    bm, left, size = blips[h.name]
                    m[bm] += size if bm == "latency_ms" else min(size, 45)
                    blips[h.name] = (bm, left - 1, size)
                    if left - 1 <= 0:
                        blips.pop(h.name)
                for k in ("cpu_pct", "mem_pct", "disk_pct", "latency_ms", "packet_loss_pct", "bw_in_mbps"):
                    v = m[k]
                    if k in ("cpu_pct", "latency_ms", "bw_in_mbps"):
                        v = max(0.0, v + random.gauss(0, NOISE_EXTRA * (3 if k == "bw_in_mbps" else 1)))
                    metrics.append({"source_id": h.name, "ts": iso(t * 1000), "name": k, "avg": round(v, 3),
                                    "min": round(v, 3), "max": round(v, 3), "n": 1})
                sources.append({"source_id": h.name, "role": h.role, "service": h.service, "site": "lab", "tz": "UTC"})
            p = {"schema": "aiops.meta/v1", "payload_id": str(uuid.uuid4()), "collector_id": "col-bench", "seq": i + 1,
                 "kind": "metrics", "created_at": iso(), "policy_version": "2026.11-v1",
                 "window": {"start": iso(t * 1000), "end": iso(t * 1000 + 1000)}, "sources": sources,
                 "metrics": metrics, "events": []}
            app.ingest("col-bench", "bench", [p])
        st = app.stores.for_tenant("bench")
        app.engine._incidents("bench")
        alerts = st.rows("SELECT source_id, signal, first_event_ms FROM alerts WHERE tenant_id='bench'")
        incs = st.rows("SELECT root_source, analysis FROM incidents WHERE tenant_id='bench' AND status IN ('open','resolved')")
        f_end = f_start + (FAULT + 10) * 1000
        tp_alerts, fp_alerts, delays, hit_keys, fp_detail = 0, 0, [], set(), []
        # a fault "causes" alerts on the affected hosts for its expected metrics; for cascades, dependents' latency
        for a in alerts:
            in_window = f_start <= a["first_event_ms"] <= f_end
            relevant = a["signal"] in expected and (a["source_id"] in affected or name in ("latency_rise", "db_saturation"))
            if name != "none" and in_window and relevant:
                tp_alerts += 1
                hit_keys.add((a["source_id"], a["signal"]))
                delays.append((a["first_event_ms"] - f_start) / 1000)
            else:
                fp_alerts += 1
                fp_detail.append(a["signal"])
        detected = bool(hit_keys) if name != "none" else None
        root_ok = None
        if name == "db_saturation":
            root_ok = any(i["root_source"] == "db-1" for i in incs)
        normal_host_hours = len(HOSTS) * (WARM + (RECOVER - 10 if name != "none" else FAULT + RECOVER)) / 3600
        return {"scenario": name, "magnitude": mag, "blips": blip_count, "detected": detected, "tp_alerts": tp_alerts, "fp_alerts": fp_alerts,
                "delay_s": min(delays) if delays else None, "fp_signals": fp_detail, "root_ok": root_ok, "normal_host_hours": normal_host_hours}
    finally:
        app.stores.close()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--min-precision", type=float, help="exit 1 if precision falls below this (CI gate)")
    ap.add_argument("--min-recall", type=float, help="exit 1 if recall falls below this (CI gate)")
    ap.add_argument("--no-write", action="store_true", help="do not overwrite saas/benchmark.json and docs/BENCHMARK.md")
    args = ap.parse_args()
    names = list(SCENARIOS)
    started = time.time()
    results = [trial(names[i % len(names)], args.seed * 1000 + i) for i in range(args.trials)]
    faults = [r for r in results if r["scenario"] != "none"]
    tp = sum(r["tp_alerts"] for r in results)
    fp = sum(r["fp_alerts"] for r in results)
    hours = sum(r["normal_host_hours"] for r in results)
    delays = [r["delay_s"] for r in faults if r["delay_s"] is not None]
    roots = [r["root_ok"] for r in results if r["root_ok"] is not None]
    by_mag = {}
    for r in faults:
        d = by_mag.setdefault(str(r["magnitude"]), [0, 0])
        d[0] += 1
        d[1] += bool(r["detected"])
    per = {}
    for n in names:
        rs = [r for r in results if r["scenario"] == n]
        per[n] = {"trials": len(rs), "detected": sum(1 for r in rs if r["detected"]),
                  "false_alarms": sum(r["fp_alerts"] for r in rs),
                  "median_delay_s": statistics.median([r["delay_s"] for r in rs if r["delay_s"] is not None])
                  if any(r["delay_s"] is not None for r in rs) else None}
    summary = {
        "generated_at": iso(), "trials": len(results), "seed": args.seed, "runtime_s": round(time.time() - started, 1),
        "recall": round(sum(1 for r in faults if r["detected"]) / len(faults), 3) if faults else None,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "false_alarms_per_host_hour": round(fp / hours, 2) if hours else None,
        "median_detection_delay_s": statistics.median(delays) if delays else None,
        "p95_detection_delay_s": sorted(delays)[int(0.95 * (len(delays) - 1))] if delays else None,
        "root_cause_accuracy": round(sum(roots) / len(roots), 3) if roots else None,
        "per_scenario": per,
        "recall_by_magnitude": {k: round(v[1] / v[0], 2) for k, v in sorted(by_mag.items())},
        "harmless_blips_injected": sum(r["blips"] for r in results),
        "false_alarm_signals": dict(__import__("collections").Counter(x for r in results for x in r["fp_signals"])),
        "method": "real engine, simulated telemetry with known fault windows, extra noise added "
                  f"(sigma x{NOISE_EXTRA} on cpu/latency/traffic); {WARM}s warm-up, {FAULT}s fault, {RECOVER}s recovery",
    }
    if not args.no_write:
        with open(os.path.join(ROOT, "saas", "benchmark.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    lines = ["# Detector benchmark", "",
             f"Generated by `tools/benchmark.py --trials {args.trials} --seed {args.seed}` on {summary['generated_at']} "
             f"in {summary['runtime_s']} s. It runs the real SaaS engine on simulated telemetry where the fault windows "
             "are known, with extra noise added on CPU, latency and traffic so it is harder than the live demo.", "",
             "| Measure | Result |", "|---|---|",
             f"| Recall (faults detected) | {summary['recall']:.0%} |",
             f"| Precision (alerts that were real faults) | {summary['precision']:.0%} |",
             f"| False alarms per host-hour of normal data | {summary['false_alarms_per_host_hour']} |",
             f"| Median / p95 detection delay | {summary['median_detection_delay_s']} s / {summary['p95_detection_delay_s']} s |",
             f"| Root cause ranked correctly (cascading DB fault) | {summary['root_cause_accuracy']:.0%} |",
             f"| Harmless 1-2 window blips injected (should not alert) | {summary['harmless_blips_injected']} |", "",
             "Recall by fault size (fraction of full strength): " +
             ", ".join(f"{k}: {v:.0%}" for k, v in summary["recall_by_magnitude"].items()), "",
             "| Scenario | Trials | Detected | False alarms | Median delay (s) |", "|---|---|---|---|---|"]
    for n, v in per.items():
        lines.append(f"| {n} | {v['trials']} | {v['detected'] if n != 'none' else '-'} | {v['false_alarms']} | "
                     f"{v['median_delay_s'] if v['median_delay_s'] is not None else '-'} |")
    lines += ["", "Limits of this benchmark: the faults come from our own simulator, so it shows the detector is "
              "calibrated on the fault shapes we expect, not that it generalises to every real system. Run it again "
              "on the organizer stream once ground truth for that stream is known."]
    if not args.no_write:
        with open(os.path.join(ROOT, "docs", "BENCHMARK.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_scenario"}, indent=1))
    for n, v in per.items():
        print(f"  {n:<14} {v}")
    failed = [f"{k} {summary[k]} < {lim}" for k, lim in (("precision", args.min_precision), ("recall", args.min_recall))
              if lim is not None and (summary[k] or 0) < lim]
    if failed:
        sys.exit("benchmark gate failed: " + "; ".join(failed))


if __name__ == "__main__":
    main()
