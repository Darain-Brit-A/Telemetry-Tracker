"""End-to-end validation against the judging guide (Section 2 targets + Section 8 live scenarios).

Run while `python run_all.py` is up:   python tools/verify.py
Writes docs/VALIDATION_REPORT.md with measured (not claimed) numbers.
"""
import http.cookiejar
import json
import os
import argparse
import random
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.util import CONFIG_DIR, DATA_DIR, iso, load_json, now_ms, sign  # noqa: E402
from tools import stream_adapter  # noqa: E402

DASH = "http://127.0.0.1:8080"
SIM = "http://127.0.0.1:9000"
COL = {"col-acme-dc1": "http://127.0.0.1:9101", "col-acme-cloud": "http://127.0.0.1:9102",
       "col-globex-nyc": "http://127.0.0.1:9103"}
RESULTS = []


def jget(url, opener=None):
    with (opener or urllib.request.build_opener()).open(url, timeout=10) as r:
        return json.loads(r.read())


def jpost(url, body, opener=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with (opener or urllib.request.build_opener()).open(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def session(user, pw):
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    code, _ = jpost(DASH + "/api/login", {"username": user, "password": pw}, op)
    assert code == 200, f"login failed for {user}"
    return op


def record(name, ok, evidence):
    RESULTS.append((name, ok, evidence))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {evidence}", flush=True)


def wait_for(fn, timeout, step=0.5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if v:
            return v, time.time() - t0
        time.sleep(step)
    return None, time.time() - t0


def inject(name, collector, host=None, duration=None):
    code, r = jpost(SIM + "/scenario", {"name": name, "collector": collector, "host": host, "duration": duration})
    return r


def alerts(op, pred):
    return [a for a in jget(DASH + "/api/overview", op)["alerts"] if pred(a)]


def find_alert(op, signal, since_ms, source=None):
    def f():
        for a in jget(DASH + "/api/overview", op)["alerts"]:
            if a["signal"] == signal and a["created_ms"] >= since_ms and (source is None or a["source_id"] == source):
                return a
        return None
    return f


def settle(op, others=()):
    """Heal everything and wait until no alert is open, as an operator would between demo scenarios."""
    for c in COL:
        jpost(SIM + "/scenario", {"name": "heal", "collector": c})
    wait_for(lambda: all(not [a for a in jget(DASH + "/api/overview", o)["alerts"] if a["status"] == "open"]
                         for o in (op, *others)), 120, 2)
    time.sleep(16)


def source_id(collector, host):
    st = jget(COL[collector] + "/api/state")
    return next(p["source_id"] for p in st["pseudonyms"] if p["host"] == host)


def main():
    acme = session("acme-admin", "acme-admin-demo")
    viewer = session("acme-viewer", "acme-viewer-demo")
    globex = session("globex-admin", "globex-admin-demo")
    started = iso()

    print("warming up baselines (need >=15 windows per series)...", flush=True)
    wait_for(lambda: all(len(s["spark"]["cpu_pct"]) >= 30 for s in jget(DASH + "/api/overview", acme)["sources"])
             and len(jget(DASH + "/api/overview", acme)["sources"]) >= 7, 120, 2)
    jpost(SIM + "/scenario", {"name": "heal", "collector": "col-acme-dc1"})
    time.sleep(4)
    baseline_alerts = [a for a in jget(DASH + "/api/overview", acme)["alerts"] if a["status"] == "open"]
    record("No false alarms on steady-state telemetry", not baseline_alerts,
           f"{len(baseline_alerts)} open alerts after warm-up on normal data")

    # 1. secret in raw log ---------------------------------------------------------------
    t = now_ms()
    inject("secret_in_log", "col-acme-dc1", "web-01")
    a, dt = wait_for(find_alert(acme, "security.secret_in_log", t), 20)
    time.sleep(3)   # the syslog copy arrives instantly over UDP; let the HTTP batch land too
    col_hits = jget(COL["col-acme-dc1"] + "/api/raw-search?q=Sup3rS3cret")
    saas_hits = jget(DASH + "/api/search-metadata?q=Sup3rS3cret", acme)
    akia = jget(DASH + "/api/search-metadata?q=AKIAIOSFODNN7", acme)
    record("Scenario: raw log contains a secret",
           bool(a) and col_hits["raw_matches_local"] > 0 and col_hits["egress_matches"] == 0
           and saas_hits["payload_matches"] == 0 and akia["payload_matches"] == 0,
           f"secret in local raw store: {col_hits['raw_matches_local']} lines; in outbound payloads: "
           f"{col_hits['egress_matches']}; in SaaS store: {saas_hits['payload_matches']}; SaaS received a "
           f"'security.secret_in_log' summary after {dt:.1f}s")

    # 2. repeated failed logins ----------------------------------------------------------
    t = now_ms()
    inject("failed_logins", "col-acme-dc1", "api-01")
    a, dt = wait_for(find_alert(acme, "security.auth_failure_burst", t), 30)
    ip_saas = jget(DASH + "/api/search-metadata?q=203.0.113", acme)
    ip_col = jget(COL["col-acme-dc1"] + "/api/raw-search?q=203.0.113")
    user_saas = jget(DASH + "/api/search-metadata?q=svc_deploy", acme)
    record("Scenario: repeated failed logins (local detection, no raw auth export)",
           bool(a) and ip_saas["payload_matches"] == 0 and user_saas["payload_matches"] == 0 and ip_col["raw_matches_local"] > 0,
           f"alert after {dt:.1f}s: '{(a or {}).get('title', '')[:110]}'; attacker IP in collector raw store "
           f"{ip_col['raw_matches_local']}x, in SaaS 0; usernames in SaaS {user_saas['payload_matches']}")

    # 3. CPU deviates from baseline (other tenant, other region) --------------------------
    sid = source_id("col-globex-nyc", "app-01")
    inj = inject("cpu_spike", "col-globex-nyc", "app-01", 90)
    a, dt = wait_for(find_alert(globex, "cpu_pct", inj["ms"], sid), 40)
    if a:
        lat = a["created_ms"] - inj["ms"]
        inc, _ = wait_for(lambda: (lambda i: i if i["analysis"].get("recommendation") else None)(
            jget(f"{DASH}/api/incident/{a['incident_id']}", globex)), 10)
        rec = inc["analysis"].get("recommendation", {})
        sig = inc["analysis"].get("signals", [{}])[0].get("detail", {})
        record("Scenario: CPU deviates from baseline -> explained recommendation",
               bool(rec.get("reasoning")) and sig.get("baseline") is not None,
               f"injected {inj['injected_at']}, alert {lat / 1000:.1f}s later (target 15s); z={sig.get('z')} vs "
               f"baseline {sig.get('baseline')}%; recommendation '{rec.get('title')}' ({int(rec.get('confidence', 0) * 100)}%), "
               f"action {rec.get('action', {}).get('id')}")
        record("Target: threshold breach / anomaly -> alert <= 15s", lat <= 15000, f"{lat / 1000:.1f}s measured from injection time")
    else:
        record("Scenario: CPU deviates from baseline -> explained recommendation", False, "no alert within 40s")

    settle(acme, (globex,))

    # 3b. organizer-format stream through the adapter ----------------------------------------
    # Foreign field names, epoch-ms timestamps, a cpu *ratio*, string booleans, and a host the
    # collector has never seen. 50 s of normal data, then a sustained CPU fault.
    t_start = now_ms()
    recs = []
    for i in range(75):
        cpu = 0.31 + random.uniform(-0.02, 0.02) if i < 50 else 0.86
        recs.append({"timestamp": t_start + i * 1000, "device": "edge-gw-7", "cpu_ratio": round(cpu, 3),
                     "mem_used_pct": round(48 + random.uniform(-1, 1), 2), "rtt_ms": round(12 + random.uniform(-1, 1), 2),
                     "link_up": "true", "note": "organizer-format record"})
    cfg = load_json(os.path.join(CONFIG_DIR, "collectors", "col-globex-nyc.json"))
    feeder = threading.Thread(target=stream_adapter.run, daemon=True, kwargs={
        "records": recs, "ingest_url": f"http://127.0.0.1:{cfg['ui_port']}/ingest", "rebase": True})
    feeder.start()
    fault_at = t_start + 50_000

    def foreign_alert():
        for a in jget(DASH + "/api/overview", globex)["alerts"]:
            if a["signal"] == "cpu_pct" and a["created_ms"] >= fault_at - 2000:
                st = jget(COL["col-globex-nyc"] + "/api/state")
                if any(p["host"] == "edge-gw-7" and p["source_id"] == a["source_id"] for p in st["pseudonyms"]):
                    return a
        return None
    a, _ = wait_for(foreign_alert, 110, 1)
    feeder.join(timeout=5)
    if a:
        inc, _ = wait_for(lambda: (lambda i: i if i["analysis"].get("recommendation") else None)(
            jget(f"{DASH}/api/incident/{a['incident_id']}", globex)), 10)
        record("Organizer-format stream (unknown schema) mapped, detected and explained",
               bool(inc), f"75 foreign records (epoch-ms 'timestamp', 'device', 'cpu_ratio', 'link_up') via "
               f"tools/stream_adapter.py; CPU fault alerted {(a['created_ms'] - fault_at) / 1000:.1f}s after it began; "
               f"'{inc['analysis']['recommendation']['title']}'; host name reached SaaS: "
               f"{jget(DASH + '/api/search-metadata?q=edge-gw-7', globex)['payload_matches']} payloads")
    else:
        record("Organizer-format stream (unknown schema) mapped, detected and explained", False, "no alert within 110s")
    settle(acme, (globex,))
    # 4. network latency rises -----------------------------------------------------------
    t = now_ms()
    inj = inject("latency_rise", "col-acme-cloud", None, 70)
    a, dt = wait_for(find_alert(acme, "latency_ms", t), 40)
    time.sleep(6)
    if a:
        inc, _ = wait_for(lambda: (lambda i: i if i["analysis"].get("recommendation") else None)(
            jget(f"{DASH}/api/incident/{a['incident_id']}", acme)), 10)
        rec = inc["analysis"]["recommendation"]
        srcs = {s["source_id"] for s in inc["analysis"]["signals"]}
        record("Scenario: network latency rises (source, severity, trend, impact)",
               "Network" in rec["title"] and len(srcs) >= 2,
               f"alert {(a['created_ms'] - inj['ms']) / 1000:.1f}s after injection; incident '{rec['title']}' with "
               f"{len(inc['analysis']['signals'])} signals on {len(srcs)} sources; severity {inc['severity']}")
    else:
        record("Scenario: network latency rises", False, "no latency alert")

    settle(acme)
    # 5. several alerts relate to one incident (cascading DB saturation) ----------------
    t = now_ms()
    inject("db_saturation", "col-acme-dc1", None, 90)
    db = source_id("col-acme-dc1", "db-01")

    def cascade():
        a = find_alert(acme, "cpu_pct", t, db)()
        if not a or not a["incident_id"]:
            return None
        inc = jget(f"{DASH}/api/incident/{a['incident_id']}", acme)
        sig = inc["analysis"].get("signals", [])
        lat_srcs = {s["source_id"] for s in sig if s["signal"] == "latency_ms"}
        return inc if len(lat_srcs) >= 2 else None
    inc, dt = wait_for(cascade, 50, 1)
    if inc:
        an = inc["analysis"]
        record("Scenario: several alerts -> one incident, root cause identified",
               inc["root_source"] == db and "saturation" in an["recommendation"]["title"].lower(),
               f"{an['noise']['alerts']} alerts from {an['noise']['sources']} sources merged into incident #{inc['id']}; "
               f"root ranked {inc['root_source']} (orders-db) score {an['ranking'][0]['score']}; "
               f"'{an['recommendation']['title']}'; correlation: {[c['reason'] for c in an['correlation']][:4]}")
        cascade_inc = inc
    else:
        record("Scenario: several alerts -> one incident", False, "cascade not correlated within 50s")
        cascade_inc = None

    # 6. remediation proposed: policy, approval, audit, rollback ------------------------
    if cascade_inc:
        def proposed():
            o = jget(DASH + "/api/overview", acme)
            for i in o["incidents"]:
                if i["id"] == cascade_inc["id"]:
                    return next((x for x in i["actions"] if x["status"] == "proposed"), None)
        act, _ = wait_for(proposed, 15)
        if act:
            vcode, vres = jpost(f"{DASH}/api/actions/{act['id']}/approve", {}, viewer)
            code, res = jpost(f"{DASH}/api/actions/{act['id']}/approve", {}, acme)

            def executed():
                o = jget(DASH + "/api/overview", acme)
                for i in o["incidents"]:
                    for x in i["actions"]:
                        if x["id"] == act["id"] and x["status"] == "executed":
                            return x
            ex, dt = wait_for(executed, 20)
            rcode, _ = jpost(f"{DASH}/api/actions/{act['id']}/rollback", {}, acme)

            def rolled():
                o = jget(DASH + "/api/overview", acme)
                return any(x["id"] == act["id"] and x["status"] == "rolled_back" for i in o["incidents"] for x in i["actions"])
            rb, _ = wait_for(rolled, 20)
            col_audit = [a for a in jget(COL[act["collector_id"]] + "/api/state")["audit"] if "SIMULATED" in a["detail"]]
            record("Scenario: remediation with policy check, approval, audit, rollback",
                   vcode == 403 and code == 200 and bool(ex) and bool(rb) and len(col_audit) >= 2,
                   f"viewer approve -> HTTP {vcode} (policy: role); admin approve -> {code}; executed on collector in "
                   f"{dt:.1f}s ('{(ex or {}).get('result', '')[:90]}'); rollback -> {'rolled_back' if rb else 'not done'}; "
                   f"collector-local audit entries: {len(col_audit)}")
        else:
            record("Scenario: remediation", False, "no proposed action")
    settle(acme)

    # 7. collector loses SaaS connectivity ----------------------------------------------
    jpost(COL["col-acme-dc1"] + "/api/partition", {"on": True})
    t_out = now_ms()
    st0 = jget(COL["col-acme-dc1"] + "/api/state")["stats"]

    def offline():
        o = jget(DASH + "/api/overview", acme)
        c = next(c for c in o["collectors"] if c["collector_id"] == "col-acme-dc1")
        return c if c["state"] == "Poor" else None
    c, _ = wait_for(offline, 70, 1)
    detect = (now_ms() - t_out) / 1000
    o = jget(DASH + "/api/overview", acme)
    od = o["slo"]["offline_detect"]
    record("Target: collector offline detected <= 60s of last heartbeat", bool(c) and od.get("n", 0) > 0 and od["max"] <= 60000,
           f"state Poor {detect:.0f}s after outage start; last-heartbeat->Poor measured {od.get('max', 0) / 1000:.1f}s; "
           f"reason '{(c or {}).get('reason', '')[:80]}'")
    time.sleep(8)
    buffered = jget(COL["col-acme-dc1"] + "/api/state")["stats"]["buffer_depth"]
    jpost(COL["col-acme-dc1"] + "/api/partition", {"on": False})
    t_back = time.time()
    drained, dt = wait_for(lambda: jget(COL["col-acme-dc1"] + "/api/state")["stats"]["buffer_depth"] == 0, 60)
    time.sleep(3)
    sent = jget(COL["col-acme-dc1"] + "/api/outbox-ids")["payloads"]
    recv = jget(DASH + "/api/payload-ids?collector=col-acme-dc1", acme)["payloads"]
    sent_ids = {p[0] for p in sent if p[2] == "delivered"}
    recv_ids = [p[0] for p in recv]
    seqs = sorted(p[1] for p in recv)
    gaps = (seqs[-1] - len(seqs)) if seqs else 0
    record("Scenario: SaaS outage -> buffer, retry, resume; zero loss, zero duplicates",
           bool(drained) and sent_ids == set(recv_ids) and len(recv_ids) == len(set(recv_ids)) and gaps == 0,
           f"{buffered} payloads buffered during outage; drained {dt:.1f}s after reconnect; collector delivered "
           f"{len(sent_ids)} IDs, SaaS stored {len(recv_ids)} ({len(set(recv_ids))} distinct); missing "
           f"{len(sent_ids - set(recv_ids))}; seq gaps {gaps}")

    # 8. duplicate / out-of-order delivery ----------------------------------------------
    before = jget(DASH + "/api/overview", acme)["counters"].get("delivery", {})
    jpost(COL["col-acme-cloud"] + "/api/chaos", {"on": True})
    inject("out_of_order", "col-acme-cloud")
    time.sleep(20)
    jpost(COL["col-acme-cloud"] + "/api/chaos", {"on": False})
    wait_for(lambda: jget(COL["col-acme-cloud"] + "/api/state")["stats"]["buffer_depth"] == 0, 30)
    time.sleep(3)
    after = jget(DASH + "/api/overview", acme)["counters"].get("delivery", {})
    sent = {p[0] for p in jget(COL["col-acme-cloud"] + "/api/outbox-ids")["payloads"] if p[2] == "delivered"}
    recv = [p for p in jget(DASH + "/api/payload-ids?collector=col-acme-cloud", acme)["payloads"]]
    seqs = sorted(p[1] for p in recv)
    dups = after.get("duplicates_ignored", 0) - before.get("duplicates_ignored", 0)
    ooo = after.get("out_of_order_payloads", 0) - before.get("out_of_order_payloads", 0)
    late = after.get("late_points", 0) - before.get("late_points", 0)
    rdb = sqlite3.connect(os.path.join(DATA_DIR, "saas", "region-eu-west.db"))
    dup_points = rdb.execute("SELECT COUNT(*) FROM (SELECT tenant_id,source_id,name,ts_ms,COUNT(*) c FROM metrics "
                             "GROUP BY 1,2,3,4 HAVING c>1)").fetchone()[0]
    record("Scenario: duplicate / out-of-order delivery",
           dups > 0 and len(recv) == len({p[0] for p in recv}) and sent == {p[0] for p in recv}
           and (seqs[-1] - len(seqs)) == 0 and dup_points == 0,
           f"{dups} duplicate payloads re-sent and ignored; {ooo} payloads arrived out of order; {late} late metric "
           f"points placed by event time; stored distinct={len(recv)} == delivered={len(sent)}; duplicate metric rows: {dup_points}")

    # 9. tenant isolation + residency ---------------------------------------------------
    acme_inc = [i["id"] for i in jget(DASH + "/api/overview", acme)["incidents"]]
    leak = 0
    for iid in acme_inc[:5]:
        try:   # incident IDs are per-region; a hit must still never return another tenant's record
            if jget(f"{DASH}/api/incident/{iid}", globex).get("tenant_id") != "globex":
                leak += 1
        except urllib.error.HTTPError as e:
            assert e.code == 404
    g = jget(DASH + "/api/overview", globex)
    acme_src = {s["source_id"] for s in jget(DASH + "/api/overview", acme)["sources"]}
    cross = acme_src & {s["source_id"] for s in g["sources"]}
    eu = sqlite3.connect(os.path.join(DATA_DIR, "saas", "region-eu-west.db"))
    us = sqlite3.connect(os.path.join(DATA_DIR, "saas", "region-us-east.db"))
    eu_t = {r[0] for r in eu.execute("SELECT DISTINCT tenant_id FROM payloads")}
    us_t = {r[0] for r in us.execute("SELECT DISTINCT tenant_id FROM payloads")}
    reg = load_json(os.path.join(CONFIG_DIR, "registry.json"))
    sec = reg["collectors"]["col-globex-nyc"]["secret"]
    path = "/r/eu-west/v1/ingest"
    body = b"[]"
    ts = str(int(time.time()))
    req = urllib.request.Request("https://127.0.0.1:8443" + path, data=body, method="POST", headers={
        "X-Collector-Id": "col-globex-nyc", "X-Timestamp": ts, "X-Signature": sign(sec, "POST", path, body, ts),
        "Content-Type": "application/json"})
    ctx = ssl.create_default_context(cafile=os.path.join(CONFIG_DIR, "certs", "ca.crt"))
    try:
        urllib.request.urlopen(req, context=ctx, timeout=5)
        code = 200
    except urllib.error.HTTPError as e:
        code = e.code
    bad = urllib.request.Request("https://127.0.0.1:8443" + path, data=body, method="POST", headers={
        "X-Collector-Id": "col-acme-dc1", "X-Timestamp": ts, "X-Signature": "0" * 64})
    try:
        urllib.request.urlopen(bad, context=ctx, timeout=5)
        badcode = 200
    except urllib.error.HTTPError as e:
        badcode = e.code
    record("Tenant isolation, data residency and collector authentication",
           leak == 0 and not cross and eu_t == {"acme"} and us_t == {"globex"} and code == 421 and badcode == 401,
           f"globex requesting {len(acme_inc[:5])} acme incident IDs -> {leak} acme records returned; shared sources {len(cross)}; "
           f"eu-west DB tenants {sorted(eu_t)}, us-east DB tenants {sorted(us_t)}; globex collector posting to "
           f"eu-west -> HTTP {code}; forged signature -> HTTP {badcode}")

    # 10. legit fleet-wide load spike should not be a high-severity fault --------------
    settle(acme)
    t = now_ms()
    inject("fleet_load", "col-acme-dc1", None, 60)

    def fleet():
        a = find_alert(acme, "cpu_pct", t)()
        if not a or not a["incident_id"]:
            return None
        inc = jget(f"{DASH}/api/incident/{a['incident_id']}", acme)
        return inc if "demand" in inc["analysis"].get("recommendation", {}).get("title", "").lower() else None
    inc, dt = wait_for(fleet, 45, 1)
    record("Normal usage spike distinguished from a real anomaly",
           bool(inc) and inc["severity"] in ("low", "info"),
           f"incident '{(inc or {}).get('title')}' severity {(inc or {}).get('severity')}; "
           f"{(inc or {}).get('analysis', {}).get('recommendation', {}).get('likely_cause', '')[:120]}")
    inject("heal", "col-acme-dc1")

    # 11. real-time latency -------------------------------------------------------------
    vis = []
    for _ in range(25):
        o = jget(DASH + "/api/overview", acme)
        vis.append(now_ms() - o["newest_event_ms"])
        time.sleep(1)
    vis.sort()
    p95 = vis[int(0.95 * (len(vis) - 1))]
    slo = jget(DASH + "/api/overview", acme)["slo"]
    dash = slo["dashboard"]
    record("Target: collection -> dashboard <= 10s p95",
           p95 <= 10000 and (dash.get("n", 0) == 0 or dash["p95"] <= 10000),
           f"event time -> visible in dashboard API p95 {p95 / 1000:.2f}s (n={len(vis)}); browser render-ack p95 "
           f"{(dash.get('p95') or 0) / 1000:.2f}s (n={dash.get('n', 0)}); measured from window start (conservative)")
    al = slo["alert"]
    record("Target: alert latency distribution <= 15s", al.get("n", 0) > 0 and al["p95"] <= 15000,
           f"p50 {al.get('p50', 0) / 1000:.1f}s, p95 {al.get('p95', 0) / 1000:.1f}s, max {al.get('max', 0) / 1000:.1f}s over {al.get('n')} alerts "
           f"(first breaching event time -> alert created)")

    write_report(started)


def write_report(started):
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    lines = ["# Validation report", "",
             f"Generated by `tools/verify.py` against the running system. Started {started}, finished {iso()} (UTC).", "",
             f"**{passed}/{len(RESULTS)} checks passed.** Every number below was measured from timestamps, IDs and "
             f"store queries during this run.", "", "| Check | Result | Evidence |", "|---|---|---|"]
    for name, ok, ev in RESULTS:
        lines.append(f"| {name} | {'PASS' if ok else '**FAIL**'} | {ev.replace('|', '/')} |")
    path = os.path.join(ROOT, "docs", "VALIDATION_REPORT.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\n{passed}/{len(RESULTS)} passed -> {path}")


def spawn_and_run():
    """--spawn: start the whole stack with fresh data, run the checks, stop the stack."""
    proc = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "run_all.py"), "--fresh"], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        ok, _ = wait_for(lambda: all(_up(u) for u in (DASH + "/index.html", *[c + "/" for c in COL.values()])), 40)
        if not ok:
            sys.exit("stack did not come up within 40 s")
        main()
    finally:
        if os.name == "nt":   # terminate() would orphan run_all's child servers on Windows
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.terminate()
        proc.wait(timeout=10)


def _up(url):
    try:
        urllib.request.urlopen(url, timeout=1)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--spawn", action="store_true", help="start and stop the stack itself (fresh data)")
    args = ap.parse_args()
    spawn_and_run() if args.spawn else main()
    sys.exit(0 if all(ok for _, ok, _ in RESULTS) else 1)
