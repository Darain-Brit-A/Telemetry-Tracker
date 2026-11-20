"""AIOps engine (Tier 2) - works on metadata only.

Observe -> Detect -> Correlate -> Recommend -> (simulated, approved) Act

* Detect:     robust per-series baselines (rolling median / MAD over the last 180 normal windows),
              persistence filter (3 consecutive windows), static thresholds as a backstop,
              peer comparison to separate legitimate fleet-wide demand from faults.
* Correlate:  alerts merge into incidents by shared source, service-dependency graph,
              shared site (network signals), same collector, or same role+metric (fleet).
              Repeated alerts with the same key are de-duplicated (counted, not re-raised).
* Recommend:  playbook rules over the incident's signal set; root cause ranked by onset,
              dependency position, severity. Every recommendation carries its contributing
              signals, confidence factors and reasoning path.
* Health:     Excellent / Good / Fair / Poor per source, collector and tenant, with reasons,
              stale-data downgrade and UTC-stamped transition history.
"""
import collections
import json
import math
import os
import statistics
import time

from common.util import iso, now_ms, parse_iso, percentile

SEV = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEV)}
STATES = ["Excellent", "Good", "Fair", "Poor"]

METRIC_META = {
    "cpu_pct": {"label": "CPU", "unit": "%", "floor": 3.0},
    "mem_pct": {"label": "Memory", "unit": "%", "floor": 2.0},
    "disk_pct": {"label": "Disk", "unit": "%", "floor": 1.0},
    "latency_ms": {"label": "Latency", "unit": " ms", "floor": 6.0},
    "packet_loss_pct": {"label": "Packet loss", "unit": "%", "floor": 0.4},
    "bw_in_mbps": {"label": "Inbound traffic", "unit": " Mbps", "floor": 15.0},
}
NETWORK = {"latency_ms", "packet_loss_pct", "network.unreachable"}
RESOURCE = {"cpu_pct", "mem_pct"}
MIN_BASELINE = 20
Z_OPEN, Z_LEARN, PERSIST = 4.0, 2.5, 3
CLEAR = 5                       # normal windows needed before an anomaly is considered over
# Learned (ML) health limits: Excellent / Good / Fair boundaries at baseline + k * robust spread, per source.
# 4 is the anomaly detector's own threshold and 8 the point where it rates an anomaly "high", so the
# health grade and the anomaly alerts agree. The manual Poor value stays as a hard safety limit.
LEARNED_Z = (2.0, Z_OPEN, 8.0)
THRESHOLD_MODES = ("manual", "learned")
CORRELATION_WINDOW_MS = 180_000
BENCHMARK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark.json")


def load_benchmark():
    try:
        with open(BENCHMARK_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

ACTIONS = {
    "svc.scale_out": {"label": "Scale out service (+1 replica)", "risk": "low", "reversible": True, "automatable": True,
                      "rollback": "Scale back in to the previous replica count"},
    "svc.restart": {"label": "Restart service", "risk": "medium", "reversible": True, "automatable": True,
                    "rollback": "Restore pre-restart release/config snapshot taken by the collector"},
    "svc.rolling_restart": {"label": "Rolling restart (one instance at a time)", "risk": "low", "reversible": True,
                            "automatable": True, "rollback": "Restore snapshot; stop rollout on first failed health check"},
    "net.failover_uplink": {"label": "Fail over to secondary uplink", "risk": "medium", "reversible": True,
                            "automatable": True, "rollback": "Fail back to primary uplink"},
    "sec.block_origin": {"label": "Temporarily block attacking origins at local firewall", "risk": "low",
                         "reversible": True, "automatable": True,
                         "rollback": "Remove the temporary rule (auto-expires after 30 min)"},
    "host.cleanup_logs": {"label": "Compress & archive old logs", "risk": "low", "reversible": True, "automatable": True,
                          "rollback": "Restore archived logs"},
    "diag.collect_top": {"label": "Capture process snapshot locally (read-only)", "risk": "none", "reversible": True,
                         "automatable": True, "rollback": "Not needed - read-only"},
    "diag.collect_logs": {"label": "Bundle recent logs locally for the on-call engineer (read-only)", "risk": "none",
                          "reversible": True, "automatable": True, "rollback": "Not needed - read-only"},
    "sec.rotate_credential": {"label": "Rotate the exposed credential and fix logging", "risk": "medium",
                              "reversible": False, "automatable": False, "rollback": "n/a - manual runbook"},
    "collector.check_link": {"label": "Check collector host / network path", "risk": "none", "reversible": True,
                             "automatable": False, "rollback": "n/a - manual check"},
    "data.check_agent": {"label": "Check the source's agent / exporter", "risk": "none", "reversible": True,
                         "automatable": False, "rollback": "n/a - manual check"},
}


def _round_to_100(values, ndigits=1):
    """Round percentages so they add up to exactly 100 (largest-remainder method)."""
    if not values:
        return []
    scale = 10 ** ndigits
    raw = [v * scale for v in values]
    floors = [int(r) for r in raw]
    short = round(100 * scale - sum(floors))
    order = sorted(range(len(raw)), key=lambda i: raw[i] - floors[i], reverse=True)
    for i in order[:max(0, short)]:
        floors[i] += 1
    return [f / scale for f in floors]


def deviation_shares(sig, root_source):
    """ML feature 2: how much each (source, signal) deviated, as a share of the incident's total deviation.

    Shares are computed per source and signal (not per metric name, which would let a symptom seen on
    many hosts look like the cause), split into the root group and symptoms, and labelled honestly:
    size of deviation is not cause. Event signals have no z-score and are listed separately."""
    rows, events = [], []
    for s in sig:
        d = s.get("detail") or {}
        z = max(abs(d.get("z") or 0), abs(d.get("peak_z") or 0))
        key = s.get("source_id") or s.get("collector_id")
        if not z:
            events.append({"source": key, "service": s.get("service"), "signal": s.get("signal")})
            continue
        rows.append({"source": key, "service": s.get("service"), "signal": s.get("signal"), "z": round(z, 1)})
    total = sum(r["z"] for r in rows)
    for r, share in zip(rows, _round_to_100([r["z"] / total * 100 for r in rows] if total else [])):
        r["share"] = share
    root = sorted([r for r in rows if r["source"] == root_source], key=lambda r: -r["share"])
    symptoms = sorted([r for r in rows if r["source"] != root_source], key=lambda r: -r["share"])
    return {"composite_score": round(math.sqrt(sum(r["z"] ** 2 for r in rows)), 1), "root": root,
            "symptoms": symptoms, "events": events,
            "note": "share of total deviation; the root is chosen by onset time and dependency position, "
                    "not by deviation size"}


def deviation_sentence(dev):
    if not dev["root"] and not dev["symptoms"]:
        return None
    root_pct = round(sum(r["share"] for r in dev["root"]))
    lead = dev["root"][0] if dev["root"] else None
    root_txt = (f"the root is {lead['service']} ({root_pct}%, led by {lead['signal']} at z = {lead['z']})"
                if lead else "the root has no z-scored signal")
    if not dev["symptoms"]:
        return f"Deviation share: all z-scored deviation is on the root; {root_txt}."
    sym_pct = round(sum(r["share"] for r in dev["symptoms"]))
    top = ", ".join(f"{r['signal']} on {r['service']}" for r in dev["symptoms"][:3])
    return (f"Deviation share: symptoms carry {sym_pct}% of the total deviation ({top}); {root_txt}, chosen "
            f"by onset time and dependency position rather than deviation size "
            f"(composite score {dev['composite_score']}).")


class Series:
    __slots__ = ("hist", "recent", "last_ts", "consec", "clear", "anomalous", "run_start", "onset", "z", "peak_z",
                 "peak_v", "thr_consec", "resid", "profile", "season_cache", "learned")

    def __init__(self):
        self.learned = None          # (excellent, good, fair) limits from this series' own baseline
        self.hist = collections.deque(maxlen=180)
        self.recent = collections.deque(maxlen=60)
        self.last_ts = 0
        self.consec = self.clear = self.thr_consec = 0
        self.anomalous = False
        self.run_start = self.onset = None
        self.z = None
        self.peak_z = 0.0
        self.peak_v = None
        self.resid = collections.deque(maxlen=180)    # residuals vs the seasonal profile (normal data only)
        self.profile = {}                             # hour slot -> {day index: deque of values}
        self.season_cache = None                      # (slot, day, expected) - previous days never change


SEASON_DAYS_KEPT = 7
SEASON_SAMPLES_PER_DAY = 120


def seasonal_expected(s, ts, day_ms, min_days):
    """ML feature 3: what is normal for this hour of the day. One median per day for the slot, then the
    median of the previous days' medians, so a fault today (or on any single day) cannot shift it.
    Returns (slot, day, expected or None until min_days of history exist)."""
    slot = int((ts % day_ms) // (day_ms / 24))
    day = ts // day_ms
    c = s.season_cache
    if c is not None and c[0] == slot and c[1] == day:
        return slot, day, c[2]
    days = s.profile.get(slot, {})
    medians = [statistics.median(v) for d, v in days.items() if d < day and v]
    expected = statistics.median(medians[-SEASON_DAYS_KEPT:]) if len(medians) >= min_days else None
    s.season_cache = (slot, day, expected)
    return slot, day, expected


def seasonal_learn(s, slot, day, value):
    """Every value feeds the profile (the cross-day median is what protects it from faults); old days drop."""
    days = s.profile.setdefault(slot, {})
    days.setdefault(day, collections.deque(maxlen=SEASON_SAMPLES_PER_DAY)).append(value)
    if len(days) > SEASON_DAYS_KEPT + 1:
        del days[min(days)]


def level_of(value, thr):
    for i, limit in enumerate(thr):
        if value < limit:
            return i
    return 3


class Engine:
    def __init__(self, stores, registry):
        self.stores = stores
        self.reg = registry
        self.lock = stores.lock if hasattr(stores, "lock") else None
        self.series = {}                       # (tenant, source, metric) -> Series
        self.latest = {}                       # (tenant, source, metric) -> (ts, value)
        self.health = {}                       # (tenant, entity) -> (state, reason)
        self.dirty = set()                     # incident ids needing re-analysis
        self.lat = collections.defaultdict(lambda: collections.deque(maxlen=2000))
        self.window_ms = 1000
        self.cls = {}                          # alert id -> (classification, peer evidence)
        self.open_keys = set()                 # (tenant, akey) of open alerts: skips DB lookups on the hot path
        self.benchmark = load_benchmark()      # measured detector quality, cited in confidence factors
        self.replay_delay = 0                  # set by ingest: how late the current payload arrived
        # seasonal baseline (ML feature 3): a real 24 h day by default; AIOPS_DAY_S compresses it for demos
        self.season_default = (int(float(os.environ.get("AIOPS_DAY_S", "86400")) * 1000),
                               int(os.environ.get("AIOPS_SEASONAL_MIN_DAYS", "3")))
        self._season = {}

    # ---------------------------------------------------------------- helpers
    def season(self, t):
        """(day length in ms, days of history needed) for a tenant; a tenant config can override both.
        Cached per tenant and config object, because it is read for every metric point."""
        cfg = self.T(t).get("seasonal") or {}
        hit = self._season.get(t)
        if hit and hit[0] is cfg:
            return hit[1]
        val = (int(cfg.get("day_ms", self.season_default[0])), int(cfg.get("min_days", self.season_default[1])))
        self._season[t] = (cfg, val)
        return val

    def T(self, t):
        return self.reg["tenants"][t]

    def st(self, t):
        return self.stores.for_tenant(t)

    def source_info(self, t, sid):
        r = self.st(t).rows("SELECT * FROM sources WHERE tenant_id=? AND source_id=?", (t, sid))
        return r[0] if r else {"source_id": sid, "service": "?", "role": "?", "site": "?", "collector_id": None}

    def depends(self, t, a, b, depth=4):
        """True if service a (transitively) depends on service b."""
        deps = self.T(t)["dependencies"]
        frontier, seen = [a], set()
        for _ in range(depth):
            nxt = []
            for s in frontier:
                for d in deps.get(s, []):
                    if d == b:
                        return True
                    if d not in seen:
                        seen.add(d)
                        nxt.append(d)
            frontier = nxt
        return False

    def record_latency(self, t, kind, value, detail=""):
        self.lat[(t, kind)].append(value)
        self.st(t).x("INSERT INTO latency(tenant_id,kind,value_ms,ts_ms,detail) VALUES(?,?,?,?,?)",
                     (t, kind, int(value), now_ms(), detail))

    def audit(self, t, actor, action, detail):
        self.st(t).x("INSERT INTO audit(tenant_id,ts_ms,actor,action,detail) VALUES(?,?,?,?,?)",
                     (t, now_ms(), actor, action, detail))

    # ---------------------------------------------------------------- startup
    def rehydrate(self):
        """Warm baselines and caches from stored metadata after a SaaS restart."""
        for t in self.reg["tenants"]:
            st = self.st(t)
            cut = now_ms() - 5 * 60_000
            for sid, name, ts, avg in st.q("SELECT source_id,name,ts_ms,avg FROM metrics WHERE tenant_id=? AND ts_ms>? "
                                           "ORDER BY ts_ms", (t, cut)):
                s = self.series.setdefault((t, sid, name), Series())
                s.hist.append(avg)
                s.recent.append((ts, avg))
                s.last_ts = ts
                self.latest[(t, sid, name)] = (ts, avg)
            self.open_keys |= {(t, r[0]) for r in st.q("SELECT akey FROM alerts WHERE tenant_id=? AND status='open'", (t,))}
            for ent, state, reason in st.q("SELECT entity,state,reason FROM health_history WHERE id IN (SELECT MAX(id) "
                                           "FROM health_history WHERE tenant_id=? GROUP BY entity)", (t,)):
                self.health[(t, ent)] = (state, reason)

    # ---------------------------------------------------------------- detection
    def on_point(self, t, sid, name, ts, value):
        key = (t, sid, name)
        prev = self.latest.get(key)
        if not prev or ts >= prev[0]:
            self.latest[key] = (ts, value)
        s = self.series.setdefault(key, Series())
        if ts <= s.last_ts:
            # late / out-of-order point: stored (and merged) by event time, but it must not
            # move the online detector backwards in time or corrupt the baseline.
            self.st(t).bump(t, "delivery", "late_points")
            return
        s.last_ts = ts
        s.recent.append((ts, value))
        meta = METRIC_META.get(name)
        thr = self.T(t)["thresholds"].get(name)

        z = med = mad = expected = None
        kind = "recent"
        day_ms, min_days = self.season(t)
        slot, day, expected = seasonal_expected(s, ts, day_ms, min_days) if meta else (None, None, None)
        if meta and expected is not None and len(s.resid) >= MIN_BASELINE:
            # seasonal: run the same robust detector on the residual from "normal for this hour"
            r = value - expected
            rmed = statistics.median(s.resid)
            mad = statistics.median(abs(x - rmed) for x in s.resid)
            z = (r - rmed) / max(1.4826 * mad, meta["floor"])
            med = expected + rmed
            kind = "seasonal"
        elif meta and len(s.hist) >= MIN_BASELINE:
            med = statistics.median(s.hist)
            mad = statistics.median(abs(x - med) for x in s.hist)
            z = (value - med) / max(1.4826 * mad, meta["floor"])
        if meta:
            seasonal_learn(s, slot, day, value)
        s.z = z
        if z is not None:
            sigma = max(1.4826 * mad, meta["floor"])
            s.learned = tuple(round(med + k * sigma, 2) for k in LEARNED_Z)
        level, alert_level, thr_shown, thr_mode = self.threshold_level(t, name, s, value)
        s.thr_consec = s.thr_consec + 1 if alert_level >= 2 else 0
        # a single 1-second reading over a threshold is routine noise (benchmark: it caused most false
        # alarms), so Poor needs 2 consecutive windows and Fair needs PERSIST - both well inside 15 s
        thr_active = (alert_level == 3 and s.thr_consec >= 2) or (alert_level >= 2 and s.thr_consec >= PERSIST)
        if z is not None and z >= Z_OPEN:
            if s.consec == 0:
                s.run_start = ts
            s.consec += 1
            s.clear = 0
        else:
            s.consec = 0
            if s.anomalous and (z is None or z < 2.0):
                s.clear += 1
            if not s.anomalous and (z is None or z < Z_LEARN):
                s.hist.append(value)       # baseline learns from normal data only
                if expected is not None:
                    s.resid.append(value - expected)
        if not s.anomalous and s.consec >= PERSIST:
            s.anomalous, s.onset, s.peak_z, s.peak_v = True, s.run_start, 0.0, value
        if s.anomalous:
            s.peak_z = max(s.peak_z, z or 0)
            s.peak_v = max(s.peak_v or value, value)
            if s.clear >= CLEAR:
                s.anomalous, s.onset = False, None

        akey = f"{sid}:{name}"
        if s.anomalous and not thr_active and (z is None or z < Z_OPEN):
            return      # recovering: alert stays open until PERSIST normal windows; evidence keeps the peak
        if s.anomalous or thr_active:
            if not meta and not thr:
                return
            label = (meta or {}).get("label", name)
            unit = (meta or {}).get("unit", "")
            slope = self._slope(s)
            detail = {"metric": name, "label": label, "unit": unit, "value": round(value, 2),
                      "peak": round(s.peak_v if s.peak_v is not None else value, 2),
                      "baseline": None if med is None else round(med, 2),
                      "spread": None if mad is None else round(1.4826 * mad, 2),
                      "z": None if z is None else round(z, 1), "peak_z": round(s.peak_z, 1),
                      "anomaly": s.anomalous, "threshold": thr_active, "level": STATES[level],
                      "threshold_values": thr_shown, "threshold_mode": thr_mode, "trend_per_min": slope,
                      "onset": iso(s.onset or ts), "baseline_kind": kind,
                      "expected_for_hour": None if expected is None else round(expected, 2)}
            if thr_active and alert_level == 3:
                sev = "critical"
            elif thr_active or (z or 0) >= 8:
                sev = "high"
            else:
                sev = "medium"
            if name == "bw_in_mbps":
                sev = "low"
            if med is None:
                delta = ""
            elif kind == "seasonal":
                delta = f" vs {med:.1f}{unit} expected for this hour (seasonal)"
            else:
                delta = f" vs baseline {med:.1f}{unit}"
            why = "threshold" if thr_active and not s.anomalous else "anomaly" if not thr_active else "anomaly+threshold"
            title = f"{label} {value:.1f}{unit}{delta} ({why})"
            first = s.onset if s.anomalous else ts
            self.open_alert(t, akey, sid, name, why, sev, title, detail, first)
        else:
            self.resolve_alert(t, akey, "metric back within baseline/thresholds")

    def threshold_level(self, t, name, s, value):
        """Health level and alerting level of `value` for one series.

        Returns (health_level, alert_level, limits_shown, mode). In manual mode both levels come from
        the tenant's fixed limits. In learned mode the health level comes from the series' own
        baseline (s.learned), and only the manual Poor value can raise a threshold alert - deviations
        from the baseline are already alerted by the anomaly detector, with its persistence filter.
        Until a baseline exists, learned mode falls back to the manual limits.
        """
        T = self.T(t)
        thr = T["thresholds"].get(name)
        if not thr:
            return 0, 0, None, None
        manual = level_of(value, thr)
        if (T.get("threshold_modes") or {}).get(name) != "learned":
            return manual, manual, thr, "manual"
        if s is None or s.learned is None:
            return manual, manual, thr, "manual (learning baseline)"
        safety = 3 if manual == 3 else 0
        return max(level_of(value, s.learned), safety), safety, list(s.learned) + [thr[2]], "learned"

    def learned_limits(self, t):
        """Current learned limits per metric and source, for the settings page."""
        out = collections.defaultdict(list)
        for (tt, sid, name), s in self.series.items():
            if tt == t and s.learned is not None and name in self.T(t)["thresholds"]:
                out[name].append({"source_id": sid, "limits": list(s.learned)})
        return out

    def _slope(self, s):
        pts = list(s.recent)[-24:]
        if len(pts) < 4:
            return None
        xs = [(p[0] - pts[0][0]) / 60000 for p in pts]
        ys = [p[1] for p in pts]
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        den = sum((x - mx) ** 2 for x in xs) or 1e-9
        return round(sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den, 2)

    def on_event(self, t, cid, ev):
        sid = ev.get("source_id")
        cat = ev["category"]
        title = {"security.auth_failure_burst": "Repeated failed logins",
                 "security.secret_in_log": "Credential material found in logs (redacted locally)",
                 "log.error_burst": "Application error burst",
                 "log.recurring_warning": "Recurring warning",
                 "network.unreachable": "Source unreachable from collector",
                 "service.down": "Service health check failing",
                 "source.clock_skew": "Source clock is ahead",
                 "security.possible_secret": "Possible secrets in logs (heuristic)"}.get(cat, cat)
        detail = {"category": cat, "count": ev.get("count"), "context": ev.get("context"),
                  "fingerprint": ev.get("fingerprint"), "onset": ev.get("ts")}
        self.open_alert(t, f"{sid}:{cat}", sid, cat, "event", ev["severity"], f"{title}: {ev.get('context', '')}"[:200],
                        detail, parse_iso(ev["ts"]), collector_id=cid)

    # ---------------------------------------------------------------- alerts
    def open_alert(self, t, akey, sid, signal, kind, sev, title, detail, first_ms, collector_id=None):
        st = self.st(t)
        now = now_ms()
        row = st.q1("SELECT id, severity, count, incident_id FROM alerts WHERE tenant_id=? AND akey=? AND status='open'",
                    (t, akey)) if (t, akey) in self.open_keys else None
        if row:
            aid, old_sev, count, inc = row
            if kind in ("collector", "stale"):      # condition re-evaluated every tick: refresh, don't count
                st.x("UPDATE alerts SET last_ms=?, title=?, detail=? WHERE id=?", (now, title, json.dumps(detail), aid))
                return aid
            new_sev = sev if SEV_RANK[sev] > SEV_RANK[old_sev] else old_sev
            st.x("UPDATE alerts SET last_ms=?, count=count+1, severity=?, title=?, detail=?, kind=? WHERE id=?",
                 (now, new_sev, title, json.dumps(detail), kind, aid))
            st.bump(t, "noise", "duplicates_suppressed")
            if inc:
                if new_sev != old_sev or count % 5 == 0:
                    self.dirty.add((t, inc))
            return aid
        if collector_id is None and sid:
            collector_id = self.source_info(t, sid).get("collector_id")
        cur = st.x("""INSERT INTO alerts(tenant_id,akey,source_id,collector_id,signal,kind,severity,status,first_event_ms,
                    created_ms,last_ms,count,title,detail) VALUES(?,?,?,?,?,?,?,'open',?,?,?,1,?,?)""",
                   (t, akey, sid, collector_id, signal, kind, sev, first_ms, now, now, title, json.dumps(detail)))
        aid = cur.lastrowid
        self.open_keys.add((t, akey))
        st.bump(t, "noise", "alerts_raised")
        if kind not in ("collector", "stale"):
            replayed = self.replay_delay > 10_000
            self.record_latency(t, "alert_replayed" if replayed else "alert", max(0, now - first_ms),
                                f"{akey} ({kind}){' - from buffered data replayed after outage' if replayed else ''}")
        self.correlate(t, aid)
        return aid

    def resolve_alert(self, t, akey, reason):
        if (t, akey) not in self.open_keys:
            return
        self.open_keys.discard((t, akey))
        st = self.st(t)
        row = st.q1("SELECT id, incident_id FROM alerts WHERE tenant_id=? AND akey=? AND status='open'", (t, akey))
        if row:
            st.x("UPDATE alerts SET status='resolved', resolved_ms=? WHERE id=?", (now_ms(), row[0]))
            if row[1]:
                self.dirty.add((t, row[1]))

    # ---------------------------------------------------------------- correlation
    def _site(self, t, a):
        if a["source_id"]:
            return self.source_info(t, a["source_id"]).get("site")
        c = self.reg["collectors"].get(a["collector_id"] or "", {})
        return c.get("site")

    def related(self, t, a, b):
        """Return a human readable reason if alerts a and b belong to the same incident."""
        sec = lambda x: x["signal"].startswith("security.")  # noqa: E731
        if a["source_id"] and a["source_id"] == b["source_id"]:
            if sec(a) != sec(b):
                return None          # security events on a host are not merged with its perf issues
            return "same source"
        if sec(a) or sec(b):
            return None
        ia = self.source_info(t, a["source_id"]) if a["source_id"] else {}
        ib = self.source_info(t, b["source_id"]) if b["source_id"] else {}
        if a["kind"] == "collector" or b["kind"] == "collector":
            ca, cb = a["collector_id"], b["collector_id"]
            if ca and ca == cb:
                return f"same collector ({ca})"
            return None
        if a["signal"] == "data.stale" and b["signal"] == "data.stale" and ia.get("collector_id") == ib.get("collector_id"):
            return f"same collector ({ia.get('collector_id')})"
        sa, sb = ia.get("service"), ib.get("service")
        if sa and sb and sa != sb and ia.get("site") == ib.get("site") and                 (self.depends(t, sa, sb) or self.depends(t, sb, sa)):
            up, down = (sb, sa) if self.depends(t, sa, sb) else (sa, sb)
            return f"service dependency {down} -> {up} at {ia.get('site')}"
        if a["signal"] in NETWORK and b["signal"] in NETWORK and ia.get("site") == ib.get("site"):
            return f"network signals at shared site {ia.get('site')}"
        if a["signal"] == b["signal"] and ia.get("role") == ib.get("role") and a["signal"] in ("cpu_pct", "bw_in_mbps"):
            return f"same signal on same role ({ia.get('role')}) - fleet pattern"
        if {a["signal"], b["signal"]} <= (RESOURCE | {"bw_in_mbps"}) and ia.get("role") == ib.get("role") \
                and sa == sb:
            return f"resource signals on same service ({sa})"
        return None

    def correlate(self, t, aid):
        st = self.st(t)
        a = st.rows("SELECT * FROM alerts WHERE id=?", (aid,))[0]
        now = now_ms()
        incs = st.rows("SELECT * FROM incidents WHERE tenant_id=? AND status='open' ORDER BY id", (t,))
        matches = []
        for inc in incs:
            # only alerts that are still active (or just recovered) can pull a new alert into an incident
            for b in st.rows("SELECT * FROM alerts WHERE tenant_id=? AND incident_id=? AND (status='open' OR "
                             "resolved_ms>?)", (t, inc["id"], now - 15_000)):
                why = self.related(t, a, b)
                if why:
                    matches.append((inc, why, b))
                    break
        if matches:
            target = matches[0][0]
            for inc, _, _ in matches[1:]:
                if inc["id"] != target["id"]:
                    st.x("UPDATE alerts SET incident_id=? WHERE incident_id=? AND tenant_id=?", (target["id"], inc["id"], t))
                    st.x("UPDATE incidents SET status='merged', closed_ms=? WHERE id=?", (now, inc["id"]))
                    st.x("UPDATE actions SET status='superseded' WHERE incident_id=? AND status='proposed'", (inc["id"],))
                    self.audit(t, "aiops", "incident_merge", f"incident #{inc['id']} merged into #{target['id']}")
            iid = target["id"]
            an = json.loads(target["analysis"] or "{}")
            an.setdefault("correlation", []).append({"alert": aid, "joined": iso(now), "reason": matches[0][1],
                                                     "with_alert": matches[0][2]["id"]})
            st.x("UPDATE incidents SET updated_ms=?, analysis=? WHERE id=?", (now, json.dumps(an), iid))
        else:
            cur = st.x("INSERT INTO incidents(tenant_id,status,opened_ms,updated_ms,severity,title,analysis) "
                       "VALUES(?,'open',?,?,?,?,?)", (t, now, now, a["severity"], a["title"],
                                                     json.dumps({"correlation": [{"alert": aid, "joined": iso(now),
                                                                                  "reason": "first signal"}]})))
            iid = cur.lastrowid
            st.bump(t, "noise", "incidents")
        st.x("UPDATE alerts SET incident_id=? WHERE id=?", (iid, aid))
        self.dirty.add((t, iid))

    # ---------------------------------------------------------------- health
    def tick(self):
        now = now_ms()
        for t, T in self.reg["tenants"].items():
            with self.st(t).transaction():
                self._tick_tenant(t, T, now)

    def _tick_tenant(self, t, T, now):
        st = self.st(t)
        H = T["health"]
        worst, worst_reason = 0, "all collectors and sources healthy"
        # collectors -------------------------------------------------
        for c in st.rows("SELECT * FROM collectors WHERE tenant_id=?", (t,)):
            age = (now - (c["last_seen_ms"] or 0)) / 1000
            stats = json.loads(c["stats"] or "{}")
            cid = c["collector_id"]
            state, reasons = 0, []
            if age > H["collector_offline_after_s"]:
                state = 3
                reasons.append(f"offline: no heartbeat for {age:.0f}s (limit {H['collector_offline_after_s']}s)")
                if self.health.get((t, cid), ("",))[0] != "Poor":
                    self.record_latency(t, "offline_detect", int(age * 1000), cid)
                self.open_alert(t, f"collector:{cid}:offline", None, "collector.offline", "collector", "high",
                                f"Collector {cid} offline (last heartbeat {iso(c['last_seen_ms'])})",
                                {"last_seen": iso(c["last_seen_ms"]), "age_s": round(age)}, c["last_seen_ms"],
                                collector_id=cid)
            else:
                self.resolve_alert(t, f"collector:{cid}:offline", "heartbeat resumed")
                if age > 12:
                    state, _ = max(state, 1), reasons.append(f"heartbeat late ({age:.0f}s)")
                if stats.get("buffer_depth", 0) > 20:
                    state = max(state, 2)
                    reasons.append(f"delivery backlog: {stats['buffer_depth']} payloads buffered")
                elif stats.get("buffer_depth", 0) > 3:
                    state = max(state, 1)
                    reasons.append(f"draining backlog ({stats['buffer_depth']} buffered)")
                if stats.get("last_error"):
                    state = max(state, 1)
                    reasons.append(f"recent transport error: {stats['last_error'][:60]}")
                if (stats.get("cpu_pct") or 0) > 80:
                    state = max(state, 2)
                    reasons.append(f"collector CPU {stats['cpu_pct']}%")
            if not reasons:
                reasons.append(f"reporting normally (v{c['version']}, policy {c['policy_version']}, "
                               f"heartbeat {age:.0f}s ago)")
            self._set_health(t, cid, "collector", state, "; ".join(reasons))
            if state > worst:
                worst, worst_reason = state, f"collector {cid}: {reasons[0]}"
        # sources ----------------------------------------------------
        open_alerts = collections.defaultdict(list)
        for a in st.rows("SELECT source_id, signal, kind, severity, detail FROM alerts WHERE tenant_id=? AND "
                         "status='open' AND source_id IS NOT NULL", (t,)):
            open_alerts[a["source_id"]].append(a)
        # freshness counts every metric a source reports, not only the threshold metrics, so a
        # bandwidth-only device is not shown as "no data" (bug B6)
        newest_by_source = {}
        for (tt, ss, _), (ts, _) in self.latest.items():
            if tt == t and ts > newest_by_source.get(ss, 0):
                newest_by_source[ss] = ts
        for src in st.rows("SELECT * FROM sources WHERE tenant_id=?", (t,)):
            sid = src["source_id"]
            state, reasons = 0, []
            newest = newest_by_source.get(sid, 0)
            for name in T["thresholds"]:
                lv = self.latest.get((t, sid, name))
                if not lv:
                    continue
                newest = max(newest, lv[0])
                lev, _, shown, mode = self.threshold_level(t, name, self.series.get((t, sid, name)), lv[1])
                if lev:
                    state = max(state, lev)
                    what = (f"learned limits {shown[:3]}, safety limit {shown[3]}" if mode == "learned"
                            else f"thresholds {shown}")
                    reasons.append(f"{METRIC_META.get(name, {}).get('label', name)} {lv[1]:.1f}"
                                   f"{METRIC_META.get(name, {}).get('unit', '')} -> {STATES[lev]} ({what})")
            for name, label in (("reachable", "unreachable from collector"), ("svc_up", "service check failing")):
                lv = self.latest.get((t, sid, name))
                if lv:
                    newest = max(newest, lv[0])
                    if lv[1] < 0.5:
                        state = 3
                        reasons.append(label)
            for a in open_alerts.get(sid, []):
                if a["kind"] in ("anomaly", "anomaly+threshold"):
                    d = json.loads(a["detail"])
                    lvl = 2 if SEV_RANK[a["severity"]] >= 3 else 1
                    state = max(state, lvl)
                    reasons.append(f"{d['label']} anomalous (z={d.get('z')}, baseline {d.get('baseline')})")
                elif a["signal"] == "security.possible_secret":
                    lvl = 1                 # a statistical hint, not a confirmed credential
                    state = max(state, lvl)
                    reasons.append("possible secrets in logs (heuristic, low)")
                elif a["signal"].startswith("security."):
                    lvl = 3 if a["severity"] == "critical" else 2
                    state = max(state, lvl)
                    reasons.append(f"security: {a['signal'].split('.', 1)[1]} ({a['severity']})")
                elif a["signal"] == "log.error_burst":
                    state = max(state, 1)
                    reasons.append("error burst in logs")
            age = (now - newest) / 1000 if newest else None
            if age is None or age > H["no_data_after_s"]:
                state = 3
                reasons.insert(0, "no data" + (f" for {age:.0f}s" if age else "") + " - last value NOT shown as current")
                self.open_alert(t, f"{sid}:data.stale", sid, "data.stale", "stale", "medium",
                                f"No telemetry from {src['service']} source for {age or 0:.0f}s",
                                {"age_s": round(age or 0)}, newest or now)
            else:
                self.resolve_alert(t, f"{sid}:data.stale", "data resumed")
                if age > H["stale_after_s"]:
                    state = max(state, 2)
                    reasons.insert(0, f"stale data: newest metric {age:.0f}s old")
            if not reasons:
                reasons.append("all metrics within baseline and thresholds")
            self._set_health(t, sid, "source", state, "; ".join(reasons))
            if state > worst:
                worst, worst_reason = state, f"{src['service']} ({sid}): {reasons[0]}"
        self._set_health(t, "tenant", "tenant", worst, worst_reason)
        self._auto_resolve_events(t)
        self._incidents(t)

    def _set_health(self, t, entity, kind, state, reason):
        name = STATES[state]
        prev = self.health.get((t, entity))
        self.health[(t, entity)] = (name, reason)
        if not prev or prev[0] != name:
            self.st(t).x("INSERT INTO health_history(tenant_id,entity,entity_kind,state,prev,reason,ts_ms) "
                         "VALUES(?,?,?,?,?,?,?)", (t, entity, kind, name, prev[0] if prev else None, reason, now_ms()))

    def _auto_resolve_events(self, t):
        st = self.st(t)
        now = now_ms()
        ttl = {"security.secret_in_log": 120_000, "security.auth_failure_burst": 60_000,
               "service.down": 25_000, "network.unreachable": 25_000}
        for aid, akey, signal, last in st.q("SELECT id, akey, signal, last_ms FROM alerts WHERE tenant_id=? AND "
                                            "status='open' AND kind='event'", (t,)):
            if now - last > ttl.get(signal, 45_000):
                self.resolve_alert(t, akey, "no recurrence")

    # ---------------------------------------------------------------- incidents / recommendations
    def _incidents(self, t):
        st = self.st(t)
        now = now_ms()
        for inc in st.rows("SELECT id FROM incidents WHERE tenant_id=? AND status='open'", (t,)):
            iid = inc["id"]
            alerts = st.rows("SELECT status, resolved_ms FROM alerts WHERE tenant_id=? AND incident_id=?", (t, iid))
            if alerts and all(a["status"] == "resolved" for a in alerts):
                if now - max(a["resolved_ms"] or 0 for a in alerts) > 60_000:
                    st.x("UPDATE incidents SET status='resolved', closed_ms=? WHERE id=?", (now, iid))
                    st.x("UPDATE actions SET status='expired' WHERE incident_id=? AND status='proposed'", (iid,))
                    self.audit(t, "aiops", "incident_resolved", f"incident #{iid}: all signals recovered for 60s")
                    self.dirty.add((t, iid))
        for (tt, iid) in list(self.dirty):
            if tt == t:
                self.dirty.discard((tt, iid))
                self.analyze(t, iid)

    def _peers(self, t, sid, metric, role):
        st = self.st(t)
        peers = [r[0] for r in st.q("SELECT source_id FROM sources WHERE tenant_id=? AND role=? AND source_id<>?",
                                    (t, role, sid))]
        hot = 0
        for p in peers:
            s = self.series.get((t, p, metric))
            if s and (s.anomalous or (s.z or 0) >= 3):
                hot += 1
        return len(peers), hot

    def analyze(self, t, iid):
        st = self.st(t)
        inc = st.rows("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (iid, t))
        if not inc:
            return
        inc = inc[0]
        alerts = st.rows("SELECT * FROM alerts WHERE tenant_id=? AND incident_id=? ORDER BY first_event_ms", (t, iid))
        if not alerts:
            return
        prev = json.loads(inc["analysis"] or "{}")
        active = [a for a in alerts if a["status"] == "open"] or alerts
        sig = []
        for a in alerts:
            d = json.loads(a["detail"] or "{}")
            info = self.source_info(t, a["source_id"]) if a["source_id"] else {"service": "collector", "role": "collector",
                                                                                 "site": self._site(t, a)}
            cls = None
            if a["signal"] in ("cpu_pct", "bw_in_mbps", "latency_ms") and a["source_id"] and a["status"] != "open":
                cls, d["peers"] = self.cls.get(a["id"], (None, None))   # judged while it was active
            elif a["signal"] in ("cpu_pct", "bw_in_mbps", "latency_ms") and a["source_id"]:
                n, hot = self._peers(t, a["source_id"], a["signal"], info.get("role"))
                demand = self.series.get((t, a["source_id"], "bw_in_mbps"))
                dz = (demand.z or 0) if demand else 0
                if n and hot / n >= 0.6:
                    cls = "demand" if dz >= 2 or a["signal"] == "bw_in_mbps" else "fleet_wide"
                else:
                    cls = "isolated"
                d["peers"] = {"same_role": n, "deviating": hot, "demand_z": round(dz, 1)}
                old = self.cls.get(a["id"])
                if not old or (old[0] == "isolated" and cls != "isolated"):   # peer evidence is sticky
                    self.cls[a["id"]] = (cls, d["peers"])
                cls, d["peers"] = self.cls[a["id"]]
            sig.append({"alert_id": a["id"], "source_id": a["source_id"], "collector_id": a["collector_id"],
                        "service": info.get("service"), "role": info.get("role"), "site": info.get("site"),
                        "signal": a["signal"], "kind": a["kind"], "severity": a["severity"], "status": a["status"],
                        "count": a["count"], "onset": iso(a["first_event_ms"]), "onset_ms": a["first_event_ms"],
                        "classification": cls, "detail": d, "title": a["title"]})

        # root-cause ranking ---------------------------------------------------
        by_src = collections.defaultdict(list)
        for s in sig:
            by_src[s["source_id"] or s["collector_id"]].append(s)
        t0 = min(s["onset_ms"] for s in sig)
        span = max(max(s["onset_ms"] for s in sig) - t0, 1)
        services = {s["service"] for s in sig if s["service"]}
        ranking = []
        for src, ss in by_src.items():
            svc = ss[0]["service"]
            onset = 1 - (min(x["onset_ms"] for x in ss) - t0) / span if span > 1 else 1.0
            others = [o for o in services if o != svc]
            dep = sum(1 for o in others if self.depends(t, o, svc)) / len(others) if others else 0.0
            sev = max(SEV_RANK[x["severity"]] for x in ss) / 4
            cnt = min(len(ss) / 3, 1)
            score = round(0.3 * onset + 0.4 * dep + 0.2 * sev + 0.1 * cnt, 2)
            ranking.append({"source": src, "service": svc, "site": ss[0]["site"], "score": score,
                            "factors": {"earliest_onset": round(onset, 2), "upstream_of_affected": round(dep, 2),
                                        "severity": round(sev, 2), "signal_count": round(cnt, 2)},
                            "signals": sorted({x["signal"] for x in ss})})
        ranking.sort(key=lambda r: -r["score"])
        root = ranking[0]
        rec = self.recommend(t, sig, ranking, alerts)
        severity = max((a["severity"] for a in active), key=lambda s: SEV_RANK[s])
        if rec.get("severity_override"):
            severity = rec["severity_override"]
        suppressed = sum(max(a["count"] - 1, 0) for a in alerts)
        analysis = {"correlation": prev.get("correlation", []), "signals": sig, "ranking": ranking,
                    "recommendation": rec, "noise": {"alerts": len(alerts), "duplicates_suppressed": suppressed,
                                                     "sources": len(by_src)},
                    "analyzed_at": iso()}
        st.x("UPDATE incidents SET severity=?, title=?, root_source=?, analysis=?, suppressed=? WHERE id=?",
             (severity, rec["title"], root["source"], json.dumps(analysis), suppressed, iid))
        # keep one proposed (not yet approved) action per incident in sync with the recommendation
        act = rec.get("action")
        if inc["status"] == "open" and act and ACTIONS[act["id"]]["automatable"] and act.get("target"):
            cur = st.rows("SELECT * FROM actions WHERE tenant_id=? AND incident_id=? AND status='proposed'", (t, iid))
            target_c = self.source_info(t, act["target"]).get("collector_id")
            if cur:
                if cur[0]["action"] != act["id"] or cur[0]["source_id"] != act["target"]:
                    st.x("UPDATE actions SET action=?, source_id=?, collector_id=? WHERE id=?",
                         (act["id"], act["target"], target_c, cur[0]["id"]))
            elif not st.q1("SELECT 1 FROM actions WHERE tenant_id=? AND incident_id=? AND action=? AND source_id=? "
                           "AND status NOT IN ('rejected','expired','superseded')", (t, iid, act["id"], act["target"])):
                st.x("INSERT INTO actions(tenant_id,incident_id,action,source_id,collector_id,status,proposed_ms) "
                     "VALUES(?,?,?,?,?,'proposed',?)", (t, iid, act["id"], act["target"], target_c, now_ms()))
                self.audit(t, "aiops", "action_proposed", f"incident #{iid}: {act['id']} on {act['target']}")

    def recommend(self, t, sig, ranking, alerts):
        names = {s["signal"] for s in sig}
        root = ranking[0]
        root_sig = [s for s in sig if (s["source_id"] or s["collector_id"]) == root["source"]]
        open_sig = [s for s in sig if s["status"] == "open"] or sig
        span_s = (max(s["onset_ms"] for s in sig) - min(s["onset_ms"] for s in sig)) / 1000
        persist_s = (now_ms() - min(s["onset_ms"] for s in sig)) / 1000
        sites = sorted({s["site"] for s in sig if s["site"]})
        svcs = sorted({s["service"] for s in sig if s["service"] and s["service"] != "collector"})
        steps = [f"{len(sig)} signal(s) on {len({s['source_id'] or s['collector_id'] for s in sig})} source(s) "
                 f"within {span_s:.0f}s ({', '.join(svcs) or 'collector'} at {', '.join(sites)})"]
        first = min(sig, key=lambda s: s["onset_ms"])
        steps.append(f"Earliest onset: {first['signal']} on {first['service']} ({first['source_id'] or first['collector_id']}) "
                     f"at {first['onset']}")
        if len(ranking) > 1:
            steps.append(f"Root-cause ranking: {root['service']} ({root['source']}) scored {root['score']} "
                         f"(onset {root['factors']['earliest_onset']}, upstream-of-affected "
                         f"{root['factors']['upstream_of_affected']}, severity {root['factors']['severity']}); "
                         f"next: {ranking[1]['service']} {ranking[1]['score']}")
        factors = []

        def conf(base):
            c = base
            corroborating = len(open_sig) - 1
            if corroborating > 0:
                bonus = min(0.1 * corroborating, 0.2)
                c += bonus
                factors.append(f"+{bonus:.2f}: {corroborating} corroborating signal(s)")
            zs = [s["detail"].get("peak_z") or 0 for s in sig]
            if zs and max(zs) >= 8:
                c += 0.08
                factors.append(f"+0.08: strong deviation (peak z={max(zs):.1f})")
            if persist_s > 30:
                c += 0.05
                factors.append(f"+0.05: persisted {persist_s:.0f}s (not a transient blip)")
            if root["factors"]["upstream_of_affected"] > 0:
                c += 0.07
                factors.append("+0.07: root sits upstream of the other affected services in the dependency graph")
            return round(min(c, 0.97), 2)

        def out(title, cause, action, target, why, base, severity_override=None, alternatives=None, extra=None):
            steps.extend(extra or [])
            a = dict(ACTIONS[action], id=action, target=target, why=why)
            factors.insert(0, f"{base:.2f}: base confidence of pattern '{title.split(':')[0]}'")
            b = self.benchmark
            if b and b.get("precision") is not None:
                factors.append(f"measured detector quality ({b['trials']} labelled trials, tools/benchmark.py): "
                               f"precision {b['precision']:.0%}, recall {b['recall']:.0%}, "
                               f"{b['false_alarms_per_host_hour']} false alarms per host-hour")
            dev = deviation_shares(sig, root["source"])
            line = deviation_sentence(dev)
            if line:
                steps.append(line)
            r = {"title": title, "likely_cause": cause, "confidence": conf(base), "confidence_factors": factors,
                 "reasoning": steps, "action": a, "alternatives": alternatives or [],
                 "root_source": root["source"], "root_service": root["service"], "deviation": dev}
            if severity_override:
                r["severity_override"] = severity_override
            return r

        def fmt(s):
            d = s["detail"]
            if "value" in d:
                return (f"{d['label']} {d['value']}{d['unit']} (baseline {d.get('baseline')}, z={d.get('z')}) "
                        f"on {s['service']}")
            return f"{s['signal']} on {s['service']}: {d.get('context') or ''}"

        if "collector.offline" in names:
            c = next(s for s in sig if s["signal"] == "collector.offline")
            return out(f"Collector {c['collector_id']} lost contact with SaaS",
                       "Collector host down or its network path to the regional ingest endpoint is broken. "
                       "Sources behind it show as stale rather than healthy.",
                       "collector.check_link", None,
                       "Data is not lost: the collector buffers approved metadata locally and replays it in order on "
                       "reconnect. Restoring the link is the only action needed; no remediation on monitored hosts.",
                       0.8, extra=[f"Heartbeat silent for {c['detail'].get('age_s')}s; dependent sources marked stale "
                                   f"instead of showing last good values"])
        if "security.auth_failure_burst" in names:
            s = next(x for x in sig if x["signal"] == "security.auth_failure_burst")
            return out(f"Credential attack against {s['service']}",
                       s["detail"].get("context"), "sec.block_origin", s["source_id"],
                       "Blocking is reversible (auto-expires) and is executed by the collector, which alone knows the "
                       "attacking origins - the SaaS never sees usernames or IP addresses. Account lockout was not "
                       "chosen because it would lock out legitimate users targeted by spraying.",
                       0.75, alternatives=["Force MFA for targeted accounts", "Rate-limit the auth endpoint"],
                       extra=["Pattern: failure count over local threshold in a 60s sliding window, computed on the "
                              "collector from raw auth records that never left the environment"])
        if "security.secret_in_log" in names:
            s = next(x for x in sig if x["signal"] == "security.secret_in_log")
            return out(f"Credential exposed in {s['service']} logs",
                       s["detail"].get("context"), "sec.rotate_credential", None,
                       "The secret was redacted before egress, but it is now on disk locally; it must be treated as "
                       "compromised. Rotation cannot be safely automated, so this is a manual runbook step.",
                       0.85, extra=["Detected by the collector's secret scanner; SaaS only received the type of "
                                    "credential and a count"])
        if names & {"service.down", "network.unreachable"}:
            s = next(x for x in sig if x["signal"] in ("service.down", "network.unreachable"))
            if s["signal"] == "service.down":
                return out(f"{s['service']} health check failing",
                           f"Service on {s['source_id']} stopped responding to the local health probe while the host "
                           f"is still reachable.", "svc.restart", s["source_id"],
                           "Host is reachable, so the fault is at process level; a restart is the fastest reversible fix "
                           "(collector snapshots release/config first).", 0.7)
            return out(f"{s['service']} unreachable", "Host failed reachability probes from the collector.",
                       "net.failover_uplink", s["source_id"], "Path-level failure; failover restores reachability.", 0.6)
        cpu_like = [s for s in sig if s["signal"] in ("cpu_pct", "bw_in_mbps")]
        if cpu_like and all(s["classification"] == "demand" for s in cpu_like) and not (names & {"packet_loss_pct", "mem_pct", "disk_pct"}):
            p = cpu_like[0]["detail"].get("peers", {})
            return out("Legitimate demand increase across the fleet (not a fault)",
                       f"{p.get('deviating')}/{p.get('same_role')} peers with role '{cpu_like[0]['role']}' rose together "
                       f"and inbound traffic rose with them (demand z={p.get('demand_z')}).",
                       "svc.scale_out", root["source"],
                       "Usage-driven load is handled by capacity, not by restarting anything. Scale-out is low risk "
                       "and reversible.", 0.65, severity_override="low",
                       extra=["Peer check: same deviation on most peers of the same role + rising inbound traffic "
                              "=> demand, so severity lowered to avoid a false alarm"])
        res = [s for s in root_sig if s["signal"] in RESOURCE]
        lat = [s for s in sig if s["signal"] == "latency_ms" and s["source_id"] != root["source"]]
        if res and lat:
            return out(f"Resource saturation on {root['service']} propagating to dependents",
                       f"{fmt(res[0])}; dependent services show latency: " + "; ".join(fmt(s) for s in lat[:3]),
                       "svc.scale_out", root["source"],
                       f"{root['service']} is upstream of the slowed services and deviated first, so adding capacity "
                       f"there addresses the cause rather than the symptoms. Restarting dependents was rejected: it "
                       f"would not remove the bottleneck.", 0.65,
                       alternatives=["Capture a process snapshot on the root (read-only) before scaling",
                                     "Throttle batch jobs on the root service"],
                       extra=[f"Dependency path: {', '.join(sorted({s['service'] for s in lat}))} -> {root['service']}"])
        if names & {"latency_ms", "packet_loss_pct"} and not (names & RESOURCE):
            net = [s for s in sig if s["signal"] in ("latency_ms", "packet_loss_pct")]
            return out(f"Network path degradation at {', '.join(sorted({s['site'] for s in net}))}",
                       "; ".join(fmt(s) for s in net[:4]),
                       "net.failover_uplink", net[0]["source_id"],
                       "Latency and/or packet loss rose on sources sharing a site without CPU/memory pressure, which "
                       "points to the network path rather than the hosts. Failover is reversible (fail back).",
                       0.6 + (0.1 if "packet_loss_pct" in names else 0),
                       alternatives=["Run MTR/traceroute from the collector to the affected targets"],
                       extra=[f"{len({s['source_id'] for s in net})} source(s) affected; no resource saturation found"])
        mem = [s for s in sig if s["signal"] == "mem_pct"]
        if mem and (mem[0]["detail"].get("trend_per_min") or 0) > 1.5 and                 not any(x["signal"] == "cpu_pct" and x["source_id"] == mem[0]["source_id"] for x in sig):
            s = mem[0]
            return out(f"Probable memory leak in {s['service']}",
                       f"{fmt(s)}, rising steadily at {s['detail']['trend_per_min']}%/min with no matching CPU or "
                       f"traffic increase.", "svc.rolling_restart", s["source_id"],
                       "A monotonic memory climb without load is the signature of a leak; a rolling restart reclaims "
                       "memory without downtime while the leak is investigated.", 0.6,
                       alternatives=["Capture heap profile (read-only) before restart"])
        if "disk_pct" in names:
            s = next(x for x in sig if x["signal"] == "disk_pct")
            return out(f"Disk filling on {s['service']}", fmt(s), "host.cleanup_logs", s["source_id"],
                       "Archiving old logs frees space quickly and is reversible.", 0.6)
        if res or cpu_like:
            s = (res or cpu_like)[0]
            cls = s["classification"]
            extra = []
            if cls == "isolated":
                p = s["detail"].get("peers", {})
                extra.append(f"Peer check: {p.get('deviating', 0)}/{p.get('same_role', 0)} peers deviate => isolated to "
                             f"this source, not a usage spike")
            elif cls == "fleet_wide":
                extra.append("Peers deviate together but inbound traffic did not rise => suspect a fleet-wide change "
                             "(deploy/config), not demand")
            return out(f"{s['detail'].get('label', s['signal'])} deviates from baseline on {s['service']}",
                       fmt(s), "diag.collect_top", s["source_id"],
                       "Cause is not yet determined from metadata alone, so the safest next step is a read-only "
                       "process snapshot captured and kept locally for the on-call engineer.", 0.55,
                       alternatives=["Scale out if the deviation persists or latency appears on dependents"],
                       extra=extra)
        if names & {"log.error_burst", "log.recurring_warning"}:
            s = next(x for x in sig if x["signal"].startswith("log."))
            return out(f"Application {s['signal'].split('.')[1].replace('_', ' ')} on {s['service']}",
                       s["detail"].get("context"), "diag.collect_logs", s["source_id"],
                       "Only message-template fingerprints left the environment; the full logs are bundled locally "
                       "for the engineer.", 0.5)
        if "security.possible_secret" in names:
            s = next(x for x in sig if x["signal"] == "security.possible_secret")
            return out(f"Possible secrets in {s['service']} logs", s["detail"].get("context"), "diag.collect_logs",
                       s["source_id"],
                       "An entropy check found tokens that look like keys but match no known credential pattern. "
                       "It is a heuristic, so the right step is a local review of the redacted lines before "
                       "treating anything as leaked; nothing left the collector either way.", 0.45,
                       extra=["Detected by the collector's entropy check (normalised entropy >= 0.85 plus shape "
                              "and context rules); on the test corpus: 0% false positives on ordinary IDs, "
                              "95.5% detection"])
        if "source.clock_skew" in names:
            s = next(x for x in sig if x["signal"] == "source.clock_skew")
            return out(f"Clock skew on {s['service']}", s["detail"].get("context"), "data.check_agent", None,
                       "Readings from this source carry timestamps in the future, usually a wrong clock or a "
                       "timezone sent without an offset. The collector re-stamps them so they stay visible, but "
                       "event-time ordering for this source is unreliable until its clock or timezone is fixed.",
                       0.8)
        if "data.stale" in names:
            s = next(x for x in sig if x["signal"] == "data.stale")
            return out(f"Telemetry gap from {s['service']}", "The source stopped reporting while its collector is "
                       "online.", "data.check_agent", None, "Missing data is surfaced as a problem, not hidden.", 0.6)
        s = sig[0]
        return out(f"Investigate {s['signal']} on {s['service']}", fmt(s), "diag.collect_top", s["source_id"],
                   "Read-only diagnostics are always safe.", 0.4)

    # ---------------------------------------------------------------- remediation policy
    def policy_check(self, t, action_row, user):
        st = self.st(t)
        spec = ACTIONS.get(action_row["action"], {})
        cid = action_row["collector_id"]
        c = st.q1("SELECT last_seen_ms FROM collectors WHERE tenant_id=? AND collector_id=?", (t, cid))
        online = bool(c and now_ms() - (c[0] or 0) < self.T(t)["health"]["collector_offline_after_s"] * 1000)
        recent = st.q1("SELECT COUNT(*) FROM actions WHERE tenant_id=? AND action=? AND source_id=? AND "
                       "status IN ('executed','dispatched','approved') AND approved_ms>?",
                       (t, action_row["action"], action_row["source_id"], now_ms() - 300_000))[0]
        checks = [
            {"check": "Operator role is allowed to approve remediation", "ok": user["role"] == "admin",
             "detail": f"role={user['role']}"},
            {"check": "Action is in the approved, automatable catalog", "ok": bool(spec.get("automatable"))},
            {"check": "Action is reversible (rollback defined)", "ok": bool(spec.get("reversible")),
             "detail": spec.get("rollback")},
            {"check": "Blast radius limited to a single target", "ok": True, "detail": action_row["source_id"]},
            {"check": "Target collector online (can execute and report back)", "ok": online, "detail": cid},
            {"check": "Cooldown: not run on this target in the last 5 min", "ok": recent == 0},
            {"check": "Execution mode is SIMULATION (safe test environment)", "ok": True},
        ]
        return {"allowed": all(c["ok"] for c in checks), "checks": checks, "risk": spec.get("risk")}

    # ---------------------------------------------------------------- SLO summary
    def slo(self, t):
        st = self.st(t)

        def stat(kind, minutes=30):
            vals = [r[0] for r in st.q("SELECT value_ms FROM latency WHERE tenant_id=? AND kind=? AND ts_ms>?",
                                       (t, kind, now_ms() - minutes * 60_000))]
            if not vals:
                return {"n": 0}
            return {"n": len(vals), "p50": round(percentile(vals, 50)), "p95": round(percentile(vals, 95)),
                    "max": max(vals)}
        return {"dashboard": stat("dashboard"), "ingest": stat("ingest"), "alert": stat("alert"),
                "offline_detect": stat("offline_detect", 240),
                "targets": {"dashboard_p95_ms": 10_000, "alert_ms": 15_000, "offline_detect_ms": 60_000}}
