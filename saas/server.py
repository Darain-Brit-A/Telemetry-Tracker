"""Tier 2 - Central multi-tenant SaaS platform (metadata only).

Two listeners:
  * Ingest  (TLS, :8443)  - collector-facing, HMAC-authenticated, regional paths /r/<region>/v1/...
  * Dashboard (:8080)     - operator UI + JSON API, session-authenticated, tenant-scoped

Ingest guarantees:
  * tenant is derived from the collector credential, never from the payload
  * payload must target the tenant's residency region (else 421 Misdirected + correct endpoint)
  * payload must pass the same allow-list as the collector (strict: reject, don't fix) and a DLP scan
  * idempotent: payload_id is a primary key -> retries / duplicates are acknowledged but ignored
  * metric points are stored by event time and merged, so late / out-of-order data lands correctly
"""
import argparse
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.policy import dlp_scan, load_policy, validate_inbound  # noqa: E402
from common.tlsserver import TLSThreadingHTTPServer, peer_fingerprint, server_context  # noqa: E402
from common.web import SECURITY_HEADERS, host_ok, origin_ok  # noqa: E402
from common.util import CERT_DIR, CONFIG_DIR, DATA_DIR, dumps, iso, like_contains, load_json, now_ms, parse_iso, \
    save_json, sha256_hex, verify_sig  # noqa: E402
from saas.aiops import ACTIONS, STATES, THRESHOLD_MODES, Engine  # noqa: E402
from saas.store import Stores  # noqa: E402

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
LOCK = threading.RLock()          # serialises AIOps state mutations
SESSIONS = {}
REG_PATH = os.path.join(CONFIG_DIR, "registry.json")


class App:
    def __init__(self, reg=None, data_dir=None, reg_path=None):
        # an App built from an in-memory registry (tests, benchmark) must never write the real
        # config/registry.json: it saves config changes to reg_path, or nowhere
        self.reg_path = reg_path or (None if reg else REG_PATH)
        self.reg = reg or load_json(REG_PATH)
        if not self.reg:
            sys.exit("config/registry.json missing - run setup_env.py first")
        self.policy = load_policy()
        self.stores = Stores(data_dir or DATA_DIR, self.reg)
        self.engine = Engine(self.stores, self.reg)
        self.engine.rehydrate()
        self.max_seq = {}
        self.ingest_port = self.reg["ingest_port"]
        self.scheme = "https" if self.reg.get("tls") else "http"
        # Two-machine deployments: the ingest listener binds to a network interface (setup_env.py
        # --saas-host sets 0.0.0.0) and collectors are told to reach it at the public host name / IP.
        # The dashboard always stays on loopback.
        self.ingest_bind = os.environ.get("AIOPS_INGEST_BIND") or self.reg.get("ingest_bind", "127.0.0.1")
        self.public_host = os.environ.get("AIOPS_PUBLIC_HOST") or self.reg.get("ingest_public_host", "127.0.0.1")

    def ingest_url(self, region):
        host = f"[{self.public_host}]" if ":" in self.public_host else self.public_host
        return f"{self.scheme}://{host}:{self.ingest_port}/r/{region}"

    # ---------------------------------------------------------------- ingest
    def authenticate(self, h, body):
        cid = h.headers.get("X-Collector-Id", "")
        c = self.reg["collectors"].get(cid)
        if not c:
            return None, "unknown collector"
        if c.get("disabled"):
            return None, "collector disabled"
        if self.reg.get("mtls"):
            # the TLS layer already proved the client holds a key certified by our CA; here the
            # certificate must also be the one enrolled for the collector the request claims to be
            if peer_fingerprint(h.connection) not in (c.get("cert_fingerprints") or []):
                return None, "client certificate not enrolled for this collector"
        ok, why = verify_sig(c["secret"], h.command, urllib.parse.urlsplit(h.path).path, body,
                             h.headers.get("X-Timestamp"), h.headers.get("X-Signature"))
        if not ok:
            return None, why
        return (cid, c["tenant_id"]), "ok"

    def ingest(self, cid, t, items):
        st = self.stores.for_tenant(t)
        res = {"accepted": [], "duplicates": [], "rejected": [], "receipts": {}}
        with LOCK, st.transaction():          # one SQLite transaction per batch
            for p in items:
                pid = p.get("payload_id") if isinstance(p, dict) else None
                if not pid:
                    res["rejected"].append({"id": None, "reason": "missing payload_id"})
                    continue
                if p.get("collector_id") != cid:
                    res["rejected"].append({"id": pid, "reason": "collector_id does not match credential"})
                    continue
                dropped = validate_inbound(p, self.policy)
                if dropped or p.get("schema") != "aiops.meta/v1":
                    st.bump(t, "security", "policy_rejections")
                    res["rejected"].append({"id": pid, "reason": f"policy violation: {dropped[:5]}"})
                    continue
                body = dumps(p)
                hits = dlp_scan(body)
                if hits:
                    st.bump(t, "security", "dlp_rejections")
                    self.engine.audit(t, f"collector:{cid}", "dlp_reject", f"payload {pid} rejected: {hits}")
                    res["rejected"].append({"id": pid, "reason": f"DLP: {sorted(set(hits))}"})
                    continue
                recv = now_ms()
                seq = p.get("seq") or 0
                ooo = 1 if seq < self.max_seq.get(cid, 0) else 0
                try:
                    with st.savepoint():
                        outcome = self._store_one(t, cid, p, pid, body, recv, seq, ooo, st)
                except Exception as e:      # one bad payload must not take the batch down (bug B2)
                    st.bump(t, "delivery", "processing_errors")
                    self.engine.audit(t, f"collector:{cid}", "processing_error", f"payload {pid}: {e!r}"[:300])
                    res["rejected"].append({"id": pid, "reason": f"processing error: {type(e).__name__}"})
                    continue
                if outcome == "conflict":
                    res["rejected"].append({"id": pid, "reason": "conflict: payload_id already stored with "
                                                              "different content", "code": 409})
                    continue
                if outcome[0] == "duplicate":
                    res["receipts"][pid] = outcome[1]
                    res["duplicates"].append(pid)
                    continue
                if ooo:
                    st.bump(t, "delivery", "out_of_order_payloads")
                    st.bump(t, f"collector:{cid}", "out_of_order_payloads")
                self.max_seq[cid] = max(self.max_seq.get(cid, 0), seq)
                res["accepted"].append(pid)
                res["receipts"][pid] = sha256_hex(body)
        return res

    def _store_one(self, t, cid, p, pid, body, recv, seq, ooo, st):
        """Insert (idempotently) and process one payload. Runs inside a savepoint, so any exception
        here rolls back only this payload. Returns "accepted", "conflict" or ("duplicate", sha)."""
        cur = st.x("INSERT OR IGNORE INTO payloads(payload_id,tenant_id,collector_id,seq,kind,created_ms,"
                   "received_ms,sha256,bytes,body,out_of_order) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (pid, t, cid, seq, p["kind"], parse_iso(p["created_at"]), recv, sha256_hex(body),
                    len(body), body, ooo))
        if cur.rowcount == 0:
            stored = st.q1("SELECT sha256 FROM payloads WHERE payload_id=? AND tenant_id=?", (pid, t))
            if not stored or stored[0] != sha256_hex(body):
                # same ID, different bytes: a bug or tampering - never silently accept
                st.bump(t, "security", "payload_id_conflicts")
                self.engine.audit(t, f"collector:{cid}", "payload_id_conflict",
                                  f"payload {pid} re-sent with different content; rejected")
                return "conflict"
            st.bump(t, "delivery", "duplicates_ignored")
            st.bump(t, f"collector:{cid}", "duplicates_ignored")
            return ("duplicate", stored[0])
        self.engine.replay_delay = recv - parse_iso(p["created_at"])
        try:
            self._process(t, cid, p, recv, st)
        finally:
            self.engine.replay_delay = 0
        return ("accepted", None)

    def _process(self, t, cid, p, recv, st):
        for s in p.get("sources", []):
            st.x("INSERT INTO sources(tenant_id,source_id,collector_id,role,service,site,tz,first_seen_ms) "
                 "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,source_id) DO UPDATE SET role=excluded.role, "
                 "service=excluded.service, site=excluded.site, tz=excluded.tz, collector_id=excluded.collector_id",
                 (t, s["source_id"], cid, s.get("role"), s.get("service"), s.get("site"), s.get("tz"), recv))
        points = sorted(((parse_iso(m["ts"]), m) for m in p.get("metrics", [])), key=lambda x: x[0])
        newest = points[-1][0] if points else 0
        with st.lock:
            st.db.executemany(
                """INSERT INTO metrics(tenant_id,source_id,name,ts_ms,avg,min,max,n,received_ms) VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(tenant_id,source_id,name,ts_ms) DO UPDATE SET
                     avg=(avg*n + excluded.avg*excluded.n)/(n+excluded.n), min=MIN(min,excluded.min),
                     max=MAX(max,excluded.max), n=n+excluded.n""",
                [(t, m["source_id"], m["name"], ts, m["avg"], m["min"], m["max"], m["n"], recv) for ts, m in points])
        for ts, m in points:
            value = m["min"] if m["name"] in ("reachable", "svc_up") else m["avg"]
            self.engine.on_point(t, m["source_id"], m["name"], ts, value)
        if newest:
            # for late-publishing sources the event-time delay is the publisher's, not the pipeline's
            self.engine.record_latency(t, "ingest_source_delayed" if self.reg["tenants"][t].get("history_after_s")
                                       else "ingest", recv - newest, cid)
        for e in p.get("events", []):
            st.x("INSERT INTO events(tenant_id,collector_id,source_id,ts_ms,category,severity,count,context,fingerprint,"
                 "received_ms,payload_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 (t, cid, e.get("source_id"), parse_iso(e["ts"]), e["category"], e["severity"], e.get("count"),
                  e.get("context"), e.get("fingerprint"), recv, p["payload_id"]))
            self.engine.on_event(t, cid, e)

    def heartbeat(self, cid, t, hb):
        st = self.stores.for_tenant(t)
        if validate_inbound(hb, self.policy) or hb.get("collector_id") != cid:
            return {"error": "policy violation"}, 422
        body = dumps(hb)
        with LOCK, st.transaction():
            st.x("INSERT INTO collectors(tenant_id,collector_id,last_seen_ms,version,config_hash,policy_version,tz,stats) "
                 "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,collector_id) DO UPDATE SET last_seen_ms=excluded.last_seen_ms,"
                 " version=excluded.version, config_hash=excluded.config_hash, policy_version=excluded.policy_version,"
                 " tz=excluded.tz, stats=excluded.stats",
                 (t, cid, now_ms(), hb.get("version"), hb.get("config_hash"), hb.get("policy_version"), hb.get("tz"),
                  json.dumps(hb.get("stats", {}))))
            st.x("INSERT OR IGNORE INTO payloads(payload_id,tenant_id,collector_id,seq,kind,created_ms,received_ms,sha256,"
                 "bytes,body) VALUES(?,?,?,?,?,?,?,?,?,?)",
                 ("hb-" + sha256_hex(body)[:20], t, cid, None, "heartbeat", parse_iso(hb["created_at"]), now_ms(),
                  sha256_hex(body), len(body), body))
        return {"ok": True, "server_time": iso()}, 200

    def commands(self, cid, t):
        st = self.stores.for_tenant(t)
        out = []
        with LOCK:
            for a in st.rows("SELECT * FROM actions WHERE tenant_id=? AND collector_id=? AND status IN "
                             "('approved','rollback_requested')", (t, cid)):
                mode = "rollback" if a["status"] == "rollback_requested" else "execute"
                st.x("UPDATE actions SET status=? WHERE id=?",
                     ("rollback_dispatched" if mode == "rollback" else "dispatched", a["id"]))
                out.append({"id": a["id"], "action": a["action"], "source_id": a["source_id"], "mode": mode,
                            "approved_by": a["rollback_by"] if mode == "rollback" else a["approved_by"]})
                self.engine.audit(t, "saas", f"command_dispatched:{mode}", f"action #{a['id']} {a['action']} -> {cid}")
        return out

    def command_result(self, cid, t, aid, res):
        st = self.stores.for_tenant(t)
        with LOCK:
            a = st.rows("SELECT * FROM actions WHERE id=? AND tenant_id=? AND collector_id=?", (aid, t, cid))
            if not a:
                return False
            status = {"executed": "executed", "rolled_back": "rolled_back"}.get(res.get("status"), "failed")
            st.x("UPDATE actions SET status=?, executed_ms=?, result=? WHERE id=?",
                 (status, now_ms(), str(res.get("detail", ""))[:300], aid))
            self.engine.audit(t, f"collector:{cid}", f"action_{status}", f"action #{aid}: {res.get('detail')}")
        return True

    # ---------------------------------------------------------------- dashboard data
    def overview(self, user):
        t = user["tenant_id"]
        T = self.reg["tenants"][t]
        st = self.stores.for_tenant(t)
        eng = self.engine
        now = now_ms()
        with LOCK:
            cols = []
            counters = st.counters(t)
            for c in st.rows("SELECT * FROM collectors WHERE tenant_id=? ORDER BY collector_id", (t,)):
                stats = json.loads(c["stats"] or "{}")
                recv = st.q1("SELECT COUNT(*), MAX(seq) FROM payloads WHERE tenant_id=? AND collector_id=? AND "
                             "kind='metrics'", (t, c["collector_id"]))
                seqs = [r[0] for r in st.q("SELECT seq FROM payloads WHERE tenant_id=? AND collector_id=? AND "
                                           "kind='metrics' ORDER BY seq", (t, c["collector_id"]))]
                missing = (seqs[-1] - len(seqs)) if seqs else 0
                state, reason = eng.health.get((t, c["collector_id"]), ("Fair", "no evaluation yet"))
                cc = counters.get(f"collector:{c['collector_id']}", {})
                cols.append({"collector_id": c["collector_id"], "state": state, "reason": reason,
                             "last_seen": iso(c["last_seen_ms"]), "age_s": round((now - c["last_seen_ms"]) / 1000, 1),
                             "version": c["version"], "config_hash": c["config_hash"], "policy_version": c["policy_version"],
                             "tz": c["tz"], "stats": stats, "site": self.reg["collectors"].get(c["collector_id"], {}).get("site"),
                             "received": recv[0], "max_seq": recv[1], "missing": missing,
                             "duplicates_ignored": cc.get("duplicates_ignored", 0),
                             "out_of_order": cc.get("out_of_order_payloads", 0)})
            sources = []
            for s in st.rows("SELECT * FROM sources WHERE tenant_id=? ORDER BY site, service, source_id", (t,)):
                sid = s["source_id"]
                state, reason = eng.health.get((t, sid), ("Fair", "no evaluation yet"))
                latest = {n: {"ts": iso(v[0]), "value": round(v[1], 2)} for (tt, ss, n), v in eng.latest.items()
                          if tt == t and ss == sid}
                spark = {}
                for name in ("cpu_pct", "latency_ms", "mem_pct", "pm25_ugm3", "pm10_ugm3"):
                    spark[name] = [[r[0], round(r[1], 1)] for r in reversed(st.q(
                        "SELECT ts_ms, avg FROM metrics WHERE tenant_id=? AND source_id=? AND name=? "
                        "ORDER BY ts_ms DESC LIMIT 150", (t, sid, name)))]
                sources.append(dict(s, state=state, reason=reason, latest=latest, spark=spark))
            incidents = []
            for i in st.rows("SELECT * FROM incidents WHERE tenant_id=? AND status IN ('open','resolved') ORDER BY "
                             "status='open' DESC, updated_ms DESC LIMIT 12", (t,)):
                i["analysis"] = json.loads(i["analysis"] or "{}")
                acts = st.rows("SELECT * FROM actions WHERE tenant_id=? AND incident_id=? ORDER BY id DESC", (t, i["id"]))
                for a in acts:
                    a["spec"] = ACTIONS.get(a["action"])
                    a["policy_preview"] = eng.policy_check(t, a, user) if a["status"] == "proposed" else \
                        json.loads(a["policy"] or "null")
                i["actions"] = acts
                incidents.append(i)
            alerts = st.rows("SELECT id, akey, source_id, collector_id, signal, kind, severity, status, first_event_ms, "
                             "created_ms, last_ms, resolved_ms, count, title, incident_id FROM alerts WHERE tenant_id=? "
                             "ORDER BY status='open' DESC, id DESC LIMIT 40", (t,))
            history = st.rows("SELECT entity, entity_kind, state, prev, reason, ts_ms FROM health_history WHERE "
                              "tenant_id=? ORDER BY id DESC LIMIT 60", (t,))
            tenant_state = eng.health.get((t, "tenant"), ("Fair", "warming up"))
            newest = max((v[0] for (tt, _, _), v in eng.latest.items() if tt == t), default=0)
            audit = st.rows("SELECT ts_ms, actor, action, detail FROM audit WHERE tenant_id=? ORDER BY id DESC LIMIT 40",
                            (t,))
            return {
                "tenant": {"id": t, "name": T["name"], "region": T["region"],
                           "region_name": self.reg["regions"][T["region"]], "state": tenant_state[0],
                           "reason": tenant_state[1], "dependencies": T["dependencies"]},
                "user": {"username": user["username"], "role": user["role"]},
                "server_time": iso(), "newest_event_ms": newest, "collectors": cols, "sources": sources,
                "incidents": incidents, "alerts": alerts, "history": history, "slo": eng.slo(t),
                "counters": counters, "audit": audit, "thresholds": T["thresholds"], "health_settings": T["health"],
                "threshold_modes": {k: (T.get("threshold_modes") or {}).get(k, "learned") for k in T["thresholds"]},
                "learned_limits": eng.learned_limits(t),
                "states": STATES, "policy_version": self.policy["policy_version"],
            }

    def search_metadata(self, t, term):
        """Count stored payloads / event contexts containing `term` (proof that a value never arrived)."""
        st = self.stores.for_tenant(t)
        pat = like_contains(term)
        n = st.q1(r"SELECT COUNT(*) FROM payloads WHERE tenant_id=? AND body LIKE ? ESCAPE '\'", (t, pat))[0] if term else 0
        e = st.q1(r"SELECT COUNT(*) FROM events WHERE tenant_id=? AND context LIKE ? ESCAPE '\'", (t, pat))[0] if term else 0
        return {"term": term, "payload_matches": n, "event_matches": e}

    def act(self, user, aid, op):
        t = user["tenant_id"]
        st = self.stores.for_tenant(t)
        with LOCK:
            rows = st.rows("SELECT * FROM actions WHERE id=? AND tenant_id=?", (aid, t))
            if not rows:
                return 404, {"error": "not found"}
            a = rows[0]
            who = user["username"]
            if op == "approve":
                if a["status"] != "proposed":
                    return 409, {"error": f"action is {a['status']}"}
                pol = self.engine.policy_check(t, a, user)
                st.x("UPDATE actions SET policy=? WHERE id=?", (json.dumps(pol), aid))
                if not pol["allowed"]:
                    failed = [c["check"] for c in pol["checks"] if not c["ok"]]
                    self.engine.audit(t, who, "action_blocked_by_policy", f"action #{aid}: {failed}")
                    return 403, {"error": "blocked by policy", "policy": pol}
                st.x("UPDATE actions SET status='approved', approved_by=?, approved_ms=?, requested_by='aiops' WHERE id=?",
                     (who, now_ms(), aid))
                self.engine.audit(t, who, "action_approved", f"action #{aid} {a['action']} on {a['source_id']} "
                                  f"(policy checks passed; queued for collector {a['collector_id']}, simulation mode)")
            elif op == "reject":
                if a["status"] != "proposed":
                    return 409, {"error": f"action is {a['status']}"}
                st.x("UPDATE actions SET status='rejected', approved_by=? WHERE id=?", (who, aid))
                self.engine.audit(t, who, "action_rejected", f"action #{aid} {a['action']}")
            elif op == "rollback":
                if user["role"] != "admin":
                    return 403, {"error": "admin role required"}
                if a["status"] != "executed":
                    return 409, {"error": f"action is {a['status']}"}
                st.x("UPDATE actions SET status='rollback_requested', rollback_by=? WHERE id=?", (who, aid))
                self.engine.audit(t, who, "rollback_requested", f"action #{aid}: {ACTIONS[a['action']]['rollback']}")
            return 200, {"ok": True}

    def update_config(self, user, data):
        if user["role"] != "admin":
            return 403, {"error": "admin role required"}
        t = user["tenant_id"]
        T = self.reg["tenants"][t]
        for k, v in (data.get("thresholds") or {}).items():
            if k in T["thresholds"] and isinstance(v, list) and len(v) == 3 and v == sorted(v):
                T["thresholds"][k] = [float(x) for x in v]
        for k, v in (data.get("threshold_modes") or {}).items():
            if k in T["thresholds"] and v in THRESHOLD_MODES:
                T.setdefault("threshold_modes", {})[k] = v
        for k, v in (data.get("health") or {}).items():
            if k in T["health"]:
                T["health"][k] = max(5, int(v))
        if self.reg_path:
            save_json(self.reg_path, self.reg)
        self.engine.audit(t, user["username"], "config_change", json.dumps({"thresholds": T["thresholds"],
                                                                            "threshold_modes": T.get("threshold_modes", {}),
                                                                            "health": T["health"]}))
        return 200, {"ok": True}


APP = None


class Base(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30            # slow or idle clients release their thread instead of holding it forever

    def log_message(self, *a):
        pass

    def send(self, code, obj, ctype="application/json", headers=None):
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 5_000_000:
            raise ValueError("payload too large")
        return self.rfile.read(n) if n else b""


class IngestHandler(Base):
    """Collector-facing API. Every request is HMAC-signed by an enrolled collector."""
    RX = re.compile(r"^/r/(?P<region>[a-z0-9-]+)/v1/(?P<op>ingest|heartbeat|commands)(?:/(?P<id>\d+)/result)?$")

    def handle_any(self):
        body = self.body()
        ident, why = APP.authenticate(self, body)
        if not ident:
            return self.send(401, {"error": why})
        cid, t = ident
        path = urllib.parse.urlsplit(self.path).path
        region = APP.reg["tenants"][t]["region"]
        if path == "/v1/discover":
            return self.send(200, {"region": region, "region_name": APP.reg["regions"][region],
                                   "ingest_url": APP.ingest_url(region)})
        m = self.RX.match(path)
        if not m:
            return self.send(404, {"error": "not found"})
        if m["region"] != region:
            # data residency: never accept a tenant's metadata in another region
            return self.send(421, {"error": "misdirected: tenant data resides in another region",
                                   "region": region, "ingest_url": APP.ingest_url(region)})
        op = m["op"]
        try:
            if op == "ingest" and self.command == "POST":
                items = json.loads(body)
                items = items if isinstance(items, list) else [items]
                return self.send(200, APP.ingest(cid, t, items))
            if op == "heartbeat" and self.command == "POST":
                res, code = APP.heartbeat(cid, t, json.loads(body))
                return self.send(code, res)
            if op == "commands" and self.command == "GET" and not m["id"]:
                return self.send(200, {"commands": APP.commands(cid, t)})
            if op == "commands" and self.command == "POST" and m["id"]:
                ok = APP.command_result(cid, t, int(m["id"]), json.loads(body))
                return self.send(200 if ok else 404, {"ok": ok})
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            return self.send(400, {"error": f"bad request: {e}"})
        self.send(405, {"error": "method not allowed"})

    do_GET = do_POST = handle_any


def check_pw(user, pw):
    exp = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(user["salt"]), 120_000).hex()
    return hmac.compare_digest(exp, user["pw_hash"])


class DashHandler(Base):
    MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript", ".css": "text/css"}

    def send(self, code, obj, ctype="application/json", headers=None):
        super().send(code, obj, ctype, {**SECURITY_HEADERS, **(headers or {})})

    def guard(self, write=False):
        """Reject DNS-rebinding (foreign Host) and cross-site writes (foreign Origin)."""
        port = APP.reg["dashboard_port"]
        if not host_ok(self.headers, port) or (write and not origin_ok(self.headers, port)):
            self.send(403, {"error": "forbidden host or origin"})
            return False
        return True

    def user(self):
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"sid=([A-Za-z0-9_-]+)", cookie)
        s = SESSIONS.get(m.group(1)) if m else None
        if s and s["exp"] > time.time():
            return s
        return None

    def do_GET(self):
        if not self.guard():
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/" or path == "/index.html":
            path = "/index.html"
        if not path.startswith("/api/"):
            f = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
            if not f.startswith(STATIC) or not os.path.isfile(f):
                return self.send(404, b"not found", "text/plain")
            with open(f, "rb") as fh:
                return self.send(200, fh.read(), self.MIME.get(os.path.splitext(f)[1], "application/octet-stream"))
        u = self.user()
        if not u:
            return self.send(401, {"error": "login required"})
        t = u["tenant_id"]
        st = APP.stores.for_tenant(t)
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "/api/me":
            return self.send(200, {"username": u["username"], "tenant_id": t, "role": u["role"]})
        if path == "/api/overview":
            return self.send(200, APP.overview(u))
        if path == "/api/series":
            sid = qs.get("source", [""])[0]
            minutes = min(int(qs.get("minutes", ["10"])[0]), 7 * 1440)
            since = now_ms() - minutes * 60_000
            if minutes <= 120:
                rows = st.q("SELECT name, ts_ms, avg, max FROM metrics WHERE tenant_id=? AND source_id=? AND ts_ms>? "
                            "ORDER BY ts_ms", (t, sid, since))
            else:   # long windows: at most ~400 points per metric (averaged buckets)
                bucket = max(60_000, minutes * 60_000 // 400)
                rows = st.q("SELECT name, (ts_ms / ?) * ? AS b, AVG(avg), MAX(max) FROM metrics WHERE tenant_id=? "
                            "AND source_id=? AND ts_ms>? GROUP BY name, b ORDER BY b", (bucket, bucket, t, sid, since))
            out = {}
            for name, ts, avg, mx in rows:
                out.setdefault(name, []).append([ts, round(avg, 2), mx])
            alerts = st.rows("SELECT signal, first_event_ms, resolved_ms, kind, severity FROM alerts WHERE tenant_id=? "
                             "AND source_id=? AND created_ms>?", (t, sid, now_ms() - minutes * 60_000))
            return self.send(200, {"source_id": sid, "series": out, "alerts": alerts})
        if path == "/api/trends":
            # one metric for every source of the tenant, bucketed, plus the per-site (city) average
            name = qs.get("metric", ["cpu_pct"])[0]
            if name not in APP.policy["metric_names"]:
                return self.send(400, {"error": "unknown metric"})
            minutes = max(5, min(int(qs.get("minutes", ["30"])[0]), 7 * 1440))
            bucket = max(10_000, minutes * 60_000 // 200)
            rows = st.q("SELECT m.source_id, s.service, s.site, (m.ts_ms / ?) * ? AS b, AVG(m.avg) FROM metrics m "
                        "JOIN sources s ON s.tenant_id = m.tenant_id AND s.source_id = m.source_id "
                        "WHERE m.tenant_id=? AND m.name=? AND m.ts_ms>? GROUP BY m.source_id, b ORDER BY b",
                        (bucket, bucket, t, name, now_ms() - minutes * 60_000))
            srcs, sites = {}, {}
            for sid, service, site, b, v in rows:
                srcs.setdefault(sid, {"source_id": sid, "service": service, "site": site, "points": []})["points"].append(
                    [b, round(v, 2)])
                sites.setdefault(site, {}).setdefault(b, []).append(v)
            return self.send(200, {"metric": name, "minutes": minutes, "bucket_ms": bucket,
                                   "sources": list(srcs.values()),
                                   "sites": [{"site": k, "points": [[b, round(sum(v) / len(v), 2)] for b, v in sorted(pts.items())]}
                                             for k, pts in sorted(sites.items())]})
        if path == "/api/payloads":
            kind = qs.get("kind", ["metrics"])[0]
            rows = st.rows("SELECT payload_id, collector_id, seq, kind, created_ms, received_ms, sha256, bytes, body, "
                           "out_of_order FROM payloads WHERE tenant_id=? AND (?='all' OR kind=?) ORDER BY received_ms DESC "
                           "LIMIT 60", (t, kind, kind))
            return self.send(200, {"payloads": rows})
        if path == "/api/payload-ids":
            cid = qs.get("collector", [""])[0]
            rows = st.q("SELECT payload_id, seq FROM payloads WHERE tenant_id=? AND collector_id=? AND kind='metrics' "
                        "ORDER BY seq", (t, cid))
            return self.send(200, {"collector_id": cid, "payloads": [list(r) for r in rows]})
        if path.startswith("/api/incident/"):
            iid = path.rsplit("/", 1)[1]
            rows = st.rows("SELECT * FROM incidents WHERE id=? AND tenant_id=?", (iid, t))   # tenant-scoped lookup
            if not rows:
                return self.send(404, {"error": "not found"})
            rows[0]["analysis"] = json.loads(rows[0]["analysis"] or "{}")
            return self.send(200, rows[0])
        if path == "/api/search-metadata":
            return self.send(200, APP.search_metadata(t, qs.get("q", [""])[0]))
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if not self.guard(write=True):
            return
        path = urllib.parse.urlsplit(self.path).path
        try:
            data = json.loads(self.body() or b"{}")
        except (json.JSONDecodeError, ValueError):
            return self.send(400, {"error": "bad json"})
        if path == "/api/login":
            u = APP.reg["users"].get(str(data.get("username", "")))
            if not u or not check_pw(u, str(data.get("password", ""))):
                time.sleep(0.5)
                return self.send(401, {"error": "invalid credentials"})
            sid = secrets.token_urlsafe(24)
            SESSIONS[sid] = {"username": data["username"], "tenant_id": u["tenant_id"], "role": u["role"],
                             "exp": time.time() + 12 * 3600}
            APP.engine.audit(u["tenant_id"], data["username"], "login", "dashboard session started")
            return self.send(200, {"ok": True, "tenant_id": u["tenant_id"]},
                             headers={"Set-Cookie": f"sid={sid}; HttpOnly; SameSite=Strict; Path=/"})
        u = self.user()
        if not u:
            return self.send(401, {"error": "login required"})
        if path == "/api/logout":
            for k, v in list(SESSIONS.items()):
                if v is u:
                    SESSIONS.pop(k)
            return self.send(200, {"ok": True}, headers={"Set-Cookie": "sid=; Max-Age=0; Path=/"})
        if path == "/api/render-ack":
            # collection -> dashboard latency, measured from the event timestamp to the browser render time
            ev, rd = int(data.get("event_ts_ms", 0)), int(data.get("render_ms", 0))
            if ev and rd and 0 <= rd - ev < 600_000:
                with LOCK:
                    APP.engine.record_latency(u["tenant_id"], "dashboard", rd - ev, "browser render")
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/actions/(\d+)/(approve|reject|rollback)$", path)
        if m:
            code, res = APP.act(u, int(m.group(1)), m.group(2))
            return self.send(code, res)
        if path == "/api/config":
            code, res = APP.update_config(u, data)
            return self.send(code, res)
        self.send(404, {"error": "not found"})


def engine_loop():
    while True:
        time.sleep(1)
        try:
            with LOCK:
                APP.engine.tick()
        except Exception as e:
            print(f"[saas] engine error: {e!r}", flush=True)
            import traceback
            traceback.print_exc()


def main():
    global APP
    ap = argparse.ArgumentParser()
    ap.parse_args()
    APP = App()
    http.server.ThreadingHTTPServer.request_queue_size = 256   # default backlog of 5 refused bursts
    threading.Thread(target=engine_loop, daemon=True).start()
    if APP.reg.get("tls"):
        # TLS 1.3 only; with mtls, collectors must present a certificate from our CA (fingerprint
        # checked per collector in authenticate())
        ctx = server_context(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"),
                             os.path.join(CERT_DIR, "ca.crt") if APP.reg.get("mtls") else None)
        # handshake per connection thread, never in accept() (bug B1)
        ingest = TLSThreadingHTTPServer((APP.ingest_bind, APP.ingest_port), IngestHandler, ctx)
    else:
        ingest = http.server.ThreadingHTTPServer((APP.ingest_bind, APP.ingest_port), IngestHandler)
    threading.Thread(target=ingest.serve_forever, daemon=True).start()
    dash = http.server.ThreadingHTTPServer(("127.0.0.1", APP.reg["dashboard_port"]), DashHandler)
    print(f"[saas] ingest {APP.scheme}://{APP.public_host}:{APP.ingest_port} (listening on {APP.ingest_bind}; "
          f"regions: {', '.join(APP.reg['regions'])})  "
          f"dashboard http://localhost:{APP.reg['dashboard_port']}", flush=True)
    try:
        dash.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
