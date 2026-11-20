"""Tier 1 - Local Collector (runs inside the customer environment).

Pipeline:  collect -> filter/redact -> aggregate -> analyze locally -> apply data policy -> transmit

* Raw logs, auth records (usernames / IPs) and secrets are kept in a LOCAL SQLite store
  with a retention limit. They are never put into an outbound payload.
* Outbound payloads are built only from aggregates + templated summaries, then passed
  through the allow-list (common/data_policy.json) and a DLP scan. A payload that fails
  the DLP scan is blocked, not sent.
* Every outbound payload is persisted in the outbox *before* transmission (egress proof
  panel + buffering). Delivery is at-least-once with unique payload IDs; the SaaS dedupes.
"""
import argparse
import collections
import ctypes
import hashlib
import http.server
import json
import os
import random
import re
import socket
import socketserver
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.policy import CREDENTIAL_TYPES, dlp_scan, enforce, load_policy, pseudonymize, redact_text  # noqa: E402
from common.web import SECURITY_HEADERS, host_ok, origin_ok  # noqa: E402
from common.util import CONFIG_DIR, DATA_DIR, dumps, iso, load_json, now_ms, parse_iso, sha256_hex, sign  # noqa: E402

VERSION = "1.4.0"
METRIC_NAMES = None  # filled from policy
UI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html")
UI_JS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.js")

SYSLOG_RX = re.compile(r"^<(?P<pri>\d{1,3})>(?:1 )?(?P<ts>\d{4}-\d\d-\d\dT\S+|\w{3}\s+\d+\s[\d:]{8})\s+(?P<host>\S+)\s+(?P<app>[^:\[\s]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
AUTH_FAIL_RX = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
AUTH_OK_RX = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
SYSLOG_LEVELS = ["CRITICAL", "CRITICAL", "CRITICAL", "ERROR", "WARN", "INFO", "INFO", "DEBUG"]


def _rss_mb():
    try:
        if os.name == "nt":
            class PMC(ctypes.Structure):
                _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
            pmc = PMC()
            pmc.cb = ctypes.sizeof(PMC)
            k32 = ctypes.windll.kernel32
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            fn = ctypes.windll.psapi.GetProcessMemoryInfo
            fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_ulong]
            fn(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb)
            return round(pmc.WorkingSetSize / 1048576, 1)
        import resource
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    except Exception:
        return 0.0


def template_of(msg):
    t = re.sub(r"\[REDACTED:[a-z_]+\]", "<r>", msg)
    t = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<h>", t)
    t = re.sub(r"\d+(\.\d+)?", "<n>", t)
    t = re.sub(r"(\"[^\"]*\"|'[^']*')", "<s>", t)
    return t


class Collector:
    def __init__(self, cfg):
        global METRIC_NAMES
        self.cfg = cfg
        self.cid = cfg["collector_id"]
        self.policy = load_policy()
        METRIC_NAMES = set(self.policy["metric_names"])
        self.config_hash = sha256_hex(dumps({k: v for k, v in cfg.items() if k not in ("secret", "pseudonym_salt")}))[:12]
        self.started = time.time()
        self.lock = threading.RLock()
        ddir = os.path.join(DATA_DIR, "collectors", self.cid)
        os.makedirs(ddir, exist_ok=True)
        self.db = sqlite3.connect(os.path.join(ddir, "local.db"), check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._schema()

        self.ssl_ctx = None
        if cfg.get("ca_file"):
            self.ssl_ctx = ssl.create_default_context(cafile=cfg["ca_file"])  # pinned private CA, hostname checked
        self.ingest_base = None
        self.region = None

        # aggregation state
        self.windows = {}                    # window_start_ms -> host -> metric -> [values]
        self.flushed_upto = 0                # windows below this have been flushed once already
        self.pending_events = []
        self.sources_seen = {}
        self.auth = collections.defaultdict(collections.deque)      # host -> (ts, user, ip, ok)
        self.logs = collections.defaultdict(collections.deque)      # host -> (ts, level, fp)
        self.last_emit = {}
        self.stats = collections.Counter()
        self.partition = False
        self.chaos = False
        self.held = {}
        self.single_sends = 0          # >0: send one payload at a time to isolate a refused one
        self.last_error = ""
        self.link_state = "starting"
        self.last_delivery_ms = None
        self._cpu_sample = (time.time(), time.process_time())
        seq = self.db.execute("SELECT MAX(seq) FROM egress").fetchone()[0]
        self.seq = seq or 0
        self.findings = collections.deque(maxlen=200)    # LOCAL security findings incl. usernames/IPs
        self.pseudo = {}

    # ------------------------------------------------------------------ storage
    def _schema(self):
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS raw_events(id INTEGER PRIMARY KEY, received_ms INT, ts_ms INT, host TEXT,
            type TEXT, raw TEXT, redacted TEXT, findings TEXT);
        CREATE INDEX IF NOT EXISTS raw_recv ON raw_events(received_ms);
        CREATE TABLE IF NOT EXISTS egress(id INTEGER PRIMARY KEY, payload_id TEXT UNIQUE, seq INT, kind TEXT,
            created_ms INT, body TEXT, sha256 TEXT, bytes INT, status TEXT, attempts INT DEFAULT 0,
            last_attempt_ms INT, delivered_ms INT, dropped TEXT, dlp TEXT, redactions INT, policy_version TEXT,
            note TEXT);
        CREATE INDEX IF NOT EXISTS egress_status ON egress(status, seq);
        CREATE TABLE IF NOT EXISTS local_audit(id INTEGER PRIMARY KEY, ts_ms INT, actor TEXT, action TEXT, detail TEXT);
        """)

    def q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def x(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args)

    def audit(self, actor, action, detail):
        self.x("INSERT INTO local_audit(ts_ms,actor,action,detail) VALUES(?,?,?,?)", (now_ms(), actor, action, detail))

    # ------------------------------------------------------------------ identity
    def source_id(self, host):
        sid = self.pseudo.get(host)
        if not sid:
            sid = pseudonymize(self.cfg["pseudonym_salt"], f"{self.cid}/{host}")
            self.pseudo[host] = sid
        return sid

    def host_of(self, source_id):
        for h, s in self.pseudo.items():
            if s == source_id:
                return h
        for h in self.cfg["hosts"]:
            if self.source_id(h) == source_id:
                return h
        return None

    def source_meta(self, host):
        h = self.cfg["hosts"].get(host, {})
        return {"source_id": self.source_id(host), "role": h.get("role", "unknown"),
                "service": h.get("service", "unknown"), "site": self.cfg["site"], "tz": self.cfg["tz"]}

    # ------------------------------------------------------------------ collect
    def ingest(self, ev, transport="http"):
        """Accept one raw event (metric | log | auth). Raw content is stored locally only."""
        recv = now_ms()
        try:
            ts = parse_iso(ev.get("ts")) if ev.get("ts") is not None else recv
        except Exception:
            ts = recv
        host = str(ev.get("host", "unknown"))[:64]
        etype = ev.get("type", "log")
        self.stats["raw_events_total"] += 1
        raw = json.dumps(ev) if transport == "http" else ev.get("_raw", json.dumps(ev))
        redacted, findings = redact_text(raw)
        if findings:
            self.stats["redactions_total"] += len(findings)
        self.x("INSERT INTO raw_events(received_ms,ts_ms,host,type,raw,redacted,findings) VALUES(?,?,?,?,?,?,?)",
               (recv, ts, host, etype, raw, redacted, ",".join(findings)))
        if host not in self.cfg["hosts"]:
            self.cfg["hosts"][host] = {"role": ev.get("role", "unknown"), "service": ev.get("service", "unknown")}
        if etype == "metric":
            self._metric(host, ts, ev.get("metrics") or {})
        elif etype == "auth":
            self._auth(host, ts, ev.get("user", "?"), ev.get("src_ip", "?"), ev.get("result") == "success",
                       ev.get("method", "ssh"))
        else:
            self._log(host, ts, str(ev.get("level", "INFO")).upper(), str(ev.get("message", "")))

    def ingest_syslog(self, line):
        m = SYSLOG_RX.match(line.strip())
        if not m:
            self.ingest({"type": "log", "host": "unknown", "level": "INFO", "message": line, "_raw": line}, "syslog")
            return
        pri = int(m.group("pri"))
        try:
            ts = parse_iso(m.group("ts"))
        except Exception:
            ts = now_ms()
        msg = m.group("msg")
        host = m.group("host")
        af, ok = AUTH_FAIL_RX.search(msg), AUTH_OK_RX.search(msg)
        if af or ok:
            mm = af or ok
            ev = {"type": "auth", "host": host, "ts": ts, "user": mm.group("user"), "src_ip": mm.group("ip"),
                  "result": "success" if ok else "failure", "method": m.group("app"), "_raw": line}
        else:
            ev = {"type": "log", "host": host, "ts": ts, "level": SYSLOG_LEVELS[pri % 8], "message": msg, "_raw": line}
        self.ingest(ev, "syslog")

    def _metric(self, host, ts, metrics):
        w = self.cfg["window_s"] * 1000
        start = ts - ts % w
        with self.lock:
            if start < self.flushed_upto:
                self.stats["late_events"] += 1
            bucket = self.windows.setdefault(start, {}).setdefault(host, collections.defaultdict(list))
            for k, v in metrics.items():
                if k in METRIC_NAMES and isinstance(v, (int, float)):
                    bucket[k].append(float(v))
            # locally derived connectivity / availability events
            if metrics.get("reachable") == 0:
                self._event_once(host, ts, "network.unreachable", "high", 1,
                                 "Source failed local reachability probe (ICMP/TCP) from collector")
            if metrics.get("svc_up") == 0:
                self._event_once(host, ts, "service.down", "critical", 1,
                                 "Service health check failing on source")

    def _log(self, host, ts, level, message):
        redacted, findings = redact_text(message)
        creds = [f for f in findings if f in CREDENTIAL_TYPES]
        fp = "fp-" + hashlib.sha256(template_of(redacted).encode()).hexdigest()[:8]
        with self.lock:
            dq = self.logs[host]
            dq.append((ts, level, fp))
            while dq and dq[0][0] < ts - 60_000:
                dq.popleft()
            if creds:
                types = sorted(set(creds))
                self.findings.appendleft({"ts": iso(ts), "host": host, "kind": "secret_in_log",
                                          "detail": f"credential material ({', '.join(types)}) in log line",
                                          "raw_redacted": redacted[:160]})
                sev = "high" if {"private_key", "aws_key", "jwt"} & set(types) else "medium"
                self.pending_events.append(self._ev(host, ts, "security.secret_in_log", sev, 1,
                                                    f"1 log line contained credential material ({', '.join(types)}); "
                                                    f"redacted, raw retained locally only", fp))
            errors = [e for e in dq if e[1] in ("ERROR", "CRITICAL") and e[0] >= ts - 10_000]
            if len(errors) >= 5:
                top = collections.Counter(e[2] for e in errors).most_common(1)[0][0]
                self._event_once(host, ts, "log.error_burst", "medium", len(errors),
                                 f"{len(errors)} ERROR log lines in 10s; dominant message template {top}", top, every_ms=10_000)
            if level == "WARN":
                same = sum(1 for e in dq if e[2] == fp and e[1] == "WARN")
                if same >= 10:
                    self._event_once(host, ts, "log.recurring_warning", "low", same,
                                     f"Warning template {fp} repeated {same}x in 60s", fp, every_ms=30_000, key=fp)

    def _auth(self, host, ts, user, ip, ok, method):
        thr = self.cfg.get("auth_burst_threshold", 5)
        with self.lock:
            dq = self.auth[host]
            dq.append((ts, user, ip, ok))
            while dq and dq[0][0] < ts - 60_000:
                dq.popleft()
            fails = [e for e in dq if not e[3]]
            if not ok and len(fails) >= thr:
                users = {e[1] for e in fails}
                ips = {e[2] for e in fails}
                pattern = "password spraying" if len(users) >= 3 else "brute force"
                sev = "critical" if len(fails) >= 4 * thr or len(users) >= 5 else "high"
                key = ("auth", host)
                last = self.last_emit.get(key, (0, 0))
                if ts - last[0] >= 10_000 or len(fails) >= last[1] * 2:
                    self.last_emit[key] = (ts, len(fails))
                    self.pending_events.append(self._ev(
                        host, ts, "security.auth_failure_burst", sev, len(fails),
                        f"{len(fails)} failed {method} logins in 60s, {len(users)} distinct accounts, "
                        f"{len(ips)} distinct origins (pattern: {pattern})"))
                    # the identities stay here - visible on the collector only
                    self.findings.appendleft({"ts": iso(ts), "host": host, "kind": "auth_failure_burst",
                                              "detail": f"{len(fails)} failures; accounts={sorted(users)[:8]} origins={sorted(ips)[:8]}"})

    def _ev(self, host, ts, cat, sev, count, ctx, fp=None):
        self.sources_seen[host] = True
        e = {"source_id": self.source_id(host), "ts": iso(ts), "category": cat, "severity": sev,
             "count": count, "context": ctx, "_host": host}
        if fp:
            e["fingerprint"] = fp
        return e

    def _event_once(self, host, ts, cat, sev, count, ctx, fp=None, every_ms=10_000, key=None):
        k = (cat, host, key)
        if ts - self.last_emit.get(k, (0, 0))[0] >= every_ms:
            self.last_emit[k] = (ts, count)
            self.pending_events.append(self._ev(host, ts, cat, sev, count, ctx, fp))

    # ------------------------------------------------------------------ aggregate + policy
    def flush_loop(self):
        w = self.cfg["window_s"] * 1000
        grace = 400
        while True:
            time.sleep(0.25)
            try:
                cutoff = now_ms() - grace
                with self.lock:
                    closed = sorted(s for s in self.windows if s + w <= cutoff)
                    if not closed and not self.pending_events:
                        continue
                    wins = {s: self.windows.pop(s) for s in closed}
                    events = self.pending_events
                    self.pending_events = []
                    if closed:
                        self.flushed_upto = max(self.flushed_upto, closed[-1] + w)
                self.build_payload(wins, events, w)
            except Exception as e:  # never let the pipeline die
                self.last_error = f"flush: {e}"

    def build_payload(self, wins, events, w):
        metrics, hosts = [], set()
        for start, by_host in sorted(wins.items()):
            for host, ms in by_host.items():
                hosts.add(host)
                for name, vals in ms.items():
                    if not vals:
                        continue
                    metrics.append({"source_id": self.source_id(host), "ts": iso(start), "name": name,
                                    "avg": round(sum(vals) / len(vals), 3), "min": round(min(vals), 3),
                                    "max": round(max(vals), 3), "n": len(vals)})
        for e in events:
            hosts.add(e.pop("_host"))
        starts = sorted(wins) or [now_ms()]
        with self.lock:
            self.seq += 1
            seq = self.seq
        payload = {
            "schema": "aiops.meta/v1", "payload_id": str(uuid.uuid4()), "collector_id": self.cid, "seq": seq,
            "kind": "metrics", "created_at": iso(), "policy_version": self.policy["policy_version"],
            "window": {"start": iso(starts[0]), "end": iso(starts[-1] + w)},
            "sources": [self.source_meta(h) for h in sorted(hosts)],
            "metrics": metrics, "events": events,
        }
        self.stage(payload, seq)

    def stage(self, payload, seq):
        """Apply data policy, DLP-scan, persist to outbox (= egress proof record)."""
        clean, dropped = enforce(payload, self.policy)
        body = dumps(clean)
        hits = dlp_scan(body)
        status = "pending" if not hits else "blocked"
        if hits:
            self.stats["blocked_payloads"] += 1
            # keep seq contiguous: replace with an empty, policy-clean marker payload
            marker = dict(clean, metrics=[], events=[], sources=[])
            body = dumps(marker)
            status = "pending"
            note = f"original payload BLOCKED by DLP ({','.join(sorted(set(hits)))}); empty marker sent instead"
        else:
            note = None
        self.x("""INSERT INTO egress(payload_id,seq,kind,created_ms,body,sha256,bytes,status,dropped,dlp,
                  redactions,policy_version,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (clean.get("payload_id"), seq, clean.get("kind"), now_ms(), body, sha256_hex(body), len(body),
                status, json.dumps(dropped), json.dumps(hits), self.stats["redactions_total"],
                self.policy["policy_version"], note))

    # ------------------------------------------------------------------ transport
    def _request(self, method, url, body=b"", timeout=5):
        if self.partition:
            raise ConnectionError("network partition (simulated by operator)")
        path = urllib.parse.urlsplit(url).path
        ts = str(int(time.time()))
        req = urllib.request.Request(url, data=body if method == "POST" else None, method=method, headers={
            "Content-Type": "application/json", "X-Collector-Id": self.cid, "X-Timestamp": ts,
            "X-Signature": sign(self.cfg["secret"], method, path, body, ts), "User-Agent": f"aiops-collector/{VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout, context=self.ssl_ctx) as r:
            return json.loads(r.read() or b"{}")

    def discover(self):
        r = self._request("GET", self.cfg["saas_url"] + "/v1/discover")
        self.region = r["region"]
        self.ingest_base = r["ingest_url"]
        self.audit("collector", "region_discovery", f"assigned region {self.region} -> {self.ingest_base}")

    def sender_loop(self):
        backoff = 0.5
        while True:
            try:
                if not self.ingest_base:
                    self.discover()
                if not self.send_once():
                    time.sleep(0.2)
                    continue
                backoff = 0.5
            except urllib.error.HTTPError as e:
                if e.code == 421:              # misdirected: wrong region -> re-discover
                    self.ingest_base = None
                self._fail(f"HTTP {e.code}: {e.read()[:120]!r}")
                time.sleep(backoff)
                backoff = min(backoff * 2, 4)
            except Exception as e:
                self._fail(str(e)[:160])
                time.sleep(backoff)
                backoff = min(backoff * 2, 4)    # capped so the backlog drains quickly on reconnect

    def send_once(self):
        """Send one batch from the outbox. Returns False when there is nothing to send.

        If the SaaS refuses a whole batch with a client error (4xx other than auth / region / rate
        limit), the next sends go one payload at a time; a single payload that is still refused is
        marked rejected, so one bad payload can never block the queue behind it (bug B2)."""
        limit = 1 if self.single_sends > 0 else 100
        rows = self.q("SELECT payload_id, body FROM egress WHERE status='pending' AND kind='metrics' "
                      "ORDER BY seq LIMIT ?", (limit,))
        if not rows:
            self.single_sends = 0
            return False
        batch = list(rows)
        if self.chaos:
            batch = self._chaos(batch)
            if not batch:
                return False
        ids = [r[0] for r in batch]
        self.x(f"UPDATE egress SET attempts=attempts+1, last_attempt_ms=? WHERE payload_id IN "
               f"({','.join('?' * len(ids))})", (now_ms(), *ids))
        body = ("[" + ",".join(r[1] for r in batch) + "]").encode()
        try:
            res = self._request("POST", self.ingest_base + "/v1/ingest", body)
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500 and e.code not in (401, 421, 429):
                if len(batch) > 1:
                    self.single_sends = len(batch)          # find the bad one
                else:
                    reason = f"refused by SaaS: HTTP {e.code}"
                    self.x("UPDATE egress SET status='rejected', note=? WHERE payload_id=?", (reason, ids[0]))
                    self.audit("collector", "payload_rejected", f"{ids[0]}: {reason}")
                    self.single_sends = max(0, self.single_sends - 1)
            raise
        if self.single_sends:
            self.single_sends -= 1
        done = set(res.get("accepted", [])) | set(res.get("duplicates", []))
        receipts = res.get("receipts", {})
        t = now_ms()
        for pid in done:
            mine = self.q("SELECT sha256 FROM egress WHERE payload_id=?", (pid,))
            if not mine or receipts.get(pid) != mine[0][0]:
                # the SaaS must echo the digest of the exact bytes we sent; otherwise keep it pending
                self.stats["ack_mismatch"] += 1
                self.x("UPDATE egress SET note=? WHERE payload_id=?",
                       ("acknowledgement digest mismatch - will retry", pid))
                continue
            self.x("UPDATE egress SET status='delivered', delivered_ms=COALESCE(delivered_ms, ?), "
                   "note=NULL WHERE payload_id=?", (t, pid))
        for rj in res.get("rejected", []):
            self.x("UPDATE egress SET status='rejected', note=? WHERE payload_id=?", (rj["reason"], rj["id"]))
        self.link_state = "connected"
        self.last_delivery_ms = t
        self.last_error = ""
        return True

    def _fail(self, msg):
        self.stats["send_errors"] += 1
        self.last_error = msg
        self.link_state = "disconnected - buffering locally"

    def _chaos(self, batch):
        """Deliberately produce duplicates + out-of-order arrival to prove SaaS idempotency/ordering."""
        now = now_ms()
        kept = []
        for row in batch:                         # hold some payloads back ~3s -> they arrive after newer ones
            rel = self.held.get(row[0])
            if rel is None and random.random() < 0.35:
                self.held[row[0]] = rel = now + 3000
            if rel is None or rel <= now:
                kept.append(row)
        batch = kept
        if not batch:
            return []
        dups = self.q("SELECT payload_id, body FROM egress WHERE status='delivered' AND kind='metrics' "
                      "ORDER BY seq DESC LIMIT 20")
        if dups:
            batch += random.sample(dups, min(len(dups), random.randint(1, 3)))
        random.shuffle(batch)
        self.stats["chaos_dups_sent"] += 1
        return batch

    def heartbeat_loop(self):
        while True:
            time.sleep(5)
            hb = {"schema": "aiops.meta/v1", "collector_id": self.cid, "kind": "heartbeat", "created_at": iso(),
                  "version": VERSION, "config_hash": self.config_hash, "policy_version": self.policy["policy_version"],
                  "uptime_s": int(time.time() - self.started), "tz": self.cfg["tz"], "stats": self.self_stats()}
            clean, dropped = enforce(hb, self.policy)
            body = dumps(clean)
            pid = str(uuid.uuid4())
            status, note = "delivered", None
            try:
                if not self.ingest_base:
                    self.discover()
                self._request("POST", self.ingest_base + "/v1/heartbeat", body.encode())
            except Exception as e:
                status, note = "dropped", f"not buffered (heartbeats are point-in-time): {str(e)[:80]}"
                if not isinstance(e, urllib.error.HTTPError):
                    self.link_state = "disconnected - buffering locally"
            self.x("""INSERT INTO egress(payload_id,seq,kind,created_ms,body,sha256,bytes,status,dropped,dlp,
                      policy_version,note,attempts,delivered_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
                   (pid, None, "heartbeat", now_ms(), body, sha256_hex(body), len(body), status, json.dumps(dropped),
                    json.dumps(dlp_scan(body)), self.policy["policy_version"], note,
                    now_ms() if status == "delivered" else None))

    def self_stats(self):
        t, p = time.time(), time.process_time()
        t0, p0 = self._cpu_sample
        self._cpu_sample = (t, p)
        depth = self.q("SELECT COUNT(*) FROM egress WHERE status='pending'")[0][0]
        delivered = self.q("SELECT MAX(seq) FROM egress WHERE status='delivered' AND kind='metrics'")[0][0] or 0
        return {"cpu_pct": round(100 * (p - p0) / max(t - t0, 1e-6), 1), "rss_mb": _rss_mb(), "buffer_depth": depth,
                "seq_created": self.seq, "seq_delivered": delivered, "send_errors": self.stats["send_errors"],
                "raw_events_total": self.stats["raw_events_total"], "redactions_total": self.stats["redactions_total"],
                "blocked_payloads": self.stats["blocked_payloads"], "last_error": self.last_error[:150],
                "partition": self.partition, "chaos": self.chaos}

    # ------------------------------------------------------------------ remediation (simulated)
    def command_loop(self):
        while True:
            time.sleep(2)
            try:
                if not self.ingest_base:
                    continue
                cmds = self._request("GET", self.ingest_base + "/v1/commands").get("commands", [])
                for c in cmds:
                    self.execute(c)
            except Exception:
                pass

    def execute(self, c):
        host = self.host_of(c["source_id"])
        mode = c.get("mode", "execute")
        if not host:
            result = {"status": "failed", "detail": "target pseudonym not known to this collector"}
        else:
            # SIMULATION ONLY: no real system is touched. The pseudonym is resolved to a real host
            # *locally* - the SaaS never learns the hostname it asked to act on.
            self.audit(f"saas:{c.get('approved_by')}", f"{mode}:{c['action']}",
                       f"[SIMULATED] {mode} '{c['action']}' on {host} ({c['source_id']}); command {c['id']}")
            healed = False
            if mode == "execute" and self.cfg.get("simulator_url"):
                try:
                    req = urllib.request.Request(self.cfg["simulator_url"] + "/heal", method="POST",
                                                 data=json.dumps({"collector": self.cid, "host": host,
                                                                  "action": c["action"]}).encode(),
                                                 headers={"Content-Type": "application/json"})
                    urllib.request.urlopen(req, timeout=2).read()
                    healed = True
                except Exception:
                    pass
            result = {"status": "rolled_back" if mode == "rollback" else "executed",
                      "detail": f"[SIMULATED] {mode} of {c['action']} completed on {c['source_id']} "
                                f"(host resolved locally){'; test environment updated' if healed else ''}"}
        try:
            self._request("POST", f"{self.ingest_base}/v1/commands/{c['id']}/result", dumps(result).encode())
        except Exception as e:
            self.last_error = f"command result: {e}"

    # ------------------------------------------------------------------ retention
    def retention_loop(self):
        while True:
            time.sleep(30)
            cut = now_ms() - int(self.cfg["raw_retention_min"]) * 60_000
            n = self.x("DELETE FROM raw_events WHERE received_ms < ?", (cut,)).rowcount
            self.x("DELETE FROM egress WHERE status IN ('delivered','dropped') AND created_ms < ?",
                   (now_ms() - 24 * 3600_000,))
            if n:
                self.audit("collector", "retention_purge", f"purged {n} raw events older than "
                           f"{self.cfg['raw_retention_min']} min")

    # ------------------------------------------------------------------ UI state
    def state(self, since_raw=0):
        raw = self.q("SELECT id, received_ms, ts_ms, host, type, raw, redacted, findings FROM raw_events "
                     "ORDER BY id DESC LIMIT 60")
        flagged = self.q("SELECT id, received_ms, ts_ms, host, type, raw, redacted, findings FROM raw_events "
                         "WHERE findings<>'' ORDER BY id DESC LIMIT 12")
        seen = {r[0] for r in flagged}
        raw = list(flagged) + [r for r in raw if r[0] not in seen]
        eg = self.q("SELECT payload_id, seq, kind, created_ms, sha256, bytes, status, attempts, delivered_ms, "
                    "dropped, dlp, note FROM egress ORDER BY id DESC LIMIT 80")
        counts = dict(self.q("SELECT status, COUNT(*) FROM egress WHERE kind='metrics' GROUP BY status"))
        return {
            "collector_id": self.cid, "version": VERSION, "site": self.cfg["site"], "tz": self.cfg["tz"],
            "region": self.region, "ingest": self.ingest_base, "link": self.link_state, "partition": self.partition,
            "chaos": self.chaos, "last_error": self.last_error, "stats": self.self_stats(), "counts": counts,
            "retention_min": self.cfg["raw_retention_min"], "tls": bool(self.ssl_ctx), "policy": self.policy,
            "raw": [dict(zip(["id", "received_ms", "ts_ms", "host", "type", "raw", "redacted", "findings"], r)) for r in raw],
            "egress": [dict(zip(["payload_id", "seq", "kind", "created_ms", "sha256", "bytes", "status", "attempts",
                                 "delivered_ms", "dropped", "dlp", "note"], r)) for r in eg],
            "pseudonyms": [{"host": h, "source_id": self.source_id(h), **self.cfg["hosts"][h]} for h in sorted(self.cfg["hosts"])],
            "findings": list(self.findings)[:40],
            "audit": [dict(zip(["ts_ms", "actor", "action", "detail"], r)) for r in
                      self.q("SELECT ts_ms, actor, action, detail FROM local_audit ORDER BY id DESC LIMIT 40")],
        }


def make_handler(col):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 30

        def log_message(self, *a):
            pass

        def _send(self, code, obj, ctype="application/json"):
            data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _guard(self, write=False):
            # loopback console: refuse DNS-rebinding hosts and cross-site writes. /ingest is for
            # local sources (no browser Origin), so it only needs the Host check.
            port = col.cfg["ui_port"]
            if not host_ok(self.headers, port) or (write and not origin_ok(self.headers, port)):
                self._send(403, {"error": "forbidden host or origin"})
                return False
            return True

        def do_GET(self):
            if not self._guard():
                return
            if self.path in ("/", "/index.html"):
                with open(UI_FILE, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if self.path == "/ui.js":
                with open(UI_JS, "rb") as f:
                    return self._send(200, f.read(), "application/javascript")
            if self.path.startswith("/api/state"):
                return self._send(200, col.state())
            if self.path.startswith("/api/egress/"):
                pid = self.path.rsplit("/", 1)[1]
                r = col.q("SELECT body, sha256, status, dropped, dlp, note FROM egress WHERE payload_id=?", (pid,))
                if not r:
                    return self._send(404, {"error": "not found"})
                return self._send(200, dict(zip(["body", "sha256", "status", "dropped", "dlp", "note"], r[0])))
            if self.path.startswith("/api/outbox-ids"):
                rows = col.q("SELECT payload_id, seq, status FROM egress WHERE kind='metrics' ORDER BY seq")
                return self._send(200, {"collector_id": col.cid, "payloads": [list(r) for r in rows]})
            if self.path.startswith("/api/raw-search"):
                term = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("q", [""])[0]
                n = col.q("SELECT COUNT(*) FROM raw_events WHERE raw LIKE ?", (f"%{term}%",))[0][0] if term else 0
                m = col.q("SELECT COUNT(*) FROM egress WHERE body LIKE ?", (f"%{term}%",))[0][0] if term else 0
                return self._send(200, {"term": term, "raw_matches_local": n, "egress_matches": m})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            body = self._body()
            if not self._guard(write=True):
                return
            if self.path == "/ingest":
                text = body.decode("utf-8", "replace").strip()
                try:
                    if text.startswith("["):
                        items = json.loads(text)
                    else:
                        items = [json.loads(line) for line in text.splitlines() if line.strip()]
                except json.JSONDecodeError as e:
                    return self._send(400, {"error": f"bad json: {e}"})
                for ev in items:
                    col.ingest(ev)
                return self._send(202, {"accepted": len(items)})
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                data = {}
            if self.path == "/api/partition":
                col.partition = bool(data.get("on"))
                col.audit("operator", "partition", f"simulated SaaS network partition {'ON' if col.partition else 'OFF'}")
                return self._send(200, {"partition": col.partition})
            if self.path == "/api/chaos":
                col.chaos = bool(data.get("on"))
                col.audit("operator", "chaos", f"duplicate/out-of-order delivery chaos {'ON' if col.chaos else 'OFF'}")
                return self._send(200, {"chaos": col.chaos})
            if self.path == "/api/retention":
                col.cfg["raw_retention_min"] = max(1, int(data.get("minutes", 60)))
                col.audit("operator", "retention", f"raw retention set to {col.cfg['raw_retention_min']} min")
                return self._send(200, {"retention_min": col.cfg["raw_retention_min"]})
            if self.path == "/api/scenario":
                data["collector"] = col.cid
                try:
                    req = urllib.request.Request(col.cfg["simulator_url"] + "/scenario", data=json.dumps(data).encode(),
                                                 method="POST", headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=3) as r:
                        return self._send(200, json.loads(r.read()))
                except Exception as e:
                    return self._send(502, {"error": f"simulator unreachable: {e}"})
            self._send(404, {"error": "not found"})
    return H


class SyslogUDP(socketserver.BaseRequestHandler):
    col = None

    def handle(self):
        data = self.request[0].decode("utf-8", "replace")
        for line in data.splitlines():
            if line.strip():
                self.col.ingest_syslog(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="collector id or path to config json")
    args = ap.parse_args()
    path = args.config if args.config.endswith(".json") else os.path.join(CONFIG_DIR, "collectors", f"{args.config}.json")
    cfg = load_json(path)
    if not cfg:
        sys.exit(f"config not found: {path} (run setup_env.py)")
    col = Collector(cfg)
    for fn in (col.flush_loop, col.sender_loop, col.heartbeat_loop, col.command_loop, col.retention_loop):
        threading.Thread(target=fn, daemon=True).start()
    SyslogUDP.col = col
    udp = socketserver.ThreadingUDPServer(("127.0.0.1", cfg["syslog_port"]), SyslogUDP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", cfg["ui_port"]), make_handler(col))
    print(f"[collector {col.cid}] UI http://127.0.0.1:{cfg['ui_port']}  syslog udp/{cfg['syslog_port']}  "
          f"saas {cfg['saas_url']} tls={'on' if col.ssl_ctx else 'OFF'}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
