"""Tier 2 storage.

Data residency: one SQLite database *per region*. A tenant's metadata is only ever written to
the database of the region it chose; the control plane (config/registry.json) holds tenant
and collector registration only - never telemetry.

Tenant isolation: every table carries tenant_id, and every read helper takes the tenant_id
from the authenticated session/credential (never from user input).
"""
import contextlib
import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS payloads(payload_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, collector_id TEXT,
    seq INT, kind TEXT, created_ms INT, received_ms INT, sha256 TEXT, bytes INT, body TEXT, out_of_order INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS payloads_t ON payloads(tenant_id, received_ms);
CREATE INDEX IF NOT EXISTS payloads_c ON payloads(tenant_id, collector_id, seq);
CREATE TABLE IF NOT EXISTS metrics(tenant_id TEXT NOT NULL, source_id TEXT, name TEXT, ts_ms INT, avg REAL, min REAL,
    max REAL, n INT, received_ms INT, PRIMARY KEY(tenant_id, source_id, name, ts_ms));
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, collector_id TEXT, source_id TEXT,
    ts_ms INT, category TEXT, severity TEXT, count INT, context TEXT, fingerprint TEXT, received_ms INT, payload_id TEXT);
CREATE INDEX IF NOT EXISTS events_t ON events(tenant_id, ts_ms);
CREATE TABLE IF NOT EXISTS sources(tenant_id TEXT NOT NULL, source_id TEXT, collector_id TEXT, role TEXT, service TEXT,
    site TEXT, tz TEXT, first_seen_ms INT, PRIMARY KEY(tenant_id, source_id));
CREATE TABLE IF NOT EXISTS collectors(tenant_id TEXT NOT NULL, collector_id TEXT, last_seen_ms INT, version TEXT,
    config_hash TEXT, policy_version TEXT, tz TEXT, stats TEXT, PRIMARY KEY(tenant_id, collector_id));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, akey TEXT, source_id TEXT,
    collector_id TEXT, signal TEXT, kind TEXT, severity TEXT, status TEXT, first_event_ms INT, created_ms INT,
    last_ms INT, resolved_ms INT, count INT, title TEXT, detail TEXT, incident_id INT);
CREATE INDEX IF NOT EXISTS alerts_t ON alerts(tenant_id, status);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, status TEXT, opened_ms INT,
    updated_ms INT, closed_ms INT, severity TEXT, title TEXT, root_source TEXT, analysis TEXT, suppressed INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS health_history(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, entity TEXT,
    entity_kind TEXT, state TEXT, prev TEXT, reason TEXT, ts_ms INT);
CREATE INDEX IF NOT EXISTS hh_t ON health_history(tenant_id, ts_ms);
CREATE TABLE IF NOT EXISTS actions(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, incident_id INT, action TEXT,
    source_id TEXT, collector_id TEXT, status TEXT, policy TEXT, proposed_ms INT, requested_by TEXT, approved_by TEXT,
    approved_ms INT, executed_ms INT, result TEXT, rollback_by TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, ts_ms INT, actor TEXT, action TEXT,
    detail TEXT);
CREATE TABLE IF NOT EXISTS counters(tenant_id TEXT NOT NULL, scope TEXT, key TEXT, value INT,
    PRIMARY KEY(tenant_id, scope, key));
CREATE TABLE IF NOT EXISTS latency(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT, value_ms INT,
    ts_ms INT, detail TEXT);
CREATE INDEX IF NOT EXISTS lat_t ON latency(tenant_id, kind, ts_ms);
"""


class RegionStore:
    def __init__(self, region, path):
        self.region = region
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()
        self._depth = 0

    @contextlib.contextmanager
    def transaction(self):
        """Group many writes into one SQLite transaction (re-entrant). Per-statement autocommit was
        the main throughput limit in the load test."""
        with self.lock:
            outer = self._depth == 0
            if outer:
                self.db.execute("BEGIN")
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if outer:
                    self.db.execute("ROLLBACK")
                raise
            self._depth -= 1
            if outer:
                self.db.execute("COMMIT")

    @contextlib.contextmanager
    def savepoint(self, name="p"):
        """Roll back just this unit of work on error, keeping the surrounding transaction (bug B2)."""
        with self.lock:
            self.db.execute(f"SAVEPOINT {name}")
            try:
                yield
            except BaseException:
                self.db.execute(f"ROLLBACK TO {name}")
                self.db.execute(f"RELEASE {name}")
                raise
            self.db.execute(f"RELEASE {name}")

    def q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def q1(self, sql, args=()):
        r = self.q(sql, args)
        return r[0] if r else None

    def x(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args)

    def rows(self, sql, args=()):
        with self.lock:
            cur = self.db.execute(sql, args)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def bump(self, tenant, scope, key, n=1):
        self.x("INSERT INTO counters(tenant_id,scope,key,value) VALUES(?,?,?,?) "
               "ON CONFLICT(tenant_id,scope,key) DO UPDATE SET value=value+excluded.value", (tenant, scope, key, n))

    def counters(self, tenant):
        out = {}
        for scope, key, v in self.q("SELECT scope,key,value FROM counters WHERE tenant_id=?", (tenant,)):
            out.setdefault(scope, {})[key] = v
        return out


class Stores:
    """Routes every tenant to the store of its residency region."""

    def __init__(self, data_dir, registry):
        self.registry = registry
        self.by_region = {r: RegionStore(r, os.path.join(data_dir, "saas", f"region-{r}.db"))
                          for r in registry["regions"]}

    def close(self):
        for st in self.by_region.values():
            st.db.close()

    def for_tenant(self, tenant_id):
        return self.by_region[self.registry["tenants"][tenant_id]["region"]]
