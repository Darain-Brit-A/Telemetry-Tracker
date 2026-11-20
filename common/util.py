"""Small shared helpers: UTC time, request signing, JSON."""
import functools
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import date, datetime, timedelta, timezone, tzinfo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# overridable so tests and the load test can run fully isolated from the live demo
CONFIG_DIR = os.environ.get("AIOPS_CONFIG_DIR", os.path.join(ROOT, "config"))
DATA_DIR = os.environ.get("AIOPS_DATA_DIR", os.path.join(ROOT, "data"))
CERT_DIR = os.environ.get("AIOPS_CERT_DIR", os.path.join(CONFIG_DIR, "certs"))

SIG_SKEW_S = 300


def now_ms():
    return int(time.time() * 1000)


def iso(ms=None):
    """UTC ISO-8601 with milliseconds and a 'Z' suffix."""
    if ms is None:
        ms = now_ms()
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(ms % 1000):03d}Z"


def _nth_sunday(year, month, n):
    """Date of the n-th Sunday of a month; n = -1 means the last one."""
    if n > 0:
        first = date(year, month, 1)
        return first + timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))
    nxt = date(year + month // 12, month % 12 + 1, 1)
    last = nxt - timedelta(days=1)
    return last - timedelta(days=(last.weekday() - 6) % 7)


# Daylight-saving rules as (start month, n-th Sunday, local hour, end month, n-th Sunday, local hour);
# the end hour is in summer time.
_DST_RULES = {"eu": (3, -1, None, 10, -1, None),     # EU: 01:00 UTC on the last Sunday of Mar / Oct
              "us": (3, 2, 2, 11, 1, 2)}             # US: 02:00 local, 2nd Sunday Mar / 1st Sunday Nov
# Zones the demo and the adapter use, so offset-less timestamps are read correctly even where Python has no
# timezone database (stock Windows without the `tzdata` package): name -> (standard, summer offset in min, rule)
_BUILTIN_ZONES = {
    "UTC": (0, None, None), "Etc/UTC": (0, None, None), "GMT": (0, None, None),
    "Asia/Kolkata": (330, None, None), "Asia/Calcutta": (330, None, None), "Asia/Singapore": (480, None, None),
    "Asia/Dubai": (240, None, None), "Asia/Tokyo": (540, None, None),
    "Europe/London": (0, 60, "eu"), "Europe/Dublin": (0, 60, "eu"), "Europe/Berlin": (60, 120, "eu"),
    "Europe/Paris": (60, 120, "eu"), "Europe/Amsterdam": (60, 120, "eu"), "Europe/Madrid": (60, 120, "eu"),
    "America/New_York": (-300, -240, "us"), "America/Chicago": (-360, -300, "us"),
    "America/Denver": (-420, -360, "us"), "America/Los_Angeles": (-480, -420, "us"),
}


class _RuleZone(tzinfo):
    """Fixed offset plus an optional EU/US daylight-saving rule (wall-clock based)."""

    def __init__(self, name, std, dst=None, rule=None):
        self.name, self.std, self.dst_off, self.rule = name, timedelta(minutes=std), dst, rule

    def _is_dst(self, dt):
        if not self.rule or dt is None:
            return False
        sm, sn, sh, em, en, eh = _DST_RULES[self.rule]
        if sh is None:                                   # EU: switch at 01:00 UTC
            sh = 1 + self.std.total_seconds() / 3600
            eh = 1 + self.dst_off / 60
        wall = dt.replace(tzinfo=None)
        start = datetime.combine(_nth_sunday(dt.year, sm, sn), datetime.min.time()) + timedelta(hours=sh)
        end = datetime.combine(_nth_sunday(dt.year, em, en), datetime.min.time()) + timedelta(hours=eh)
        return start <= wall < end

    def utcoffset(self, dt):
        return timedelta(minutes=self.dst_off) if self._is_dst(dt) else self.std

    def dst(self, dt):
        return self.utcoffset(dt) - self.std

    def tzname(self, dt):
        return self.name

    def __repr__(self):
        return f"_RuleZone({self.name!r})"


_ZONE_WARNED = set()


def builtin_zone(name):
    z = _BUILTIN_ZONES.get(name)
    return _RuleZone(name, *z) if z else None


@functools.lru_cache(maxsize=64)
def _zone(name):
    """tzinfo for an IANA name: zoneinfo when this Python has a timezone database, else the built-in table
    above; an unknown name falls back to UTC with a warning (once per name) instead of silently."""
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        z = builtin_zone(name)
        if z:
            return z
        if name not in _ZONE_WARNED:
            _ZONE_WARNED.add(name)
            print(f"[warn] timezone {name!r} unknown on this machine (install 'tzdata' or add it to "
                  f"common/util.py); reading offset-less timestamps from it as UTC", file=sys.stderr)
        return timezone.utc


def parse_iso(s, default_tz=None):
    """Parse ISO-8601 to epoch ms (UTC). A timestamp without an offset is read in `default_tz`
    (an IANA name such as "Asia/Kolkata") when given, otherwise as UTC."""
    if isinstance(s, (int, float)):
        return int(s)
    s = s.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_zone(default_tz) if default_tz else timezone.utc)
    return int(dt.timestamp() * 1000)


def dumps(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def sign(secret, method, path, body, ts):
    msg = f"{ts}\n{method.upper()}\n{path}\n{sha256_hex(body)}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_sig(secret, method, path, body, ts, sig):
    try:
        if abs(int(time.time()) - int(ts)) > SIG_SKEW_S:
            return False, "timestamp outside allowed skew (replay protection)"
    except (TypeError, ValueError):
        return False, "bad timestamp"
    expected = sign(secret, method, path, body, ts)
    if not hmac.compare_digest(expected, sig or ""):
        return False, "bad signature"
    return True, "ok"


def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def percentile(values, p):
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)


def like_contains(term):
    r"""LIKE pattern that matches `term` literally; use it with ESCAPE '\'.

    Without escaping, '_' and '%' act as wildcards and a proof-panel search reports matches that
    are not there (bug B5)."""
    esc = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{esc}%"
