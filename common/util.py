"""Small shared helpers: UTC time, request signing, JSON."""
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

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


def parse_iso(s):
    """Parse ISO-8601 (any offset) to epoch ms (UTC)."""
    if isinstance(s, (int, float)):
        return int(s)
    s = s.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
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
