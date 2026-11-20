"""Data-protection primitives shared by both tiers.

* ``redact_text``     - scrub secrets / PII out of a raw log line (collector only).
* ``dlp_scan``        - last-line-of-defence scan of a serialized payload.
* ``enforce``         - allow-list enforcement of an outbound metadata payload.
* ``pseudonymize``    - keyed HMAC pseudonymous IDs for hosts (mapping stays local).
"""
import hashlib
import hmac
import json
import os
import re

POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_policy.json")


def load_policy(path=POLICY_PATH):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- secret patterns
# (name, regex, replacement).  Order matters: the most specific patterns first.
SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[REDACTED:private_key]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), "[REDACTED:jwt]"),
    ("bearer", re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED:token]"),
    ("aws_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    ("api_key", re.compile(r"\b(sk|pk|rk|ghp|gho|xox[abp])[-_][A-Za-z0-9_-]{10,}\b"), "[REDACTED:api_key]"),
    ("kv_secret", re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth)\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"), r"\1=[REDACTED:secret]"),
    ("url_creds", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@"), r"\1[REDACTED:creds]@"),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED:pan]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED:email]"),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "[REDACTED:ip]"),
]

# Patterns considered *credential material* (vs. PII) - used to raise a security event.
CREDENTIAL_TYPES = {"private_key", "jwt", "bearer", "aws_key", "api_key", "kv_secret", "url_creds"}


def redact_text(text):
    """Return (redacted_text, [finding types])."""
    findings = []
    out = text
    for name, rx, repl in SECRET_PATTERNS:
        out, n = rx.subn(repl, out)
        if n:
            findings.extend([name] * n)
    return out, findings


# DLP scan of the *serialized* outbound payload. Placeholders like [REDACTED:x] are fine.
_DLP = [(n, rx) for n, rx, _ in SECRET_PATTERNS if n in CREDENTIAL_TYPES | {"credit_card", "email", "ipv4"}]


def dlp_scan(serialized):
    hits = []
    for name, rx in _DLP:
        for m in rx.finditer(serialized):
            frag = m.group(0)
            if "REDACTED" in frag:
                continue
            # timestamps / uuids can look like PANs - only flag digit-runs that pass Luhn
            if name == "credit_card" and not _luhn(re.sub(r"\D", "", frag)):
                continue
            hits.append(name)
    return hits


def _luhn(digits):
    if not 13 <= len(digits) <= 19:
        return False
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def pseudonymize(salt, value, prefix="src"):
    digest = hmac.new(salt.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{prefix}-{digest[:10]}"


# ---------------------------------------------------------------- allow-list enforcement
def _clip(v, policy, limit_key="string_max_len"):
    if isinstance(v, str):
        return v[: policy[limit_key]]
    return v


def _scalar(v):
    return v is None or isinstance(v, (int, float, str, bool))


def enforce(payload, policy):
    """Strip every field that is not allow-listed.

    Returns (clean_payload, dropped) where ``dropped`` is a list of human readable
    descriptions of what was removed - shown on the egress proof panel.
    """
    dropped = []
    clean = {}
    kind = payload.get("kind")
    top = policy["heartbeat_fields"] if kind == "heartbeat" else policy["payload_fields"]
    for k, v in payload.items():
        if k not in top:
            dropped.append(f"field '{k}'")
            continue
        clean[k] = v

    if kind == "heartbeat":
        stats = {}
        for k, v in (clean.get("stats") or {}).items():
            if k in policy["heartbeat_stats_fields"] and _scalar(v):
                stats[k] = _clip(v, policy, "context_max_len")
            else:
                dropped.append(f"stats.{k}")
        clean["stats"] = stats
        for k in ("version", "config_hash", "tz", "collector_id"):
            if k in clean:
                clean[k] = _clip(clean[k], policy)
        return clean, dropped

    if "window" in clean:
        clean["window"] = {k: v for k, v in clean["window"].items() if k in policy["window_fields"]}

    def filter_list(items, allowed, label, extra_check=None):
        out = []
        for i, item in enumerate(items or []):
            row = {}
            for k, v in item.items():
                if k not in allowed or not _scalar(v):
                    dropped.append(f"{label}[{i}].{k}")
                    continue
                row[k] = _clip(v, policy, "context_max_len" if k == "context" else "string_max_len")
            if extra_check and not extra_check(row):
                dropped.append(f"{label}[{i}] (rejected: value not allow-listed)")
                continue
            out.append(row)
        return out

    clean["sources"] = filter_list(clean.get("sources"), policy["source_fields"], "sources")
    clean["metrics"] = filter_list(clean.get("metrics"), policy["metric_fields"], "metrics",
                                   lambda r: r.get("name") in policy["metric_names"])
    clean["events"] = filter_list(clean.get("events"), policy["event_fields"], "events",
                                  lambda r: r.get("category") in policy["event_categories"]
                                  and r.get("severity") in policy["severities"])
    return clean, dropped


def _is_iso(v):
    if not isinstance(v, str) or len(v) > 40:
        return False
    try:
        from common.util import parse_iso
        parse_iso(v)
        return True
    except (ValueError, TypeError):
        return False


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) < 1e12


def validate_values(payload):
    """Value-level checks (field *names* are covered by the allow-list). Returns a list of problems."""
    problems = []
    if not _is_iso(payload.get("created_at")):
        problems.append("created_at is not an ISO-8601 timestamp")
    if payload.get("kind") == "heartbeat":
        return problems
    if not isinstance(payload.get("seq"), int) or isinstance(payload.get("seq"), bool) or payload["seq"] < 0:
        problems.append("seq must be a non-negative integer")
    for k in ("start", "end"):
        if not _is_iso((payload.get("window") or {}).get(k)):
            problems.append(f"window.{k} is not an ISO-8601 timestamp")
    for i, m in enumerate(payload.get("metrics") or []):
        if not _is_iso(m.get("ts")):
            problems.append(f"metrics[{i}].ts is not an ISO-8601 timestamp")
        if not all(_is_num(m.get(k)) for k in ("avg", "min", "max")):
            problems.append(f"metrics[{i}] avg/min/max must be finite numbers")
        if not isinstance(m.get("n"), int) or m["n"] < 1:
            problems.append(f"metrics[{i}].n must be a positive integer")
        if not isinstance(m.get("source_id"), str):
            problems.append(f"metrics[{i}].source_id must be a string")
    for i, e in enumerate(payload.get("events") or []):
        if not _is_iso(e.get("ts")):
            problems.append(f"events[{i}].ts is not an ISO-8601 timestamp")
        if e.get("count") is not None and (not isinstance(e["count"], int) or e["count"] < 0):
            problems.append(f"events[{i}].count must be a non-negative integer")
    return problems[:10]


def validate_inbound(payload, policy):
    """SaaS-side: reject (not silently fix) anything outside the allow-list or with malformed values."""
    clean, dropped = enforce(payload, policy)
    return dropped + validate_values(payload)
