# Feature 1: Intelligent Privacy Segregation & Shannon Entropy ML

> **Component:** Tier 1 Local Collector & Data Protection Engine  
> **Target Files:** `common/policy.py`, `collector/collector.py`  
> **Test File:** `tests/test_policy.py`  
> **Evaluation Phase:** Phase 1 (Problem Understanding & Ideation), Phase 3 (Working Prototype), and Bonus Challenge (Privacy-Aware Metadata Pipeline)

---

## 1. Executive Summary & Objective

In a secure two-tier AIOps architecture, **raw logs, user identities, credentials, and sensitive payloads must strictly remain within the customer's on-premises / local environment**. Only scrubbed, allow-listed operational metadata (aggregated rates, health indicators, pseudonyms) is permitted to egress to the centralized SaaS platform.

Traditional Data Loss Prevention (DLP) relying purely on static keyword matching (e.g., regex searching for `password=`, `token=`, `AKIA...`) has two critical vulnerabilities:
1. **Unlabelled High-Entropy Secrets:** Developers frequently log raw API tokens, cryptographic hashes, and private session keys without accompanying variable keywords (e.g., `connecting with key 8f9b4c12d9e03fa57b21e84c90d2`).
2. **Dynamic Unstructured Payloads:** Unfamiliar telemetry streams from microservices contain unexpected keys where static allow-lists fail to distinguish between safe metrics and private customer parameters.

**Feature 1 introduces an Intelligent Privacy Segregation & Shannon Entropy ML Classifier** running locally on the Tier 1 collector. It calculates real-time information density in bits/character, intercepts keyword-less secrets, and dynamically segregates telemetry fields into local-retained storage versus SaaS-eligible egress metadata.

---

## 2. Mathematical & Theoretical Foundation

### 2.1 Shannon Information Entropy Formulation
Information entropy quantifies the uncertainty or randomness of a sequence of characters. For a given string $S$, its Shannon Entropy $H(S)$ is defined as:

$$H(S) = -\sum_{i=1}^{n} P(c_i) \log_2 P(c_i)$$

Where:
* $n$ is the count of unique characters appearing in string $S$.
* $P(c_i) = \frac{\text{count}(c_i)}{|S|}$ is the empirical probability of character $c_i$ occurring in $S$.
* $\log_2$ measures information in **bits per character**.

### 2.2 Character Entropy Distribution & Thresholds

```
Entropy (bits/char)
  │
5.0 ├── High Entropy: Cryptographic Keys, Random Tokens (H >= 3.65 - 4.50)
    │   [Examples: "8f9b4c12d9e03fa57b21e84c90d2", Base64 tokens]  ==> QUARANTINED & REDACTED
    │
3.5 ├── Boundary Zone: Hex strings, complex paths
    │
2.5 ├── Low Entropy: Natural Language & Service Names (H < 3.20)
    │   [Examples: "checkout-api", "database connection timeout"]  ==> SAFE FOR LOCAL PROCESSING
    │
0.0 └── Monotonous: Repeated characters ("aaaaaaaa")
```

* **Natural Text & System Identifiers:** Exhibit lower entropy ($H < 3.20\text{ bits/char}$) because human languages and standard identifiers reuse a restricted set of vowels and predictable syllables.
* **Cryptographic Tokens & Raw Credentials:** Exhibit high entropy ($H \ge 3.65\text{ bits/char}$) due to pseudo-random uniform character distributions designed to maximize key search space.

---

## 3. Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ TIER 1: CUSTOMER LOCAL ENVIRONMENT (Collector Edge)                                      │
│                                                                                         │
│  [ Incoming Raw Telemetry / Log Line ]                                                  │
│                    │                                                                    │
│                    ▼                                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐                  │
│  │ 1. Regex DLP Baseline Filter (Known formats: JWT, AWS, PAN, PII)  │                  │
│  └─────────────────────────────────┬─────────────────────────────────┘                  │
│                                    │                                                    │
│                                    ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐                  │
│  │ 2. Shannon Entropy ML Classifier                                  │                  │
│  │    - Extract candidate tokens (len >= 16)                         │                  │
│  │    - Bypass known non-secrets (UUIDs, timestamps, pseudonyms)     │                  │
│  │    - Compute H(S) -> If H >= 3.65 bits/char:                      │                  │
│  │        Replace with [REDACTED:high_entropy_secret]                │                  │
│  │        Trigger security finding: "high_entropy_secret"            │                  │
│  └─────────────────────────────────┬─────────────────────────────────┘                  │
│                                    │                                                    │
│                                    ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐                  │
│  │ 3. Intelligent Telemetry Segregator (segregate_telemetry)          │                  │
│  │    - Classifies record: SAFE_METADATA vs SENSITIVE_QUARANTINED    │                  │
│  └───────────────┬───────────────────────────────────┬───────────────┘                  │
│                  │                                   │                                  │
│                  ▼                                   ▼                                  │
│  ┌───────────────────────────────┐   ┌───────────────────────────────┐                  │
│  │ local_retained Store (SQLite) │   │ saas_eligible Egress Buffer   │                  │
│  │ - Raw payload & parameters    │   │ - Anonymized metric summaries │                  │
│  │ - Full audit trail            │   │ - Timestamp (UTC)             │                  │
│  │ - Stays 100% on premises      │   │ - Pseudonymous ID (src-xxxx)  │                  │
│  └───────────────────────────────┘   └───────────────┬───────────────┘                  │
└──────────────────────────────────────────────────────┼──────────────────────────────────┘
                                                       │  TLS 1.2+ / HMAC Signed
                                                       ▼  (Metadata Only)
                                       ┌───────────────────────────────┐
                                       │ TIER 2: CENTRAL SAAS PLATFORM │
                                       └───────────────────────────────┘
```

---

## 4. Complete Implementation Code

### 4.1 In `common/policy.py`

```python
import math
import re
from collections import Counter

# Register high_entropy_secret under credential material to alert Tier 1
CREDENTIAL_TYPES = {
    "private_key", "jwt", "bearer", "aws_key", "api_key",
    "kv_secret", "url_creds", "high_entropy_secret"
}

def shannon_entropy(s: str) -> float:
    """Calculate the Shannon Entropy of string s in bits per character."""
    if not s or len(s) < 2:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())

_ENTROPY_TOKEN_RX = re.compile(r"\b[A-Za-z0-9+/=_-]{16,}\b")
_UUID_RX = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

def _scrub_high_entropy(text: str):
    """Scans for unlabelled high-entropy secrets and scrubs them."""
    findings = []
    def repl(m):
        token = m.group(0)
        # Skip UUIDs, pseudonymous source IDs, collector IDs, and existing tags
        if "REDACTED" in token or token.startswith("src-") or token.startswith("col-") or token.startswith("fp-"):
            return token
        if _UUID_RX.search(token):
            return token
        
        h = shannon_entropy(token)
        has_digit = any(c.isdigit() for c in token)
        has_alpha = any(c.isalpha() for c in token)
        
        # High entropy decision boundary:
        # 1. Mixed alphanumeric token with len >= 16 and entropy >= 3.65
        # 2. Long pseudo-random token with len >= 24 and entropy >= 3.90
        if (has_digit and has_alpha and len(token) >= 16 and h >= 3.65) or (len(token) >= 24 and h >= 3.90):
            findings.append("high_entropy_secret")
            return "[REDACTED:high_entropy_secret]"
        return token

    out = _ENTROPY_TOKEN_RX.sub(repl, text)
    return out, findings

def redact_text(text: str):
    """Full DLP redaction pipeline combining regex patterns and Shannon entropy."""
    findings = []
    out = text
    # 1. Regex scrub (known keywords, PAN, PII, AWS keys)
    for name, rx, repl in SECRET_PATTERNS:
        out, n = rx.subn(repl, out)
        if n:
            findings.extend([name] * n)
    
    # 2. ML Shannon Entropy scrub (unlabelled raw secrets)
    out, entropy_findings = _scrub_high_entropy(out)
    if entropy_findings:
        findings.extend(entropy_findings)
        
    return out, findings

def segregate_telemetry(record: dict) -> dict:
    """Intelligently segregate incoming telemetry into what can egress to SaaS
    vs what must be retained locally in Tier 1.
    
    Returns a dict with:
      - 'saas_eligible': scrubbed operational metrics, timestamps, and aggregate counts
      - 'local_retained': raw logs, sensitive parameters, or high-entropy fields
      - 'classification': 'SAFE_METADATA' or 'SENSITIVE_QUARANTINED'
    """
    local_retained = {}
    saas_eligible = {}
    is_sensitive = False

    for k, v in record.items():
        k_lower = str(k).lower()
        if any(s in k_lower for s in ("password", "secret", "token", "auth", "query", "payload", "raw")):
            local_retained[k] = v
            is_sensitive = True
        elif isinstance(v, str):
            redacted, findings = redact_text(v)
            if findings:
                local_retained[k] = v
                saas_eligible[k] = redacted
                is_sensitive = True
            elif len(v) > 120 or shannon_entropy(v) > 4.2:
                local_retained[k] = v
                is_sensitive = True
            else:
                saas_eligible[k] = v
        elif isinstance(v, (int, float, bool)):
            saas_eligible[k] = v
        else:
            local_retained[k] = v

    return {
        "saas_eligible": saas_eligible,
        "local_retained": local_retained,
        "classification": "SENSITIVE_QUARANTINED" if is_sensitive else "SAFE_METADATA"
    }
```

---

## 5. Verification & Test Suite (`tests/test_policy.py`)

Run the automated test case:
```powershell
python -m unittest tests.test_policy.PrivacyMLSegregation
```

### Test Assertions:
1. **Unlabelled Hex Secret:** `connecting with token 8f9b4c12d9e03fa57b21e84c90d2` is redacted to `[REDACTED:high_entropy_secret]` and emits the security finding.
2. **Telemetry Segregation:**
   * `cpu_pct: 82.5` and `timestamp` route to `saas_eligible`.
   * `SELECT * FROM users WHERE email='alice@corp.com'` routes to `local_retained`.
   * Overall classification is confirmed as `SENSITIVE_QUARANTINED`.

---

## 6. Live Hackathon Evaluation Walkthrough

When presenting to judges:

1. **Open the Local Collector Console:** Navigate to `http://127.0.0.1:9101` (Acme Bangalore DC).
2. **Inject Unlabelled Secret Telemetry:**
   ```json
   {"service": "orders-db", "log": "DB handshake completed using 7f3a9e1c2b5d408f6a1e3c5b"}
   ```
3. **Show Egress Proof Panel:**
   * Point to the **Left Panel (Tier 1 Raw Storage):** Shows the full line with token stored on disk locally.
   * Point to the **Right Panel (Egress Outbound):** Shows `DB handshake completed using [REDACTED:high_entropy_secret]`.
4. **Answer the Judge's Question:**
   * *Judge:* *"How do you catch secrets if the developer didn't write `password=` in front of it?"*
   * *Answer:* *"Our collector runs an online Shannon Entropy classifier in Tier 1. It calculates character uncertainty in real-time. Any unlabelled token exceeding 3.65 bits/char is classified as an encryption key or token and automatically redacted before leaving the perimeter."*
