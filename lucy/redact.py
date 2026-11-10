"""Secret patterns, redaction and the audit log. Everything logged goes through redact()."""
import json
import re
from datetime import datetime, timezone

from . import config

# (rule, severity, pattern). Shared by redaction and the built-in repo scanner.
RULES = [
    ("private-key", "critical", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
    ("aws-access-key", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "high", re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", "critical", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("api-secret-key", "high", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("public-env-secret", "high", re.compile(r"\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE)[A-Z0-9_]*")),
    ("url-credentials", "high", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]{4,}@")),
    ("assigned-secret", "medium", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|service[_-]?role[_-]?key)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9+/_\-.]{12,})")),
]


def redact(text):
    if not isinstance(text, str):
        return text
    for rule, _sev, pat in RULES:
        text = pat.sub(lambda m, r=rule: f"[REDACTED:{r}]", text)
    return text


def redact_obj(obj):
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(event, **fields):
    line = json.dumps(redact_obj({"at": now(), "event": event, **fields}), sort_keys=True)
    with open(config.home() / "audit.log", "a") as f:
        f.write(line + "\n")
