"""Argument redaction and canonical digests.

Redaction is ON by default: the inline copy of tool/prompt arguments has
sensitive values replaced with "[REDACTED]" before it ever reaches an
exporter. A SHA-256 digest of the canonical JSON encoding of the ORIGINAL
arguments is always recorded, so two records can still be correlated (and
tampering detected) without storing the sensitive payload.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern, Tuple

REDACTED = "[REDACTED]"

# Key-name deny list. A key matches when its normalized form (lowercase,
# "-"/"_" removed) contains one of these substrings.
DEFAULT_SENSITIVE_KEY_PARTS: Tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "authorization",
    "credential",
    "privatekey",
    "accesskey",
    "sessionkey",
    "cookie",
)

# Keys that match exactly (after normalization) even though they are short.
DEFAULT_SENSITIVE_KEY_EXACT: Tuple[str, ...] = ("auth", "ssn", "pin", "otp")

# Value patterns treated as secrets regardless of the key they appear under:
# JWTs, AWS access key ids, GitHub tokens, OpenAI-style keys, Bearer values.
DEFAULT_SENSITIVE_VALUE_PATTERNS: Tuple[Pattern[str], ...] = (
    re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}$"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"^Bearer\s+\S+$", re.IGNORECASE),
)


@dataclass
class RedactionPolicy:
    """Redaction configuration accepted by AuditLogger.

    mode:
      omit   -- no inline copy at all, digest only.
      redact -- inline copy with sensitive values replaced (default).
      raw    -- inline copy unchanged. Only for closed environments.
    """

    mode: str = "redact"
    extra_sensitive_keys: List[str] = field(default_factory=list)
    extra_value_patterns: List[Pattern[str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in ("omit", "redact", "raw"):
            raise ValueError(f"invalid redaction mode: {self.mode!r}")


def _normalize_key(key: str) -> str:
    return key.lower().replace("-", "").replace("_", "")


def _is_sensitive_key(key: str, extra_parts: List[str]) -> bool:
    norm = _normalize_key(key)
    if norm in DEFAULT_SENSITIVE_KEY_EXACT:
        return True
    for part in DEFAULT_SENSITIVE_KEY_PARTS:
        if part in norm:
            return True
    for part in extra_parts:
        if _normalize_key(part) in norm:
            return True
    return False


def _is_sensitive_value(value: str, extra_patterns: List[Pattern[str]]) -> bool:
    for pattern in DEFAULT_SENSITIVE_VALUE_PATTERNS:
        if pattern.search(value):
            return True
    for pattern in extra_patterns:
        if pattern.search(value):
            return True
    return False


def _redact_value(value: Any, path: str, policy: RedactionPolicy, redacted_keys: List[str]) -> Any:
    if isinstance(value, str):
        if _is_sensitive_value(value, policy.extra_value_patterns):
            redacted_keys.append(path)
            return REDACTED
        return value
    if isinstance(value, list):
        return [
            _redact_value(item, f"{path}[{i}]", policy, redacted_keys)
            for i, item in enumerate(value)
        ]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, child in value.items():
            child_path = key if path == "" else f"{path}.{key}"
            if _is_sensitive_key(str(key), policy.extra_sensitive_keys) and child is not None:
                redacted_keys.append(child_path)
                out[key] = REDACTED
            else:
                out[key] = _redact_value(child, child_path, policy, redacted_keys)
        return out
    return value


def redact_arguments(
    args: Optional[Dict[str, Any]], policy: Optional[RedactionPolicy] = None
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Apply a redaction policy; returns (redacted_copy, redacted_key_paths)."""
    if args is None:
        return None, []
    policy = policy or RedactionPolicy()
    redacted_keys: List[str] = []
    redacted = _redact_value(args, "", policy, redacted_keys)
    return redacted, redacted_keys


def canonical_json(value: Any) -> str:
    """Canonical JSON: sorted keys, no insignificant whitespace, UTF-8.

    Matches the TypeScript SDK's canonicalJson for the JSON subset both
    languages produce.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_arguments(
    args: Optional[Dict[str, Any]], redacted_keys: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Compute the integrity digest of the original (pre-redaction) arguments."""
    canonical = canonical_json(args if args is not None else None)
    raw = canonical.encode("utf-8")
    digest: Dict[str, Any] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "byte_length": len(raw),
    }
    if redacted_keys:
        digest["redacted_keys"] = list(redacted_keys)
    return digest
