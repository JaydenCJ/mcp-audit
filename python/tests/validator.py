"""Structural validator used by the Python tests.

This mirrors the load-bearing constraints of schema/audit-event.schema.json
using only the standard library. The authoritative validation of Python
events against the actual JSON Schema happens in the TypeScript test suite
(ts/tests/cross-language.test.ts), which feeds `python3 -m mcp_audit.samples`
output through ajv.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TRACEPARENT_RE = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_EVENT_TYPES = {
    "tool_call",
    "resource_read",
    "prompt_invoke",
    "session_start",
    "session_end",
    "error",
}

_TOP_LEVEL_KEYS = {
    "spec_version",
    "event_id",
    "event_type",
    "timestamp",
    "traceparent",
    "tracestate",
    "session_id",
    "server",
    "client",
    "principal",
    "tool",
    "resource",
    "prompt",
    "outcome",
    "duration_ms",
    "attributes",
}


def validate_event(event: Dict[str, Any]) -> List[str]:
    """Return a list of constraint violations (empty = structurally valid)."""
    errors: List[str] = []

    for key in ("spec_version", "event_id", "event_type", "timestamp", "traceparent", "session_id", "server", "outcome"):
        if key not in event:
            errors.append(f"missing required field: {key}")
    for key in event:
        if key not in _TOP_LEVEL_KEYS:
            errors.append(f"unknown top-level field: {key}")
    if errors:
        return errors

    if event["spec_version"] != "0.1":
        errors.append(f"bad spec_version: {event['spec_version']!r}")
    if not _UUID_RE.match(str(event["event_id"])):
        errors.append(f"bad event_id: {event['event_id']!r}")
    if event["event_type"] not in _EVENT_TYPES:
        errors.append(f"bad event_type: {event['event_type']!r}")
    if not _TIMESTAMP_RE.match(str(event["timestamp"])):
        errors.append(f"bad timestamp: {event['timestamp']!r}")
    if not _TRACEPARENT_RE.match(str(event["traceparent"])):
        errors.append(f"bad traceparent: {event['traceparent']!r}")
    if not isinstance(event["server"], dict) or "name" not in event["server"]:
        errors.append("server.name is required")

    outcome = event["outcome"]
    if not isinstance(outcome, dict) or outcome.get("status") not in ("success", "error"):
        errors.append(f"bad outcome: {outcome!r}")
    elif outcome["status"] == "error" and "error" not in outcome:
        errors.append("outcome.status=error requires outcome.error")

    event_type = event["event_type"]
    if event_type == "tool_call":
        errors.extend(_check_operation(event, "tool", needs_digest=True))
    elif event_type == "resource_read":
        if "resource" not in event or "uri" not in event.get("resource", {}):
            errors.append("resource_read requires resource.uri")
        if "duration_ms" not in event:
            errors.append("resource_read requires duration_ms")
    elif event_type == "prompt_invoke":
        errors.extend(_check_operation(event, "prompt", needs_digest=True))
    return errors


def _check_operation(event: Dict[str, Any], key: str, needs_digest: bool) -> List[str]:
    errors: List[str] = []
    details = event.get(key)
    if not isinstance(details, dict) or "name" not in details:
        errors.append(f"{event['event_type']} requires {key}.name")
        return errors
    if "duration_ms" not in event:
        errors.append(f"{event['event_type']} requires duration_ms")
    if needs_digest:
        digest = details.get("arguments_digest")
        if not isinstance(digest, dict):
            errors.append(f"{key}.arguments_digest is required")
        else:
            if not _SHA256_RE.match(str(digest.get("sha256", ""))):
                errors.append(f"bad {key}.arguments_digest.sha256")
            if not isinstance(digest.get("byte_length"), int) or digest["byte_length"] < 0:
                errors.append(f"bad {key}.arguments_digest.byte_length")
    return errors
