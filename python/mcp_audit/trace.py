"""Minimal W3C Trace Context (traceparent) support, aligned with SEP-414.

When an MCP request carries a ``traceparent`` in its ``_meta``, audit events
continue that trace; otherwise the audit layer starts a new one.
"""

from __future__ import annotations

import re
import secrets
from typing import NamedTuple, Optional

_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


class TraceContext(NamedTuple):
    """Parsed form of a traceparent header value."""

    trace_id: str
    span_id: str
    flags: str


def parse_traceparent(value: str) -> Optional[TraceContext]:
    """Parse a traceparent value. Returns None for malformed or all-zero ids."""
    match = _TRACEPARENT_RE.match(value or "")
    if not match:
        return None
    trace_id, span_id, flags = match.groups()
    if trace_id == "0" * 32 or span_id == "0" * 16:
        return None
    return TraceContext(trace_id, span_id, flags)


def _random_hex(num_bytes: int) -> str:
    value = secrets.token_hex(num_bytes)
    # The spec forbids all-zero trace/span ids; regenerate in that edge case.
    while set(value) == {"0"}:
        value = secrets.token_hex(num_bytes)
    return value


def generate_traceparent() -> str:
    """Generate a new root traceparent (sampled)."""
    return f"00-{_random_hex(16)}-{_random_hex(8)}-01"


def child_traceparent(parent: str) -> str:
    """Derive a child traceparent: same trace-id and flags, fresh span-id.

    Falls back to a new root when the parent value is malformed.
    """
    ctx = parse_traceparent(parent)
    if ctx is None:
        return generate_traceparent()
    return f"00-{ctx.trace_id}-{_random_hex(8)}-{ctx.flags}"


def is_valid_traceparent(value: str) -> bool:
    """True when the value is a well-formed, non-zero traceparent."""
    return parse_traceparent(value) is not None
