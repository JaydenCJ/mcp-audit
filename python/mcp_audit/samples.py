"""Emit one sample audit event of every type as JSON lines on stdout.

Used by the cross-language conformance test and the smoke script: events
produced here must validate against schema/audit-event.schema.json, the same
schema the TypeScript SDK is tested against.

Run: python3 -m mcp_audit.samples
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from .logger import AuditLogger


class _CollectExporter:
    """Test exporter that collects events in memory."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def export(self, events: List[Dict[str, Any]]) -> None:
        self.events.extend(events)


def build_sample_events() -> List[Dict[str, Any]]:
    """Produce one realistic event per event_type through the public API."""
    collector = _CollectExporter()
    audit = AuditLogger(
        server_name="sample-server",
        server_version="0.1.0",
        transport="stdio",
        exporters=[collector],
    )
    audit.session_start(client_name="sample-client", client_version="1.0.0")
    with audit.tool_call(
        "lookup_order",
        {"order_id": "42", "api_key": "sk-abcdefghijklmnopqrstuvwx"},
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
    ):
        pass
    with audit.resource_read("file:///etc/motd", name="motd"):
        pass
    with audit.prompt_invoke("summarize", {"style": "short"}):
        pass
    try:
        with audit.tool_call("lookup_order", {"order_id": "missing"}):
            raise LookupError("order not found")
    except LookupError:
        pass
    audit.record_error("client disconnected mid-request", code=-32000)
    audit.session_end()
    return collector.events


def main() -> int:
    for event in build_sample_events():
        sys.stdout.write(json.dumps(event, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
