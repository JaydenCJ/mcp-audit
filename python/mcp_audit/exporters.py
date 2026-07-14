"""Exporters: console, JSONL file, OTLP/HTTP, Splunk HEC, Datadog.

HTTP delivery uses urllib from the standard library. Requests are only made
when an event is exported -- importing this module has no side effects.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from .trace import parse_traceparent


class AuditExporter(Protocol):
    """Destination for audit events (structural interface)."""

    def export(self, events: List[Dict[str, Any]]) -> None:
        """Deliver a batch of events."""

    # shutdown() is optional; AuditLogger calls it when present.


def _http_post(url: str, headers: Dict[str, str], body: bytes, timeout: float) -> None:
    """POST a payload; raises on network failure or non-2xx status."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (caller controls URL)
        status = getattr(response, "status", 200)
        if status < 200 or status >= 300:
            raise RuntimeError(f"HTTP {status} from {url}")
        response.read()


def _epoch_seconds(timestamp: str) -> float:
    parsed = datetime.strptime(timestamp[:23].rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f") if "." in timestamp else datetime.strptime(
        timestamp.rstrip("Z"), "%Y-%m-%dT%H:%M:%S"
    )
    return parsed.replace(tzinfo=timezone.utc).timestamp()


class ConsoleExporter:
    """One JSON line per event, written to stderr by default.

    stderr matters for stdio MCP servers, where stdout carries the JSON-RPC
    protocol stream and must stay clean.
    """

    def __init__(self, stream: Any = None, prefix: str = "[mcp-audit] ") -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._prefix = prefix

    def export(self, events: List[Dict[str, Any]]) -> None:
        for event in events:
            self._stream.write(f"{self._prefix}{json.dumps(event, ensure_ascii=False)}\n")


class JsonlExporter:
    """Appends one JSON event per line; tail the file with any log shipper."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._dir_ensured = False

    def export(self, events: List[Dict[str, Any]]) -> None:
        if not self._dir_ensured:
            parent = os.path.dirname(os.path.abspath(self._path))
            os.makedirs(parent, exist_ok=True)
            self._dir_ensured = True
        with open(self._path, "a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def _otlp_attr(key: str, value: Any) -> Dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def to_otlp_logs_payload(events: List[Dict[str, Any]], service_name: Optional[str] = None) -> Dict[str, Any]:
    """Build the OTLP/JSON logs payload for a batch (exposed for tests)."""
    records = []
    for event in events:
        is_error = event.get("outcome", {}).get("status") == "error"
        attributes = [
            _otlp_attr("event.name", f"mcp.audit.{event['event_type']}"),
            _otlp_attr("mcp.session.id", event["session_id"]),
            _otlp_attr("mcp.server.name", event["server"]["name"]),
            _otlp_attr("mcp.outcome.status", event["outcome"]["status"]),
        ]
        if "tool" in event:
            attributes.append(_otlp_attr("mcp.tool.name", event["tool"]["name"]))
        if "resource" in event:
            attributes.append(_otlp_attr("mcp.resource.uri", event["resource"]["uri"]))
        if "prompt" in event:
            attributes.append(_otlp_attr("mcp.prompt.name", event["prompt"]["name"]))
        if "duration_ms" in event:
            attributes.append(_otlp_attr("mcp.duration_ms", float(event["duration_ms"])))
        record: Dict[str, Any] = {
            "timeUnixNano": str(int(_epoch_seconds(event["timestamp"]) * 1e9)),
            "severityNumber": 17 if is_error else 9,
            "severityText": "ERROR" if is_error else "INFO",
            "body": {"stringValue": json.dumps(event, ensure_ascii=False)},
            "attributes": attributes,
        }
        trace = parse_traceparent(event.get("traceparent", ""))
        if trace is not None:
            record["traceId"] = trace.trace_id
            record["spanId"] = trace.span_id
        records.append(record)
    resolved_service = service_name or (events[0]["server"]["name"] if events else "mcp-server")
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": [_otlp_attr("service.name", resolved_service)]},
                "scopeLogs": [
                    {
                        "scope": {"name": "mcp-audit", "version": "0.1.0"},
                        "logRecords": records,
                    }
                ],
            }
        ]
    }


class OtlpHttpExporter:
    """OTLP/HTTP logs exporter (JSON encoding). SPEC.md section 6 for mapping."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:4318/v1/logs",
        headers: Optional[Dict[str, str]] = None,
        service_name: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self._endpoint = endpoint
        self._headers = {"content-type": "application/json", **(headers or {})}
        self._service_name = service_name
        self._timeout = timeout

    def export(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            return
        payload = to_otlp_logs_payload(events, self._service_name)
        _http_post(self._endpoint, self._headers, json.dumps(payload).encode("utf-8"), self._timeout)


def to_hec_payload(
    events: List[Dict[str, Any]],
    source: str = "mcp-audit",
    sourcetype: str = "mcp:audit",
    index: Optional[str] = None,
    host: Optional[str] = None,
) -> str:
    """Build the newline-delimited Splunk HEC payload (exposed for tests)."""
    items = []
    for event in events:
        envelope: Dict[str, Any] = {
            "time": _epoch_seconds(event["timestamp"]),
            "source": source,
            "sourcetype": sourcetype,
            "event": event,
        }
        if index:
            envelope["index"] = index
        if host:
            envelope["host"] = host
        items.append(json.dumps(envelope, ensure_ascii=False))
    return "\n".join(items)


class SplunkHecExporter:
    """Splunk HTTP Event Collector exporter. SPEC.md section 6 for CIM mapping."""

    def __init__(
        self,
        url: str,
        token: str,
        source: str = "mcp-audit",
        sourcetype: str = "mcp:audit",
        index: Optional[str] = None,
        host: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self._url = url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._source = source
        self._sourcetype = sourcetype
        self._index = index
        self._host = host
        self._timeout = timeout

    def export(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            return
        body = to_hec_payload(events, self._source, self._sourcetype, self._index, self._host)
        headers = {
            "authorization": f"Splunk {self._token}",
            "content-type": "application/json",
        }
        _http_post(self._url, headers, body.encode("utf-8"), self._timeout)


def _lower64_decimal(hex_id: str) -> str:
    """Decimal form of the lower 64 bits, as Datadog APM correlation expects."""
    return str(int(hex_id[-16:], 16))


def to_datadog_payload(
    events: List[Dict[str, Any]],
    service: Optional[str] = None,
    ddtags: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build the Datadog logs intake v2 payload (exposed for tests)."""
    items = []
    for event in events:
        is_error = event.get("outcome", {}).get("status") == "error"
        item: Dict[str, Any] = {
            "ddsource": "mcp-audit",
            "service": service or event["server"]["name"],
            "message": json.dumps(event, ensure_ascii=False),
            "status": "error" if is_error else "info",
            "evt": {"name": f"mcp.audit.{event['event_type']}"},
            "mcp": {"session_id": event["session_id"]},
        }
        if ddtags:
            item["ddtags"] = ddtags
        if "tool" in event:
            item["mcp"]["tool_name"] = event["tool"]["name"]
        if "duration_ms" in event:
            item["mcp"]["duration_ms"] = event["duration_ms"]
        trace = parse_traceparent(event.get("traceparent", ""))
        if trace is not None:
            item["dd"] = {
                "trace_id": _lower64_decimal(trace.trace_id),
                "span_id": _lower64_decimal(trace.span_id),
            }
        items.append(item)
    return items


class DatadogExporter:
    """Datadog Logs exporter (HTTP intake v2). SPEC.md section 6 for mapping."""

    def __init__(
        self,
        api_key: str,
        site: str = "datadoghq.com",
        url: Optional[str] = None,
        service: Optional[str] = None,
        ddtags: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self._url = url or f"https://http-intake.logs.{site}/api/v2/logs"
        self._api_key = api_key
        self._service = service
        self._ddtags = ddtags
        self._timeout = timeout

    def export(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            return
        payload = to_datadog_payload(events, self._service, self._ddtags)
        headers = {"dd-api-key": self._api_key, "content-type": "application/json"}
        _http_post(self._url, headers, json.dumps(payload).encode("utf-8"), self._timeout)
