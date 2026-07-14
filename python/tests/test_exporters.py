"""Exporter tests against a local mock HTTP receiver on 127.0.0.1.

Every HTTP exporter posts to a stdlib http.server instance; the test then
asserts headers and validates the audit event embedded in the request body
with the structural validator (the authoritative JSON Schema check for
Python-produced events runs in ts/tests/cross-language.test.ts via ajv).
"""

import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List

from mcp_audit import (
    AuditLogger,
    ConsoleExporter,
    DatadogExporter,
    JsonlExporter,
    OtlpHttpExporter,
    SplunkHecExporter,
)
from tests.validator import validate_event


def sample_events() -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []

    class Collect:
        def export(self, events: List[Dict[str, Any]]) -> None:
            collected.extend(events)

    logger = AuditLogger(
        server_name="exporter-test",
        server_version="0.1.0",
        transport="stdio",
        exporters=[Collect()],
    )
    logger.session_start(client_name="c", client_version="1")
    with logger.tool_call("echo", {"text": "hi", "token": "secret"}):
        pass
    try:
        with logger.tool_call("echo", {}):
            raise RuntimeError("kaput")
    except RuntimeError:
        pass
    return collected


class _Handler(BaseHTTPRequestHandler):
    captured: List[Dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        _Handler.captured.append(
            {
                "path": self.path,
                # urllib capitalizes header names; normalize for assertions.
                "headers": {key.lower(): value for key, value in self.headers.items()},
                "body": body,
            }
        )
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # keep test output clean


class HttpExporterTest(unittest.TestCase):
    server: HTTPServer
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        _Handler.captured = []

    def test_otlp_exporter(self) -> None:
        events = sample_events()
        OtlpHttpExporter(endpoint=f"{self.base_url}/v1/logs").export(events)
        (request,) = _Handler.captured
        self.assertEqual(request["path"], "/v1/logs")
        self.assertEqual(request["headers"].get("content-type"), "application/json")
        payload = json.loads(request["body"])
        records = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        self.assertEqual(len(records), len(events))
        for i, record in enumerate(records):
            embedded = json.loads(record["body"]["stringValue"])
            self.assertEqual(validate_event(embedded), [])
            self.assertEqual(embedded["event_id"], events[i]["event_id"])
            self.assertRegex(record["traceId"], r"^[0-9a-f]{32}$")
            self.assertRegex(record["timeUnixNano"], r"^\d+$")
        self.assertEqual(records[2]["severityText"], "ERROR")

    def test_splunk_hec_exporter(self) -> None:
        events = sample_events()
        SplunkHecExporter(url=self.base_url, token="test-hec-token", index="mcp").export(events)
        (request,) = _Handler.captured
        self.assertEqual(request["path"], "/services/collector/event")
        self.assertEqual(request["headers"].get("authorization"), "Splunk test-hec-token")
        envelopes = [json.loads(line) for line in request["body"].split("\n")]
        self.assertEqual(len(envelopes), len(events))
        for i, envelope in enumerate(envelopes):
            self.assertEqual(validate_event(envelope["event"]), [])
            self.assertEqual(envelope["event"]["event_id"], events[i]["event_id"])
            self.assertEqual(envelope["sourcetype"], "mcp:audit")
            self.assertEqual(envelope["index"], "mcp")
            self.assertIsInstance(envelope["time"], float)

    def test_datadog_exporter(self) -> None:
        events = sample_events()
        DatadogExporter(
            api_key="test-dd-key", url=f"{self.base_url}/api/v2/logs", ddtags="env:test"
        ).export(events)
        (request,) = _Handler.captured
        self.assertEqual(request["path"], "/api/v2/logs")
        self.assertEqual(request["headers"].get("dd-api-key"), "test-dd-key")
        items = json.loads(request["body"])
        self.assertEqual(len(items), len(events))
        for i, item in enumerate(items):
            embedded = json.loads(item["message"])
            self.assertEqual(validate_event(embedded), [])
            self.assertEqual(embedded["event_id"], events[i]["event_id"])
            self.assertEqual(item["ddsource"], "mcp-audit")
            self.assertRegex(item["dd"]["trace_id"], r"^\d+$")
        self.assertEqual(items[2]["status"], "error")
        self.assertEqual(items[1]["mcp"]["tool_name"], "echo")

    def test_http_error_is_isolated_by_the_logger(self) -> None:
        failures: List[BaseException] = []
        logger = AuditLogger(
            server_name="unreachable",
            # Nothing listens on this port of the loopback interface.
            exporters=[OtlpHttpExporter(endpoint="http://127.0.0.1:9/v1/logs", timeout=0.5)],
            on_export_error=lambda error, exporter: failures.append(error),
        )
        with logger.tool_call("ping", {}):
            pass
        self.assertEqual(len(failures), 1)


class FileAndConsoleExporterTest(unittest.TestCase):
    def test_jsonl_exporter_appends_valid_lines(self) -> None:
        events = sample_events()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "audit.jsonl")
            exporter = JsonlExporter(path)
            exporter.export(events)
            exporter.export(events[:1])
            with open(path, encoding="utf-8") as handle:
                lines = [line for line in handle.read().splitlines() if line]
        self.assertEqual(len(lines), len(events) + 1)
        for line in lines:
            self.assertEqual(validate_event(json.loads(line)), [])

    def test_console_exporter_writes_prefixed_lines(self) -> None:
        events = sample_events()
        buffer = io.StringIO()
        ConsoleExporter(stream=buffer).export(events)
        lines = [line for line in buffer.getvalue().splitlines() if line]
        self.assertEqual(len(lines), len(events))
        for line in lines:
            self.assertTrue(line.startswith("[mcp-audit] "))
            self.assertEqual(validate_event(json.loads(line[len("[mcp-audit] "):])), [])


class ReadmeSnippetTest(unittest.TestCase):
    def test_python_readme_snippet_works_as_documented(self) -> None:
        # Mirrors the snippet in python/README.md and the root README.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            audit = AuditLogger(
                server_name="demo",
                server_version="1.0.0",
                exporters=[JsonlExporter(path)],
            )

            @audit.audited_tool("lookup_order")
            def lookup_order(order_id: str, api_key: str) -> str:
                return f"order {order_id}: shipped"

            result = lookup_order(order_id="42", api_key="sk-secret-value-1234567890")
            self.assertEqual(result, "order 42: shipped")
            with open(path, encoding="utf-8") as handle:
                events = [json.loads(line) for line in handle if line.strip()]
        (event,) = events
        self.assertEqual(validate_event(event), [])
        self.assertEqual(event["tool"]["arguments"]["api_key"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
