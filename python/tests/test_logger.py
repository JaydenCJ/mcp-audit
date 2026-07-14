"""AuditLogger behaviour: event structure, spans, decorator, resilience."""

import unittest
from typing import Any, Dict, List

from mcp_audit import AuditLogger, RedactionPolicy, REDACTED
from tests.validator import validate_event


class CollectExporter:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def export(self, events: List[Dict[str, Any]]) -> None:
        self.events.extend(events)

    def by_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [event for event in self.events if event["event_type"] == event_type]


def make_logger(**kwargs: Any):
    sink = CollectExporter()
    logger = AuditLogger(
        server_name="logger-test",
        server_version="0.1.0",
        transport="stdio",
        exporters=[sink],
        **kwargs,
    )
    return logger, sink


class LifecycleTest(unittest.TestCase):
    def test_session_start_and_end_are_valid(self) -> None:
        logger, sink = make_logger()
        logger.session_start(client_name="client", client_version="1.0")
        logger.session_end()
        self.assertEqual(len(sink.events), 2)
        for event in sink.events:
            self.assertEqual(validate_event(event), [])
        start, end = sink.events
        self.assertEqual(start["client"], {"name": "client", "version": "1.0"})
        self.assertEqual(start["session_id"], end["session_id"])
        self.assertGreaterEqual(end["duration_ms"], 0)

    def test_record_error(self) -> None:
        logger, sink = make_logger()
        event = logger.record_error("transport failure", code=-32000)
        self.assertEqual(validate_event(event), [])
        self.assertEqual(event["outcome"]["error"], {"message": "transport failure", "code": -32000})


class ToolCallTest(unittest.TestCase):
    def test_success_span_with_redaction(self) -> None:
        logger, sink = make_logger()
        with logger.tool_call("search", {"query": "hi", "password": "hunter2"}):
            pass
        (event,) = sink.by_type("tool_call")
        self.assertEqual(validate_event(event), [])
        self.assertEqual(event["outcome"], {"status": "success"})
        self.assertEqual(event["tool"]["arguments"], {"query": "hi", "password": REDACTED})
        self.assertEqual(event["tool"]["arguments_digest"]["redacted_keys"], ["password"])
        self.assertGreaterEqual(event["duration_ms"], 0)

    def test_exception_records_error_and_reraises(self) -> None:
        logger, sink = make_logger()
        with self.assertRaises(RuntimeError):
            with logger.tool_call("search", {"query": "x"}):
                raise RuntimeError("backend unavailable")
        (event,) = sink.by_type("tool_call")
        self.assertEqual(validate_event(event), [])
        self.assertEqual(event["outcome"]["status"], "error")
        self.assertEqual(event["outcome"]["error"]["message"], "backend unavailable")

    def test_traceparent_propagates_from_request(self) -> None:
        logger, sink = make_logger()
        parent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        with logger.tool_call("search", {}, traceparent=parent, tracestate="vendor=1"):
            pass
        (event,) = sink.by_type("tool_call")
        self.assertTrue(event["traceparent"].startswith("00-0af7651916cd43dd8448eb211c80319c-"))
        self.assertNotIn("b7ad6b7169203331", event["traceparent"])
        self.assertEqual(event["tracestate"], "vendor=1")

    def test_redaction_modes(self) -> None:
        for mode, expect_inline in (("omit", False), ("redact", True), ("raw", True)):
            logger, sink = make_logger(redaction=RedactionPolicy(mode=mode))
            with logger.tool_call("t", {"password": "x"}):
                pass
            (event,) = sink.by_type("tool_call")
            self.assertEqual(validate_event(event), [], msg=mode)
            if not expect_inline:
                self.assertNotIn("arguments", event["tool"])
            elif mode == "raw":
                self.assertEqual(event["tool"]["arguments"], {"password": "x"})
            else:
                self.assertEqual(event["tool"]["arguments"], {"password": REDACTED})


class OtherOperationsTest(unittest.TestCase):
    def test_resource_read(self) -> None:
        logger, sink = make_logger()
        with logger.resource_read("file:///tmp/a.txt", name="a"):
            pass
        (event,) = sink.by_type("resource_read")
        self.assertEqual(validate_event(event), [])
        self.assertEqual(event["resource"], {"uri": "file:///tmp/a.txt", "name": "a"})

    def test_prompt_invoke(self) -> None:
        logger, sink = make_logger()
        with logger.prompt_invoke("summarize", {"style": "short"}):
            pass
        (event,) = sink.by_type("prompt_invoke")
        self.assertEqual(validate_event(event), [])
        self.assertEqual(event["prompt"]["name"], "summarize")


class AuditedToolDecoratorTest(unittest.TestCase):
    def test_decorator_captures_named_arguments(self) -> None:
        logger, sink = make_logger()

        @logger.audited_tool("lookup_order")
        def lookup_order(order_id: str, api_key: str) -> str:
            return f"order {order_id}"

        result = lookup_order("42", api_key="sk-abcdefghijklmnopqrstuvwx")
        self.assertEqual(result, "order 42")
        (event,) = sink.by_type("tool_call")
        self.assertEqual(validate_event(event), [])
        self.assertEqual(event["tool"]["name"], "lookup_order")
        self.assertEqual(event["tool"]["arguments"], {"order_id": "42", "api_key": REDACTED})

    def test_decorator_records_exceptions(self) -> None:
        logger, sink = make_logger()

        @logger.audited_tool()
        def flaky() -> None:
            raise ValueError("nope")

        with self.assertRaises(ValueError):
            flaky()
        (event,) = sink.by_type("tool_call")
        self.assertEqual(event["tool"]["name"], "flaky")
        self.assertEqual(event["outcome"]["status"], "error")


class ResilienceTest(unittest.TestCase):
    def test_failing_exporter_never_breaks_the_tool_path(self) -> None:
        failures: List[BaseException] = []

        class ThrowingExporter:
            def export(self, events: List[Dict[str, Any]]) -> None:
                raise ConnectionError("sink offline")

        sink = CollectExporter()
        logger = AuditLogger(
            server_name="resilient",
            exporters=[ThrowingExporter(), sink],
            on_export_error=lambda error, exporter: failures.append(error),
        )
        with logger.tool_call("ping", {}):
            pass
        self.assertEqual(len(sink.by_type("tool_call")), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ConnectionError)

    def test_invalid_transport_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AuditLogger(server_name="x", transport="carrier-pigeon")


if __name__ == "__main__":
    unittest.main()
