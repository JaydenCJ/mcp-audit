"""AuditLogger: builds spec-conformant audit events and fans them out.

Mirrors the TypeScript AuditLogger. Operations are recorded through context
managers (``with audit.tool_call(...)``) or the ``audited_tool`` decorator,
so success/failure and duration are captured automatically.
"""

from __future__ import annotations

import inspect
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .redact import RedactionPolicy, digest_arguments, redact_arguments
from .trace import child_traceparent, generate_traceparent, is_valid_traceparent

SPEC_VERSION = "0.1"

_OPERATION_DETAIL_KEY = {
    "tool_call": "tool",
    "prompt_invoke": "prompt",
    "resource_read": "resource",
}


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _default_export_error(error: BaseException, exporter: Any) -> None:
    name = type(exporter).__name__
    sys.stderr.write(f"[mcp-audit] export failed via {name}: {error}\n")


class AuditSpan:
    """An in-flight tool_call / resource_read / prompt_invoke operation.

    Used as a context manager: leaving the block normally records success,
    leaving via an exception records an error event and re-raises.
    """

    def __init__(
        self,
        logger: "AuditLogger",
        kind: str,
        details: Dict[str, Any],
        arguments: Optional[Dict[str, Any]],
        traceparent: str,
        tracestate: Optional[str],
        session_id: Optional[str],
    ) -> None:
        self._logger = logger
        self._kind = kind
        self._details = details
        self._arguments = arguments
        self.traceparent = traceparent
        self._tracestate = tracestate
        self._session_id = session_id
        self._started = time.monotonic()
        self._done = False

    def __enter__(self) -> "AuditSpan":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc is None:
            self.succeed()
        else:
            self.fail(message=str(exc), code=getattr(exc, "code", None))
        return False  # never swallow exceptions

    def succeed(self) -> None:
        """Record the operation as succeeded."""
        self._finish({"status": "success"})

    def fail(self, message: str, code: Optional[int] = None) -> None:
        """Record the operation as failed."""
        error: Dict[str, Any] = {"message": message[:1024]}
        if isinstance(code, int):
            error["code"] = code
        self._finish({"status": "error", "error": error})

    def _finish(self, outcome: Dict[str, Any]) -> None:
        if self._done:
            return
        self._done = True
        duration_ms = round((time.monotonic() - self._started) * 1000, 3)
        body = dict(self._details)
        if self._kind in ("tool_call", "prompt_invoke"):
            body.update(self._logger._capture_arguments(self._arguments))
        detail_key = _OPERATION_DETAIL_KEY[self._kind]
        self._logger._emit(
            event_type=self._kind,
            traceparent=self.traceparent,
            tracestate=self._tracestate,
            outcome=outcome,
            duration_ms=duration_ms,
            body={detail_key: body},
            session_id=self._session_id,
        )


class AuditLogger:
    """Builds audit events and dispatches them to the configured exporters.

    Export failures never propagate into the tool path: every exporter call
    is wrapped and routed to ``on_export_error`` (default: one line on
    stderr).
    """

    def __init__(
        self,
        server_name: str,
        server_version: Optional[str] = None,
        transport: Optional[str] = None,
        exporters: Optional[List[Any]] = None,
        redaction: Optional[RedactionPolicy] = None,
        on_export_error: Optional[Callable[[BaseException, Any], None]] = None,
        session_id: Optional[str] = None,
    ) -> None:
        self._server: Dict[str, Any] = {"name": server_name}
        if server_version is not None:
            self._server["version"] = server_version
        if transport is not None:
            if transport not in ("stdio", "streamable_http", "sse", "custom"):
                raise ValueError(f"invalid transport: {transport!r}")
            self._server["transport"] = transport
        self._exporters = list(exporters or [])
        self._redaction = redaction or RedactionPolicy()
        self._on_export_error = on_export_error or _default_export_error
        self._session_id = session_id or str(uuid.uuid4())
        self._session_traceparent = generate_traceparent()
        self._client: Optional[Dict[str, str]] = None
        self._session_started_at: Optional[float] = None

    @property
    def session_id(self) -> str:
        """The session id events are stamped with."""
        return self._session_id

    # -- lifecycle events ---------------------------------------------------

    def session_start(
        self,
        client_name: Optional[str] = None,
        client_version: Optional[str] = None,
        traceparent: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a session_start event; call when the MCP session initializes."""
        if session_id:
            self._session_id = session_id
        if client_name or client_version:
            self._client = {}
            if client_name:
                self._client["name"] = client_name
            if client_version:
                self._client["version"] = client_version
        if traceparent and is_valid_traceparent(traceparent):
            self._session_traceparent = traceparent
        self._session_started_at = time.monotonic()
        return self._emit(
            event_type="session_start",
            traceparent=self._resolve_traceparent(traceparent),
            tracestate=None,
            outcome={"status": "success"},
        )

    def session_end(self) -> Dict[str, Any]:
        """Record a session_end event; call when the MCP session closes."""
        duration = None
        if self._session_started_at is not None:
            duration = round((time.monotonic() - self._session_started_at) * 1000, 3)
        return self._emit(
            event_type="session_end",
            traceparent=self._resolve_traceparent(None),
            tracestate=None,
            outcome={"status": "success"},
            duration_ms=duration,
        )

    def record_error(self, message: str, code: Optional[int] = None) -> Dict[str, Any]:
        """Record a protocol-level error event not tied to one operation."""
        error: Dict[str, Any] = {"message": message[:1024]}
        if isinstance(code, int):
            error["code"] = code
        return self._emit(
            event_type="error",
            traceparent=self._resolve_traceparent(None),
            tracestate=None,
            outcome={"status": "error", "error": error},
        )

    # -- operations ---------------------------------------------------------

    def tool_call(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> AuditSpan:
        """Start timing a tool call. Use as a context manager."""
        return AuditSpan(
            self,
            "tool_call",
            {"name": name},
            arguments,
            self._resolve_traceparent(traceparent),
            tracestate if traceparent else None,
            session_id,
        )

    def resource_read(
        self,
        uri: str,
        name: Optional[str] = None,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> AuditSpan:
        """Start timing a resource read. Use as a context manager."""
        details: Dict[str, Any] = {"uri": uri}
        if name:
            details["name"] = name
        return AuditSpan(
            self,
            "resource_read",
            details,
            None,
            self._resolve_traceparent(traceparent),
            tracestate if traceparent else None,
            session_id,
        )

    def prompt_invoke(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> AuditSpan:
        """Start timing a prompt invocation. Use as a context manager."""
        return AuditSpan(
            self,
            "prompt_invoke",
            {"name": name},
            arguments,
            self._resolve_traceparent(traceparent),
            tracestate if traceparent else None,
            session_id,
        )

    def audited_tool(self, name: Optional[str] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: audit every call of a tool handler function.

        Arguments are captured by parameter name (positional and keyword)
        and pass through the redaction policy before export. Works with
        plain functions and with handlers registered on FastMCP-style
        servers, since decoration happens before registration.
        """

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            signature = inspect.signature(fn)

            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    bound = signature.bind_partial(*args, **kwargs)
                    captured: Optional[Dict[str, Any]] = dict(bound.arguments)
                except TypeError:
                    captured = None
                with self.tool_call(tool_name, captured):
                    return fn(*args, **kwargs)

            wrapper.__name__ = fn.__name__
            wrapper.__doc__ = fn.__doc__
            wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
            return wrapper

        return decorate

    # -- internals ----------------------------------------------------------

    def _resolve_traceparent(self, request_traceparent: Optional[str]) -> str:
        if request_traceparent and is_valid_traceparent(request_traceparent):
            return child_traceparent(request_traceparent)
        return child_traceparent(self._session_traceparent)

    def _capture_arguments(self, args: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        mode = self._redaction.mode
        if mode == "raw":
            return {"arguments": args, "arguments_digest": digest_arguments(args)}
        redacted, redacted_keys = redact_arguments(args, self._redaction)
        digest = digest_arguments(args, redacted_keys)
        if mode == "omit":
            return {"arguments_digest": digest}
        return {"arguments": redacted, "arguments_digest": digest}

    def _emit(
        self,
        event_type: str,
        traceparent: str,
        tracestate: Optional[str],
        outcome: Dict[str, Any],
        duration_ms: Optional[float] = None,
        body: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        event: Dict[str, Any] = {
            "spec_version": SPEC_VERSION,
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "timestamp": _now_rfc3339(),
            "traceparent": traceparent,
            "session_id": session_id or self._session_id,
            "server": dict(self._server),
            "outcome": outcome,
        }
        if tracestate:
            event["tracestate"] = tracestate
        if self._client:
            event["client"] = dict(self._client)
        if body:
            event.update(body)
        if duration_ms is not None:
            event["duration_ms"] = duration_ms
        self._dispatch(event)
        return event

    def _dispatch(self, event: Dict[str, Any]) -> None:
        for exporter in self._exporters:
            try:
                exporter.export([event])
            except Exception as error:  # noqa: BLE001 - audit must never break the tool path
                try:
                    self._on_export_error(error, exporter)
                except Exception:  # noqa: BLE001
                    pass

    def shutdown(self) -> None:
        """Shut down every exporter that supports it."""
        for exporter in self._exporters:
            shutdown = getattr(exporter, "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown()
                except Exception as error:  # noqa: BLE001
                    self._on_export_error(error, exporter)
