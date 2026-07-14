"""mcp-audit: open audit-log standard for the Model Context Protocol.

Python SDK mirroring the TypeScript package: an AuditLogger that produces
spec-conformant audit events (spec_version 0.1) plus exporters for console,
JSONL files, OTLP/HTTP, Splunk HEC and Datadog.

Importing this package has zero side effects: no network, no file writes.
Zero third-party runtime dependencies.
"""

from .trace import (
    parse_traceparent,
    generate_traceparent,
    child_traceparent,
    is_valid_traceparent,
)
from .redact import (
    REDACTED,
    DEFAULT_SENSITIVE_KEY_PARTS,
    DEFAULT_SENSITIVE_KEY_EXACT,
    DEFAULT_SENSITIVE_VALUE_PATTERNS,
    RedactionPolicy,
    redact_arguments,
    digest_arguments,
    canonical_json,
)
from .logger import AuditLogger, AuditSpan
from .exporters import (
    AuditExporter,
    ConsoleExporter,
    JsonlExporter,
    OtlpHttpExporter,
    SplunkHecExporter,
    DatadogExporter,
)

SPEC_VERSION = "0.1"

__version__ = "0.1.0"

__all__ = [
    "SPEC_VERSION",
    "AuditLogger",
    "AuditSpan",
    "AuditExporter",
    "ConsoleExporter",
    "JsonlExporter",
    "OtlpHttpExporter",
    "SplunkHecExporter",
    "DatadogExporter",
    "RedactionPolicy",
    "REDACTED",
    "DEFAULT_SENSITIVE_KEY_PARTS",
    "DEFAULT_SENSITIVE_KEY_EXACT",
    "DEFAULT_SENSITIVE_VALUE_PATTERNS",
    "redact_arguments",
    "digest_arguments",
    "canonical_json",
    "parse_traceparent",
    "generate_traceparent",
    "child_traceparent",
    "is_valid_traceparent",
]
