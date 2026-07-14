# mcp-audit (Python SDK)

Python implementation of the mcp-audit event specification: an `AuditLogger`
that produces spec-conformant audit events for MCP tool calls, resource reads
and prompt invocations, with exporters for console, JSONL files, OTLP/HTTP,
Splunk HEC and Datadog. Zero third-party runtime dependencies.

See the repository root [README](../README.md) and [SPEC.md](../SPEC.md) for
the full specification, field semantics and SIEM mapping tables.

```python
from mcp_audit import AuditLogger, JsonlExporter

audit = AuditLogger(server_name="demo", server_version="1.0.0",
                    exporters=[JsonlExporter("./audit.jsonl")])

@audit.audited_tool("lookup_order")
def lookup_order(order_id: str, api_key: str) -> str:
    return f"order {order_id}: shipped"

lookup_order(order_id="42", api_key="sk-secret-value-1234567890")
```

Run the tests (standard library only):

```bash
python3 -m unittest discover -s tests -v
```
