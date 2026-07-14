# mcp-audit

TypeScript implementation of the mcp-audit event specification: an open,
vendor-neutral audit-log format for Model Context Protocol (MCP) servers.
One spec-conformant, SIEM-ready audit event per tool call, resource read,
prompt invocation and session lifecycle transition — including calls the
protocol layer rejects before a handler runs (unknown tools, schema-invalid
arguments), so probe traffic stays visible.

- `withAudit(server)` instruments an existing `@modelcontextprotocol/sdk`
  `McpServer` in one line; no gateway or proxy in the request path.
- Argument redaction is on by default (sensitive-key deny list plus
  secret-shaped value detection), with a canonical SHA-256 digest so records
  stay correlatable and tamper-evident without storing plaintext.
- Every event carries a W3C Trace Context `traceparent`; requests with
  SEP-414 style `_meta.traceparent` continue the caller's trace.
- Exporters: console (stderr), JSONL file, OTLP/HTTP, Splunk HEC and
  Datadog Logs. Export failures never fail the audited operation.

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { withAudit, JsonlExporter } from "mcp-audit";

const server = withAudit(new McpServer({ name: "demo", version: "1.0.0" }), {
  exporters: [new JsonlExporter("./audit.jsonl")],
});
server.registerTool("echo", { inputSchema: { text: z.string() } }, async ({ text }) => ({
  content: [{ type: "text", text }],
}));
```

The canonical JSON Schema ships with the package and is importable as
`mcp-audit/schema`.

The full specification (`SPEC.md`), SIEM field mapping tables, the MCP
Extension proposal draft and the Python SDK live in the repository:
<https://github.com/JaydenCJ/mcp-audit>

License: [MIT](LICENSE)
