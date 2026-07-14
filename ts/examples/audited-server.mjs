#!/usr/bin/env node
// Minimal MCP server (stdio) instrumented with mcp-audit.
// Used by scripts/smoke.sh and directly runnable from Claude Code via .mcp.json.
//
// Env:
//   MCP_AUDIT_LOG      path of the JSONL audit log (default: ./audit.jsonl)
//   MCP_AUDIT_CONSOLE  set to "1" to also print events on stderr
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { withAudit, JsonlExporter, ConsoleExporter } from "../dist/index.js";

const exporters = [new JsonlExporter(process.env.MCP_AUDIT_LOG ?? "./audit.jsonl")];
if (process.env.MCP_AUDIT_CONSOLE === "1") {
  exporters.push(new ConsoleExporter());
}

const server = withAudit(new McpServer({ name: "audited-demo", version: "0.1.0" }), {
  transport: "stdio",
  exporters,
});

server.registerTool(
  "echo",
  {
    description: "Echo the text back. The optional api_key demonstrates redaction.",
    inputSchema: { text: z.string(), api_key: z.string().optional() },
  },
  async ({ text }) => ({ content: [{ type: "text", text }] })
);

server.registerTool(
  "add",
  {
    description: "Add two numbers.",
    inputSchema: { a: z.number(), b: z.number() },
  },
  async ({ a, b }) => ({ content: [{ type: "text", text: String(a + b) }] })
);

await server.connect(new StdioServerTransport());

// The SDK's stdio transport does not react to stdin EOF by itself. Closing
// the server here triggers the transport close path, which lets the audit
// middleware record session_end before the process exits.
process.stdin.on("end", () => {
  void server.close().finally(() => process.exit(0));
});
