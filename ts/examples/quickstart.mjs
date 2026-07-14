#!/usr/bin/env node
// Quickstart demo: an audited MCP server and a real MCP client talking over
// an in-memory transport. Prints the audit events the middleware produces.
// Run from ts/ after `npm install && npm run build`:  node examples/quickstart.mjs
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { withAudit, ConsoleExporter, getAuditLogger } from "../dist/index.js";

const server = withAudit(new McpServer({ name: "quickstart", version: "0.1.0" }), {
  exporters: [new ConsoleExporter({ stream: process.stdout })],
});

server.registerTool(
  "lookup_order",
  { inputSchema: { order_id: z.string(), api_key: z.string() } },
  async ({ order_id }) => ({ content: [{ type: "text", text: `order ${order_id}: shipped` }] })
);

const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const client = new Client({ name: "quickstart-client", version: "1.0.0" });
await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

await client.callTool({
  name: "lookup_order",
  arguments: { order_id: "42", api_key: "sk-abcdefghijklmnopqrstuvwx" },
});

await getAuditLogger(server)?.flush();
await client.close();
await server.close();
