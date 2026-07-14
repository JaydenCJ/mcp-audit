/**
 * The README Quickstart snippet must be real: this file embeds it verbatim
 * (the test asserts byte-equality against README.md) and then drives it with
 * a real MCP client to prove the documented ten lines actually audit a call.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { getAuditLogger } from "../src/index.js";
import { expectValid } from "./helpers.js";

// --- README Quickstart snippet (verbatim) ---
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { withAudit, JsonlExporter } from "mcp-audit";

const server = withAudit(new McpServer({ name: "demo", version: "1.0.0" }), {
  exporters: [new JsonlExporter("./audit.jsonl")],
});
server.registerTool("echo", { inputSchema: { text: z.string() } }, async ({ text }) => ({
  content: [{ type: "text", text }],
}));
// --- end snippet ---

const originalCwd = process.cwd();
let workDir: string;

beforeAll(() => {
  workDir = mkdtempSync(join(tmpdir(), "mcp-audit-readme-"));
  process.chdir(workDir);
});

afterAll(() => {
  process.chdir(originalCwd);
  rmSync(workDir, { recursive: true, force: true });
});

describe("README Quickstart snippet", () => {
  it("is byte-identical to the snippet in README.md", () => {
    const readme = readFileSync(
      fileURLToPath(new URL("../../README.md", import.meta.url)),
      "utf8"
    );
    const self = readFileSync(fileURLToPath(import.meta.url), "utf8");
    const marker = "// --- README Quickstart snippet (verbatim) ---\n";
    const endMarker = "// --- end snippet ---";
    const snippet = self.slice(self.indexOf(marker) + marker.length, self.indexOf(endMarker));
    expect(snippet.trim().length).toBeGreaterThan(0);
    expect(readme).toContain(snippet);
  });

  it("actually audits a tool call into ./audit.jsonl", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "readme-client", version: "1.0.0" });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    await client.callTool({ name: "echo", arguments: { text: "documented" } });
    await getAuditLogger(server)!.flush();

    const lines = readFileSync(join(workDir, "audit.jsonl"), "utf8").trim().split("\n");
    const events = lines.map((line) => JSON.parse(line));
    for (const event of events) expectValid(event);
    const toolCall = events.find((event) => event.event_type === "tool_call");
    expect(toolCall.tool.name).toBe("echo");
    expect(toolCall.tool.arguments).toEqual({ text: "documented" });
    await client.close();
    await server.close();
  });
});
