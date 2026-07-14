/**
 * Protocol round-trip tests: a real McpServer wrapped by withAudit talks to
 * a real SDK Client over an in-memory transport. Assertions cover session
 * lifecycle events, tool/resource/prompt auditing, redaction, W3C trace
 * propagation via request _meta, and the invalid-input paths (unknown
 * names and schema-invalid arguments produce error-outcome audit events;
 * the protocol response stays conformant and the process stays healthy).
 */
import { describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { withAudit, getAuditLogger, REDACTED } from "../src/index.js";
import { MemoryExporter, expectValid } from "./helpers.js";

async function setup() {
  const sink = new MemoryExporter();
  const server = withAudit(new McpServer({ name: "audited-test", version: "0.1.0" }), {
    transport: "custom",
    exporters: [sink],
  });

  server.registerTool(
    "echo",
    { inputSchema: { text: z.string(), api_key: z.string().optional() } },
    async ({ text }: { text: string }) => ({ content: [{ type: "text" as const, text }] })
  );
  server.registerTool(
    "boom",
    { inputSchema: { reason: z.string() } },
    async ({ reason }: { reason: string }) => {
      throw new Error(`boom: ${reason}`);
    }
  );
  server.registerResource("motd", "demo://motd", { description: "message of the day" }, async (uri: URL) => ({
    contents: [{ uri: uri.href, text: "hello" }],
  }));
  server.registerPrompt(
    "summarize",
    { argsSchema: { style: z.string() } },
    async ({ style }: { style: string }) => ({
      messages: [{ role: "user" as const, content: { type: "text" as const, text: `summarize ${style}` } }],
    })
  );

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "9.9.9" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { server, client, sink };
}

describe("withAudit protocol round-trip", () => {
  it("records the session lifecycle with client identity", async () => {
    const { server, client, sink } = await setup();
    await client.close();
    await server.close();
    await getAuditLogger(server)!.flush();

    const starts = sink.byType("session_start");
    const ends = sink.byType("session_end");
    expect(starts).toHaveLength(1);
    expect(ends).toHaveLength(1);
    expectValid(starts[0]);
    expectValid(ends[0]);
    expect(starts[0]!.client).toEqual({ name: "test-client", version: "9.9.9" });
    expect(starts[0]!.session_id).toBe(ends[0]!.session_id);
  });

  it("audits a successful tool call with redacted arguments", async () => {
    const { server, client, sink } = await setup();
    const result = await client.callTool({
      name: "echo",
      arguments: { text: "hi", api_key: "sk-abcdefghijklmnopqrstuvwx" },
    });
    expect((result.content as Array<{ text: string }>)[0]!.text).toBe("hi");

    const calls = sink.byType("tool_call");
    expect(calls).toHaveLength(1);
    const event = calls[0]!;
    expectValid(event);
    expect(event.tool!.name).toBe("echo");
    expect(event.tool!.arguments).toEqual({ text: "hi", api_key: REDACTED });
    expect(event.tool!.arguments_digest.redacted_keys).toEqual(["api_key"]);
    expect(event.outcome.status).toBe("success");
    expect(event.duration_ms).toBeGreaterThanOrEqual(0);
    expect(event.server).toEqual({ name: "audited-test", version: "0.1.0", transport: "custom" });
    await client.close();
    await server.close();
  });

  it("propagates a W3C traceparent from request _meta (SEP-414)", async () => {
    const { server, client, sink } = await setup();
    const traceId = "0af7651916cd43dd8448eb211c80319c";
    await client.callTool({
      name: "echo",
      arguments: { text: "traced" },
      _meta: { traceparent: `00-${traceId}-b7ad6b7169203331-01`, tracestate: "vendor=1" },
    });
    const [event] = sink.byType("tool_call");
    expectValid(event);
    expect(event!.traceparent).toMatch(new RegExp(`^00-${traceId}-[0-9a-f]{16}-01$`));
    expect(event!.traceparent).not.toContain("b7ad6b7169203331");
    expect(event!.tracestate).toBe("vendor=1");
    await client.close();
    await server.close();
  });

  it("records a thrown tool error and the server keeps serving", async () => {
    const { server, client, sink } = await setup();
    const result = await client.callTool({ name: "boom", arguments: { reason: "test" } });
    // The SDK converts handler exceptions into an isError tool result.
    expect(result.isError).toBe(true);

    const errorEvents = sink.byType("tool_call").filter((event) => event.outcome.status === "error");
    expect(errorEvents).toHaveLength(1);
    expectValid(errorEvents[0]);
    expect(errorEvents[0]!.outcome.error!.message).toContain("boom: test");

    // The process/session survives: a follow-up call still works and is audited.
    const followUp = await client.callTool({ name: "echo", arguments: { text: "alive" } });
    expect((followUp.content as Array<{ text: string }>)[0]!.text).toBe("alive");
    expect(sink.byType("tool_call")).toHaveLength(2);
    await client.close();
    await server.close();
  });

  it("audits an unknown-tool probe as a tool_call error and stays healthy", async () => {
    const { server, client, sink } = await setup();
    const traceId = "4bf92f3577b34da6a3ce929d0e0e4736";
    // The SDK surfaces unknown tools as an isError result carrying the
    // JSON-RPC "Invalid params" code; no handler runs, but the probe must
    // still produce exactly one audit event (SPEC section 2).
    const rejected = await client.callTool({
      name: "does-not-exist",
      arguments: { probe: "1" },
      _meta: { traceparent: `00-${traceId}-00f067aa0ba902b7-01` },
    });
    expect(rejected.isError).toBe(true);
    expect(JSON.stringify(rejected.content)).toContain("-32602");

    const calls = sink.byType("tool_call");
    expect(calls).toHaveLength(1);
    expectValid(calls[0]);
    expect(calls[0]!.tool!.name).toBe("does-not-exist");
    expect(calls[0]!.tool!.arguments).toEqual({ probe: "1" });
    expect(calls[0]!.outcome.status).toBe("error");
    expect(calls[0]!.outcome.error!.code).toBe(-32602);
    expect(calls[0]!.outcome.error!.message).toContain("not found");
    // Rejected probes continue the caller's trace like any other operation.
    expect(calls[0]!.traceparent).toMatch(new RegExp(`^00-${traceId}-[0-9a-f]{16}-01$`));

    const ok = await client.callTool({ name: "echo", arguments: { text: "still up" } });
    expect((ok.content as Array<{ text: string }>)[0]!.text).toBe("still up");
    expect(sink.byType("tool_call")).toHaveLength(2);
    await client.close();
    await server.close();
  });

  it("audits schema-invalid tool arguments (with redaction) without crashing", async () => {
    const { server, client, sink } = await setup();
    const outcome = await client
      .callTool({
        name: "echo",
        arguments: { text: 123 as unknown as string, api_key: "sk-abcdefghijklmnopqrstuvwx" },
      })
      .then(
        (result) => ({ kind: "result" as const, result }),
        (error) => ({ kind: "error" as const, error })
      );
    // Depending on SDK version this surfaces as a protocol error or an
    // isError result; both are protocol-conformant. The handler never ran,
    // yet the probe is audited with the offending arguments redacted.
    if (outcome.kind === "result") {
      expect(outcome.result.isError).toBe(true);
    }
    const failed = sink.byType("tool_call").filter((event) => event.outcome.status === "error");
    expect(failed).toHaveLength(1);
    expectValid(failed[0]);
    expect(failed[0]!.tool!.name).toBe("echo");
    expect(failed[0]!.tool!.arguments).toEqual({ text: 123, api_key: REDACTED });
    expect(failed[0]!.tool!.arguments_digest.redacted_keys).toEqual(["api_key"]);

    const ok = await client.callTool({ name: "echo", arguments: { text: "recovered" } });
    expect((ok.content as Array<{ text: string }>)[0]!.text).toBe("recovered");
    expect(sink.byType("tool_call").filter((event) => event.outcome.status === "success").length)
      .toBeGreaterThanOrEqual(1);
    await client.close();
    await server.close();
  });

  it("audits protocol-rejected resource reads and prompt invocations", async () => {
    const { server, client, sink } = await setup();
    // Unknown resources and prompts reject with a protocol error (no
    // isError result shape exists for them); the probe is still audited.
    await expect(client.readResource({ uri: "demo://missing" })).rejects.toThrow();
    const reads = sink.byType("resource_read");
    expect(reads).toHaveLength(1);
    expectValid(reads[0]);
    expect(reads[0]!.resource!.uri).toBe("demo://missing");
    expect(reads[0]!.outcome.status).toBe("error");
    expect(reads[0]!.outcome.error!.code).toBe(-32602);

    await expect(client.getPrompt({ name: "missing", arguments: {} })).rejects.toThrow();
    const prompts = sink.byType("prompt_invoke");
    expect(prompts).toHaveLength(1);
    expectValid(prompts[0]);
    expect(prompts[0]!.prompt!.name).toBe("missing");
    expect(prompts[0]!.outcome.status).toBe("error");
    await client.close();
    await server.close();
  });

  it("audits resource reads and prompt invocations", async () => {
    const { server, client, sink } = await setup();
    await client.readResource({ uri: "demo://motd" });
    await client.getPrompt({ name: "summarize", arguments: { style: "short" } });

    const reads = sink.byType("resource_read");
    expect(reads).toHaveLength(1);
    expectValid(reads[0]);
    expect(reads[0]!.resource!.uri).toBe("demo://motd");

    const prompts = sink.byType("prompt_invoke");
    expect(prompts).toHaveLength(1);
    expectValid(prompts[0]);
    expect(prompts[0]!.prompt!.name).toBe("summarize");
    expect(prompts[0]!.prompt!.arguments).toEqual({ style: "short" });
    await client.close();
    await server.close();
  });

  it("a failing exporter never breaks the tool path", async () => {
    const failures: unknown[] = [];
    const throwing = {
      export(): void {
        throw new Error("sink offline");
      },
    };
    const sink = new MemoryExporter();
    const server = withAudit(new McpServer({ name: "resilient", version: "0.1.0" }), {
      exporters: [throwing, sink],
      onExportError: (error) => failures.push(error),
    });
    server.registerTool("ping", {}, async () => ({ content: [{ type: "text" as const, text: "pong" }] }));

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "c", version: "1" });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const result = await client.callTool({ name: "ping", arguments: {} });
    expect((result.content as Array<{ text: string }>)[0]!.text).toBe("pong");
    expect(failures.length).toBeGreaterThanOrEqual(1);
    expect(sink.byType("tool_call")).toHaveLength(1);
    await client.close();
    await server.close();
  });

  it("also audits tools registered via the deprecated tool() signature", async () => {
    const sink = new MemoryExporter();
    const server = withAudit(new McpServer({ name: "legacy", version: "0.1.0" }), {
      exporters: [sink],
    });
    // Deprecated zero-argument registration: cb receives only the extra.
    server.tool("legacy-ping", async () => ({
      content: [{ type: "text" as const, text: "legacy-pong" }],
    }));

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "c", version: "1" });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const result = await client.callTool({ name: "legacy-ping", arguments: {} });
    expect((result.content as Array<{ text: string }>)[0]!.text).toBe("legacy-pong");

    const calls = sink.byType("tool_call");
    expect(calls).toHaveLength(1);
    expectValid(calls[0]);
    expect(calls[0]!.tool!.name).toBe("legacy-ping");
    // Zero-argument tool: no inline arguments, digest of null.
    expect(calls[0]!.tool!.arguments).toBeNull();
    await client.close();
    await server.close();
  });

  it("withAudit is idempotent on the same server", async () => {
    const sink = new MemoryExporter();
    const raw = new McpServer({ name: "once", version: "0.1.0" });
    const audited = withAudit(raw, { exporters: [sink] });
    expect(withAudit(audited, { exporters: [sink] })).toBe(audited);
    audited.registerTool("ping", {}, async () => ({ content: [{ type: "text" as const, text: "pong" }] }));

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "c", version: "1" });
    await Promise.all([audited.connect(serverTransport), client.connect(clientTransport)]);
    await client.callTool({ name: "ping", arguments: {} });
    // Exactly one event per call even though withAudit was applied twice.
    expect(sink.byType("tool_call")).toHaveLength(1);
    await client.close();
    await audited.close();
  });
});
