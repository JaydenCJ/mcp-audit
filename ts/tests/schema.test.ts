/**
 * The AuditLogger must produce events that validate against the canonical
 * JSON Schema for every event type, and the schema must reject malformed
 * records (this is what makes the schema a real contract, not decoration).
 */
import { describe, expect, it } from "vitest";
import { AuditLogger } from "../src/index.js";
import { MemoryExporter, validateEvent, expectValid } from "./helpers.js";

function makeLogger(): { logger: AuditLogger; sink: MemoryExporter } {
  const sink = new MemoryExporter();
  const logger = new AuditLogger({
    server: { name: "schema-test", version: "0.1.0", transport: "stdio" },
    exporters: [sink],
  });
  return { logger, sink };
}

describe("events conform to schema/audit-event.schema.json", () => {
  it("session_start and session_end validate", () => {
    const { logger, sink } = makeLogger();
    logger.recordSessionStart({ client: { name: "c", version: "1.0" } });
    logger.recordSessionEnd();
    expect(sink.events).toHaveLength(2);
    for (const event of sink.events) expectValid(event);
    expect(sink.events[1]!.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it("tool_call success validates and carries digest + duration", () => {
    const { logger, sink } = makeLogger();
    const span = logger.beginOperation("tool_call", {
      name: "search",
      arguments: { query: "hello", password: "hunter2" },
    });
    span.succeed();
    const [event] = sink.byType("tool_call");
    expectValid(event);
    expect(event!.tool!.arguments_digest.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(event!.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it("tool_call error requires and carries outcome.error", () => {
    const { logger, sink } = makeLogger();
    const span = logger.beginOperation("tool_call", { name: "search", arguments: {} });
    span.fail({ code: -32603, message: "backend unavailable" });
    const [event] = sink.byType("tool_call");
    expectValid(event);
    expect(event!.outcome).toEqual({
      status: "error",
      error: { code: -32603, message: "backend unavailable" },
    });
  });

  it("resource_read, prompt_invoke and error validate", () => {
    const { logger, sink } = makeLogger();
    logger.beginOperation("resource_read", { uri: "file:///tmp/a.txt", name: "a" }).succeed();
    logger.beginOperation("prompt_invoke", { name: "summarize", arguments: { style: "short" } }).succeed();
    logger.recordError({ code: -32000, message: "transport failure" });
    expect(sink.events).toHaveLength(3);
    for (const event of sink.events) expectValid(event);
  });

  it("a span reports success/failure exactly once", () => {
    const { logger, sink } = makeLogger();
    const span = logger.beginOperation("tool_call", { name: "t", arguments: {} });
    span.succeed();
    span.fail({ message: "late failure ignored" });
    span.succeed();
    expect(sink.byType("tool_call")).toHaveLength(1);
    expect(sink.events[0]!.outcome.status).toBe("success");
  });
});

describe("schema rejects malformed records", () => {
  function base(): Record<string, unknown> {
    const { logger, sink } = makeLogger();
    logger.recordSessionStart();
    return JSON.parse(JSON.stringify(sink.events[0]));
  }

  it("rejects a bad traceparent", () => {
    const event = base();
    event.traceparent = "00-zzzz-1234-01";
    expect(validateEvent(event)).not.toBeNull();
  });

  it("rejects tool_call without tool details or duration", () => {
    const event = base();
    event.event_type = "tool_call";
    expect(validateEvent(event)).not.toBeNull();
  });

  it("rejects unknown top-level fields", () => {
    const event = base();
    event.surprise = true;
    expect(validateEvent(event)).not.toBeNull();
  });

  it("rejects error status without error details", () => {
    const event = base();
    (event.outcome as Record<string, unknown>).status = "error";
    expect(validateEvent(event)).not.toBeNull();
  });

  it("rejects unknown event_type and non-UTC timestamps", () => {
    const badType = base();
    badType.event_type = "tool_called";
    expect(validateEvent(badType)).not.toBeNull();

    const badTime = base();
    badTime.timestamp = "2026-07-08T12:00:00+09:00";
    expect(validateEvent(badTime)).not.toBeNull();
  });
});
