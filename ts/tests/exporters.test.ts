/**
 * Exporter tests. Every HTTP exporter is exercised against a local mock
 * receiver on 127.0.0.1 and the audit event embedded in the request body is
 * validated against the canonical JSON Schema — the exporters must not
 * mangle events on the way to the SIEM.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AuditLogger,
  ConsoleExporter,
  DatadogExporter,
  JsonlExporter,
  OtlpHttpExporter,
  SplunkHecExporter,
  type AuditEvent,
} from "../src/index.js";
import { expectValid, MemoryExporter } from "./helpers.js";

interface CapturedRequest {
  url: string;
  headers: IncomingMessage["headers"];
  body: string;
}

let httpServer: Server;
let baseUrl: string;
const captured: CapturedRequest[] = [];

beforeAll(async () => {
  httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      captured.push({ url: req.url ?? "", headers: req.headers, body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"ok":true}');
    });
  });
  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const address = httpServer.address();
  if (address === null || typeof address === "string") throw new Error("no address");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    httpServer.close((err) => (err ? reject(err) : resolve()))
  );
});

function sampleEvents(): AuditEvent[] {
  const sink = new MemoryExporter();
  const logger = new AuditLogger({
    server: { name: "exporter-test", version: "0.1.0", transport: "stdio" },
    exporters: [sink],
  });
  logger.recordSessionStart({ client: { name: "c", version: "1" } });
  logger
    .beginOperation("tool_call", { name: "echo", arguments: { text: "hi", token: "secret" } })
    .succeed();
  const failing = logger.beginOperation("tool_call", { name: "echo", arguments: {} });
  failing.fail({ code: -32603, message: "kaput" });
  return sink.events;
}

describe("JsonlExporter", () => {
  it("appends schema-valid JSON lines", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-audit-test-"));
    const path = join(dir, "nested", "audit.jsonl");
    const exporter = new JsonlExporter(path);
    const events = sampleEvents();
    exporter.export(events);
    exporter.export(events.slice(0, 1));
    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(events.length + 1);
    for (const line of lines) expectValid(JSON.parse(line));
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("ConsoleExporter", () => {
  it("writes one prefixed, schema-valid JSON line per event", () => {
    const chunks: string[] = [];
    const exporter = new ConsoleExporter({ stream: { write: (chunk: string) => chunks.push(chunk) } });
    const events = sampleEvents();
    exporter.export(events);
    expect(chunks).toHaveLength(events.length);
    for (const chunk of chunks) {
      expect(chunk.startsWith("[mcp-audit] ")).toBe(true);
      expectValid(JSON.parse(chunk.slice("[mcp-audit] ".length)));
    }
  });
});

describe("OtlpHttpExporter", () => {
  it("POSTs OTLP/JSON logs whose body is the schema-valid event", async () => {
    captured.length = 0;
    const exporter = new OtlpHttpExporter({ endpoint: `${baseUrl}/v1/logs` });
    const events = sampleEvents();
    await exporter.export(events);

    expect(captured).toHaveLength(1);
    const request = captured[0]!;
    expect(request.url).toBe("/v1/logs");
    expect(request.headers["content-type"]).toBe("application/json");

    const payload = JSON.parse(request.body);
    const scope = payload.resourceLogs[0].scopeLogs[0];
    expect(scope.scope.name).toBe("mcp-audit");
    expect(scope.logRecords).toHaveLength(events.length);
    for (const [i, record] of scope.logRecords.entries()) {
      const embedded = JSON.parse(record.body.stringValue);
      expectValid(embedded);
      expect(embedded.event_id).toBe(events[i]!.event_id);
      expect(record.traceId).toMatch(/^[0-9a-f]{32}$/);
      expect(record.spanId).toMatch(/^[0-9a-f]{16}$/);
      expect(record.timeUnixNano).toMatch(/^\d+$/);
    }
    const errorRecord = scope.logRecords[2];
    expect(errorRecord.severityText).toBe("ERROR");
    const names = scope.logRecords[1].attributes.map((a: { key: string }) => a.key);
    expect(names).toContain("mcp.tool.name");
  });

  it("throws on a non-2xx response so the logger can report it", async () => {
    const failing = createServer((_req, res) => {
      res.writeHead(503);
      res.end();
    });
    await new Promise<void>((resolve) => failing.listen(0, "127.0.0.1", resolve));
    const address = failing.address();
    if (address === null || typeof address === "string") throw new Error("no address");
    const exporter = new OtlpHttpExporter({
      endpoint: `http://127.0.0.1:${address.port}/v1/logs`,
    });
    await expect(exporter.export(sampleEvents())).rejects.toThrow(/HTTP 503/);
    await new Promise<void>((resolve, reject) =>
      failing.close((err) => (err ? reject(err) : resolve()))
    );
  });
});

describe("SplunkHecExporter", () => {
  it("POSTs HEC envelopes whose event field is the schema-valid record", async () => {
    captured.length = 0;
    const exporter = new SplunkHecExporter({
      url: baseUrl,
      token: "test-hec-token",
      index: "mcp",
    });
    const events = sampleEvents();
    await exporter.export(events);

    expect(captured).toHaveLength(1);
    const request = captured[0]!;
    expect(request.url).toBe("/services/collector/event");
    expect(request.headers["authorization"]).toBe("Splunk test-hec-token");

    const envelopes = request.body.split("\n").map((line) => JSON.parse(line));
    expect(envelopes).toHaveLength(events.length);
    for (const [i, envelope] of envelopes.entries()) {
      expectValid(envelope.event);
      expect(envelope.event.event_id).toBe(events[i]!.event_id);
      expect(envelope.sourcetype).toBe("mcp:audit");
      expect(envelope.index).toBe("mcp");
      expect(typeof envelope.time).toBe("number");
    }
  });
});

describe("DatadogExporter", () => {
  it("POSTs intake items whose message is the schema-valid record", async () => {
    captured.length = 0;
    const exporter = new DatadogExporter({
      apiKey: "test-dd-key",
      url: `${baseUrl}/api/v2/logs`,
      ddtags: "env:test",
    });
    const events = sampleEvents();
    await exporter.export(events);

    expect(captured).toHaveLength(1);
    const request = captured[0]!;
    expect(request.url).toBe("/api/v2/logs");
    expect(request.headers["dd-api-key"]).toBe("test-dd-key");

    const items = JSON.parse(request.body);
    expect(items).toHaveLength(events.length);
    for (const [i, item] of items.entries()) {
      const embedded = JSON.parse(item.message);
      expectValid(embedded);
      expect(embedded.event_id).toBe(events[i]!.event_id);
      expect(item.ddsource).toBe("mcp-audit");
      expect(item.ddtags).toBe("env:test");
      expect(item.dd.trace_id).toMatch(/^\d+$/);
      expect(item.dd.span_id).toMatch(/^\d+$/);
    }
    expect(items[2].status).toBe("error");
    expect(items[1].mcp.tool_name).toBe("echo");
  });
});

describe("AuditLogger flush", () => {
  it("waits for in-flight async exports", async () => {
    captured.length = 0;
    const logger = new AuditLogger({
      server: { name: "flush-test" },
      exporters: [new OtlpHttpExporter({ endpoint: `${baseUrl}/v1/logs` })],
    });
    logger.recordSessionStart();
    logger.recordSessionEnd();
    await logger.flush();
    expect(captured).toHaveLength(2);
  });
});
