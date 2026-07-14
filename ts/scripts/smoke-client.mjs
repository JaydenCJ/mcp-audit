#!/usr/bin/env node
// Protocol round-trip smoke client (no SDK: raw JSON-RPC 2.0 over stdio).
// Spawns the audited example server, performs initialize -> tools/list ->
// tools/call, exercises invalid input, then asserts the audit trail on disk
// validates against the canonical JSON Schema.
// Usage: node ts/scripts/smoke-client.mjs <audit-log-path>
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const auditLog = process.argv[2];
if (!auditLog) {
  process.stderr.write("usage: node smoke-client.mjs <audit-log-path>\n");
  process.exit(2);
}

const serverPath = fileURLToPath(new URL("../examples/audited-server.mjs", import.meta.url));
const TRACE_ID = "0af7651916cd43dd8448eb211c80319c";

function fail(message) {
  process.stderr.write(`[smoke] FAIL: ${message}\n`);
  process.exit(1);
}

function ok(message) {
  process.stdout.write(`[smoke] ${message}\n`);
}

const child = spawn(process.execPath, [serverPath], {
  env: { ...process.env, MCP_AUDIT_LOG: auditLog },
  stdio: ["pipe", "pipe", "inherit"],
});

let buffer = "";
const pending = new Map();
child.stdout.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  let newline;
  while ((newline = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    if (!line.trim()) continue;
    const message = JSON.parse(line);
    if (message.id !== undefined && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  }
});

let nextId = 1;
function request(method, params, { timeoutMs = 5000 } = {}) {
  const id = nextId++;
  const payload = { jsonrpc: "2.0", id, method, ...(params ? { params } : {}) };
  child.stdin.write(`${JSON.stringify(payload)}\n`);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout waiting for ${method} (id ${id})`)), timeoutMs);
    pending.set(id, (message) => {
      clearTimeout(timer);
      resolve(message);
    });
  });
}

function notify(method, params) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, ...(params ? { params } : {}) })}\n`);
}

try {
  // 1. initialize
  const init = await request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "smoke-client", version: "0.1.0" },
  });
  if (!init.result?.serverInfo?.name) fail("initialize: missing serverInfo");
  if (init.result.serverInfo.name !== "audited-demo") fail(`unexpected server name: ${init.result.serverInfo.name}`);
  if (typeof init.result.protocolVersion !== "string") fail("initialize: missing protocolVersion");
  ok(`initialize -> serverInfo=${init.result.serverInfo.name}@${init.result.serverInfo.version} protocol=${init.result.protocolVersion}`);
  notify("notifications/initialized");

  // 2. tools/list
  const list = await request("tools/list", {});
  const toolNames = (list.result?.tools ?? []).map((tool) => tool.name).sort();
  if (!toolNames.includes("echo") || !toolNames.includes("add")) {
    fail(`tools/list missing expected tools, got: ${toolNames.join(", ")}`);
  }
  ok(`tools/list -> [${toolNames.join(", ")}]`);

  // 3. tools/call with W3C trace propagation and a secret argument
  const echo = await request("tools/call", {
    name: "echo",
    arguments: { text: "hello smoke", api_key: "sk-abcdefghijklmnopqrstuvwx" },
    _meta: { traceparent: `00-${TRACE_ID}-b7ad6b7169203331-01` },
  });
  if (echo.result?.content?.[0]?.text !== "hello smoke") fail("echo returned wrong content");
  ok('tools/call echo -> "hello smoke"');

  const add = await request("tools/call", { name: "add", arguments: { a: 2, b: 3 } });
  if (add.result?.content?.[0]?.text !== "5") fail("add returned wrong content");
  ok('tools/call add {a:2,b:3} -> "5"');

  // 4. invalid input #1: unknown tool -> spec-conformant error, process alive
  const unknown = await request("tools/call", { name: "does-not-exist", arguments: { probe: "smoke" } });
  const unknownIsError = unknown.error !== undefined || unknown.result?.isError === true;
  if (!unknownIsError) fail("unknown tool did not produce an error response");
  ok("tools/call unknown tool -> protocol-conformant error, process alive");

  // 5. invalid input #2: schema-invalid arguments -> error, process alive
  const badArgs = await request("tools/call", { name: "echo", arguments: { text: 123 } });
  const badArgsIsError = badArgs.error !== undefined || badArgs.result?.isError === true;
  if (!badArgsIsError) fail("schema-invalid arguments did not produce an error response");
  ok("tools/call with invalid arguments -> protocol-conformant error, process alive");

  // 6. prove liveness after both error paths
  const alive = await request("tools/call", { name: "echo", arguments: { text: "still alive" } });
  if (alive.result?.content?.[0]?.text !== "still alive") fail("server not healthy after error paths");
  ok('tools/call echo after errors -> "still alive"');
} catch (error) {
  fail(String(error));
} finally {
  child.stdin.end();
}

await new Promise((resolve) => child.on("exit", resolve));
ok("server exited after stdin close");

// 7. audit trail assertions
const schemaPath = fileURLToPath(new URL("../../schema/audit-event.schema.json", import.meta.url));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8")));

const events = readFileSync(auditLog, "utf8")
  .split("\n")
  .filter((line) => line.trim())
  .map((line) => JSON.parse(line));

for (const [index, event] of events.entries()) {
  if (!validate(event)) {
    fail(`audit event ${index + 1} failed schema validation: ${ajv.errorsText(validate.errors)}`);
  }
}
ok(`audit log: ${events.length} events, all valid against audit-event.schema.json`);

const byType = (type) => events.filter((event) => event.event_type === type);
if (byType("session_start").length !== 1) fail("expected exactly 1 session_start event");
if (byType("session_end").length !== 1) fail("expected exactly 1 session_end event");
const toolCalls = byType("tool_call");
// 5 tools/call requests were sent: echo, add, unknown tool, invalid
// arguments, echo again. Every one of them must be audited (SPEC section 2),
// including the two the protocol layer rejected before any handler ran.
if (toolCalls.length !== 5) fail(`expected 5 tool_call events, got ${toolCalls.length}`);
const successCalls = toolCalls.filter((event) => event.outcome.status === "success");
const errorCalls = toolCalls.filter((event) => event.outcome.status === "error");
if (successCalls.length !== 3) fail(`expected 3 successful tool_call events, got ${successCalls.length}`);
if (errorCalls.length !== 2) fail(`expected 2 error tool_call events for the probes, got ${errorCalls.length}`);
const unknownProbe = errorCalls.find((event) => event.tool.name === "does-not-exist");
if (!unknownProbe) fail("unknown-tool probe was not audited");
if (unknownProbe.tool.arguments?.probe !== "smoke") fail("unknown-tool probe arguments were not captured");
if (!unknownProbe.outcome.error?.message) fail("unknown-tool probe event carries no error message");
const badArgsProbe = errorCalls.find((event) => event.tool.name === "echo");
if (!badArgsProbe) fail("invalid-arguments probe was not audited");
if (badArgsProbe.tool.arguments?.text !== 123) fail("invalid-arguments probe did not capture the offending arguments");

const traced = successCalls.find((event) => event.traceparent.includes(TRACE_ID));
if (!traced) fail("no tool_call event carries the propagated W3C trace id");
if (traced.tool.arguments.api_key !== "[REDACTED]") fail("api_key was not redacted");
if (!(traced.tool.arguments_digest.redacted_keys ?? []).includes("api_key")) {
  fail("redacted_keys does not record api_key");
}
if (!toolCalls.every((event) => event.duration_ms >= 0)) fail("tool_call missing duration");
ok("audit assertions: session lifecycle, rejected-probe visibility, trace propagation, redaction, durations");

process.stdout.write("[smoke] client checks passed\n");
