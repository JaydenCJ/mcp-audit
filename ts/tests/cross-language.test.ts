/**
 * Cross-language conformance: events produced by the Python SDK must
 * validate against the exact same JSON Schema as the TypeScript events,
 * and both SDKs must agree on the canonical argument digest.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { digestArguments } from "../src/index.js";
import { expectValid } from "./helpers.js";

const PYTHON_DIR = fileURLToPath(new URL("../../python", import.meta.url));

function runPython(args: string[]): string {
  return execFileSync("python3", args, { cwd: PYTHON_DIR, encoding: "utf8" });
}

describe("Python SDK conformance", () => {
  it("emits one schema-valid event per event type", () => {
    const output = runPython(["-m", "mcp_audit.samples"]);
    const events = output
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const types = events.map((event) => event.event_type);
    expect(types).toEqual([
      "session_start",
      "tool_call",
      "resource_read",
      "prompt_invoke",
      "tool_call",
      "error",
      "session_end",
    ]);
    for (const event of events) expectValid(event);
    // Redaction parity: the Python sample includes an api_key argument.
    const toolEvent = events[1];
    expect(toolEvent.tool.arguments.api_key).toBe("[REDACTED]");
    expect(toolEvent.tool.arguments_digest.redacted_keys).toEqual(["api_key"]);
  });

  it("computes the same canonical digest as TypeScript", () => {
    const script = [
      "import json, sys",
      "from mcp_audit import digest_arguments",
      'args = {"b": 1, "a": {"z": True, "y": [2, {"d": 1, "c": 0}]}, "text": "héllo"}',
      "print(json.dumps(digest_arguments(args)))",
    ].join("\n");
    const pyDigest = JSON.parse(runPython(["-c", script]));
    const tsDigest = digestArguments({ b: 1, a: { z: true, y: [2, { d: 1, c: 0 }] }, text: "héllo" });
    expect(pyDigest.sha256).toBe(tsDigest.sha256);
    expect(pyDigest.byte_length).toBe(tsDigest.byte_length);
  });
});
