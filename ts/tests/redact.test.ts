/** Redaction policy and canonical digest behaviour. */
import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  digestArguments,
  redactArguments,
  REDACTED,
  AuditLogger,
} from "../src/index.js";
import { MemoryExporter } from "./helpers.js";

describe("redactArguments", () => {
  it("redacts well-known sensitive key names, including nested ones", () => {
    const { redacted, redactedKeys } = redactArguments({
      username: "alice",
      password: "hunter2",
      config: { api_key: "abc123", retries: 3 },
    });
    expect(redacted).toEqual({
      username: "alice",
      password: REDACTED,
      config: { api_key: REDACTED, retries: 3 },
    });
    expect(redactedKeys.sort()).toEqual(["config.api_key", "password"]);
  });

  it("matches key names case-insensitively and across -/_ variants", () => {
    const { redacted } = redactArguments({
      "API-KEY": "x",
      AccessKey: "y",
      Authorization: "z",
      author: "ok, not sensitive",
    });
    expect(redacted).toEqual({
      "API-KEY": REDACTED,
      AccessKey: REDACTED,
      Authorization: REDACTED,
      author: "ok, not sensitive",
    });
  });

  it("redacts secret-shaped values under innocent keys", () => {
    const { redacted, redactedKeys } = redactArguments({
      note: "sk-abcdefghijklmnopqrstuvwxyz123456",
      header: "Bearer abc.def.ghi",
      aws: ["AKIAIOSFODNN7EXAMPLE is the key"],
      plain: "hello world",
    });
    expect(redacted).toEqual({
      note: REDACTED,
      header: REDACTED,
      aws: [REDACTED],
      plain: "hello world",
    });
    expect(redactedKeys).toContain("aws[0]");
  });

  it("supports custom keys and patterns", () => {
    const { redacted } = redactArguments(
      { internal_id: "42", code_name: "blue-falcon" },
      { extraSensitiveKeys: ["codename"], extraValuePatterns: [] }
    );
    expect(redacted).toEqual({ internal_id: "42", code_name: REDACTED });
  });

  it("returns null for missing arguments", () => {
    expect(redactArguments(null)).toEqual({ redacted: null, redactedKeys: [] });
  });
});

describe("canonicalJson and digestArguments", () => {
  it("sorts keys recursively and strips whitespace", () => {
    expect(canonicalJson({ b: 1, a: { z: true, y: [2, { d: 1, c: 0 }] } })).toBe(
      '{"a":{"y":[2,{"c":0,"d":1}],"z":true},"b":1}'
    );
  });

  it("produces the pinned cross-language digest vector", () => {
    // The same vector is asserted in python/tests/test_redact.py; both SDKs
    // must agree byte-for-byte on the canonical encoding.
    const digest = digestArguments({ order_id: "42", api_key: "sk-abcdefghijklmnopqrstuvwx" });
    expect(digest.byte_length).toBe(57);
    expect(digest.sha256).toBe("9edc1256cf72675158f929c4db1d7fc635892123a6fb91d12cf74b42742616de");
  });

  it("digest covers the ORIGINAL value while the inline copy is redacted", () => {
    const args = { token: "secret-token-value" };
    const { redacted, redactedKeys } = redactArguments(args);
    const digest = digestArguments(args, redactedKeys);
    expect(redacted).toEqual({ token: REDACTED });
    expect(digest.sha256).toBe(digestArguments({ token: "secret-token-value" }).sha256);
    expect(digest.sha256).not.toBe(digestArguments({ token: REDACTED }).sha256);
    expect(digest.redacted_keys).toEqual(["token"]);
  });
});

describe("redaction modes on the logger", () => {
  function toolEvent(redaction: ConstructorParameters<typeof AuditLogger>[0]["redaction"]) {
    const sink = new MemoryExporter();
    const logger = new AuditLogger({ server: { name: "t" }, exporters: [sink], redaction });
    logger.beginOperation("tool_call", { name: "t", arguments: { password: "x", q: "y" } }).succeed();
    return sink.events[0]!;
  }

  it("mode redact (default) inlines a redacted copy", () => {
    const event = toolEvent(undefined);
    expect(event.tool!.arguments).toEqual({ password: REDACTED, q: "y" });
  });

  it("mode omit drops the inline copy but keeps the digest", () => {
    const event = toolEvent({ mode: "omit" });
    expect(event.tool!.arguments).toBeUndefined();
    expect(event.tool!.arguments_digest.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("mode raw keeps the original arguments", () => {
    const event = toolEvent({ mode: "raw" });
    expect(event.tool!.arguments).toEqual({ password: "x", q: "y" });
  });
});
