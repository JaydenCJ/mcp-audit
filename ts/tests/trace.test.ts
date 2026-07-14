/** W3C Trace Context helpers. */
import { describe, expect, it } from "vitest";
import {
  childTraceparent,
  generateTraceparent,
  isValidTraceparent,
  parseTraceparent,
} from "../src/index.js";

const SAMPLE = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

describe("parseTraceparent", () => {
  it("parses a valid header", () => {
    expect(parseTraceparent(SAMPLE)).toEqual({
      traceId: "0af7651916cd43dd8448eb211c80319c",
      spanId: "b7ad6b7169203331",
      flags: "01",
    });
  });

  it("rejects malformed and all-zero values", () => {
    expect(parseTraceparent("not-a-traceparent")).toBeNull();
    expect(parseTraceparent("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")).toBeNull();
    expect(parseTraceparent(`00-${"0".repeat(32)}-b7ad6b7169203331-01`)).toBeNull();
    expect(parseTraceparent(`00-0af7651916cd43dd8448eb211c80319c-${"0".repeat(16)}-01`)).toBeNull();
    expect(parseTraceparent("00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01")).toBeNull();
  });
});

describe("generateTraceparent / childTraceparent", () => {
  it("generates valid, unique values", () => {
    const a = generateTraceparent();
    const b = generateTraceparent();
    expect(isValidTraceparent(a)).toBe(true);
    expect(isValidTraceparent(b)).toBe(true);
    expect(a).not.toBe(b);
  });

  it("child keeps trace-id and flags, changes span-id", () => {
    const child = childTraceparent(SAMPLE);
    const parsed = parseTraceparent(child)!;
    expect(parsed.traceId).toBe("0af7651916cd43dd8448eb211c80319c");
    expect(parsed.flags).toBe("01");
    expect(parsed.spanId).not.toBe("b7ad6b7169203331");
  });

  it("falls back to a fresh root for a malformed parent", () => {
    const child = childTraceparent("garbage");
    expect(isValidTraceparent(child)).toBe(true);
  });
});
