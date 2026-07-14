/**
 * Minimal W3C Trace Context (traceparent) support, aligned with SEP-414:
 * when an MCP request carries a `traceparent` in its `_meta`, audit events
 * continue that trace; otherwise the audit layer starts a new one.
 */
import { randomBytes } from "node:crypto";

const TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

/** Parsed form of a traceparent header value. */
export interface TraceContext {
  traceId: string;
  spanId: string;
  flags: string;
}

/** Parse a traceparent value. Returns null for malformed or all-zero ids. */
export function parseTraceparent(value: string): TraceContext | null {
  const m = TRACEPARENT_RE.exec(value);
  if (!m) return null;
  const [, traceId, spanId, flags] = m;
  if (traceId === "0".repeat(32) || spanId === "0".repeat(16)) return null;
  return { traceId: traceId!, spanId: spanId!, flags: flags! };
}

function randomHex(bytes: number): string {
  let hex = randomBytes(bytes).toString("hex");
  // The spec forbids all-zero trace/span ids; regenerate in that edge case.
  while (/^0+$/.test(hex)) hex = randomBytes(bytes).toString("hex");
  return hex;
}

/** Generate a new root traceparent (sampled). */
export function generateTraceparent(): string {
  return `00-${randomHex(16)}-${randomHex(8)}-01`;
}

/**
 * Derive a child traceparent: same trace-id and flags, fresh span-id.
 * Falls back to a new root when the parent value is malformed.
 */
export function childTraceparent(parent: string): string {
  const ctx = parseTraceparent(parent);
  if (!ctx) return generateTraceparent();
  return `00-${ctx.traceId}-${randomHex(8)}-${ctx.flags}`;
}

/** True when the value is a well-formed, non-zero traceparent. */
export function isValidTraceparent(value: string): boolean {
  return parseTraceparent(value) !== null;
}
