/**
 * Argument redaction and canonical digests.
 *
 * Redaction is ON by default: the inline copy of tool/prompt arguments has
 * sensitive values replaced with "[REDACTED]" before it ever reaches an
 * exporter. A SHA-256 digest of the canonical JSON encoding of the ORIGINAL
 * arguments is always recorded, so two records can still be correlated (and
 * tampering detected) without storing the sensitive payload.
 */
import { createHash } from "node:crypto";
import type { ArgumentsDigest } from "./types.js";

/** Replacement string used for redacted values. */
export const REDACTED = "[REDACTED]";

/**
 * Key-name deny list. A key matches when its normalized form (lowercase,
 * `-`/`_` removed) contains one of these substrings.
 */
export const DEFAULT_SENSITIVE_KEY_PARTS: readonly string[] = [
  "password",
  "passwd",
  "secret",
  "token",
  "apikey",
  "authorization",
  "credential",
  "privatekey",
  "accesskey",
  "sessionkey",
  "cookie",
];

/** Keys that match exactly (after normalization) even though they are short. */
export const DEFAULT_SENSITIVE_KEY_EXACT: readonly string[] = ["auth", "ssn", "pin", "otp"];

/**
 * Value patterns treated as secrets regardless of the key they appear under:
 * JWTs, AWS access key ids, GitHub tokens, OpenAI-style keys, Bearer values.
 */
export const DEFAULT_SENSITIVE_VALUE_PATTERNS: readonly RegExp[] = [
  /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}$/, // JWT
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, // GitHub token
  /\bsk-[A-Za-z0-9_-]{20,}\b/, // OpenAI-style secret key
  /^Bearer\s+\S+$/i, // Authorization: Bearer <...>
];

/** Redaction behaviour for the inline arguments copy. */
export type RedactionMode = "omit" | "redact" | "raw";

/** Redaction configuration accepted by AuditLogger and withAudit. */
export interface RedactionPolicy {
  /**
   * omit   – no inline copy at all, digest only.
   * redact – inline copy with sensitive values replaced (default).
   * raw    – inline copy unchanged. Only for closed environments.
   */
  mode?: RedactionMode;
  /** Extra key substrings to treat as sensitive (normalized matching). */
  extraSensitiveKeys?: string[];
  /** Extra value patterns to treat as sensitive. */
  extraValuePatterns?: RegExp[];
}

export interface RedactionResult {
  /** Deep copy of the arguments with sensitive values replaced. */
  redacted: Record<string, unknown> | null;
  /** Dot-paths of the keys that were redacted. */
  redactedKeys: string[];
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_]/g, "");
}

function isSensitiveKey(key: string, extraParts: string[]): boolean {
  const norm = normalizeKey(key);
  if (DEFAULT_SENSITIVE_KEY_EXACT.includes(norm)) return true;
  for (const part of DEFAULT_SENSITIVE_KEY_PARTS) {
    if (norm.includes(part)) return true;
  }
  for (const part of extraParts) {
    if (norm.includes(normalizeKey(part))) return true;
  }
  return false;
}

function isSensitiveValue(value: string, extraPatterns: RegExp[]): boolean {
  for (const re of DEFAULT_SENSITIVE_VALUE_PATTERNS) {
    if (re.test(value)) return true;
  }
  for (const re of extraPatterns) {
    if (re.test(value)) return true;
  }
  return false;
}

function redactValue(
  value: unknown,
  path: string,
  policy: Required<Pick<RedactionPolicy, "extraSensitiveKeys" | "extraValuePatterns">>,
  redactedKeys: string[]
): unknown {
  if (typeof value === "string") {
    if (isSensitiveValue(value, policy.extraValuePatterns)) {
      redactedKeys.push(path);
      return REDACTED;
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, i) => redactValue(item, `${path}[${i}]`, policy, redactedKeys));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = path === "" ? key : `${path}.${key}`;
      if (isSensitiveKey(key, policy.extraSensitiveKeys) && child !== null && child !== undefined) {
        redactedKeys.push(childPath);
        out[key] = REDACTED;
      } else {
        out[key] = redactValue(child, childPath, policy, redactedKeys);
      }
    }
    return out;
  }
  return value;
}

/** Apply a redaction policy to a set of arguments. */
export function redactArguments(
  args: Record<string, unknown> | null | undefined,
  policy: RedactionPolicy = {}
): RedactionResult {
  if (args === null || args === undefined) {
    return { redacted: null, redactedKeys: [] };
  }
  const redactedKeys: string[] = [];
  const redacted = redactValue(
    args,
    "",
    {
      extraSensitiveKeys: policy.extraSensitiveKeys ?? [],
      extraValuePatterns: policy.extraValuePatterns ?? [],
    },
    redactedKeys
  ) as Record<string, unknown>;
  return { redacted, redactedKeys };
}

/**
 * Canonical JSON encoding: object keys sorted lexicographically at every
 * level, no insignificant whitespace, UTF-8. Matches the Python SDK's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))` for the JSON
 * subset both languages produce.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortValue((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/** Compute the integrity digest of the original (pre-redaction) arguments. */
export function digestArguments(
  args: Record<string, unknown> | null | undefined,
  redactedKeys: string[] = []
): ArgumentsDigest {
  const canonical = canonicalJson(args ?? null);
  const bytes = Buffer.from(canonical, "utf8");
  const digest: ArgumentsDigest = {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    byte_length: bytes.byteLength,
  };
  if (redactedKeys.length > 0) digest.redacted_keys = redactedKeys;
  return digest;
}
