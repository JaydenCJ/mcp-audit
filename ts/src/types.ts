/**
 * Event model for the mcp-audit specification, spec_version 0.1.
 * Field semantics are defined in SPEC.md; the canonical machine-readable
 * definition is schema/audit-event.schema.json at the repository root.
 */

/** The kinds of actions an audit event can record. */
export type AuditEventType =
  | "tool_call"
  | "resource_read"
  | "prompt_invoke"
  | "session_start"
  | "session_end"
  | "error";

/** Transport the MCP session runs over. */
export type AuditTransport = "stdio" | "streamable_http" | "sse" | "custom";

/** Result status of the recorded action. */
export type AuditStatus = "success" | "error";

/** Integrity digest of the original (pre-redaction) arguments. */
export interface ArgumentsDigest {
  /** SHA-256 (lowercase hex) of the canonical JSON encoding of the original arguments. */
  sha256: string;
  /** Byte length of the canonical JSON encoding of the original arguments. */
  byte_length: number;
  /** Dot-paths of keys whose values were redacted in the inline copy. */
  redacted_keys?: string[];
}

/** Identity of the MCP server that produced an event. */
export interface AuditServerInfo {
  name: string;
  version?: string;
  transport?: AuditTransport;
}

/** Identity of the MCP client, as reported during initialize. */
export interface AuditClientInfo {
  name?: string;
  version?: string;
}

/** Result of the recorded action. */
export interface AuditOutcome {
  status: AuditStatus;
  error?: {
    code?: number;
    message: string;
  };
}

/** Tool invocation details (event_type tool_call). */
export interface AuditToolDetails {
  name: string;
  /** Inline copy of the arguments after redaction; absent when redaction mode is "omit". */
  arguments?: Record<string, unknown> | null;
  arguments_digest: ArgumentsDigest;
}

/** Resource read details (event_type resource_read). */
export interface AuditResourceDetails {
  uri: string;
  name?: string;
}

/** Prompt invocation details (event_type prompt_invoke). */
export interface AuditPromptDetails {
  name: string;
  arguments?: Record<string, unknown> | null;
  arguments_digest: ArgumentsDigest;
}

/**
 * A single structured audit record describing one observable action on an
 * MCP server. Serializes 1:1 to schema/audit-event.schema.json.
 */
export interface AuditEvent {
  spec_version: "0.1";
  event_id: string;
  event_type: AuditEventType;
  /** RFC 3339 UTC timestamp with millisecond precision. */
  timestamp: string;
  /** W3C Trace Context traceparent (version 00). */
  traceparent: string;
  tracestate?: string;
  session_id: string;
  server: AuditServerInfo;
  client?: AuditClientInfo;
  principal?: string;
  tool?: AuditToolDetails;
  resource?: AuditResourceDetails;
  prompt?: AuditPromptDetails;
  outcome: AuditOutcome;
  duration_ms?: number;
  attributes?: Record<string, unknown>;
}

/**
 * Destination for audit events. Exporters must not throw out of `export`;
 * failures should be reported through the logger's onExportError hook, which
 * wraps every exporter call.
 */
export interface AuditExporter {
  /** Deliver a batch of events. May be sync or async. */
  export(events: AuditEvent[]): void | Promise<void>;
  /** Flush buffers and release resources. Called by AuditLogger.shutdown(). */
  shutdown?(): void | Promise<void>;
}
