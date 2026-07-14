/**
 * mcp-audit — open audit-log standard for the Model Context Protocol.
 *
 * Public API surface:
 * - withAudit / getAuditLogger: middleware for @modelcontextprotocol/sdk servers
 * - AuditLogger: low-level event builder for custom integrations
 * - Exporters: Console, JSONL file, OTLP/HTTP, Splunk HEC, Datadog
 * - Redaction and W3C Trace Context helpers
 *
 * Importing this module has zero side effects: no network, no file writes.
 */
export type {
  AuditEvent,
  AuditEventType,
  AuditExporter,
  AuditOutcome,
  AuditServerInfo,
  AuditClientInfo,
  AuditStatus,
  AuditTransport,
  AuditToolDetails,
  AuditResourceDetails,
  AuditPromptDetails,
  ArgumentsDigest,
} from "./types.js";

export {
  AuditLogger,
  type AuditLoggerOptions,
  type OperationContext,
  type AuditSpan,
} from "./logger.js";

export { withAudit, getAuditLogger, type WithAuditOptions, type AuditableServer } from "./withAudit.js";

export {
  redactArguments,
  digestArguments,
  canonicalJson,
  REDACTED,
  DEFAULT_SENSITIVE_KEY_PARTS,
  DEFAULT_SENSITIVE_KEY_EXACT,
  DEFAULT_SENSITIVE_VALUE_PATTERNS,
  type RedactionPolicy,
  type RedactionMode,
  type RedactionResult,
} from "./redact.js";

export {
  parseTraceparent,
  generateTraceparent,
  childTraceparent,
  isValidTraceparent,
  type TraceContext,
} from "./trace.js";

export { ConsoleExporter, type ConsoleExporterOptions } from "./exporters/console.js";
export { JsonlExporter } from "./exporters/jsonl.js";
export { OtlpHttpExporter, toOtlpLogsPayload, type OtlpHttpExporterOptions } from "./exporters/otlp.js";
export { SplunkHecExporter, toHecPayload, type SplunkHecExporterOptions } from "./exporters/splunk.js";
export { DatadogExporter, toDatadogPayload, type DatadogExporterOptions } from "./exporters/datadog.js";
