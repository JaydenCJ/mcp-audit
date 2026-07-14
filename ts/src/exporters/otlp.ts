/**
 * OTLP/HTTP logs exporter.
 *
 * Emits audit events as OTLP LogRecords (JSON encoding) to an OpenTelemetry
 * Collector or any OTLP/HTTP-compatible backend. The full canonical audit
 * event travels as the log body; key fields are mirrored as attributes and
 * the W3C trace/span ids are set so SIEM/APM backends can join audit records
 * with application traces. Field mapping table: SPEC.md section 6.
 */
import type { AuditEvent, AuditExporter } from "../types.js";
import { parseTraceparent } from "../trace.js";
import { httpPost } from "./http.js";

export interface OtlpHttpExporterOptions {
  /** OTLP/HTTP logs endpoint. Default http://127.0.0.1:4318/v1/logs (local collector). */
  endpoint?: string;
  /** Extra headers, e.g. authentication for a hosted collector. */
  headers?: Record<string, string>;
  /** Resource attribute service.name. Defaults to the event's server.name. */
  serviceName?: string;
  timeoutMs?: number;
}

interface OtlpKeyValue {
  key: string;
  value: { stringValue?: string; intValue?: string; doubleValue?: number; boolValue?: boolean };
}

function attr(key: string, value: string | number | boolean): OtlpKeyValue {
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? { key, value: { intValue: String(value) } }
      : { key, value: { doubleValue: value } };
  }
  if (typeof value === "boolean") return { key, value: { boolValue: value } };
  return { key, value: { stringValue: value } };
}

/** Build the OTLP/JSON payload for a batch of events (exported for tests). */
export function toOtlpLogsPayload(events: AuditEvent[], serviceName?: string): unknown {
  const logRecords = events.map((event) => {
    const trace = parseTraceparent(event.traceparent);
    const attributes: OtlpKeyValue[] = [
      attr("event.name", `mcp.audit.${event.event_type}`),
      attr("mcp.session.id", event.session_id),
      attr("mcp.server.name", event.server.name),
      attr("mcp.outcome.status", event.outcome.status),
    ];
    if (event.tool) attributes.push(attr("mcp.tool.name", event.tool.name));
    if (event.resource) attributes.push(attr("mcp.resource.uri", event.resource.uri));
    if (event.prompt) attributes.push(attr("mcp.prompt.name", event.prompt.name));
    if (event.duration_ms !== undefined) attributes.push(attr("mcp.duration_ms", event.duration_ms));
    const record: Record<string, unknown> = {
      timeUnixNano: String(BigInt(Date.parse(event.timestamp)) * 1_000_000n),
      severityNumber: event.outcome.status === "error" ? 17 : 9,
      severityText: event.outcome.status === "error" ? "ERROR" : "INFO",
      body: { stringValue: JSON.stringify(event) },
      attributes,
    };
    if (trace) {
      record.traceId = trace.traceId;
      record.spanId = trace.spanId;
    }
    return record;
  });
  return {
    resourceLogs: [
      {
        resource: {
          attributes: [attr("service.name", serviceName ?? events[0]?.server.name ?? "mcp-server")],
        },
        scopeLogs: [
          {
            scope: { name: "mcp-audit", version: "0.1.0" },
            logRecords,
          },
        ],
      },
    ],
  };
}

export class OtlpHttpExporter implements AuditExporter {
  private readonly endpoint: string;
  private readonly headers: Record<string, string>;
  private readonly serviceName?: string;
  private readonly timeoutMs?: number;

  constructor(options: OtlpHttpExporterOptions = {}) {
    this.endpoint = options.endpoint ?? "http://127.0.0.1:4318/v1/logs";
    this.headers = { "content-type": "application/json", ...options.headers };
    this.serviceName = options.serviceName;
    this.timeoutMs = options.timeoutMs;
  }

  async export(events: AuditEvent[]): Promise<void> {
    if (events.length === 0) return;
    await httpPost({
      url: this.endpoint,
      headers: this.headers,
      body: JSON.stringify(toOtlpLogsPayload(events, this.serviceName)),
      timeoutMs: this.timeoutMs,
    });
  }
}
