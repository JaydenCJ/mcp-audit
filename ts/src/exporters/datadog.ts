/**
 * Datadog Logs exporter (HTTP intake v2).
 *
 * Sends each audit event as a Datadog log item. The canonical audit record
 * travels in `message`; standard attributes (service, ddsource, evt.name)
 * and the APM correlation ids (dd.trace_id / dd.span_id, derived from the
 * W3C traceparent) are set so audit records join traces in Datadog.
 * Field mapping table: SPEC.md section 6.
 */
import type { AuditEvent, AuditExporter } from "../types.js";
import { parseTraceparent } from "../trace.js";
import { httpPost } from "./http.js";

export interface DatadogExporterOptions {
  /** Datadog API key. Sent as the DD-API-KEY header. */
  apiKey: string;
  /** Datadog site, e.g. datadoghq.com, datadoghq.eu, us5.datadoghq.com. */
  site?: string;
  /** Full intake URL override (takes precedence over site). Useful for tests and proxies. */
  url?: string;
  /** Log `service`. Defaults to the event's server.name. */
  service?: string;
  /** Comma-separated ddtags, e.g. "env:prod,team:platform". */
  ddtags?: string;
  timeoutMs?: number;
}

/**
 * Datadog APM correlation expects the decimal form of the lower 64 bits of
 * the trace id and of the span id.
 */
function lower64Decimal(hex: string): string {
  return BigInt(`0x${hex.slice(-16)}`).toString(10);
}

/** Build the intake payload for a batch (exported for tests). */
export function toDatadogPayload(
  events: AuditEvent[],
  options: Pick<DatadogExporterOptions, "service" | "ddtags">
): unknown[] {
  return events.map((event) => {
    const trace = parseTraceparent(event.traceparent);
    return {
      ddsource: "mcp-audit",
      ...(options.ddtags ? { ddtags: options.ddtags } : {}),
      service: options.service ?? event.server.name,
      message: JSON.stringify(event),
      status: event.outcome.status === "error" ? "error" : "info",
      evt: { name: `mcp.audit.${event.event_type}` },
      mcp: {
        session_id: event.session_id,
        ...(event.tool ? { tool_name: event.tool.name } : {}),
        ...(event.duration_ms !== undefined ? { duration_ms: event.duration_ms } : {}),
      },
      ...(trace
        ? { dd: { trace_id: lower64Decimal(trace.traceId), span_id: lower64Decimal(trace.spanId) } }
        : {}),
    };
  });
}

export class DatadogExporter implements AuditExporter {
  private readonly options: DatadogExporterOptions;

  constructor(options: DatadogExporterOptions) {
    this.options = options;
  }

  async export(events: AuditEvent[]): Promise<void> {
    if (events.length === 0) return;
    const url =
      this.options.url ?? `https://http-intake.logs.${this.options.site ?? "datadoghq.com"}/api/v2/logs`;
    await httpPost({
      url,
      headers: {
        "dd-api-key": this.options.apiKey,
        "content-type": "application/json",
      },
      body: JSON.stringify(toDatadogPayload(events, this.options)),
      timeoutMs: this.options.timeoutMs,
    });
  }
}
