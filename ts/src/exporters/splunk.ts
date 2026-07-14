/**
 * Splunk HTTP Event Collector (HEC) exporter.
 *
 * Sends each audit event as a HEC event envelope whose `event` field is the
 * canonical audit record. Splunk CIM field mapping: SPEC.md section 6.
 */
import type { AuditEvent, AuditExporter } from "../types.js";
import { httpPost } from "./http.js";

export interface SplunkHecExporterOptions {
  /** Base URL of the HEC endpoint, e.g. https://splunk.example.com:8088 */
  url: string;
  /** HEC token. Sent as `Authorization: Splunk <token>`. */
  token: string;
  /** HEC metadata. */
  source?: string;
  sourcetype?: string;
  index?: string;
  host?: string;
  timeoutMs?: number;
}

/** Build the newline-delimited HEC payload for a batch (exported for tests). */
export function toHecPayload(events: AuditEvent[], meta: Omit<SplunkHecExporterOptions, "url" | "token" | "timeoutMs">): string {
  return events
    .map((event) =>
      JSON.stringify({
        time: Date.parse(event.timestamp) / 1000,
        source: meta.source ?? "mcp-audit",
        sourcetype: meta.sourcetype ?? "mcp:audit",
        ...(meta.index ? { index: meta.index } : {}),
        ...(meta.host ? { host: meta.host } : {}),
        event,
      })
    )
    .join("\n");
}

export class SplunkHecExporter implements AuditExporter {
  private readonly options: SplunkHecExporterOptions;

  constructor(options: SplunkHecExporterOptions) {
    this.options = options;
  }

  async export(events: AuditEvent[]): Promise<void> {
    if (events.length === 0) return;
    const { url, token, timeoutMs, ...meta } = this.options;
    await httpPost({
      url: `${url.replace(/\/$/, "")}/services/collector/event`,
      headers: {
        authorization: `Splunk ${token}`,
        "content-type": "application/json",
      },
      body: toHecPayload(events, meta),
      timeoutMs,
    });
  }
}
