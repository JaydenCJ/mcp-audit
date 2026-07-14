/**
 * JSONL file exporter: appends one canonical JSON event per line.
 * The resulting file can be tailed by any log shipper (Fluent Bit,
 * Splunk Universal Forwarder, Datadog Agent, OTel Collector filelog).
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { AuditEvent, AuditExporter } from "../types.js";

export class JsonlExporter implements AuditExporter {
  private readonly path: string;
  private dirEnsured = false;

  constructor(path: string) {
    this.path = path;
  }

  export(events: AuditEvent[]): void {
    if (!this.dirEnsured) {
      mkdirSync(dirname(this.path), { recursive: true });
      this.dirEnsured = true;
    }
    let chunk = "";
    for (const event of events) {
      chunk += `${JSON.stringify(event)}\n`;
    }
    appendFileSync(this.path, chunk, "utf8");
  }
}
