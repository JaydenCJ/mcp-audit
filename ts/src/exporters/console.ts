/**
 * Console exporter: one JSON line per event.
 *
 * Writes to stderr by default. This matters for stdio MCP servers, where
 * stdout carries the JSON-RPC protocol stream and must stay clean.
 */
import type { AuditEvent, AuditExporter } from "../types.js";

export interface ConsoleExporterOptions {
  /** Target stream. Defaults to process.stderr. */
  stream?: { write(chunk: string): unknown };
  /** Prefix for each line. Defaults to "[mcp-audit] ". */
  prefix?: string;
}

export class ConsoleExporter implements AuditExporter {
  private readonly stream: { write(chunk: string): unknown };
  private readonly prefix: string;

  constructor(options: ConsoleExporterOptions = {}) {
    this.stream = options.stream ?? process.stderr;
    this.prefix = options.prefix ?? "[mcp-audit] ";
  }

  export(events: AuditEvent[]): void {
    for (const event of events) {
      this.stream.write(`${this.prefix}${JSON.stringify(event)}\n`);
    }
  }
}
