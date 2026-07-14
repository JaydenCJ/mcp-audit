/**
 * AuditLogger builds spec-conformant audit events and fans them out to the
 * configured exporters. It is the low-level API; most MCP server authors
 * should use withAudit() instead and never touch this class directly.
 */
import { randomUUID } from "node:crypto";
import type {
  AuditClientInfo,
  AuditEvent,
  AuditEventType,
  AuditExporter,
  AuditOutcome,
  AuditServerInfo,
} from "./types.js";
import { digestArguments, redactArguments, type RedactionPolicy } from "./redact.js";
import { childTraceparent, generateTraceparent, isValidTraceparent } from "./trace.js";

/** Configuration for AuditLogger. */
export interface AuditLoggerOptions {
  /** Identity of the MCP server being audited. */
  server: AuditServerInfo;
  /** Destinations for events. Defaults to an empty list (events are dropped). */
  exporters?: AuditExporter[];
  /** Redaction policy for inline argument copies. Default mode: "redact". */
  redaction?: RedactionPolicy;
  /**
   * Called when an exporter throws or rejects. Defaults to a single-line
   * warning on stderr. Export failures never propagate into the MCP handler.
   */
  onExportError?: (error: unknown, exporter: AuditExporter) => void;
}

/** Per-operation fields accepted by the record* helpers. */
export interface OperationContext {
  /** traceparent carried by the incoming request _meta, if any (SEP-414). */
  requestTraceparent?: string;
  /** tracestate carried alongside the request traceparent, if any. */
  tracestate?: string;
  /** Transport session id, when the transport provides one. */
  sessionId?: string;
  client?: AuditClientInfo;
  principal?: string;
  attributes?: Record<string, unknown>;
}

/** An in-flight operation returned by beginOperation(). */
export interface AuditSpan {
  /** The traceparent assigned to this operation. */
  traceparent: string;
  /** Record the operation as succeeded. */
  succeed(): void;
  /** Record the operation as failed. */
  fail(error: { code?: number; message: string }): void;
}

function defaultExportError(error: unknown, exporter: AuditExporter): void {
  const name = exporter.constructor?.name ?? "exporter";
  process.stderr.write(`[mcp-audit] export failed via ${name}: ${String(error)}\n`);
}

function nowRfc3339(): string {
  return new Date().toISOString();
}

export class AuditLogger {
  readonly serverInfo: AuditServerInfo;
  private readonly exporters: AuditExporter[];
  private readonly redaction: RedactionPolicy;
  private readonly onExportError: (error: unknown, exporter: AuditExporter) => void;
  private readonly pending = new Set<Promise<void>>();
  /** Session-scoped state. One logger instance serves one MCP session by default. */
  private sessionId: string;
  private sessionTraceparent: string;
  private client?: AuditClientInfo;
  private sessionStartedAt?: number;

  constructor(options: AuditLoggerOptions) {
    this.serverInfo = options.server;
    this.exporters = options.exporters ?? [];
    this.redaction = options.redaction ?? {};
    this.onExportError = options.onExportError ?? defaultExportError;
    this.sessionId = randomUUID();
    this.sessionTraceparent = generateTraceparent();
  }

  /** The session id events are stamped with. */
  getSessionId(): string {
    return this.sessionId;
  }

  /** Resolve the traceparent for an operation, honouring request _meta. */
  private resolveTraceparent(requestTraceparent?: string): string {
    if (requestTraceparent && isValidTraceparent(requestTraceparent)) {
      return childTraceparent(requestTraceparent);
    }
    return childTraceparent(this.sessionTraceparent);
  }

  /** Build and export a session_start event. */
  recordSessionStart(ctx: OperationContext = {}): AuditEvent {
    if (ctx.sessionId) this.sessionId = ctx.sessionId;
    if (ctx.client) this.client = ctx.client;
    this.sessionStartedAt = Date.now();
    if (ctx.requestTraceparent && isValidTraceparent(ctx.requestTraceparent)) {
      this.sessionTraceparent = ctx.requestTraceparent;
    }
    return this.emit({
      event_type: "session_start",
      traceparent: this.resolveTraceparent(ctx.requestTraceparent),
      outcome: { status: "success" },
      ctx,
    });
  }

  /** Build and export a session_end event. */
  recordSessionEnd(ctx: OperationContext = {}): AuditEvent {
    const duration =
      this.sessionStartedAt === undefined ? undefined : Math.max(0, Date.now() - this.sessionStartedAt);
    return this.emit({
      event_type: "session_end",
      traceparent: this.resolveTraceparent(ctx.requestTraceparent),
      outcome: { status: "success" },
      duration_ms: duration,
      ctx,
    });
  }

  /** Build and export a protocol-level error event (not tied to one operation). */
  recordError(error: { code?: number; message: string }, ctx: OperationContext = {}): AuditEvent {
    return this.emit({
      event_type: "error",
      traceparent: this.resolveTraceparent(ctx.requestTraceparent),
      outcome: { status: "error", error },
      ctx,
    });
  }

  /**
   * Start timing a tool_call / resource_read / prompt_invoke operation.
   * Exactly one of succeed()/fail() must be called; the event is exported then.
   */
  beginOperation(
    kind: Extract<AuditEventType, "tool_call" | "resource_read" | "prompt_invoke">,
    details: { name?: string; uri?: string; arguments?: Record<string, unknown> | null },
    ctx: OperationContext = {}
  ): AuditSpan {
    const startedAt = process.hrtime.bigint();
    const traceparent = this.resolveTraceparent(ctx.requestTraceparent);
    const finish = (outcome: AuditOutcome): void => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
      const body: Partial<AuditEvent> = {};
      if (kind === "tool_call") {
        body.tool = { name: details.name ?? "", ...this.captureArguments(details.arguments) };
      } else if (kind === "prompt_invoke") {
        body.prompt = { name: details.name ?? "", ...this.captureArguments(details.arguments) };
      } else {
        body.resource = { uri: details.uri ?? "", ...(details.name ? { name: details.name } : {}) };
      }
      this.emit({
        event_type: kind,
        traceparent,
        outcome,
        duration_ms: Math.round(durationMs * 1000) / 1000,
        body,
        ctx,
      });
    };
    let done = false;
    return {
      traceparent,
      succeed: () => {
        if (done) return;
        done = true;
        finish({ status: "success" });
      },
      fail: (error) => {
        if (done) return;
        done = true;
        finish({ status: "error", error });
      },
    };
  }

  /** Apply the redaction policy and compute the digest for arguments. */
  private captureArguments(args: Record<string, unknown> | null | undefined): {
    arguments?: Record<string, unknown> | null;
    arguments_digest: ReturnType<typeof digestArguments>;
  } {
    const mode = this.redaction.mode ?? "redact";
    if (mode === "raw") {
      return { arguments: args ?? null, arguments_digest: digestArguments(args) };
    }
    const { redacted, redactedKeys } = redactArguments(args, this.redaction);
    const digest = digestArguments(args, redactedKeys);
    if (mode === "omit") {
      return { arguments_digest: digest };
    }
    return { arguments: redacted, arguments_digest: digest };
  }

  private emit(input: {
    event_type: AuditEventType;
    traceparent: string;
    outcome: AuditOutcome;
    duration_ms?: number;
    body?: Partial<AuditEvent>;
    ctx: OperationContext;
  }): AuditEvent {
    const event: AuditEvent = {
      spec_version: "0.1",
      event_id: randomUUID(),
      event_type: input.event_type,
      timestamp: nowRfc3339(),
      traceparent: input.traceparent,
      session_id: input.ctx.sessionId ?? this.sessionId,
      server: this.serverInfo,
      outcome: input.outcome,
      ...input.body,
    };
    if (input.ctx.tracestate) event.tracestate = input.ctx.tracestate;
    const client = input.ctx.client ?? this.client;
    if (client && (client.name || client.version)) event.client = client;
    if (input.ctx.principal) event.principal = input.ctx.principal;
    if (input.duration_ms !== undefined) event.duration_ms = input.duration_ms;
    if (input.ctx.attributes) event.attributes = input.ctx.attributes;
    this.dispatch(event);
    return event;
  }

  private dispatch(event: AuditEvent): void {
    for (const exporter of this.exporters) {
      try {
        const result = exporter.export([event]);
        if (result && typeof (result as Promise<void>).then === "function") {
          const tracked: Promise<void> = (result as Promise<void>)
            .catch((err) => this.onExportError(err, exporter))
            .finally(() => this.pending.delete(tracked));
          this.pending.add(tracked);
        }
      } catch (err) {
        this.onExportError(err, exporter);
      }
    }
  }

  /** Wait for all in-flight async exports to settle. */
  async flush(): Promise<void> {
    while (this.pending.size > 0) {
      await Promise.all([...this.pending]);
    }
  }

  /** Flush and shut down every exporter. */
  async shutdown(): Promise<void> {
    await this.flush();
    for (const exporter of this.exporters) {
      try {
        await exporter.shutdown?.();
      } catch (err) {
        this.onExportError(err, exporter);
      }
    }
  }
}
