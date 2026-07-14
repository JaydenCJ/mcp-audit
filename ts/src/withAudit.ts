/**
 * withAudit(server) — audit middleware for MCP servers built with the
 * official @modelcontextprotocol/sdk McpServer class.
 *
 * It wraps tool/resource/prompt registration so every invocation emits one
 * spec-conformant audit event, wraps the SDK's request handlers so
 * operations the protocol layer rejects before any callback runs (unknown
 * tool/resource/prompt names, disabled entries, schema-invalid arguments)
 * are audited too, and hooks the session lifecycle (initialize, close,
 * protocol errors). The server object is patched in place and returned, so
 * it drops into existing code:
 *
 *   const server = withAudit(new McpServer(...), { exporters: [...] });
 *
 * The SDK is a type-erased structural dependency here: withAudit only
 * relies on the documented public surface (registerTool/registerResource/
 * registerPrompt, the deprecated tool/resource/prompt variants,
 * setRequestHandler on the underlying server, and its
 * oninitialized/onclose/onerror hooks).
 */
import { AuditLogger, type AuditLoggerOptions, type OperationContext, type AuditSpan } from "./logger.js";
import type { AuditServerInfo, AuditTransport } from "./types.js";
import type { RedactionPolicy } from "./redact.js";

/** Structural view of the SDK's McpServer that withAudit relies on. */
export interface AuditableServer {
  server: {
    oninitialized?: (() => void) | undefined;
    onclose?: (() => void) | undefined;
    onerror?: ((error: Error) => void) | undefined;
    getClientVersion(): { name?: string; version?: string } | undefined;
    transport?: { sessionId?: string } | undefined;
  };
  registerTool(...args: unknown[]): unknown;
  registerResource(...args: unknown[]): unknown;
  registerPrompt(...args: unknown[]): unknown;
  tool(...args: unknown[]): unknown;
  resource(...args: unknown[]): unknown;
  prompt(...args: unknown[]): unknown;
}

export interface WithAuditOptions {
  /** Bring your own logger; when set, the other logger options are ignored. */
  logger?: AuditLogger;
  /** Identity stamped on events. Defaults to the McpServer's own info when readable. */
  server?: Partial<AuditServerInfo>;
  /** Transport label stamped on events (stdio, streamable_http, sse, custom). */
  transport?: AuditTransport;
  exporters?: AuditLoggerOptions["exporters"];
  redaction?: RedactionPolicy;
  onExportError?: AuditLoggerOptions["onExportError"];
}

const AUDITED = Symbol.for("mcp-audit.audited");

interface RequestExtraLike {
  requestId?: unknown;
  signal?: unknown;
  sessionId?: string;
  _meta?: Record<string, unknown>;
}

function isRequestExtra(value: unknown): value is RequestExtraLike {
  return (
    typeof value === "object" && value !== null && "requestId" in value && "signal" in value
  );
}

function operationContext(cbArgs: unknown[]): OperationContext {
  const last = cbArgs[cbArgs.length - 1];
  const ctx: OperationContext = {};
  if (isRequestExtra(last)) {
    const meta = last._meta;
    if (meta && typeof meta["traceparent"] === "string") {
      ctx.requestTraceparent = meta["traceparent"];
      if (typeof meta["tracestate"] === "string") {
        ctx.tracestate = meta["tracestate"];
      }
    }
    if (typeof last.sessionId === "string") ctx.sessionId = last.sessionId;
  }
  return ctx;
}

function errorInfo(err: unknown): { code?: number; message: string } {
  if (err && typeof err === "object") {
    const anyErr = err as { code?: unknown; message?: unknown };
    return {
      ...(typeof anyErr.code === "number" ? { code: anyErr.code } : {}),
      message: typeof anyErr.message === "string" ? anyErr.message : String(err),
    };
  }
  return { message: String(err) };
}

/** Extract a short error message from a CallToolResult with isError: true. */
function toolResultErrorMessage(result: Record<string, unknown>): string {
  const content = result["content"];
  if (Array.isArray(content)) {
    for (const item of content) {
      if (item && typeof item === "object" && (item as { type?: string }).type === "text") {
        const text = (item as { text?: unknown }).text;
        if (typeof text === "string" && text.length > 0) return text.slice(0, 512);
      }
    }
  }
  return "tool returned isError";
}

function finishFromResult(span: AuditSpan, kind: string, value: unknown): void {
  if (
    kind === "tool_call" &&
    value !== null &&
    typeof value === "object" &&
    (value as { isError?: unknown }).isError === true
  ) {
    span.fail({ message: toolResultErrorMessage(value as Record<string, unknown>) });
    return;
  }
  span.succeed();
}

/** Request methods whose protocol-layer rejections must still be audited. */
const OPERATION_METHODS: Record<string, "tool_call" | "resource_read" | "prompt_invoke"> = {
  "tools/call": "tool_call",
  "resources/read": "resource_read",
  "prompts/get": "prompt_invoke",
};

/**
 * Read the method literal out of an SDK request schema (a zod object whose
 * `method` field is a literal). Returns undefined for shapes we do not
 * recognize; those handlers are installed un-instrumented.
 */
function methodOfSchema(schema: unknown): string | undefined {
  if (schema === null || typeof schema !== "object") return undefined;
  const withShape = schema as { shape?: unknown; _def?: { shape?: unknown } };
  let shape = withShape.shape;
  if (shape === undefined) {
    const defShape = withShape._def?.shape;
    shape = typeof defShape === "function" ? (defShape as () => unknown)() : defShape;
  }
  if (shape === null || typeof shape !== "object") return undefined;
  const method = (shape as { method?: unknown }).method;
  if (method === null || typeof method !== "object") return undefined;
  const literal = method as { value?: unknown; _def?: { value?: unknown } };
  const value = literal.value ?? literal._def?.value;
  return typeof value === "string" ? value : undefined;
}

/** Stable set key for the JSON-RPC request id carried in RequestHandlerExtra. */
function requestKey(extra: unknown): string | undefined {
  if (!isRequestExtra(extra)) return undefined;
  const id = extra.requestId;
  if (typeof id === "string" || typeof id === "number") return `${typeof id}:${id}`;
  return undefined;
}

/** The params object of a JSON-RPC request, or an empty object. */
function paramsOf(request: unknown): Record<string, unknown> {
  const params = (request as { params?: unknown } | null)?.params;
  return params !== null && typeof params === "object" ? (params as Record<string, unknown>) : {};
}

/** The SDK bakes the JSON-RPC error code into McpError messages; recover it. */
function errorCodeFromMessage(message: string): number | undefined {
  const match = /^MCP error (-?\d+):/.exec(message);
  return match ? Number(match[1]) : undefined;
}

type ProtocolOutcome =
  | { status: "success" }
  | { status: "error"; error: { code?: number; message: string } };

/** Outcome for a request the protocol layer answered without a callback. */
function protocolResultOutcome(kind: string, value: unknown): ProtocolOutcome {
  if (
    kind === "tool_call" &&
    value !== null &&
    typeof value === "object" &&
    (value as { isError?: unknown }).isError === true
  ) {
    const message = toolResultErrorMessage(value as Record<string, unknown>);
    const code = errorCodeFromMessage(message);
    return { status: "error", error: { ...(code !== undefined ? { code } : {}), message } };
  }
  return { status: "success" };
}

function bestEffortServerInfo(server: AuditableServer): Partial<AuditServerInfo> {
  // The SDK keeps the Implementation passed to the constructor in a private
  // field; read it defensively and fall back to a generic name.
  const impl = (server.server as unknown as { _serverInfo?: { name?: string; version?: string } })
    ._serverInfo;
  if (impl && typeof impl.name === "string") {
    return { name: impl.name, ...(typeof impl.version === "string" ? { version: impl.version } : {}) };
  }
  return {};
}

type AnyFn = (...args: unknown[]) => unknown;

/**
 * Patch an MCP server so that every tool call, resource read and prompt
 * invocation emits an audit event — including requests the protocol layer
 * rejects before a handler runs (unknown names, schema-invalid arguments),
 * which are recorded with an error outcome — and the session lifecycle is
 * recorded.
 *
 * Call withAudit BEFORE registering tools/resources/prompts: only
 * registrations (and the request handlers the SDK installs for them) made
 * after the call are instrumented.
 */
export function withAudit<T extends AuditableServer>(server: T, options: WithAuditOptions = {}): T {
  const marked = server as T & { [AUDITED]?: AuditLogger };
  if (marked[AUDITED]) return server;

  const inferred = bestEffortServerInfo(server);
  const logger =
    options.logger ??
    new AuditLogger({
      server: {
        name: options.server?.name ?? inferred.name ?? "mcp-server",
        ...(options.server?.version ?? inferred.version
          ? { version: options.server?.version ?? inferred.version }
          : {}),
        ...(options.transport ?? options.server?.transport
          ? { transport: options.transport ?? options.server?.transport }
          : {}),
      },
      ...(options.exporters ? { exporters: options.exporters } : {}),
      ...(options.redaction ? { redaction: options.redaction } : {}),
      ...(options.onExportError ? { onExportError: options.onExportError } : {}),
    });
  marked[AUDITED] = logger;

  // Request ids whose registered callback has begun an audit span. The
  // protocol-layer wrapper below consults this set so a request is never
  // counted twice; entries are removed when the request handler settles.
  const callbackAudited = new Set<string>();

  const wrap = (
    kind: "tool_call" | "resource_read" | "prompt_invoke",
    name: string,
    cb: AnyFn
  ): AnyFn => {
    return function wrapped(this: unknown, ...cbArgs: unknown[]): unknown {
      const key = requestKey(cbArgs[cbArgs.length - 1]);
      if (key !== undefined) callbackAudited.add(key);
      const ctx = operationContext(cbArgs);
      const details =
        kind === "resource_read"
          ? { uri: String(cbArgs[0] ?? ""), name }
          : {
              name,
              arguments:
                cbArgs.length >= 2 && !isRequestExtra(cbArgs[0])
                  ? (cbArgs[0] as Record<string, unknown>)
                  : undefined,
            };
      const span = logger.beginOperation(kind, details, ctx);
      try {
        const result = cb.apply(this, cbArgs);
        if (result && typeof (result as PromiseLike<unknown>).then === "function") {
          return (result as Promise<unknown>).then(
            (value) => {
              finishFromResult(span, kind, value);
              return value;
            },
            (err) => {
              span.fail(errorInfo(err));
              throw err;
            }
          );
        }
        finishFromResult(span, kind, result);
        return result;
      } catch (err) {
        span.fail(errorInfo(err));
        throw err;
      }
    };
  };

  /** Replace the trailing function argument with its wrapped version. */
  const patchRegistration = (
    method: "registerTool" | "registerResource" | "registerPrompt" | "tool" | "resource" | "prompt",
    kind: "tool_call" | "resource_read" | "prompt_invoke"
  ): void => {
    const original = server[method].bind(server) as AnyFn;
    (server as Record<string, unknown>)[method] = (...args: unknown[]): unknown => {
      const lastIndex = args.length - 1;
      const cb = args[lastIndex];
      if (typeof cb === "function") {
        const name = typeof args[0] === "string" ? args[0] : "";
        args[lastIndex] = wrap(kind, name, cb as AnyFn);
      }
      return original(...args);
    };
  };

  patchRegistration("registerTool", "tool_call");
  patchRegistration("tool", "tool_call");
  patchRegistration("registerResource", "resource_read");
  patchRegistration("resource", "resource_read");
  patchRegistration("registerPrompt", "prompt_invoke");
  patchRegistration("prompt", "prompt_invoke");

  // Protocol-layer coverage: requests the SDK rejects before any registered
  // callback runs (unknown tool/resource/prompt, disabled entries, argument
  // schema validation failures) must still produce one audit event — probe
  // traffic is a security signal. The SDK resolves some of these as isError
  // tool results and rejects others as protocol errors; both paths are
  // captured by wrapping the request handlers it installs for tools/call,
  // resources/read and prompts/get.
  const emitProtocolOperation = (
    kind: "tool_call" | "resource_read" | "prompt_invoke",
    request: unknown,
    extra: unknown,
    outcome: ProtocolOutcome
  ): void => {
    const params = paramsOf(request);
    const details =
      kind === "resource_read"
        ? { uri: typeof params["uri"] === "string" ? (params["uri"] as string) : "" }
        : {
            name: typeof params["name"] === "string" ? (params["name"] as string) : "",
            ...(params["arguments"] !== null && typeof params["arguments"] === "object"
              ? { arguments: params["arguments"] as Record<string, unknown> }
              : {}),
          };
    const span = logger.beginOperation(kind, details, operationContext([extra]));
    if (outcome.status === "error") span.fail(outcome.error);
    else span.succeed();
  };

  const underlying = server.server as unknown as {
    setRequestHandler?: (schema: unknown, handler: AnyFn) => unknown;
  };
  if (typeof underlying.setRequestHandler === "function") {
    const originalSetRequestHandler = underlying.setRequestHandler.bind(server.server);
    underlying.setRequestHandler = (schema: unknown, handler: AnyFn): unknown => {
      const method = methodOfSchema(schema);
      const kind = method === undefined ? undefined : OPERATION_METHODS[method];
      if (kind === undefined || typeof handler !== "function") {
        return originalSetRequestHandler(schema, handler);
      }
      const audited = async (request: unknown, extra: unknown): Promise<unknown> => {
        const key = requestKey(extra);
        try {
          const result = await handler(request, extra);
          if (key !== undefined && !callbackAudited.has(key)) {
            emitProtocolOperation(kind, request, extra, protocolResultOutcome(kind, result));
          }
          return result;
        } catch (err) {
          if (key !== undefined && !callbackAudited.has(key)) {
            emitProtocolOperation(kind, request, extra, { status: "error", error: errorInfo(err) });
          }
          throw err;
        } finally {
          if (key !== undefined) callbackAudited.delete(key);
        }
      };
      return originalSetRequestHandler(schema, audited);
    };
  }

  // Session lifecycle: initialize -> session_start, close -> session_end.
  const previousInit = server.server.oninitialized;
  server.server.oninitialized = () => {
    const clientVersion = server.server.getClientVersion();
    const transportSession = server.server.transport?.sessionId;
    logger.recordSessionStart({
      ...(clientVersion ? { client: { name: clientVersion.name, version: clientVersion.version } } : {}),
      ...(typeof transportSession === "string" ? { sessionId: transportSession } : {}),
    });
    previousInit?.();
  };

  let sessionEnded = false;
  const previousClose = server.server.onclose;
  server.server.onclose = () => {
    if (!sessionEnded) {
      sessionEnded = true;
      logger.recordSessionEnd();
    }
    previousClose?.();
  };

  const previousError = server.server.onerror;
  server.server.onerror = (error: Error) => {
    logger.recordError(errorInfo(error));
    previousError?.(error);
  };

  return server;
}

/** Access the AuditLogger attached to a server by withAudit (e.g. to flush). */
export function getAuditLogger(server: AuditableServer): AuditLogger | undefined {
  return (server as AuditableServer & { [AUDITED]?: AuditLogger })[AUDITED];
}
