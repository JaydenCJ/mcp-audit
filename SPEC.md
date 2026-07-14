# MCP Audit Event Specification

**Version:** 0.1 (draft)
**Status:** Proposed as an MCP Extension — see [docs/sep-draft.md](docs/sep-draft.md)
**Canonical schema:** [`schema/audit-event.schema.json`](schema/audit-event.schema.json) (JSON Schema draft 2020-12)

This document defines a vendor-neutral, structured audit event format for
Model Context Protocol (MCP) servers and gateways. One audit event describes
one observable action: a tool call, a resource read, a prompt invocation, a
session lifecycle transition, or a protocol-level error. The format is
designed to land directly in existing SIEM/observability pipelines (Splunk,
Datadog, OpenTelemetry) without per-vendor translation.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

## 1. Design goals

1. **One event per action.** Every `tools/call`, `resources/read` and
   `prompts/get` handled by an instrumented server produces exactly one
   audit event, plus lifecycle events for session start/end. "Handled"
   includes requests the server rejects before any handler runs — unknown
   tool names and schema-invalid arguments are attacker-probing signals a
   SIEM must see, so they are recorded with an `error` outcome
   (section 2).
2. **Safe by default.** Tool arguments pass a redaction policy before they
   are stored anywhere; secrets never reach the exporter in the default
   configuration. An integrity digest of the original arguments is always
   kept so records stay correlatable and tamper-evident.
3. **Trace-joinable.** Every event carries a W3C Trace Context
   `traceparent`. When the MCP request itself carries one (per SEP-414
   style `_meta` propagation), the audit event continues that trace, so an
   agent action can be joined with application traces in an APM.
4. **SIEM-native.** Field names and the mapping tables in section 6 are
   chosen so that Splunk CIM, Datadog standard attributes and OTel log
   semantics can be populated mechanically.
5. **Implementation-neutral.** The format does not assume any particular
   server SDK, gateway or transport. This repository ships TypeScript and
   Python reference implementations; gateways are encouraged to emit the
   same format.

## 2. Event types

| `event_type` | Emitted when | Required extra fields |
|---|---|---|
| `tool_call` | A `tools/call` request was handled | `tool`, `duration_ms` |
| `resource_read` | A `resources/read` request was handled | `resource`, `duration_ms` |
| `prompt_invoke` | A `prompts/get` request was handled | `prompt`, `duration_ms` |
| `session_start` | The MCP session completed `initialize` | — |
| `session_end` | The MCP session closed | — (`duration_ms` SHOULD carry the session duration) |
| `error` | A protocol-level failure not attributable to one operation | `outcome.status` MUST be `error` |

**Rejected operations.** A `tools/call`, `resources/read` or `prompts/get`
request that the protocol layer rejects before any registered handler runs
— unknown or disabled tool/resource/prompt names, argument schema
validation failures — MUST still produce its operation event: same
`event_type`, the requested name or URI, the submitted arguments (passed
through the same capture/redaction policy of section 4) and an `outcome`
of `error` carrying the JSON-RPC error code when one exists. Enumeration
of tool names and malformed-argument probing are exactly the signals a
SIEM needs; they MUST NOT be invisible. Requests that never reach the
server's request dispatch — malformed JSON-RPC envelopes, requests for
methods the server registered no handler for, transport-level failures —
cannot be observed by in-process middleware; producers SHOULD emit an
`error` event when the underlying SDK surfaces such failures (the
reference TypeScript implementation does so via the server error hook),
and gateways SHOULD emit `error` events for traffic they reject
themselves.

## 3. Field reference

All field names are `snake_case`. Producers MUST NOT add top-level fields
beyond those defined here; deployment-specific data belongs under
`attributes` with namespaced keys (e.g. `acme.region`).

| Field | Type | Req. | Semantics |
|---|---|---|---|
| `spec_version` | const `"0.1"` | MUST | Version of this specification. |
| `event_id` | string (UUID) | MUST | Unique id of this event, lowercase hex. |
| `event_type` | enum | MUST | See section 2. |
| `timestamp` | string | MUST | Completion time, RFC 3339 UTC (`Z` suffix), millisecond or finer precision. |
| `traceparent` | string | MUST | W3C Trace Context value, version `00`, non-zero ids. See section 5. |
| `tracestate` | string | MAY | W3C `tracestate`, when propagated with the request. |
| `session_id` | string | MUST | MCP session identifier. Transport session id when the transport provides one, otherwise generated per connection. Stable across all events of one session. |
| `server` | object | MUST | `name` (MUST), `version`, `transport` (`stdio` \| `streamable_http` \| `sse` \| `custom`). |
| `client` | object | SHOULD | `name`, `version` as reported by the client during `initialize`. |
| `principal` | string | MAY | Authenticated identity the action ran for (e.g. OAuth subject). |
| `tool` | object | tool_call | `name` (MUST), `arguments` (inline copy after redaction; absent in `omit` mode), `arguments_digest` (MUST, see section 4). |
| `resource` | object | resource_read | `uri` (MUST), `name`. |
| `prompt` | object | prompt_invoke | `name` (MUST), `arguments`, `arguments_digest` (MUST). |
| `outcome` | object | MUST | `status`: `success` \| `error`. When `error`, `outcome.error.message` MUST be present; `outcome.error.code` SHOULD carry the JSON-RPC error code when one exists. |
| `duration_ms` | number ≥ 0 | see §2 | Wall-clock duration of the operation in milliseconds. |
| `attributes` | object | MAY | Namespaced extension attributes. |

## 4. Argument capture, redaction and digests

Producers MUST support three capture modes for `tool.arguments` /
`prompt.arguments` and default to `redact`:

| Mode | Inline copy | Digest |
|---|---|---|
| `omit` | absent | present |
| `redact` (default) | present, sensitive values replaced by `"[REDACTED]"` | present |
| `raw` | present, unchanged — only for closed environments | present |

**Redaction policy.** In `redact` mode a value MUST be replaced when either
(a) its key matches a deny list — the reference deny list matches keys whose
normalized form (lowercase, `-`/`_` stripped) contains `password`, `passwd`,
`secret`, `token`, `apikey`, `authorization`, `credential`, `privatekey`,
`accesskey`, `sessionkey` or `cookie`, or equals `auth`, `ssn`, `pin`,
`otp` — or (b) the string value itself matches a secret-shaped pattern
(JWTs, AWS access key ids, GitHub tokens, `sk-`-style API keys, `Bearer `
values). Deployments MAY extend both lists. The dot-paths of redacted keys
MUST be listed in `arguments_digest.redacted_keys`.

**Digest.** `arguments_digest.sha256` is the SHA-256 (lowercase hex) of the
**canonical JSON** encoding of the **original, pre-redaction** arguments;
`byte_length` is the byte length of that encoding. Canonical JSON here
means: object keys sorted lexicographically at every nesting level, no
insignificant whitespace, UTF-8 encoding, `null` for absent arguments. This
lets an auditor prove that two records saw identical arguments — and detect
tampering — without the payload ever being stored. Note the digest of
low-entropy arguments can be brute-forced; `omit`/`redact` modes protect
the inline copy, not the digest, and deployments with that threat model
SHOULD treat the digest as sensitive metadata.

## 5. Trace context (W3C / SEP-414 alignment)

1. If the incoming MCP request carries a valid `traceparent` string in its
   `_meta`, the producer MUST emit the event with a **child** context: same
   `trace-id` and flags, fresh `span-id`. A `tracestate` in `_meta` SHOULD
   be copied to the event.
2. Otherwise the producer MUST mint a session-scoped trace at
   `session_start` and emit every event of that session as a child of it,
   so all actions of one session share one `trace-id`.
3. All-zero `trace-id` or `span-id` values are invalid and MUST NOT be
   emitted; malformed inbound values MUST be ignored (fall back to rule 2).

## 6. SIEM field mappings

The canonical record is the JSON event itself. The reference exporters
apply these mappings so events are first-class citizens in each backend.

### 6.1 Splunk (HEC envelope / CIM)

| Audit field | HEC / CIM field |
|---|---|
| `timestamp` | envelope `time` (epoch seconds) |
| whole event | envelope `event` |
| — | `sourcetype`: `mcp:audit` (default), `source`: `mcp-audit` |
| `event_type` | CIM `action` (search-time alias) |
| `outcome.status` | CIM `status` |
| `principal` | CIM `user` |
| `server.name` | CIM `dest` |
| `duration_ms` | CIM `duration` (ms) |

### 6.2 Datadog (Logs intake v2)

| Audit field | Datadog attribute |
|---|---|
| whole event | `message` (JSON string) |
| `server.name` | `service` (unless overridden) |
| `event_type` | `evt.name` = `mcp.audit.<event_type>` |
| `outcome.status` | `status` (`info` / `error`) |
| `traceparent` trace-id (low 64 bits, decimal) | `dd.trace_id` |
| `traceparent` span-id (decimal) | `dd.span_id` |
| `session_id`, `tool.name`, `duration_ms` | `mcp.session_id`, `mcp.tool_name`, `mcp.duration_ms` |
| — | `ddsource`: `mcp-audit` |

### 6.3 OpenTelemetry (OTLP/HTTP logs)

| Audit field | OTLP LogRecord field |
|---|---|
| whole event | `body` (string value) |
| `timestamp` | `timeUnixNano` |
| `outcome.status` | `severityNumber`/`severityText` (INFO=9 / ERROR=17) |
| `traceparent` | `traceId`, `spanId` |
| `event_type` | attribute `event.name` = `mcp.audit.<event_type>` |
| `session_id`, `server.name`, `tool.name`, `resource.uri`, `prompt.name`, `duration_ms`, `outcome.status` | attributes `mcp.session.id`, `mcp.server.name`, `mcp.tool.name`, `mcp.resource.uri`, `mcp.prompt.name`, `mcp.duration_ms`, `mcp.outcome.status` |
| `server.name` | resource attribute `service.name` |

## 7. Delivery (non-normative)

How events reach a backend is out of scope for conformance. The reference
implementations ship five exporters: console (stderr — stdout belongs to
the stdio protocol stream), JSONL file (for log shippers), OTLP/HTTP,
Splunk HEC and Datadog. Producers SHOULD guarantee that audit failures
never fail the audited operation: exporter errors are reported out of band.

## 8. Conformance

A producer conforms to this specification when:

1. every emitted event validates against
   [`schema/audit-event.schema.json`](schema/audit-event.schema.json);
2. the redaction default is `redact` (section 4);
3. trace context follows section 5;
4. one operation produces exactly one operation event (section 2),
   including operations the protocol layer rejects before a handler runs.

`node ts/scripts/validate-events.mjs <file.jsonl>` validates any JSONL
audit log against the canonical schema and is the reference conformance
check. The cross-language test suite in this repository runs events from
both SDKs through that same schema.

## 9. Versioning

`spec_version` follows the specification, not the SDKs. Backwards-
compatible additions (new optional fields, new `attributes` conventions)
bump the minor version; breaking changes bump the major version. Consumers
SHOULD ignore unknown optional fields when a newer minor version appears.

The MCP protocol revision this specification targets is the 2025-06-18
protocol as extended by the Extensions mechanism finalized in 2026; SEP
numbering and extension registration details are tracked in
[docs/sep-draft.md](docs/sep-draft.md) and follow the published upstream
text once available.
