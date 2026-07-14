# SEP Draft: Structured Audit Events Extension for MCP

> Draft proposal intended for submission to the Model Context Protocol
> specification repository as an Extension SEP. Field-level details live in
> [../SPEC.md](../SPEC.md); this document is the proposal narrative.
> Section numbering of the upstream SEP template should be re-checked
> against the published Extensions process before submission.

- **Title:** Structured Audit Events for MCP Servers and Gateways
- **Type:** Extension
- **Status:** Draft (pre-submission)
- **Requires:** W3C Trace Context propagation via request `_meta`
  (SEP-414-style), MCP Extensions mechanism
- **Reference implementation:** https://github.com/JaydenCJ/mcp-audit
  (TypeScript + Python, MIT)

## Abstract

This SEP defines a vendor-neutral structured audit event format for MCP
servers and gateways. Each tool call, resource read, prompt invocation,
session lifecycle transition and protocol error maps to exactly one JSON
event with a fixed schema, W3C Trace Context correlation, a default-on
argument redaction policy, and documented field mappings to Splunk CIM,
Datadog and OpenTelemetry logs.

## Motivation

The MCP 2026 roadmap lists structured audit trails that can feed
SIEM/APM systems as an open gap, to be addressed through Extensions.
Joint NSA/CISA guidance on MCP deployments (2026-06) likewise calls out
authorization and audit as the weakest links in current enterprise MCP
rollouts.

Today every gateway and enterprise platform that audits MCP traffic
invents its own log format. The result:

1. **No portability.** Detection rules, dashboards and retention policies
   written against one gateway's format do not transfer to another.
2. **No end-to-end story.** A tool call that crosses a client, a gateway
   and a server produces three unrelated log lines that cannot be joined
   with application traces.
3. **Redaction as an afterthought.** Tool arguments routinely contain
   credentials and personal data; ad-hoc logging pipelines ship them to
   log storage in clear text.

A common event schema solves all three at the ecosystem level, the same
way W3C Trace Context solved cross-vendor trace correlation. This proposal
deliberately specifies **only the event format** — not transport, not
storage, not gateway behaviour — so existing gateways can adopt it as
their export format rather than compete with it.

## Specification

The normative text is the MCP Audit Event Specification v0.1
([SPEC.md](../SPEC.md)) and its canonical JSON Schema
([schema/audit-event.schema.json](../schema/audit-event.schema.json)).
Summary of the normative core:

- Six event types: `tool_call`, `resource_read`, `prompt_invoke`,
  `session_start`, `session_end`, `error`.
- Required fields on every event: `spec_version`, `event_id`,
  `event_type`, `timestamp` (RFC 3339 UTC), `traceparent` (W3C, version
  00), `session_id`, `server`, `outcome`.
- Operation events additionally require operation details and
  `duration_ms`; tool/prompt events require an `arguments_digest`
  (SHA-256 over canonical JSON of the original arguments).
- Argument capture modes `omit` / `redact` / `raw`, default `redact`,
  with a specified minimum deny list and secret-shaped value patterns.
- Trace continuation rules: requests carrying `traceparent` in `_meta`
  produce child contexts; otherwise events share a session-scoped trace.
- Operations rejected by the protocol layer before a handler runs
  (unknown tool/resource/prompt names, argument schema validation
  failures) still produce their operation event with an `error` outcome,
  so enumeration and malformed-input probing stay visible to the SIEM.

## Rationale

- **Events, not wire messages.** Auditing at the JSON-RPC message level
  would couple the format to protocol revisions and record noise
  (pings, progress). Auditing at the *action* level matches what
  security teams review and what SIEM correlation rules operate on.
- **Digest over payload.** Storing full arguments is a data-retention
  liability; storing nothing breaks incident forensics. A canonical-JSON
  SHA-256 with an explicit redaction manifest is the middle ground: it
  proves what was sent without storing it.
- **`snake_case` flat-ish JSON.** Chosen for direct ingestion by Splunk,
  Datadog and OTel collectors without field renaming.
- **Extension, not core.** Audit is an enterprise deployment concern;
  the Extensions mechanism exists precisely so such concerns do not
  bloat the core protocol.

## Backwards compatibility

The extension is additive. Servers that do not implement it are
unaffected. Instrumented servers emit events out of band (files, HTTP
exporters); nothing changes on the MCP wire except optional use of the
already-proposed `_meta` trace propagation.

## Reference implementation

This repository provides:

- TypeScript middleware `withAudit(server)` for
  `@modelcontextprotocol/sdk` servers, and a Python `AuditLogger` with a
  decorator/context-manager API (zero third-party dependencies);
- five exporters per SDK (console, JSONL, OTLP/HTTP, Splunk HEC, Datadog);
- the canonical JSON Schema plus a conformance validator
  (`ts/scripts/validate-events.mjs`);
- a cross-language conformance suite that validates events from both SDKs
  against the same schema, and an end-to-end stdio protocol round-trip
  test (`scripts/smoke.sh`).

## Security considerations

- Redaction defaults to ON; the `raw` mode is opt-in and documented as
  unsuitable outside closed environments.
- Argument digests of low-entropy inputs are brute-forceable; the
  specification calls this out and deployments can treat digests as
  sensitive metadata.
- Audit event delivery must never block or fail the audited operation
  (availability of the agent must not depend on availability of the
  SIEM); the reference implementations isolate exporter failures.
- Exporters authenticate with bearer-style secrets (HEC token, Datadog
  API key); implementations must not log these values and must not embed
  defaults.

## Open questions for review

1. Should `principal` be structured (issuer + subject) instead of an
   opaque string?
2. Is one event per `tools/call` sufficient for streaming/long-running
   tasks, or do `task_*` lifecycle events belong in v0.2?
3. Should the extension register a well-known capability name so clients
   can discover that a server emits audit events?
