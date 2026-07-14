# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-08

### Added

- MCP Audit Event Specification v0.1 (`SPEC.md`) with six event types
  (`tool_call`, `resource_read`, `prompt_invoke`, `session_start`,
  `session_end`, `error`) and SIEM field mapping tables for Splunk CIM,
  Datadog and OpenTelemetry logs.
- Canonical JSON Schema (`schema/audit-event.schema.json`, draft 2020-12)
  plus positive/negative validation test suites.
- TypeScript SDK (`ts/`): `withAudit(server)` middleware for
  `@modelcontextprotocol/sdk` servers, `AuditLogger`, W3C Trace Context
  helpers, default-on argument redaction with canonical SHA-256 digests,
  and five exporters (console, JSONL file, OTLP/HTTP, Splunk HEC, Datadog).
- Protocol-rejected operations are audited: `withAudit` wraps the SDK's
  `tools/call` / `resources/read` / `prompts/get` request handlers so
  unknown names, disabled entries and schema-invalid arguments emit their
  operation event with an `error` outcome (probe traffic stays visible),
  without double-counting handled requests.
- Python SDK (`python/`, zero third-party dependencies): `AuditLogger`
  with context-manager spans and an `audited_tool` decorator, mirroring
  the TypeScript API and exporters.
- Cross-language conformance tests: events from both SDKs validate
  against the same JSON Schema, with a pinned shared digest vector.
- Protocol round-trip smoke test (`scripts/smoke.sh`): stdio MCP server,
  raw JSON-RPC client, invalid-input paths, audit-trail assertions.
- Audit log conformance validator (`ts/scripts/validate-events.mjs`).
- MCP Extension proposal draft (`docs/sep-draft.md`).

[0.1.0]: https://github.com/JaydenCJ/mcp-audit
