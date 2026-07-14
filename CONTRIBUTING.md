# Contributing to mcp-audit

Thanks for your interest in improving mcp-audit. The project has two SDKs
(TypeScript and Python) and one canonical specification; most contributions
touch one of the three.

## Development setup

```bash
git clone https://github.com/JaydenCJ/mcp-audit.git
cd mcp-audit
cd mcp-audit

# TypeScript SDK
cd ts && npm install && npm run build && npm test

# Python SDK (standard library only, no install step needed)
cd ../python && python3 -m unittest discover -s tests -v

# End-to-end protocol round-trip
cd .. && bash scripts/smoke.sh
```

Node.js >= 18 and Python >= 3.9 are required. The TypeScript test suite
shells out to `python3` for the cross-language conformance tests, so both
toolchains must be present to run it fully.

## Ground rules

- **The schema is the contract.** Any change to event semantics must update
  `schema/audit-event.schema.json`, `SPEC.md`, both SDKs and the tests in
  the same pull request. The cross-language suite
  (`ts/tests/cross-language.test.ts`) must stay green.
- **Redaction defaults stay on.** Changes that weaken the default redaction
  policy will not be accepted.
- **Audit must never break the audited server.** Exporter and logger code
  paths that can throw into an MCP handler are bugs.
- **No new runtime dependencies in the Python SDK** (it is intentionally
  stdlib-only) and no non-optional runtime dependencies in the TypeScript
  SDK beyond the optional `@modelcontextprotocol/sdk` peer.
- Code comments and test descriptions are written in English.

## Pull requests

1. Open an issue or discussion first for spec-level changes (new fields,
   new event types) — those need review as SEP feedback too.
2. Include tests: schema changes need positive and negative validation
   cases; exporter changes need mock-receiver assertions.
3. Run all three test entry points above before submitting.
4. Keep commits focused; one logical change per PR.

## Reporting security issues

If you find a way to make the middleware leak secrets that the default
policy should have redacted, please report it privately via GitHub security
advisories rather than a public issue.
