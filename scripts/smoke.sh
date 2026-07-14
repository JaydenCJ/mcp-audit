#!/usr/bin/env bash
# Protocol round-trip smoke test for mcp-audit.
# Starts the audited example MCP server (stdio), drives it with a raw
# JSON-RPC client (initialize -> tools/list -> tools/call, plus invalid
# input), then validates the audit trail on disk against the JSON Schema.
# Also validates Python-SDK sample events against the same schema.
# No network access: everything runs in-process or on 127.0.0.1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS_DIR="$ROOT/ts"
PY_DIR="$ROOT/python"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "[smoke] work dir: $WORK_DIR"

command -v node >/dev/null || { echo "[smoke] FAIL: node not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "[smoke] FAIL: python3 not found" >&2; exit 1; }

if [ ! -d "$TS_DIR/node_modules" ]; then
  echo "[smoke] FAIL: run 'npm install' in ts/ first (smoke itself stays offline)" >&2
  exit 1
fi

if [ ! -f "$TS_DIR/dist/index.js" ]; then
  echo "[smoke] building ts/dist (tsc)"
  (cd "$TS_DIR" && npm run build --silent)
fi

echo "[smoke] === MCP protocol round-trip against the audited stdio server ==="
node "$TS_DIR/scripts/smoke-client.mjs" "$WORK_DIR/audit.jsonl"

echo "[smoke] === cross-language: Python SDK events vs the same JSON Schema ==="
(cd "$PY_DIR" && python3 -m mcp_audit.samples) > "$WORK_DIR/python-events.jsonl"
node "$TS_DIR/scripts/validate-events.mjs" "$WORK_DIR/python-events.jsonl"

echo "SMOKE OK"
