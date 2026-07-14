#!/usr/bin/env node
// Validate a JSONL audit log against schema/audit-event.schema.json.
// Usage: node ts/scripts/validate-events.mjs <file.jsonl>
// Exits 0 when every line validates; prints the first failure and exits 1 otherwise.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPath = fileURLToPath(new URL("../../schema/audit-event.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

const file = process.argv[2];
if (!file) {
  process.stderr.write("usage: node validate-events.mjs <file.jsonl>\n");
  process.exit(2);
}

let raw;
try {
  raw = readFileSync(file, "utf8");
} catch (error) {
  const reason = error?.code === "ENOENT" ? "no such file" : error?.message ?? String(error);
  process.stderr.write(`validate-events: cannot read ${file}: ${reason}\n`);
  process.exit(1);
}

const lines = raw
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line.length > 0);

if (lines.length === 0) {
  process.stderr.write(`${file}: no events found\n`);
  process.exit(1);
}

const counts = new Map();
for (const [index, line] of lines.entries()) {
  let event;
  try {
    event = JSON.parse(line);
  } catch (error) {
    process.stderr.write(`${file}:${index + 1}: not JSON: ${error}\n`);
    process.exit(1);
  }
  if (!validate(event)) {
    process.stderr.write(
      `${file}:${index + 1}: schema violation: ${ajv.errorsText(validate.errors)}\n`
    );
    process.exit(1);
  }
  counts.set(event.event_type, (counts.get(event.event_type) ?? 0) + 1);
}

const summary = [...counts.entries()].map(([type, count]) => `${type}=${count}`).join(" ");
process.stdout.write(`${file}: ${lines.length} events valid (${summary})\n`);
