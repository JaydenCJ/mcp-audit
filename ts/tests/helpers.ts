/** Shared test helpers: schema validator and in-memory exporter. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import AjvModule from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import type { AuditEvent, AuditExporter } from "../src/index.js";

// ajv ships CJS; normalize the default export under both interop modes.
const Ajv2020 = (AjvModule as unknown as { default?: typeof AjvModule }).default ?? AjvModule;
const addFormats =
  (addFormatsModule as unknown as { default?: typeof addFormatsModule }).default ?? addFormatsModule;

export const SCHEMA_PATH = fileURLToPath(
  new URL("../../schema/audit-event.schema.json", import.meta.url)
);

const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const compiled = ajv.compile(schema);

/** Validate an event against the canonical JSON Schema; returns error text or null. */
export function validateEvent(event: unknown): string | null {
  if (compiled(event)) return null;
  return ajv.errorsText(compiled.errors);
}

/** Assert helper: throws with ajv's message when the event is invalid. */
export function expectValid(event: unknown): void {
  const error = validateEvent(event);
  if (error !== null) {
    throw new Error(`event failed schema validation: ${error}\n${JSON.stringify(event, null, 2)}`);
  }
}

/** Exporter that collects events in memory for assertions. */
export class MemoryExporter implements AuditExporter {
  events: AuditEvent[] = [];
  export(events: AuditEvent[]): void {
    this.events.push(...events);
  }
  byType(type: AuditEvent["event_type"]): AuditEvent[] {
    return this.events.filter((event) => event.event_type === type);
  }
}
