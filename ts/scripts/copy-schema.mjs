#!/usr/bin/env node
// Copy the canonical JSON Schema from the repository root into the package
// so the published npm tarball is self-contained (exports "./schema").
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const source = fileURLToPath(new URL("../../schema/audit-event.schema.json", import.meta.url));
const targetDir = fileURLToPath(new URL("../schema", import.meta.url));
mkdirSync(targetDir, { recursive: true });
copyFileSync(source, `${targetDir}/audit-event.schema.json`);
