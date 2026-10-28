import { describe, expect, it } from "vitest";
import type { z } from "zod";

import { toolContract } from "../../../src/contracts/index.js";
import { PREDICATES } from "../../../src/domain/evidence/predicates.js";
import type { JsonObject } from "../../../src/domain/json.js";
import { literalsOf } from "../../../src/domain/redaction/literals.js";
import { redactJsonPayload } from "../../../src/domain/redaction/redact.js";

/**
 * Review fix SEC-4: the real builder nulls a redacted byte or text field (S2 §15.2); every output field it can null
 * must accept null, or the tool reports an internal error after the record (and, for write_memory, the write) landed.
 */
const MARKER = "MARKER-SECRET";
const hex = (text: string): string => Buffer.from(text, "latin1").toString("hex");
const fieldOf = (shape: z.ZodRawShape, key: string): z.ZodType => {
  const field = shape[key];
  if (field === undefined) throw new Error(`no field ${key}`);
  return field as z.ZodType;
};

describe("redacted output fields stay inside their contracts (SEC-4)", () => {
  const literals = literalsOf([MARKER]);

  it("read_memory data and text, write_memory before_hex/after_hex, disassemble rows b", () => {
    const read = redactJsonPayload(
      { data: hex(`xx${MARKER}xx`), text: `a ${MARKER} b` } as JsonObject,
      literals,
      "/result",
      PREDICATES["bea.memory.read"].byteFields,
    );
    expect(read.redactions).toHaveLength(2);
    const readShape = toolContract("read_memory").outputSchema.shape;
    for (const key of ["data", "text"]) {
      const value = (read.value as JsonObject)[key];
      expect(value, key).toBeNull();
      expect(fieldOf(readShape, key).safeParse(value).success, key).toBe(true);
    }
    expect(fieldOf(readShape, "values").safeParse(null).success).toBe(true);

    const write = redactJsonPayload(
      { before_hex: hex(MARKER), after_hex: hex(`${MARKER}!`) } as JsonObject,
      literals,
      "/result",
      PREDICATES["bea.memory.write"].byteFields,
    );
    const writeShape = toolContract("write_memory").outputSchema.shape;
    for (const key of ["before_hex", "after_hex"]) {
      const value = (write.value as JsonObject)[key];
      expect(value, key).toBeNull();
      expect(fieldOf(writeShape, key).safeParse(value).success, key).toBe(true);
    }

    const disasm = redactJsonPayload(
      { rows: [{ rva: null, va: "0x1000", b: hex(MARKER), t: "db", ref: null }] } as JsonObject,
      literals,
      "/result",
      PREDICATES["bea.code.disassembly"].byteFields,
    );
    const rows = fieldOf(toolContract("disassemble").outputSchema.shape, "rows");
    expect(rows.safeParse((disasm.value as JsonObject)["rows"]).success).toBe(true);
    expect(((disasm.value as JsonObject)["rows"] as JsonObject[])[0]?.["b"]).toBeNull();
  });
});
