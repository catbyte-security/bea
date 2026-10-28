import { describe, expect, it } from "vitest";
import { z } from "zod";

import { createApplication } from "../../src/application/createApplication.js";
import type { ToolHandler } from "../../src/application/handlerContext.js";
import { createToolHandlers } from "../../src/application/handlers/index.js";
import { invokeTool } from "../../src/application/invokeTool.js";
import { findToolContract, TOOL_CONTRACTS } from "../../src/contracts/index.js";
import {
  ENVELOPE_RESERVED_KEYS,
  maybeRecordedEnvelopeShape,
  nextStepSchema,
  pollEnvelopeShape,
  recordedEnvelopeShape,
  REQUIRED_ENVELOPE_KEYS,
} from "../../src/contracts/schemas/envelope.js";
import type { ToolContract } from "../../src/contracts/toolContract.js";
import { loadConfig } from "../../src/domain/config.js";
import { DROP_REASON_CODES, REASONS } from "../../src/domain/evidence/coverage.js";
import { CORE_LIMITATIONS, LIMITATIONS } from "../../src/domain/evidence/limitations.js";
import { ADDRESS_LIMITATIONS } from "../../src/domain/evidence/limitations/address.js";
import { BEHAVIOR_LIMITATIONS } from "../../src/domain/evidence/limitations/behavior.js";
import { CALL_LIMITATIONS } from "../../src/domain/evidence/limitations/call.js";
import { DUMP_LIMITATIONS } from "../../src/domain/evidence/limitations/dump.js";
import { EMULATION_LIMITATIONS } from "../../src/domain/evidence/limitations/emulation.js";
import { EVIDENCE_LIMITATIONS } from "../../src/domain/evidence/limitations/evidence.js";
import { INSPECT_LIMITATIONS } from "../../src/domain/evidence/limitations/inspect.js";
import { INSTRUMENT_LIMITATIONS } from "../../src/domain/evidence/limitations/instrument.js";
import { MODIFY_LIMITATIONS } from "../../src/domain/evidence/limitations/modify.js";
import { SCAN_LIMITATIONS } from "../../src/domain/evidence/limitations/scan.js";
import { SESSIONS_LIMITATIONS } from "../../src/domain/evidence/limitations/sessions.js";
import { WATCH_LIMITATIONS } from "../../src/domain/evidence/limitations/watch.js";
import { isPredicateType } from "../../src/domain/evidence/predicates.js";
import { silentLogger } from "../../src/domain/logger.js";
import type { HostPlatform } from "../../src/domain/paths.js";
import { fakeServices } from "../support/fakes/fakeServices.js";
import { createTempHome } from "../support/workspace/tempHome.js";

/** S2 §8.2 / §22 "envelope" (DESIGN §8.3): reserved keys, next steps, worst-case size, registries. */

const MAX_ENVELOPE_BYTES = 2 * 1024 * 1024;
/** Bounding rules for schema parts without an explicit bound (S2 §8.2 inline caps). */
const UNBOUNDED_STRING_CHARS = 4096; // target strings are capped at 4,096 characters per field inline
const UNBOUNDED_ITEMS = 500; // one page is at most 500 rows
const OPEN_JSON_BYTES = 64 * 1024; // open JSON (records, digests, next.arguments): one bounded digest
const NUMBER_CHARS = 24; // -1.7976931348623157e+308

type JsonSchemaNode = Readonly<Record<string, unknown>>;

/** Longest string an anchored, quantifier-bounded pattern can match; null when unbounded (*, +, {n,}). */
const maxPatternLength = (pattern: string): number | null => {
  const source = pattern.replace(/^\^/u, "").replace(/\$$/u, "");
  let i = 0;
  const sequence = (): number | null => {
    let total = 0;
    while (i < source.length && source[i] !== "|" && source[i] !== ")") {
      let atom: number | null;
      const ch = source[i];
      if (ch === "(") {
        i += source.startsWith("(?:", i) ? 3 : 1;
        let best: number | null = 0;
        for (;;) {
          const alternative = sequence();
          best = best === null || alternative === null ? null : Math.max(best, alternative);
          if (source[i] === "|") i += 1;
          else break;
        }
        i += 1; // ")"
        atom = best;
      } else if (ch === "[") {
        i += 1;
        while (i < source.length && source[i] !== "]") i += source[i] === "\\" ? 2 : 1;
        i += 1;
        atom = 1;
      } else if (ch === "\\") {
        i += source[i + 1] === "u" && source[i + 2] === "{" ? source.indexOf("}", i) + 1 - i : 2;
        atom = 1;
      } else {
        i += 1;
        atom = 1;
      }
      let times: number | null = 1;
      const q = source[i];
      if (q === "?" || q === "*" || q === "+") {
        i += 1;
        times = q === "?" ? 1 : null;
      } else if (q === "{") {
        const close = source.indexOf("}", i);
        const [, low, high] = /^\{(\d+)(?:,(\d*))?\}$/u.exec(source.slice(i, close + 1)) ?? [];
        times = high === undefined ? Number(low) : high === "" ? null : Number(high);
        i = close + 1;
      }
      if (atom === null || times === null || total === null) return null;
      total += atom * times;
    }
    return total;
  };
  const longest = sequence();
  return i === source.length ? longest : null;
};

/** Upper bound of the compact JSON size of any value valid under `node` (characters; escaping not counted). */
const jsonBound = (node: unknown, defs: Readonly<Record<string, unknown>>, seen: readonly string[] = []): number => {
  if (node === true || node === undefined || node === null || typeof node !== "object") return OPEN_JSON_BYTES;
  const s = node as JsonSchemaNode;
  if (typeof s["$ref"] === "string") {
    const name = s["$ref"].replace(/^#\/\$defs\//u, "");
    return seen.includes(name) ? OPEN_JSON_BYTES : jsonBound(defs[name], defs, [...seen, name]);
  }
  for (const key of ["anyOf", "oneOf", "allOf"])
    if (Array.isArray(s[key])) return Math.max(...(s[key] as unknown[]).map((branch) => jsonBound(branch, defs, seen)));
  if (s["const"] !== undefined) return JSON.stringify(s["const"]).length;
  if (Array.isArray(s["enum"])) return Math.max(...s["enum"].map((v) => JSON.stringify(v).length));
  const types = Array.isArray(s["type"]) ? (s["type"] as string[]) : typeof s["type"] === "string" ? [s["type"]] : [];
  if (types.length === 0) return OPEN_JSON_BYTES;
  return Math.max(
    ...types.map((type) => {
      switch (type) {
        case "null":
          return 4;
        case "boolean":
          return 5;
        case "integer": {
          const lo = s["minimum"] ?? s["exclusiveMinimum"];
          const hi = s["maximum"] ?? s["exclusiveMaximum"];
          return typeof lo === "number" && typeof hi === "number" ? Math.max(String(lo).length, String(hi).length) : 17;
        }
        case "number":
          return NUMBER_CHARS;
        case "string": {
          const fromPattern = typeof s["pattern"] === "string" ? maxPatternLength(s["pattern"]) : null;
          const chars =
            typeof s["maxLength"] === "number"
              ? s["maxLength"]
              : (fromPattern ?? (s["format"] === "date-time" ? 35 : UNBOUNDED_STRING_CHARS));
          return 2 + chars;
        }
        case "array": {
          const items = typeof s["maxItems"] === "number" ? s["maxItems"] : UNBOUNDED_ITEMS;
          return 2 + items * (jsonBound(s["items"], defs, seen) + 1);
        }
        case "object": {
          const properties = (s["properties"] ?? {}) as Readonly<Record<string, unknown>>;
          let total = 2;
          for (const [key, value] of Object.entries(properties))
            total += JSON.stringify(key).length + 2 + jsonBound(value, defs, seen);
          const open = s["additionalProperties"] !== undefined && s["additionalProperties"] !== false;
          return open || s["patternProperties"] !== undefined ? total + OPEN_JSON_BYTES : total;
        }
        default:
          return OPEN_JSON_BYTES;
      }
    }),
  );
};

const worstCaseBytes = (contract: ToolContract): number => {
  const schema = z.toJSONSchema(contract.outputSchema, {
    io: "output",
    target: "draft-2020-12",
    unrepresentable: "any",
  }) as JsonSchemaNode;
  return jsonBound(schema, (schema["$defs"] ?? {}) as Readonly<Record<string, unknown>>);
};

const AREA_LIMITATION_FILES: Readonly<Record<string, Readonly<Record<string, unknown>>>> = {
  sessions: SESSIONS_LIMITATIONS,
  inspect: INSPECT_LIMITATIONS,
  address: ADDRESS_LIMITATIONS,
  scan: SCAN_LIMITATIONS,
  instrument: INSTRUMENT_LIMITATIONS,
  behavior: BEHAVIOR_LIMITATIONS,
  watch: WATCH_LIMITATIONS,
  call: CALL_LIMITATIONS,
  modify: MODIFY_LIMITATIONS,
  dump: DUMP_LIMITATIONS,
  emulation: EMULATION_LIMITATIONS,
  evidence: EVIDENCE_LIMITATIONS,
};

describe("result envelope (S2 §8)", () => {
  it("result fields never reuse an envelope key: every reserved key at the root comes from an envelope builder", () => {
    const shapes = [recordedEnvelopeShape, pollEnvelopeShape, maybeRecordedEnvelopeShape] as readonly Readonly<
      Record<string, unknown>
    >[];
    for (const contract of TOOL_CONTRACTS) {
      const shape = (contract.outputSchema as unknown as z.ZodObject).shape as Readonly<Record<string, unknown>>;
      for (const key of REQUIRED_ENVELOPE_KEYS)
        expect(Object.hasOwn(shape, key), `${contract.name} lacks ${key}`).toBe(true);
      for (const key of ENVELOPE_RESERVED_KEYS)
        if (Object.hasOwn(shape, key))
          expect(
            shapes.some((envelope) => envelope[key] === shape[key]),
            `${contract.name}.${key} is not the envelope's own schema`,
          ).toBe(true);
    }
  });

  it("every next step a handler returns names a tool and parses with that tool's input schema", async () => {
    const home = await createTempHome("envelope");
    const loaded = await loadConfig({
      env: { BEA_HOME: home.beaHome },
      platform: process.platform as HostPlatform,
      accountHome: home.home,
      readConfigFile: async () => null,
    });
    if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
    const app = await createApplication({
      config: loaded.value,
      logger: silentLogger,
      transport: "cli",
      services: fakeServices(),
    });
    const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
    let succeeded = 0;
    for (const contract of TOOL_CONTRACTS)
      for (const example of contract.examples) {
        const result = await invokeTool(app, (name) => table[name], contract, example.input, {
          surface: "cli",
          clientSignal: new AbortController().signal,
          progress: { report: () => undefined },
          requestId: `${contract.name}:${example.title}`,
        });
        if (!result.ok) continue; // day-0 fakes answer capability_unavailable; areas cover their own handlers
        succeeded += 1;
        const next = (result.value["next"] ?? []) as readonly unknown[];
        for (const step of next) {
          const parsed = nextStepSchema.parse(step);
          const target = findToolContract(parsed.tool);
          expect(target, `${contract.name} suggests unknown tool ${parsed.tool}`).toBeDefined();
          expect(
            target?.inputSchema.safeParse(parsed.arguments).success,
            `${contract.name} -> ${parsed.tool} arguments`,
          ).toBe(true);
        }
      }
    expect(succeeded).toBeGreaterThan(0);
    await app.lifecycle.closeAll("test");
    await home.cleanup();
  });

  it("worst-case structuredContent computed from schema bounds stays within 2 MiB per tool", () => {
    const over = TOOL_CONTRACTS.map((c) => ({ name: c.name, bytes: worstCaseBytes(c) })).filter(
      (row) => row.bytes > MAX_ENVELOPE_BYTES,
    );
    expect(over).toEqual([]);
  });

  it("bounds patterns, pages and open objects the way the estimate documents", () => {
    expect(maxPatternLength("^0x[0-9a-fA-F]{1,16}$")).toBe(18);
    expect(maxPatternLength("^(?:rec_[0-9a-f]{8}|scan_[0-9a-f]{8}|fx_[0-9a-f]{64})$")).toBe(67);
    expect(maxPatternLength("^run_\\d{8}T\\d{6}Z_[0-9a-f]{16}$")).toBe(37);
    expect(maxPatternLength("^[a-z][a-z0-9_]+$")).toBeNull();
    expect(jsonBound({ type: "array", items: { type: "boolean" }, maxItems: 3 }, {})).toBe(2 + 3 * 6);
    expect(jsonBound({ type: "object", additionalProperties: { type: "null" } }, {})).toBe(2 + OPEN_JSON_BYTES);
  });
});

describe("evidence registries (S2 §7.3, §7.5, §7.6; CI-I5)", () => {
  it("every recorded tool names a registered predicate", () => {
    for (const contract of TOOL_CONTRACTS) {
      const { predicate, recorded } = contract.evidence;
      if (recorded === "never" && predicate === null) continue;
      expect(predicate, `${contract.name} records without a predicate`).not.toBeNull();
      expect(isPredicateType(predicate ?? ""), `${contract.name}: ${String(predicate)} is not in PREDICATES`).toBe(
        true,
      );
    }
  });

  it("every coverage reason code is well-formed and has a limitation sentence", () => {
    for (const [code, limitation] of Object.entries(REASONS)) {
      expect(code).toMatch(/^[a-z][a-z0-9_]{1,47}$/u);
      expect(Object.hasOwn(LIMITATIONS, limitation), `${code} -> ${limitation}`).toBe(true);
    }
  });

  it("every agent drop reason maps to a registered coverage reason", () => {
    for (const [drop, code] of Object.entries(DROP_REASON_CODES))
      expect(Object.hasOwn(REASONS, code), `${drop} -> ${code}`).toBe(true);
  });

  it("no limitation key collides between the core set and the 12 area files", () => {
    const owners = new Map<string, string>(Object.keys(CORE_LIMITATIONS).map((key) => [key, "core"]));
    const collisions: string[] = [];
    for (const [area, sentences] of Object.entries(AREA_LIMITATION_FILES))
      for (const key of Object.keys(sentences)) {
        const owner = owners.get(key);
        if (owner !== undefined) collisions.push(`${key}: ${owner} and ${area}`);
        owners.set(key, area);
      }
    expect(collisions).toEqual([]);
    expect(Object.keys(LIMITATIONS).length).toBe(owners.size);
    for (const [key, sentence] of Object.entries(LIMITATIONS)) {
      expect(key).toMatch(/^[A-Z][A-Z0-9_]+$/u);
      expect(typeof sentence === "function" || (typeof sentence === "string" && sentence.length > 10), key).toBe(true);
    }
  });
});
