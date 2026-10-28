import { describe, expect, it } from "vitest";

import { canonicalJson, CanonicalizationError } from "../../../src/domain/canonical.js";
import type { Effect } from "../../../src/domain/effects/effect.js";
import {
  authenticateEffect,
  authenticateEvidence,
  effectIdOf,
  evidenceIdOf,
} from "../../../src/domain/evidence/authenticate.js";
import { buildEvidence, sanitizeParameters, unionPerturbation } from "../../../src/domain/evidence/build.js";
import { COMPLETE, mergeCoverage } from "../../../src/domain/evidence/coverage.js";
import { evidenceInvariantIssues, isSortedSet, sortedSet } from "../../../src/domain/evidence/invariants.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import type { BeaEvidence } from "../../../src/domain/evidence/record.js";
import { idOf, type PiId } from "../../../src/domain/ids.js";
import { instanceIdOf, moduleMapIdOf } from "../../../src/domain/process/instance.js";
import {
  literalsOf,
  NO_LITERALS,
  parseLiteralsFile,
  sensitiveLiterals,
} from "../../../src/domain/redaction/literals.js";
import { bytesContainLiteral, redactExplicitText, redactJsonPayload } from "../../../src/domain/redaction/redact.js";
import { unknownIdOf } from "../../../src/domain/unknowns/unknown.js";

const PI = instanceIdOf({
  t: "bea.pi/1",
  device_id: "local",
  pid: 4242,
  start_time: { source: "os-creation-time", value: "133000000000000000" },
  image_path_sha256: "a".repeat(64),
});

const anchor = {
  run_id: "run_20260101T000000Z_0000000000000001",
  seq: 7,
  mono_ns: "123",
  wall: "2026-01-01T00:00:00.000Z",
  effect_epoch: 0,
  module_map_epoch: 1,
} as const;

const evBody = (): Omit<BeaEvidence, "evidence_id"> => ({
  schema: "bea.evidence/1",
  predicate_type: "bea.memory.read",
  operation: "read_memory",
  parameters: { address: "0x140001000", size: 4 },
  subject: { kind: "process-instance", instance_id: PI, module_map_id: null },
  observed_at: { ...anchor },
  provider: { id: "frida", name: "frida", version: "17.23.2" },
  agent: null,
  confidence: "observed",
  authority: "live-process",
  perturbation: { level: "agent-only", active_effect_ids: [], tainted_by: [] },
  result: { data: "554889e5" },
  raw_result: null,
  blobs: [],
  coverage: COMPLETE,
  limitations: [],
  locations: [],
  evidence_links: [],
  external_refs: [],
  effects: [],
  redactions: [],
  untrusted: true,
});

const fxBody = (): Omit<Effect, "effect_id"> => ({
  schema: "bea.effect/1",
  instance_id: PI,
  kind: "hook-installed",
  class: "observe",
  reversible: true,
  target: { address: null, size: null, threads: null },
  parameters: {},
  before: null,
  after: null,
  lifetime: null,
  stream_ids: [],
  applied_by: "hook_function",
  applied_at: { ...anchor },
  display: { target_text: "kernel32.dll!CreateFileW" },
});

const EV_GOLDEN = "ev_40fb3431569ce21cb02896777af9b0c161332e1bdf3467686f464f28d0c6a89f";
const FX_GOLDEN = "fx_502aad033386a1080e84ae53c5bc07308fb4b60fff0555fb129f863654cbc47d";

describe("ids (S2 §2.4 goldens: a projection change must update these deliberately)", () => {
  it("pins one id per family", () => {
    expect(PI).toBe("pi_c0b87371f9b4394e6e534f2c844502e45ffed99bc627d2d584a0e18abd647efe");
    expect(
      moduleMapIdOf({
        instance_id: PI,
        completeness: "complete",
        modules: [
          { base: "0x140000000", size: 131072, path_sha256: "b".repeat(64), display: { name: "x", path: null } },
        ],
      }),
    ).toBe("mm_6f1afec1d5538c38924d0b405d3c9109ef53e71bc02b9c6b18665527f7b568c5");
    expect(
      idOf("st", {
        t: "bea.st/1",
        run_id: anchor.run_id,
        seq: 7,
        source: { kind: "hook", instance_id: PI, effect_id: null, channel: "s1" },
      }),
    ).toBe("st_67ea7695f0e3e53ec3901a41f28c1e6e73192dfaa90ed29405d6a273996c0bf8");
    expect(
      unknownIdOf("runtime", "Which function writes Car.speed?", { kind: "image", image_sha256: "c".repeat(64) }),
    ).toBe("unk_85b6f8c0c10d5c10838c0fd05b6d4ed12fb06d77d455233543b89ae2e70beec5");
    expect(evidenceIdOf(evBody())).toBe(EV_GOLDEN);
    expect(effectIdOf(fxBody())).toBe(FX_GOLDEN);
  });

  it("excludes wall time and display from identity; seq and content change it", () => {
    const id = evidenceIdOf(evBody());
    expect(evidenceIdOf({ ...evBody(), observed_at: { ...anchor, wall: "2030-01-01T00:00:00.000Z" } })).toBe(id);
    expect(evidenceIdOf({ ...evBody(), observed_at: { ...anchor, seq: 8 } })).not.toBe(id);
    expect(effectIdOf({ ...fxBody(), display: { target_text: null } })).toBe(effectIdOf(fxBody()));
    expect(effectIdOf({ ...fxBody(), applied_at: { ...anchor, seq: 9 } })).not.toBe(effectIdOf(fxBody()));
  });
});

describe("authentication and invariants (S2 §7.1, §7.8)", () => {
  const record = (): BeaEvidence => ({ ...evBody(), evidence_id: evidenceIdOf(evBody()) });
  it("accepts a consistent record and rejects a one-character change", () => {
    expect(authenticateEvidence(record()).ok).toBe(true);
    const changed = { ...record(), operation: "read_memorz" };
    expect(authenticateEvidence(changed)).toMatchObject({
      ok: false,
      error: { _tag: "EvidenceIntegrity", reason: "id-mismatch" },
    });
    expect(authenticateEvidence({ ...record(), extra: 1 })).toMatchObject({ ok: false, error: { reason: "schema" } });
    const fx = { ...fxBody(), effect_id: effectIdOf(fxBody()) };
    expect(authenticateEffect(fx).ok).toBe(true);
    expect(authenticateEffect({ ...fx, applied_by: "write_memory" }).ok).toBe(false);
  });

  it("flags each invariant", () => {
    const issues = (patch: Partial<BeaEvidence>): string[] =>
      evidenceInvariantIssues({ ...record(), ...patch } as BeaEvidence);
    expect(issues({})).toEqual([]);
    expect(issues({ limitations: ["b", "a"] })).toContain("limitations is not sorted and unique");
    expect(issues({ subject: null }).some((i) => i.includes("SUBJECT_UNAVAILABLE"))).toBe(true);
    expect(issues({ observed_at: null }).some((i) => i.includes("anchor"))).toBe(true);
    expect(
      issues({ subject: { kind: "image", image_sha256: "a".repeat(64), format: "pe32+", machine: "x64" } }).length,
    ).toBeGreaterThan(0);
    expect(issues({ confidence: "derived" }).some((i) => i.includes("evidence link"))).toBe(true);
    expect(
      issues({ perturbation: { level: "none", active_effect_ids: [], tainted_by: [] } }).some((i) =>
        i.includes("perturbation none"),
      ),
    ).toBe(true);
    expect(issues({ coverage: { status: "complete", truncated: true, reasons: [] } })).toContain(
      "coverage violates its invariants",
    );
    expect(issues({ predicate_type: "bea.image.pe" }).length).toBeGreaterThan(0);
  });

  it("sorts set-valued arrays by UTF-16 code units of their canonical form", () => {
    expect(sortedSet(["b", "a", "b", "\u{1F600}", "\uFFFF"])).toEqual(["a", "b", "\u{1F600}", "\uFFFF"]);
    expect(isSortedSet([{ b: 1 }, { a: 2 }])).toBe(false);
  });
});

describe("canonical JSON (S2 §2.3 additions to WP0's oracle test)", () => {
  it("orders supplementary-plane keys by UTF-16 code units and refuses cycles and non-JSON numbers", () => {
    expect(canonicalJson({ "\uFFFF": 1, "\u{1F600}": 2, a: 3 })).toBe('{"a":3,"\u{1F600}":2,"\uFFFF":1}');
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;
    expect(() => canonicalJson(cyclic as never)).toThrow(CanonicalizationError);
    expect(() => canonicalJson({ x: Number.NaN })).toThrow(CanonicalizationError);
  });
});

describe("coverage and the build pipeline (S2 §7.5, §7.9)", () => {
  it("merges coverage: worst status, OR truncation, summed drops; paging never truncates", () => {
    expect(mergeCoverage(COMPLETE, COMPLETE)).toEqual(COMPLETE);
    expect(
      mergeCoverage(
        { status: "partial", truncated: true, dropped: 2, reasons: ["row_cap"] },
        { status: "unknown", truncated: false, reasons: ["unknown_completeness"] },
      ),
    ).toEqual({ status: "unknown", truncated: true, dropped: 2, reasons: ["row_cap", "unknown_completeness"] });
    expect(mergeCoverage(COMPLETE, { status: "complete", truncated: false, dropped: 0, reasons: [] }).status).toBe(
      "complete",
    );
  });

  it("sanitizes parameters: delivery keys, identity excludes, literal-bearing keys", () => {
    const sanitized = sanitizeParameters(
      {
        session_id: "s",
        offset: 5,
        limit: 9,
        address: "0x1",
        path: "C:\\Users\\bob\\x",
        sensitive_values: ["\\bob\\"],
        wait_ms: 3,
        tag: "t",
      },
      ["tag"],
      literalsOf(["\\bob\\"]),
    );
    expect(sanitized.parameters).toEqual({ address: "0x1", sensitive_value_count: 1 });
    expect(sanitized.redactions).toEqual([
      { pointer: "/parameters/path", reason: "explicit-sensitive-value", scope: "parameter" },
    ]);
  });

  it("refuses unanchored observations of anchored predicates and a missing per-call confidence", () => {
    const draft = {
      predicate_type: "bea.memory.read" as const,
      operation: "read_memory",
      input: {},
      subject: { kind: "process-instance" as const, instance_id: PI as PiId },
      provider: { id: "frida" as const, name: "frida", version: null },
      result: {},
      coverage: COMPLETE,
      literals: NO_LITERALS,
    };
    expect(buildEvidence(draft, { parent: () => undefined })).toMatchObject({ ok: false, error: { _tag: "Internal" } });
    const perCall = {
      ...draft,
      predicate_type: "bea.symbols.module" as const,
      subject: {
        kind: "image" as const,
        image_sha256: "a".repeat(64),
        format: "pe32+" as const,
        machine: "x64" as const,
      },
    };
    expect(buildEvidence(perCall, { parent: () => undefined }).ok).toBe(false);
    const built = buildEvidence({ ...perCall, confidence: "observed" }, { parent: () => undefined });
    expect(built.ok && built.value.record).toMatchObject({
      authority: "static-artifact",
      perturbation: { level: "none" },
      observed_at: null,
    });
  });

  it("caps perturbation unions at 256 ids with a flag", () => {
    const ids = Array.from({ length: 300 }, (_, i) => `fx_${i.toString(16).padStart(64, "0")}` as const);
    const union = unionPerturbation([{ level: "passive", active_effect_ids: ids, tainted_by: [] }]);
    expect(union.capped).toBe(true);
    expect(union.perturbation.active_effect_ids).toHaveLength(256);
    expect(LIMITATIONS.PERTURBATION_CAPPED.length).toBeGreaterThan(10);
  });
});

describe("redaction (S2 §15, §22 redaction)", () => {
  it("enforces the 4-byte minimum and merges server literals longest first with both spellings", () => {
    expect(sensitiveLiterals(["abc"], [])).toMatchObject({
      ok: false,
      error: [{ path: "sensitive_values[0]", reason: "out_of_range" }],
    });
    expect(sensitiveLiterals(["é€"], []).ok).toBe(true); // 5 UTF-8 bytes
    const lits = sensitiveLiterals(["token"], ["longer-secret"]);
    expect(lits.ok && lits.value.texts).toEqual(["longer-secret", "token"]);
    expect(lits.ok && lits.value.spellings.length).toBe(4);
    expect(parseLiteralsFile("\uFEFFsecret1\r\n\r\nsecret2\n")).toEqual({ ok: true, value: ["secret1", "secret2"] });
    expect(parseLiteralsFile("abc\n").ok).toBe(false);
  });

  it("matches UTF-8 and UTF-16LE in hex and base64 byte fields, nulls whole fields and drops property names", () => {
    const lits = literalsOf(["pass"]);
    const utf16 = Buffer.from("xpassx", "utf16le");
    const out = redactJsonPayload(
      {
        data: Buffer.from("my pass").toString("hex"),
        b64: utf16.toString("base64"),
        rows: [{ b: utf16.toString("hex") }, { b: "00" }],
        ["pass-key"]: 1,
        ok: "fine",
      },
      lits,
      "/result",
      ["/data", "/b64", "/rows/*/b"],
    );
    expect(out.value).toEqual({ data: null, b64: null, rows: [{ b: null }, { b: "00" }], ok: "fine" });
    expect(out.redactions.map((r) => `${r.scope}:${r.pointer}`).sort()).toEqual([
      "property-name:/result",
      "value:/result/b64",
      "value:/result/data",
      "value:/result/rows/0/b",
    ]);
    expect(bytesContainLiteral(new Uint8Array([0x70, 0, 0x61, 0, 0x73, 0, 0x73, 0]), lits)).toBe(true);
  });

  it("uses REA's text semantics: longest first, boundary re-formation empties the text", () => {
    expect(redactExplicitText("user=alice pw=alice123", literalsOf(["alice123", "alice"]))).toBe(
      "user=[REDACTED] pw=[REDACTED]",
    );
    expect(redactExplicitText("abab", literalsOf(["[RED", "abab"]))).toBe("…");
    expect(redactExplicitText("xsecrsecretetx", literalsOf(["secret"]))).toBe("xsecr[REDACTED]etx");
    const reform = literalsOf(["aaXa", "X"].filter((l) => l.length >= 1));
    expect(redactExplicitText("aaXa", { ...reform, texts: ["XXXX", "aaXa"] })).toBe("[REDACTED]");
  });
});
