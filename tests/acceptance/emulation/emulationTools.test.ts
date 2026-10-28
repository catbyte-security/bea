import { existsSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  emuSkip,
  fixtureArtifact,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { realPython } from "../../support/emu/python.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * Emulation rows of S6 §10.8 (emu_open, emu_call; diff_function without a live leg) through the BUILT server over
 * stdio (DESIGN §8.4; run with BEA_DIST_DIR from `node scripts/snapshot-dist.mjs <id>`), the real bridge and the gcc
 * fixtures. Wave rule (CI-I1): besides the emulation tools only session_status/close_session, read_memory (earlier
 * waves) and export_coverage (the moved WP9 row). No target process is started: these rows need Python with unicorn
 * and gcc. Every bridge (launcher and interpreter) goes into the owned-PID ledger, which must be clean at the end.
 */
const skip = emuSkip() !== false ? emuSkip() : gccSkip();

let home: TempHome;
let bea: BeaConnection;
let mathlib: FixtureArtifact;
let ledger: OwnedPidLedger;

const f32 = (v: number): string => `0x${(new Uint32Array(new Float32Array([v]).buffer)[0] ?? 0).toString(16)}`;
const f64 = (v: number): string => `0x${new BigUint64Array(new Float64Array([v]).buffer)[0]?.toString(16) ?? "0"}`;
const ok = async (name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> =>
  expectToolSuccess(await bea.call(name, args));
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
/** the bridge launcher and interpreter of an emu_open result or a session_status emulation row */
const recordBridge = (bridge: { pid: number | null; child_pid: number | null }, label: string): void => {
  for (const pid of new Set([bridge.pid, bridge.child_pid]))
    if (typeof pid === "number" && pid > 0) ledger.recordOwned(pid, null, label);
};
/** the mathlib.dll session every row uses, opened once in beforeAll (the first row asserts its emu_open result) */
let session = "";
let opened: Record<string, unknown> = {};
const sig3 = { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" };
const sig4 = { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" };
const STACK_SIG = {
  args: [
    { type: "f32" },
    { type: "f32" },
    { type: "f32" },
    { type: "f32" },
    { type: "f32" },
    { type: "f64" },
    { type: "i32" },
  ],
  returns: "f64",
};
const retColumn = (result: Record<string, unknown>): { bits: string[]; value: unknown[] } =>
  (result["batch"] as { columns: Record<string, { bits: string[]; value: unknown[] }> }).columns["ret"] ?? {
    bits: [],
    value: [],
  };
/** mathlib.dll's .bss call counter in the session's CURRENT state (read_memory on an emulation session) */
const gCalls = async (): Promise<number> => {
  const read = await ok("read_memory", { session_id: session, address: "mathlib.dll!g_calls", size: 4 });
  return Buffer.from(String(read["data"]), "hex").readUInt32LE(0);
};
/** mf_stack: (double)(a + b*c - d*e) * f + (double)g, the float part in f32 steps (x64 SSE, no contraction) */
const stackRef = (v: readonly number[]): string => {
  const [a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0] = v;
  return f64(Math.fround(Math.fround(a + Math.fround(b * c)) - Math.fround(d * e)) * f + g);
};

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "mathlib");
  if (artifact === null) throw new Error("mathlib fixture unavailable");
  mathlib = artifact;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
  home = await createTempHome("wp14-emu");
  const python = realPython();
  bea = await connectBea({ home, ...(python === null ? {} : { env: { BEA_PYTHON: python } }) });
  opened = await ok("emu_open", { image_path: mathlib.path });
  session = String(opened["session_id"]);
  recordBridge(opened["bridge"] as { pid: number; child_pid: number }, "bridge of the mathlib session");
}, 120_000);

afterAll(async () => {
  if (skip !== false) return;
  const outcome = await bea.close();
  expect(outcome.exitCode).toBe(0);
  // S5 §14.1 leak assertion: neither the launcher nor the interpreter of any bridge outlives the server
  await vi.waitFor(async () => expect((await ledger.audit()).leaks).toEqual([]), { timeout: 5_000, interval: 25 });
  await ledger.assertClean();
  await home.cleanup();
});

describe.skipIf(skip !== false)(
  `emulation tools on mathlib.dll (built server): open and calls${skipNote(skip)}`,
  () => {
    it("emu_open: ISA report lists mf_avx_dot, x87 sites ≥ 1, FPCW/MXCSR 0x27f/0x1f80, session_status kind emulation", async () => {
      expect(opened).toMatchObject({
        predicate_type: "bea.emu.session",
        authority: "emulation",
        fp: { mxcsr: "0x1f80", fpcw: "0x27f" },
      });
      const isa = opened["isa"] as { sites: Record<string, number>; functions_with_vex_sample: string[] };
      expect(isa.functions_with_vex_sample).toContain(`0x${(mathlib.pe.exportRvas["mf_avx_dot"] ?? 0).toString(16)}`);
      expect(isa.sites["x87_inexact"]).toBeGreaterThanOrEqual(1);
      const status = await ok("session_status", { session_id: session });
      expect(JSON.stringify(status)).toContain("emulation");
      // bea_status: the emulator row is resolved lazily (not-loaded at connect), then available with its pin
      const emulatorRow = (s: Readonly<Record<string, unknown>>) =>
        (s["backends"] as { id: string; state: string; version: string | null; detail: string }[]).find(
          (b) => b.id === "emulator",
        );
      expect(emulatorRow(bea.status)).toMatchObject({ state: "not-loaded" });
      const now = emulatorRow(await ok("bea_status", {}));
      expect(now).toMatchObject({ state: "available", version: expect.stringMatching(/^2\.1\./u) });
      expect(now?.detail).toMatch(/\(BEA_PYTHON, (?:exact|compatible)\).*sessions 1\/4/u);
    });

    it("emu_call: mf_spring, mf_poly, mf_stack and mf_lerp equal JS references bit-exactly over 100 vectors", async () => {
      const n = 100;
      const xs = Array.from({ length: n }, (_, i) => Math.fround((i - 50) * 0.731));
      const vs = Array.from({ length: n }, (_, i) => Math.fround(3 - i * 0.07));
      const spring = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spring",
        signature: sig4,
        vectors: { columns: { arg0: xs.map(f32), arg1: vs.map(f32), arg2: xs.map(() => 40), arg3: xs.map(() => 2) } },
        inline_limit: n,
      });
      const springRef = xs.map((x, i) => {
        let f = Math.fround(Math.fround(-40 * x) - Math.fround(2 * (vs[i] ?? 0)));
        if (f > 1000) f = 1000;
        if (f < -1000) f = -1000;
        return f32(f);
      });
      expect(retColumn(spring).bits).toEqual(springRef);
      const poly = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_poly",
        signature: { args: [{ type: "f64" }, { type: "f64" }, { type: "f64" }, { type: "f64" }], returns: "f64" },
        vectors: {
          columns: {
            arg0: xs.map((x) => f64(x)),
            arg1: xs.map(() => 0.5),
            arg2: xs.map(() => -1.25),
            arg3: xs.map(() => 3),
          },
        },
        inline_limit: n,
      });
      const polyRef = xs.map((x) => {
        const y = ((0.5 * x + -1.25) * x + 3) * x;
        return f64(y < 0 ? 0 : y);
      });
      expect(retColumn(poly).bits).toEqual(polyRef);
      // mf_stack: args 5..7 on the stack (f32, f64, i32), 100 vectors in the batch and one single call
      const rows = Array.from({ length: n }, (_, i) => [
        Math.fround((i - 50) * 0.731),
        Math.fround(3 - i * 0.07),
        Math.fround(1 + i * 0.013),
        Math.fround(0.25 + i * 0.01),
        Math.fround(4 - i * 0.03),
        (i + 1) / 64,
        i - 50,
      ]);
      const column = (k: number) => rows.map((r) => r[k] ?? 0);
      const stackBatch = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_stack",
        signature: STACK_SIG,
        vectors: {
          columns: {
            arg0: column(0).map(f32),
            arg1: column(1).map(f32),
            arg2: column(2).map(f32),
            arg3: column(3).map(f32),
            arg4: column(4).map(f32),
            arg5: column(5).map(f64),
            arg6: column(6),
          },
        },
        inline_limit: n,
      });
      expect(retColumn(stackBatch).bits).toEqual(rows.map(stackRef));
      const stack = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_stack",
        signature: STACK_SIG,
        args: [1.5, 2, 3, 0.25, 4, 0.5, 7],
      });
      expect((stack["call"] as { ret: { bits: string } }).ret.bits).toBe(stackRef([1.5, 2, 3, 0.25, 4, 0.5, 7]));
      const lerp = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: sig3,
        vectors: { columns: { arg0: xs.map(f32), arg1: vs.map(f32), arg2: xs.map(() => 0.25) } },
        inline_limit: n,
      });
      const lerpRef = xs.map((a, i) => f32(Math.fround(a + Math.fround(Math.fround((vs[i] ?? 0) - a) * 0.25))));
      expect(retColumn(lerp).bits).toEqual(lerpRef);
    });
  },
);

describe.skipIf(skip !== false)(
  `emulation tools on mathlib.dll (built server): structs, state, traces${skipNote(skip)}`,
  () => {
    it("emu_call: mf_body_step out struct; mf_gain state (g_calls) under chain vs snapshot isolation", async () => {
      const body = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_body_step",
        signature: {
          args: [{ type: "buffer_ptr", buffer: "b" }, { type: "buffer_ptr", buffer: "force" }, { type: "f32" }],
          returns: "void",
        },
        buffers: [
          {
            name: "b",
            size: 32,
            out: true,
            fields: [
              { name: "pos", offset: 0, type: "f32[]", count: 3 },
              { name: "vel", offset: 12, type: "f32[]", count: 3 },
              { name: "mass", offset: 24, type: "f32", default: "2" },
              { name: "steps", offset: 28, type: "u32" },
            ],
          },
          { name: "force", size: 12, fields: [{ name: "v", offset: 0, type: "f32[]", count: 3, default: "4,0,-2" }] },
        ],
        args: [null, null, 0.5],
      });
      const outputs = (body["call"] as { outputs: Record<string, unknown> }).outputs;
      expect(outputs["b.steps"]).toMatchObject({ value: 1 });
      expect((outputs["b.vel"] as { value: number }[]).map((v) => v.value)).toEqual([1, 0, -0.5]);
      const gain = {
        session_id: session,
        address: "mathlib.dll!mf_gain",
        signature: { args: [{ type: "f32" }], returns: "f32" },
      };
      // chain: one machine for the batch, so g_calls counts 1, 2, 3 and the session's current state keeps 3
      const chain = await ok("emu_call", { ...gain, vectors: { columns: { arg0: [1, 1, 1] } }, isolation: "chain" });
      expect((chain["batch"] as { status: string[] }).status).toEqual(["returned", "returned", "returned"]);
      expect(retColumn(chain).value).toEqual([1.5, 1.5, 1.5]);
      expect(await gCalls()).toBe(3);
      // snapshot (default): every vector starts from the baseline (g_calls 0); the state after the batch is the state
      // after the LAST vector (S5 §11), so g_calls is 1, not 3
      const snap = await ok("emu_call", { ...gain, vectors: { columns: { arg0: [2, 2, 2] } } });
      expect(retColumn(snap).value).toEqual([3, 3, 3]);
      expect(await gCalls()).toBe(1);
      // a chain from "current" continues from there
      const resumed = await ok("emu_call", {
        ...gain,
        vectors: { columns: { arg0: [4, 4] } },
        isolation: "chain",
        state: { from: "current" },
      });
      expect(resumed["state"]).toMatchObject({ from: "current" });
      expect(await gCalls()).toBe(3);
    });

    it("emu_call trace.blocks: the executed blocks of mf_spring's clamp path lie inside its .pdata extent", async () => {
      const traced = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spring",
        signature: sig4,
        args: [2000, 0, 1, 0],
        trace: { blocks: true },
      });
      const view = traced["call"] as {
        status: string;
        ret: { bits: string };
        trace: { blocks: { executed: number; unique: number; sample: string[] } };
      };
      expect(view).toMatchObject({ status: "returned", ret: { bits: f32(-1000) } });
      expect(view.trace.blocks.executed).toBeGreaterThanOrEqual(2);
      expect(view.trace.blocks.unique).toBeGreaterThanOrEqual(2);
      const base = BigInt(String((opened["primary"] as { mapped_base: string }).mapped_base));
      const extent = mathlib.pe.pdata["mf_spring"] ?? { rva: 0, size: 0 };
      for (const va of view.trace.blocks.sample) {
        const rva = Number(BigInt(va) - base);
        expect(rva, va).toBeGreaterThanOrEqual(extent.rva);
        expect(rva, va).toBeLessThan(extent.rva + extent.size);
      }
    });
  },
);

describe.skipIf(skip !== false)(
  `emulation tools on mathlib.dll (built server): statuses, coverage, diff${skipNote(skip)}`,
  () => {
    it("emu_call statuses: #DE on mf_div(7,0), unsupported_instruction on mf_avx_dot, budget_exhausted on mf_spin", async () => {
      const div = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_div",
        signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
        args: [7, 0],
      });
      expect(div["call"]).toMatchObject({
        status: "cpu_exception",
        attribution: "target",
        stop: { cause: "div_error", exception: { vector: 0 } },
      });
      const avx = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_avx_dot",
        signature: { args: [{ type: "ptr" }, { type: "ptr" }, { type: "i32" }], returns: "f32" },
        args: [0, 0, 0],
      });
      expect(avx["call"]).toMatchObject({ status: "unsupported_instruction", attribution: "harness" });
      const spin = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spin",
        signature: { args: [{ type: "i32" }], returns: "i32" },
        args: [1],
        budget: { max_instructions: 50_000 },
      });
      expect(spin["call"]).toMatchObject({ status: "budget_exhausted", attribution: "harness" });
    });

    const sinWithCoverage = () =>
      ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_x87_sin",
        signature: { args: [{ type: "f64" }], returns: "f64" },
        args: [0.5],
        trace: { coverage: true },
      });

    it("emu_call: mf_x87_sin is tagged and records a coverage blob; rows above 64 stream", async () => {
      const sin = await sinWithCoverage();
      expect((sin["call"] as { deviations: { kind: string }[] }).deviations.map((d) => d.kind)).toContain(
        "x87_transcendental_inexact",
      );
      expect((sin["coverage_blob"] as { blocks: number } | null)?.blocks).toBeGreaterThan(0);
      const many = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: sig3,
        generate: {
          seed: 11,
          count: 200,
          columns: {
            arg0: { dist: "uniform", min: -1, max: 1 },
            arg1: { dist: "edge" },
            arg2: { dist: "uniform", min: 0, max: 1 },
          },
        },
      });
      const batch = many["batch"] as { stream_id: string | null; completed: number };
      expect(batch.completed).toBe(200);
      expect(batch.stream_id).toMatch(/^st_/u);
    });

    it("emu_call sweep over mathlib.dll's .text functions identifies mf_x87_sin as sin (known-function matcher)", async () => {
      const text = mathlib.pe.sections.find((s) => s.name === ".text");
      if (text === undefined) throw new Error("mathlib.dll has no .text section in the fixture manifest");
      const swept = await ok("emu_call", {
        session_id: session,
        signature: { args: [{ type: "f64" }], returns: "f64" },
        vectors: { columns: { arg0: [0.5, 1.25, -2, 3] } },
        sweep: {
          module: "mathlib.dll",
          rva_start: `0x${text.rva.toString(16)}`,
          rva_end: `0x${(text.rva + text.virtualSize).toString(16)}`,
          match: { returns: "f64", args: ["arg0"], known: "unary" },
        },
        budget: { max_instructions: 20_000 },
      });
      expect(swept["mode"]).toBe("sweep");
      const sweep = swept["sweep"] as {
        functions: number;
        completed: number;
        next_offset: number | null;
        matched: { rva: string; matches: string[] }[];
      };
      // every .pdata function of the range ran (faults, #DE, the VEX stop and the import stops are per-function
      // outcomes, not errors); the exported functions are a subset of them
      expect(sweep.completed).toBe(sweep.functions);
      expect(sweep.functions).toBeGreaterThanOrEqual(Object.keys(mathlib.pe.pdata).length);
      expect(sweep.next_offset).toBeNull();
      const sin = `0x${(mathlib.pe.exportRvas["mf_x87_sin"] ?? 0).toString(16)}`;
      expect(sweep.matched.find((m) => m.rva === sin)?.matches).toContain("sin");
    });

    it("export_coverage turns the emulation coverage into drcov (the moved WP9 row)", async () => {
      const sin = await sinWithCoverage();
      const exported = await ok("export_coverage", { evidence_id: sin["evidence_id"] });
      expect(exported).toMatchObject({ format: "drcov" });
      expect(Number(exported["blocks"])).toBeGreaterThan(0);
      expect(existsSync(String(exported["path"]))).toBe(true);
    });

    it("diff_function emulation vs expected: equivalent, then one wrong value differs with an unknown", async () => {
      const base = {
        emu_session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: sig3,
        vectors: { columns: { arg0: [0, 2], arg1: [10, 4], arg2: [0.5, 0.25] } },
      };
      const same = await ok("diff_function", { ...base, expected: { columns: { ret: [5, 2.5] } } });
      expect(same).toMatchObject({
        verdict: "equivalent-on-tested-inputs",
        predicate_type: "bea.diff",
        confidence: "derived",
      });
      const wrong = await ok("diff_function", { ...base, expected: { columns: { ret: [5, 2.25] } } });
      expect(wrong["verdict"]).toBe("differ");
      expect(String(wrong["unknown_id"])).toMatch(/^unk_/u);
      expect(wrong["effects_applied"]).toBeUndefined();
    });
  },
);

describe.skipIf(skip !== false)(
  `emulation tools on mathlib.dll (built server): deadlines and cancellation${skipNote(skip)}`,
  () => {
    /** mf_spin(1) never returns; max_instructions 0 = unbudgeted, so only a deadline or a cancel can stop it */
    const spinForever = () => ({
      session_id: session,
      address: "mathlib.dll!mf_spin",
      signature: { args: [{ type: "i32" }], returns: "i32" },
      args: [1],
      budget: { max_instructions: 0 },
    });
    const bridgeRow = async () =>
      (await ok("session_status", { session_id: session, detail: "complete" }))["emulation"] as {
        generation: number;
        bridge: { child_pid: number };
      };

    it("a single call that outlives timeout_ms ends inside it as a timeout status (cause deadline), not an error", async () => {
      const started = performance.now();
      const result = await ok("emu_call", { ...spinForever(), timeout_ms: 2_000 });
      expect(performance.now() - started).toBeLessThan(2_000);
      expect(result["call"]).toMatchObject({
        status: "timeout",
        attribution: "harness",
        deterministic: false,
        stop: { status: "timeout", cause: "deadline" },
      });
      expect((result["coverage"] as { reasons: string[] }).reasons).toContain("deadline");
    });

    it("an MCP cancel stops a running call at once; the same bridge answers the next call", async () => {
      const before = await bridgeRow();
      const controller = new AbortController();
      const pending = bea.call("emu_call", { ...spinForever(), timeout_ms: 60_000 }, { signal: controller.signal });
      const abort = new Promise<number>((resolve) =>
        setTimeout(() => {
          controller.abort();
          resolve(performance.now());
        }, 300),
      );
      await expect(pending).rejects.toThrow(/abort/iu);
      const next = await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: sig3,
        args: [0, 10, 0.25],
      });
      // the queued call ran as soon as the bridge stopped the cancelled one (the 60 s deadline was never reached)
      expect(performance.now() - (await abort)).toBeLessThan(1_000);
      expect((next["call"] as { ret: { bits: string } }).ret.bits).toBe(f32(2.5));
      const after = await bridgeRow();
      expect(after.generation).toBe(before.generation);
      expect(after.bridge.child_pid).toBe(before.bridge.child_pid);
    });
  },
);

describe.skipIf(skip !== false)(
  `emulation tools on mathlib.dll (built server): restart and close${skipNote(skip)}`,
  () => {
    it("restart policy: a killed bridge re-opens on the next call; named snapshots are reported lost", async () => {
      await ok("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: sig3,
        args: [1, 2, 0.5],
        state: { save_as: "keep" },
      });
      const status = await ok("session_status", { session_id: session, detail: "complete" });
      const before = status["emulation"] as { generation: number; bridge: { pid: number; child_pid: number } };
      expect(JSON.stringify(status)).toContain("keep");
      const victim = before.bridge.child_pid;
      if (alive(victim)) process.kill(victim);
      let next = await bea.call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: sig3,
        args: [1, 3, 0.5],
      });
      if (next.isError === true) {
        expect(parseToolError(next)).toMatchObject({ code: "capability_unavailable", retryable: true });
        next = await bea.call("emu_call", {
          session_id: session,
          address: "mathlib.dll!mf_lerp",
          signature: sig3,
          args: [1, 3, 0.5],
        });
      }
      const after = expectToolSuccess(next);
      expect((after["call"] as { ret: { bits: string } }).ret.bits).toBe(f32(2));
      expect((after["call"] as { deviations: { kind: string }[] }).deviations.map((d) => d.kind)).toContain(
        "bridge_restarted_state_reset",
      );
      const restarted = await ok("session_status", { session_id: session, detail: "complete" });
      const row = restarted["emulation"] as {
        generation: number;
        lost_snapshots: string[];
        bridge: { pid: number; child_pid: number };
      };
      expect(row.generation).toBe(before.generation + 1);
      expect(row.lost_snapshots).toEqual(["keep"]);
      expect(row.bridge.child_pid).not.toBe(victim);
      recordBridge(row.bridge, "bridge re-opened after the kill");
      // a lost named snapshot is an input error that names it, not a silent restart from the baseline
      const lost = parseToolError(
        await bea.call("emu_call", {
          session_id: session,
          address: "mathlib.dll!mf_lerp",
          signature: sig3,
          args: [1, 3, 0.5],
          state: { from: "keep" },
        }),
      );
      expect(lost.code).toBe("invalid_request");
    });

    it("close_session ends the bridge; the id answers session_not_found", async () => {
      const closed = await ok("close_session", { session_id: session });
      expect(closed).toBeDefined();
      const after = parseToolError(
        await bea.call("emu_call", {
          session_id: session,
          address: "mathlib.dll!mf_lerp",
          signature: sig3,
          args: [1, 2, 0.5],
        }),
      );
      expect(after.code).toBe("session_not_found");
      await vi.waitFor(async () => expect((await ledger.audit()).leaks).toEqual([]), { timeout: 5_000, interval: 25 });
    });
  },
);

describe.skipIf(skip !== false)(`python resolution errors (built server)${skipNote(skip)}`, () => {
  it("BEA_PYTHON that does not exist is configuration_invalid; a non-python file is capability_unavailable", async () => {
    const manifest = await loadFixtures();
    const pidcheck = fixtureArtifact(manifest, "pidcheck");
    const missingHome = await createTempHome("wp14-nopy");
    const missing = await connectBea({ home: missingHome, env: { BEA_PYTHON: `${missingHome.root}\\no-python.exe` } });
    try {
      expect(parseToolError(await missing.call("emu_open", { image_path: mathlib.path })).code).toBe(
        "configuration_invalid",
      );
    } finally {
      await missing.close();
      await missingHome.cleanup();
    }
    if (pidcheck === null) return;
    const wrongHome = await createTempHome("wp14-badpy");
    const wrong = await connectBea({ home: wrongHome, env: { BEA_PYTHON: pidcheck.path } });
    try {
      const error = parseToolError(await wrong.call("emu_open", { image_path: mathlib.path }));
      expect(error.code).toBe("capability_unavailable");
      expect(error.remediation.action).toContain("bea setup --emulator");
    } finally {
      await wrong.close();
      await wrongHome.cleanup();
    }
  });

  it("no usable Python at all (no BEA_PYTHON, no BEA venv, nothing on PATH) is capability_unavailable (S6 §10.8)", async () => {
    // PATH is an empty directory of the temp home: `python` and `py` cannot resolve, and nothing can bootstrap a
    // Python into the temp LOCALAPPDATA (the WindowsApps aliases are not on this PATH)
    const bare = await createTempHome("wp14-nopath");
    const server = await connectBea({ home: bare, env: { PATH: bare.work } });
    try {
      const error = parseToolError(await server.call("emu_open", { image_path: mathlib.path }));
      expect(error.code).toBe("capability_unavailable");
      expect(error.remediation.action).toContain("bea setup --emulator");
    } finally {
      expect((await server.close()).exitCode).toBe(0);
      await bare.cleanup();
    }
  });
});
