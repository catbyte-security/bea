import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Deadline } from "../../../../src/domain/deadline.js";
import { CORE_LIMITATIONS } from "../../../../src/domain/evidence/limitations.js";
import { EMULATION_LIMITATIONS } from "../../../../src/domain/evidence/limitations/emulation.js";
import type { PiId } from "../../../../src/domain/ids.js";
import { notImplementedPort } from "../../../../src/application/notImplemented.js";
import type { EmuPort } from "../../../../src/ports/emu.js";
import { createEmulatorService } from "../../../../src/providers/emulator/createEmulatorService.js";
import {
  fakeLiveSession,
  FakeAddressService,
  FakeOracle,
  FakeSessionPort,
  fakeSpawn,
  scenarioLayout,
  tempDir,
  writeScenario,
  type FakeScenario,
  type TempDir,
} from "../../../support/emu/harness.js";
import { fakeEvidence, type FakeEvidence } from "../../../support/fakes/fakeEvidence.js";
import { fakeServices } from "../../../support/fakes/fakeServices.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";

/**
 * emu_open, emu_call and diff_function end to end over MCP (in-memory transport): the production server, invokeTool
 * and the WP14 services and provider (resolver, locator, EmuBridge, runtime, adapter) on the fake bridge; fake
 * evidence (WP1's in-memory runtime, same record pipeline), fake sessions, addresses and live oracle.
 */
const LIVE_OWNED = "11111111-1111-4111-8111-111111111111";
const LIVE_ATTACHED = "22222222-2222-4222-8222-222222222222";
const EXPORTS = {
  "mathlib.dll!mf_add": 0x1000,
  "mathlib.dll!mf_fault": 0x1040,
  "mathlib.dll!mf_avx": 0x1080,
  "mathlib.dll!mf_spin": 0x10c0,
  "mathlib.dll!mf_first": 0x1100,
  "mathlib.dll!mf_heap": 0x1140,
};
const F32x4 = { args: [{ type: "f32" }, { type: "f32" }], returns: "f32" } as const;

interface Harness {
  readonly bea: InMemoryBea;
  readonly evidence: FakeEvidence;
  readonly sessions: FakeSessionPort;
  readonly oracle: () => FakeOracle;
  readonly imagePath: string;
}

let work: TempDir;
let main: Harness;

const connect = async (
  scenarioOverrides: FakeScenario = {},
  env: Record<string, string> = {},
  liveFunctions: Record<string, string> = { "0x1000": "sum_f32", "0x1100": "first" },
): Promise<Harness> => {
  const imagePath = join(work.dir, "mathlib.dll");
  await writeFile(imagePath, "not really a PE, the fake bridge never reads it");
  const imageSha = createHash("sha256").update("not really a PE, the fake bridge never reads it").digest("hex");
  const scenario = await writeScenario(
    work.dir,
    {
      imageSha256: imageSha,
      imagePath,
      functions: {
        "0x180001000": "sum_f32",
        "0x180001040": "fault_if_zero",
        "0x180001080": "harness",
        "0x1800010c0": "spin",
        "0x180001100": "first",
        "0x180001140": "heap_full",
      },
      spinMs: 20,
      deviations: { "0x180001000": [{ kind: "imports_hle_bound", note: "hle" }] },
      ...scenarioOverrides,
    },
    `mcp-${String(Math.random()).slice(2, 8)}.json`,
  );
  const evidence = fakeEvidence();
  const sessions = new FakeSessionPort();
  let oracle: FakeOracle | undefined;
  const bea = await connectInMemoryBea({
    env: { BEA_PYTHON: process.execPath, ...env },
    services: async (core) => {
      let emulator: EmuPort | undefined;
      const address = new FakeAddressService({
        emulator: () => {
          if (emulator === undefined) throw new Error("emulator not composed");
          return emulator;
        },
        live: [
          {
            name: "mathlib.dll",
            base: 0x7ff700000000n,
            size: 0x10000,
            sha256: imageSha,
            preferredBase: 0x180000000n,
            primary: true,
          },
        ],
        exports: EXPORTS,
      });
      emulator = createEmulatorService(
        core,
        {
          evidence,
          sessions: sessions.port(),
          pe: { images: notImplementedPort("pe.images"), hashes: notImplementedPort("pe.hashes") },
          dumps: notImplementedPort("dumps"),
        },
        { layout: scenarioLayout(work.dir, scenario), spawn: fakeSpawn },
      );
      const owned: PiId = await evidence.addInstance(4321, "owned");
      const attached: PiId = await evidence.addInstance(4322, "attached");
      sessions.lives.set(LIVE_OWNED, fakeLiveSession(LIVE_OWNED, owned));
      sessions.lives.set(LIVE_ATTACHED, fakeLiveSession(LIVE_ATTACHED, attached, { ownership: "attached" }));
      oracle = new FakeOracle({ evidence, instance: owned, functions: liveFunctions });
      return fakeServices({ evidence, sessions: sessions.port(), address: address.port(), oracle, emulator })(core);
    },
  });
  return {
    bea,
    evidence,
    sessions,
    oracle: () => {
      if (oracle === undefined) throw new Error("oracle");
      return oracle;
    },
    imagePath,
  };
};

const call = (h: Harness, name: string, args: Record<string, unknown>) =>
  h.bea.client.callTool({ name, arguments: args });
const open = async (h: Harness, extra: Record<string, unknown> = {}): Promise<string> => {
  const result = expectToolSuccess(await call(h, "emu_open", { image_path: h.imagePath, ...extra }));
  return String(result["session_id"]);
};

beforeAll(async () => {
  work = await tempDir("mcp");
  main = await connect();
});
afterAll(async () => {
  await main.bea.close();
  await work.cleanup();
});

describe("tools/list", () => {
  it("advertises the three emulation tools with derived annotations", async () => {
    const tools = (await main.bea.client.listTools()).tools.filter((t) =>
      ["emu_open", "emu_call", "diff_function"].includes(t.name),
    );
    expect(tools.map((t) => [t.name, t.annotations?.readOnlyHint, t.annotations?.destructiveHint])).toEqual([
      ["emu_open", true, false],
      ["emu_call", true, false],
      ["diff_function", false, true],
    ]);
  });
});

describe("emu_open", () => {
  it("opens an image session, records bea.emu.session and registers the id", async () => {
    const raw = await call(main, "emu_open", { image_path: main.imagePath, label: "x" });
    const result = expectToolSuccess(raw);
    expect(result).toMatchObject({
      kind: "emulation",
      source: "image",
      bundle_id: null,
      predicate_type: "bea.emu.session",
      confidence: "observed",
      authority: "emulation",
      coverage: { status: "complete" },
      primary: {
        name: "mathlib.dll",
        mapped_base: "0x180000000",
        static_base: "0x180000000",
        static_base_source: "pe-header",
      },
      fp: { mxcsr: "0x1f80", fpcw: "0x27f", source: "windows-default" },
      bridge: { protocol: "bea-emu/0.1", generation: 0, python: { source: "BEA_PYTHON", pin: "exact" } },
      imports: { unhandled_sample: ["kernel32.dll!CreateEventA"] },
    });
    expect(String(result["baseline_state"])).toMatch(/^es_[a-f0-9]{64}$/u);
    expect(result["limitations"]).toContain(EMULATION_LIMITATIONS.EMU_ENTRY_NOT_RUN);
    const sessionId = String(result["session_id"]);
    expect(main.sessions.kindOf(sessionId)).toBe("emulation");
    const record = main.evidence.records.find((r) => r.evidence_id === result["evidence_id"]);
    expect(record?.subject).toMatchObject({ kind: "emulation", state: { basis: "baseline" } });
    expect(record?.parameters).not.toHaveProperty("label");
    expect((raw as { _meta?: Record<string, unknown> })._meta).toBeDefined();
  });

  it("refuses inputs it cannot honour before starting anything", async () => {
    const both = parseToolError(
      await call(main, "emu_open", { image_path: main.imagePath, dump_path: main.imagePath }),
    );
    expect(both.code).toBe("invalid_request");
    const zero = parseToolError(await call(main, "emu_open", { image_path: main.imagePath, fault_policy: "map_zero" }));
    expect(zero.code).toBe("invalid_request");
    const patch = parseToolError(
      await call(main, "emu_open", {
        image_path: main.imagePath,
        patches: [{ address: "mathlib.dll:0x180001000", hex: "90" }],
      }),
    );
    expect(patch.details["issues"]).toEqual([expect.objectContaining({ path: "patches[0].address" })]);
    const missing = parseToolError(await call(main, "emu_open", { image_path: join(work.dir, "absent.dll") }));
    expect(missing.code).toBe("file_operation_failed");
  });

  it("reports a missing configured python as configuration_invalid", async () => {
    const other = await connect({}, { BEA_PYTHON: join(work.dir, "no-python.exe") });
    try {
      const error = parseToolError(await call(other, "emu_open", { image_path: other.imagePath }));
      expect(error.code).toBe("configuration_invalid");
    } finally {
      await other.bea.close();
    }
  });

  it("names the tool's own timeout_ms when the emulator misses the deadline", async () => {
    // the open outlives the host backstop (deadline + 1 s) and answers the cancel within the grace period
    const slow = await connect({ delays: { "session.open": 4_000 } });
    try {
      const error = parseToolError(await call(slow, "emu_open", { image_path: slow.imagePath, timeout_ms: 2_000 }));
      expect(error).toMatchObject({ code: "provider_timeout", retryable: true });
      expect(error.details["timeout_ms"]).toBe(2_000);
      expect(error.message).toContain("2000 ms");
    } finally {
      await slow.bea.close();
    }
  });
});

/** One emulation session shared by the two emu_call groups (the harness keeps within emu.max_sessions). */
let emuCallSession: Promise<string> | undefined;

describe("emu_call: single calls and state", () => {
  let session: string;
  beforeAll(async () => {
    session = await (emuCallSession ??= open(main));
  });

  it("runs a single call: typed return, raw bits, state digests and a bea.emu.run record", async () => {
    const result = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        args: [1, 2],
      }),
    );
    expect(result).toMatchObject({
      mode: "single",
      target: { module: "mathlib.dll", rva: "0x1000", va: "0x180001000" },
      predicate_type: "bea.emu.run",
      authority: "emulation",
      confidence: "observed",
      coverage: { status: "complete" },
      call: {
        status: "returned",
        attribution: null,
        ret: { type: "f32", bits: "0x40400000", value: 3 },
        deterministic: true,
      },
      state: { from: "baseline", saved_as: null },
    });
    expect(result["limitations"]).toEqual(
      expect.arrayContaining([CORE_LIMITATIONS.NOT_REAL_PROCESS, CORE_LIMITATIONS.EMU_HLE_IMPORTS]),
    );
    const state = result["state"] as Record<string, string>;
    expect(state["from_digest"]).toMatch(/^es_/u);
    expect(state["after_digest"]).not.toBe(state["from_digest"]);
  });

  it("chains state: from current follows the previous call; save_as and from <name>", async () => {
    const first = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        args: [1, 1],
        state: { save_as: "snap1" },
      }),
    );
    const after = (first["state"] as Record<string, string>)["after_digest"];
    expect((first["state"] as Record<string, unknown>)["saved_as"]).toBe("snap1");
    const chained = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        args: [1, 1],
        state: { from: "current" },
      }),
    );
    expect((chained["state"] as Record<string, string>)["from_digest"]).toBe(after);
    const named = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        args: [1, 1],
        state: { from: "snap1", drop: ["snap1"] },
      }),
    );
    expect((named["state"] as Record<string, string>)["from_digest"]).toBe(after);
    const record = main.evidence.records.find((r) => r.evidence_id === named["evidence_id"]);
    expect(record?.subject).toMatchObject({ kind: "emulation", state: { basis: "snapshot" } });
  });
});

describe("emu_call: batches and streams", () => {
  let session: string;
  beforeAll(async () => {
    session = await (emuCallSession ??= open(main));
  });

  it("runs a batch with inline columns and target-attributed faults as statuses", async () => {
    const result = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_fault",
        signature: { args: [{ type: "i32" }], returns: "i32" },
        vectors: { columns: { arg0: [5, 0, 7] } },
      }),
    );
    expect(result).toMatchObject({
      mode: "batch",
      predicate_type: "bea.emu.batch",
      batch: {
        offset: 0,
        vectors: 3,
        completed: 3,
        returned: 2,
        by_status: { returned: 2, fault: 1 },
        by_attribution: { target: 1, harness: 0 },
        status: ["returned", "fault", "returned"],
        continuation: null,
        stream_id: null,
      },
    });
    const columns = (result["batch"] as Record<string, Record<string, { bits: string[]; value: unknown[] }>>)[
      "columns"
    ];
    expect(columns?.["ret"]?.value).toEqual([5, null, 7]);
    expect((result["batch"] as { faults: unknown[] }).faults).toEqual([
      expect.objectContaining({
        index: 1,
        status: "fault",
        attribution: "target",
        cause: "read_unmapped",
        pc_rva: "0x1010",
      }),
    ]);
  });

  it("streams rows above inline_limit, builds a coverage blob, and marks harness stops partial", async () => {
    const big = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        generate: {
          seed: 7,
          count: 100,
          columns: { arg0: { dist: "uniform", min: -2, max: 2 }, arg1: { dist: "edge" } },
        },
        inline_limit: 10,
        trace: { coverage: true },
      }),
    );
    const batch = big["batch"] as Record<string, unknown>;
    expect(batch["columns"]).toBeNull();
    expect(String(batch["stream_id"])).toMatch(/^st_[a-f0-9]{64}$/u);
    const preview = batch["preview"] as { i: number }[];
    expect(preview.map((row) => row.i)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 92, 93, 94, 95, 96, 97, 98, 99]);
    const frames = main.evidence.frames(String(batch["stream_id"]) as `st_${string}`);
    const streamed = frames
      .flatMap((f) => new TextDecoder().decode(f.payload).trim().split(/\n/u))
      .map((line) => JSON.parse(line) as { i: number; s: string });
    expect(streamed).toHaveLength(100);
    expect(streamed[42]).toMatchObject({ i: 42, s: "ok" });
    expect(big["coverage_blob"]).toMatchObject({ blocks: 2 });
    const blob = main.evidence.blobBytes(String((big["coverage_blob"] as Record<string, string>)["sha256"]));
    expect(JSON.parse(new TextDecoder().decode(blob))).toMatchObject({
      schema: "bea.coverage/1",
      address_space: "emulation-image",
      blocks: [
        [0, 0x1000, 16, 3],
        [0, 0x1020, 8, 1],
      ],
    });
    const harness = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_avx",
        signature: F32x4,
        vectors: { columns: { arg0: [1], arg1: [2] } },
      }),
    );
    expect(harness).toMatchObject({ batch: { by_attribution: { harness: 1 } }, coverage: { status: "partial" } });
    expect((harness["coverage"] as { reasons: string[] }).reasons).toContain("isa_guard_stop");
  });

  it("returns a continuation when the deadline stops a batch", async () => {
    const result = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spin",
        signature: F32x4,
        vectors: { count: 500 },
        timeout_ms: 2_500,
      }),
    );
    const batch = result["batch"] as Record<string, unknown>;
    expect(Number(batch["completed"])).toBeLessThan(500);
    expect(batch["continuation"]).toEqual({ vector_offset: batch["completed"] });
    expect(result["coverage"]).toMatchObject({ status: "partial" });
  });

  it("ends a single call that outlives the tool deadline as a timeout status inside timeout_ms", async () => {
    const started = Date.now();
    const result = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spin",
        signature: F32x4,
        args: [1, 2],
        timeout_ms: 2_500,
      }),
    );
    // the per-call watchdog carries the bridge deadline (emu.call has none): a status, not a provider_timeout
    expect(Date.now() - started).toBeLessThan(2_500);
    expect(result["call"]).toMatchObject({
      status: "timeout",
      attribution: "harness",
      deterministic: false,
      stop: { status: "timeout", cause: "deadline" },
    });
    expect(result["coverage"]).toMatchObject({ status: "partial" });
    expect((result["coverage"] as { reasons: string[] }).reasons).toContain("deadline");
    // a watchdog the request sets itself keeps its own cause
    const own = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spin",
        signature: F32x4,
        args: [1, 2],
        budget: { timeout_ms_per_call: 100 },
      }),
    );
    expect(own["call"]).toMatchObject({ status: "timeout", stop: { cause: "watchdog" } });
  });
});

describe("emu_call: sweeps and session errors", () => {
  let session: string;
  beforeAll(async () => {
    session = await (emuCallSession ??= open(main));
  });

  it("sweeps functions and reports matches", async () => {
    const result = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        signature: { args: [{ type: "f32" }], returns: "f32" },
        vectors: { columns: { arg0: [1, 4] } },
        sweep: { rva_start: "0x1000", rva_end: "0x2000", match: { returns: "f32", args: ["arg0"] } },
      }),
    );
    expect(result).toMatchObject({
      mode: "sweep",
      target: null,
      predicate_type: "bea.emu.sweep",
      sweep: {
        module: "mathlib.dll",
        functions: 2,
        matched: [{ rva: "0x1000", va: "0x180001000", matches: ["sqrtf"] }],
      },
    });
  });

  it("answers session errors from the shared table", async () => {
    expect(
      parseToolError(
        await call(main, "emu_call", {
          session_id: "33333333-3333-4333-8333-333333333333",
          address: "mathlib.dll!mf_add",
          signature: F32x4,
        }),
      ).code,
    ).toBe("session_not_found");
    const live = parseToolError(
      await call(main, "emu_call", { session_id: LIVE_OWNED, address: "mathlib.dll!mf_add", signature: F32x4 }),
    );
    expect(live.code).toBe("invalid_request");
    expect(JSON.stringify(live.details)).toContain("call_function");
    const mode = parseToolError(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        args: [1],
        vectors: { count: 2 },
      }),
    );
    expect(mode.code).toBe("invalid_request");
    const closed = await open(main);
    await main.sessions.close(closed, {
      opId: 1,
      name: "close_session",
      signal: new AbortController().signal,
      deadline: Deadline.after(2_000),
    });
    expect(
      parseToolError(
        await call(main, "emu_call", { session_id: closed, address: "mathlib.dll!mf_add", signature: F32x4 }),
      ).code,
    ).toBe("session_not_found");
  });
});

describe("diff_function", () => {
  let emu: string;
  beforeAll(async () => {
    emu = await open(main);
  });

  it("finds emulation and expected values equivalent on the tested inputs", async () => {
    const result = expectToolSuccess(
      await call(main, "diff_function", {
        emu_session_id: emu,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        vectors: { columns: { arg0: [1, 2], arg1: [2, 3] } },
        expected: { columns: { ret: [3, 5] } },
      }),
    );
    expect(result).toMatchObject({
      verdict: "equivalent-on-tested-inputs",
      verdict_basis: "bit-exact",
      predicate_type: "bea.diff",
      confidence: "derived",
      authority: "emulation",
      unknown_id: null,
      pairs: [{ a: "emulation", b: "expected", verdict: "equivalent-on-tested-inputs", compared: 2, equal: 2 }],
    });
    expect(result["limitations"]).toContain(EMULATION_LIMITATIONS.DIFF_TESTED_INPUTS_ONLY);
    expect((result["rows"] as unknown[]).length).toBe(2);
  });

  it("differs on one wrong expected value, records an unknown, and applies no target effect", async () => {
    const effectsBefore = main.evidence.effectStates().length;
    const result = expectToolSuccess(
      await call(main, "diff_function", {
        emu_session_id: emu,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        vectors: { columns: { arg0: [1, 2], arg1: [2, 3] } },
        expected: { columns: { ret: [3, 6] } },
      }),
    );
    expect(result["verdict"]).toBe("differ");
    expect(String(result["unknown_id"])).toMatch(/^unk_[a-f0-9]{64}$/u);
    expect(result["worst"]).toEqual([expect.objectContaining({ index: 1, column: "ret", reason: "value" })]);
    expect(main.evidence.effectStates().length).toBe(effectsBefore);
  });

  it("refuses unknown or repeated compare.columns names instead of dropping them (EMU-12)", async () => {
    const base = {
      emu_session_id: emu,
      address: "mathlib.dll!mf_add",
      signature: F32x4,
      vectors: { columns: { arg0: [1, 2], arg1: [2, 3] } },
      expected: { columns: { ret: [3, 5] } },
    };
    const refused = async (columns: string[]) =>
      JSON.stringify(parseToolError(await call(main, "diff_function", { ...base, compare: { columns } })));
    expect(await refused(["ret", "out.velocity"])).toMatch(/invalid_request.*compare\.columns\[1\].*valid: ret/su);
    expect(await refused(["rett"])).not.toContain("returns void");
    expect(await refused(["ret", "ret"])).toContain("listed twice");
  });

  it("treats emulator harness stops as inconclusive (unknown)", async () => {
    const result = expectToolSuccess(
      await call(main, "diff_function", {
        emu_session_id: emu,
        address: "mathlib.dll!mf_avx",
        signature: F32x4,
        vectors: { columns: { arg0: [1], arg1: [2] } },
        expected: { columns: { ret: [3] } },
      }),
    );
    expect(result["verdict"]).toBe("unknown");
    expect((result["pairs"] as { inconclusive_reasons: Record<string, number> }[])[0]?.inconclusive_reasons).toEqual({
      "emulation:vex": 1,
    });
  });

  it("compares the live oracle and the emulator over the same plan, with one function-called effect", async () => {
    const result = expectToolSuccess(
      await call(main, "diff_function", {
        live_session_id: LIVE_OWNED,
        emu_session_id: emu,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        generate: {
          seed: 3,
          count: 20,
          columns: { arg0: { dist: "uniform", min: -2, max: 2 }, arg1: { dist: "uniform", min: -2, max: 2 } },
        },
      }),
    );
    expect(result).toMatchObject({
      verdict: "equivalent-on-tested-inputs",
      target: { live: { module: "mathlib.dll", rva: "0x1000" }, emulation: { module: "mathlib.dll", rva: "0x1000" } },
      legs: [
        { leg: "live", completed: 20 },
        { leg: "emulation", completed: 20 },
      ],
      vectors: { count: 20, offset: 0, source: "generated", continuation: null },
      authority: "emulation",
    });
    expect(result["effects_applied"]).toHaveLength(1);
    const request = main.oracle().calls.at(-1);
    expect(request?.fp).toMatchObject({ mxcsr: 0x1f80, fpcw: 0x27f, source: "windows-default" });
    expect(request?.target).toMatchObject({ module: "mathlib.dll", rva: "0x1000", va: "0x7ff700001000" });
  });

  it("refuses a raw address across two address spaces and an attached live leg without the gate", async () => {
    const raw = parseToolError(
      await call(main, "diff_function", {
        live_session_id: LIVE_OWNED,
        emu_session_id: emu,
        address: "0x180001000",
        signature: F32x4,
        vectors: { columns: { arg0: [1], arg1: [2] } },
      }),
    );
    expect(raw.code).toBe("invalid_request");
    const gated = parseToolError(
      await call(main, "diff_function", {
        live_session_id: LIVE_ATTACHED,
        emu_session_id: emu,
        address: "mathlib.dll!mf_add",
        signature: F32x4,
        vectors: { columns: { arg0: [1], arg1: [2] } },
      }),
    );
    expect(gated).toMatchObject({ code: "capability_unavailable", details: { gate: "call_attached" } });
  });

  it("reports a live/emulation difference with hints", async () => {
    const other = await connect({}, {}, { "0x1000": "plus_one_f32" });
    try {
      const otherEmu = await open(other);
      const result = expectToolSuccess(
        await call(other, "diff_function", {
          live_session_id: LIVE_OWNED,
          emu_session_id: otherEmu,
          address: "mathlib.dll!mf_add",
          signature: F32x4,
          vectors: { columns: { arg0: [1, 2], arg1: [0, 0] } },
        }),
      );
      expect(result["verdict"]).toBe("differ");
      const hints = (result["hints"] as { code: string }[]).map((h) => h.code);
      expect(hints).toContain("file_image_state");
      expect(hints).toContain("possible_state_carryover");
      expect(String(result["unknown_id"])).toMatch(/^unk_/u);
    } finally {
      await other.bea.close();
    }
  });
});

describe("chain batches that run out of emulated heap (review fix EMU-6)", () => {
  let session: string;
  let emu: string;
  beforeAll(async () => {
    session = await (emuCallSession ??= open(main));
    emu = await open(main);
  });

  it("a chain batch that cannot place the next vector's heap buffers ends partial, saying why (EMU-6)", async () => {
    const result = expectToolSuccess(
      await call(main, "emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_heap",
        signature: F32x4,
        vectors: { count: 5 },
        isolation: "chain",
      }),
    );
    expect(result).toMatchObject({ batch: { completed: 2, continuation: { vector_offset: 2 } } });
    expect(result["coverage"]).toMatchObject({ status: "partial" });
    expect((result["coverage"] as { reasons: string[] }).reasons).toContain("stopped_early");
    expect(result["limitations"]).toContain(EMULATION_LIMITATIONS.EMU_BATCH_STOPPED(2, "heap"));
  });

  it("names a stopped emulation chain as the reason vectors did not run, not a deadline (EMU-6)", async () => {
    const result = expectToolSuccess(
      await call(main, "diff_function", {
        emu_session_id: emu,
        address: "mathlib.dll!mf_heap",
        signature: F32x4,
        vectors: { columns: { arg0: [1, 2, 3], arg1: [0, 0, 0] } },
        expected: { columns: { ret: [1, 2, 3] } },
        emulation: { isolation: "chain" },
      }),
    );
    expect(result["verdict"]).not.toBe("equivalent-on-tested-inputs");
    expect((result["coverage"] as { reasons: string[] }).reasons).toContain("stopped_early");
    expect((result["coverage"] as { reasons: string[] }).reasons).not.toContain("deadline");
    expect(result["limitations"]).toContain(EMULATION_LIMITATIONS.EMU_BATCH_STOPPED(2, "heap"));
    expect(JSON.stringify(result["rows"])).toContain("not_run:resource_exhausted");
  });
});

describe("bea_status and shutdown", () => {
  it("reports the emulator backend and closes bridges with the application", async () => {
    const status = expectToolSuccess(await call(main, "bea_status", {}));
    const row = (status["backends"] as { id: string; state: string }[]).find((b) => b.id === "emulator");
    expect(row?.state).toBe("available");
  });
});
