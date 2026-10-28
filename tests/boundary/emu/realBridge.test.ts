import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { resolveDistLayout } from "../../../src/application/distLayout.js";
import { notImplementedPort } from "../../../src/application/notImplemented.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { PiId } from "../../../src/domain/ids.js";
import type { EmuPort } from "../../../src/ports/emu.js";
import { createEmulatorService } from "../../../src/providers/emulator/createEmulatorService.js";
import {
  emuSkip,
  fixtureArtifact,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { FakeAddressService, FakeSessionPort } from "../../support/emu/harness.js";
import { fakeEvidence, type FakeEvidence } from "../../support/fakes/fakeEvidence.js";
import { fakeServices } from "../../support/fakes/fakeServices.js";
import { connectInMemoryBea, type InMemoryBea } from "../../support/mcp/inMemory.js";
import { expectToolSuccess } from "../../support/mcp/parseToolError.js";

/**
 * The emulation lane (S5 §14.1 test:emu; DESIGN §8.2 emu-boundary): the WP14 client stack (resolver, locator,
 * EmuBridge, runtime, adapter, EmulationService, DiffService) driving the REAL bridge (bridge/emu/bea_emu_bridge.py,
 * WP14a) under the real Python with unicorn, on the gcc-built mathlib.dll fixture. No Frida, no target process.
 * The bridge resolves from BEA_DIST_DIR (a snapshot) when set, else from the repository. Named skips: EMU_SKIP
 * (no Python with unicorn 2.1.x) and GCC_SKIP (no fixtures).
 */
const skip = emuSkip() !== false ? emuSkip() : gccSkip();

let bea: InMemoryBea;
let evidence: FakeEvidence;
let sessions: FakeSessionPort;
let mathlib: FixtureArtifact;
const pids: number[] = [];
/** the session every test uses, opened once in beforeAll (its emu_open result is asserted by the first test) */
let session = "";
let opened: Readonly<Record<string, unknown>> = {};

const f32 = (v: number): string => {
  const view = new DataView(new ArrayBuffer(4));
  view.setFloat32(0, v, true);
  return `0x${view.getUint32(0, true).toString(16)}`;
};
const call = async (name: string, args: Record<string, unknown>) => bea.client.callTool({ name, arguments: args });
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "mathlib");
  if (artifact === null) throw new Error("mathlib fixture unavailable");
  mathlib = artifact;
  evidence = fakeEvidence();
  sessions = new FakeSessionPort();
  const exports = Object.fromEntries(
    Object.entries(artifact.pe.exportRvas).map(([name, rva]) => [`mathlib.dll!${name}`, rva]),
  );
  bea = await connectInMemoryBea({
    ...(process.env["BEA_PYTHON"] === undefined ? {} : { env: { BEA_PYTHON: process.env["BEA_PYTHON"] } }),
    services: async (core) => {
      let emulator: EmuPort | undefined;
      const address = new FakeAddressService({
        emulator: () => {
          if (emulator === undefined) throw new Error("emulator not composed");
          return emulator;
        },
        exports,
      });
      emulator = createEmulatorService(
        core,
        {
          evidence,
          sessions: sessions.port(),
          pe: { images: notImplementedPort("pe.images"), hashes: notImplementedPort("pe.hashes") },
          dumps: notImplementedPort("dumps"),
        },
        { layout: resolveDistLayout() },
      );
      const instance: PiId = await evidence.addInstance(1, "owned");
      void instance;
      return fakeServices({ evidence, sessions: sessions.port(), address: address.port(), emulator })(core);
    },
  });
  opened = expectToolSuccess(await call("emu_open", { image_path: artifact.path }));
  session = String(opened["session_id"]);
  const bridge = opened["bridge"] as { pid: number; child_pid: number };
  pids.push(bridge.pid, bridge.child_pid);
}, 120_000);

afterAll(async () => {
  if (skip !== false) return;
  await bea.close();
  // leak check (S5 §14.1): neither the launcher nor the interpreter of any bridge we started outlives the server
  await new Promise((r) => setTimeout(r, 300));
  expect(pids.filter(alive)).toEqual([]);
});

describe.skipIf(skip !== false)(`real bridge on mathlib.dll: open, goldens, statuses${skipNote(skip)}`, () => {
  it("opens the image: ISA report, x87 sites, FP defaults and the HLE loader deviations", () => {
    const result = opened;
    expect(result).toMatchObject({
      kind: "emulation",
      source: "image",
      primary: {
        name: "mathlib.dll",
        sha256: mathlib.artifactSha256,
        mapped_base: "0x180000000",
        preferred_base: "0x180000000",
      },
      fp: { mxcsr: "0x1f80", fpcw: "0x27f" },
      bridge: { protocol: "bea-emu/0.1", generation: 0, engines: { unicorn: "2.1.4" } },
    });
    const isa = result["isa"] as { sites: Record<string, number>; functions_with_vex_sample: string[] };
    expect(isa.functions_with_vex_sample).toContain(`0x${(mathlib.pe.exportRvas["mf_avx_dot"] ?? 0).toString(16)}`);
    expect(isa.sites["x87_inexact"]).toBeGreaterThanOrEqual(1);
    expect((result["loader_deviations"] as { kind: string }[]).map((d) => d.kind)).toContain("entry_point_not_run");
  });

  it("reproduces the bits-only goldens (tests/golden/emu/mathlib.json)", async () => {
    const golden = JSON.parse(readFileSync(new URL("../../golden/emu/mathlib.json", import.meta.url), "utf8")) as {
      cases: {
        export: string;
        signature: unknown;
        args: unknown[];
        status: string;
        ret_bits: string | null;
        max_instructions?: number;
      }[];
    };
    for (const c of golden.cases) {
      const result = expectToolSuccess(
        await call("emu_call", {
          session_id: session,
          address: `mathlib.dll!${c.export}`,
          signature: c.signature,
          args: c.args,
          ...(c.max_instructions === undefined ? {} : { budget: { max_instructions: c.max_instructions } }),
        }),
      );
      const view = result["call"] as { status: string; ret: { bits: string } | null };
      expect(view.status, `${c.export}(${JSON.stringify(c.args)})`).toBe(c.status);
      expect(view.ret?.bits ?? null, `${c.export}(${JSON.stringify(c.args)})`).toBe(c.ret_bits);
    }
  });

  it("emulates mf_lerp and mf_spring bit-exactly against JS references over 100 vectors", async () => {
    const a = Array.from({ length: 100 }, (_, i) => Math.fround(i * 0.37 - 11));
    const b = Array.from({ length: 100 }, (_, i) => Math.fround(5 - i * 0.11));
    const t = Array.from({ length: 100 }, (_, i) => Math.fround((i % 17) / 16));
    const lerp = expectToolSuccess(
      await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        vectors: { columns: { arg0: a.map(f32), arg1: b.map(f32), arg2: t.map(f32) } },
        inline_limit: 100,
      }),
    );
    const expected = a.map((x, i) => f32(Math.fround(x + Math.fround(Math.fround((b[i] ?? 0) - x) * (t[i] ?? 0)))));
    const bits = ((lerp["batch"] as { columns: Record<string, { bits: string[] }> }).columns["ret"] ?? { bits: [] })
      .bits;
    expect(bits).toEqual(expected);
    const spring = expectToolSuccess(
      await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spring",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        args: [0.25, -1.5, 40, 2],
      }),
    );
    const f = Math.fround(Math.fround(-40 * 0.25) - Math.fround(2 * -1.5));
    expect((spring["call"] as { ret: { bits: string } }).ret.bits).toBe(f32(f));
  });

  it("reports faults, unsupported instructions and budgets as statuses with attribution", async () => {
    const div = expectToolSuccess(
      await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_div",
        signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
        vectors: { columns: { arg0: [7, 7], arg1: [2, 0] } },
      }),
    );
    expect((div["batch"] as { status: string[] }).status).toEqual(["returned", "cpu_exception"]);
    expect((div["batch"] as { columns: Record<string, { value: unknown[] }> }).columns["ret"]?.value[0]).toBe(3);
    const avx = expectToolSuccess(
      await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_avx_dot",
        signature: { args: [{ type: "ptr" }, { type: "ptr" }, { type: "i32" }], returns: "f32" },
        args: [0, 0, 0],
      }),
    );
    expect(avx["call"]).toMatchObject({ status: "unsupported_instruction", attribution: "harness" });
    expect(avx["coverage"]).toMatchObject({ status: "partial" });
    const spin = expectToolSuccess(
      await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_spin",
        signature: { args: [{ type: "i32" }], returns: "i32" },
        args: [1],
        budget: { max_instructions: 10_000 },
      }),
    );
    expect(spin["call"]).toMatchObject({ status: "budget_exhausted", attribution: "harness" });
  });
});

describe.skipIf(skip !== false)(`real bridge on mathlib.dll: x87, diff, restart${skipNote(skip)}`, () => {
  it("tags the x87 path and builds a coverage blob", async () => {
    const sin = expectToolSuccess(
      await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_x87_sin",
        signature: { args: [{ type: "f64" }], returns: "f64" },
        args: [1.25],
        trace: { coverage: true },
      }),
    );
    const callView = sin["call"] as { status: string; deviations: { kind: string }[] };
    expect(callView.status).toBe("returned");
    expect(callView.deviations.map((d) => d.kind)).toContain("x87_transcendental_inexact");
    expect(sin["coverage_blob"]).toMatchObject({ blocks: expect.any(Number) });
    expect((sin["coverage_blob"] as { blocks: number }).blocks).toBeGreaterThan(0);
  });

  it("diffs the emulator against expected values (equivalent, then differ with an unknown)", async () => {
    const base = {
      emu_session_id: session,
      address: "mathlib.dll!mf_lerp",
      signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
      vectors: { columns: { arg0: [0, 1], arg1: [10, 3], arg2: [0.5, 0.5] } },
    };
    const same = expectToolSuccess(await call("diff_function", { ...base, expected: { columns: { ret: [5, 2] } } }));
    expect(same["verdict"]).toBe("equivalent-on-tested-inputs");
    const differ = expectToolSuccess(
      await call("diff_function", { ...base, expected: { columns: { ret: [5, 2.0000002] } } }),
    );
    expect(differ["verdict"]).toBe("differ");
    expect(String(differ["unknown_id"])).toMatch(/^unk_/u);
  });

  it("re-opens after the bridge is killed mid-session; named snapshots are reported lost", async () => {
    const saved = expectToolSuccess(
      await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        args: [1, 2, 0.5],
        state: { save_as: "before_kill" },
      }),
    );
    expect((saved["state"] as { saved_as: string }).saved_as).toBe("before_kill");
    const driver = sessions.externals.get(session);
    const detail = await driver?.detail("summary", {
      opId: 1,
      name: "t",
      signal: new AbortController().signal,
      deadline: Deadline.after(5_000),
    });
    const bridge = (detail?.ok ? detail.value["bridge"] : null) as {
      pid: number | null;
      child_pid: number | null;
    } | null;
    expect(bridge?.child_pid).toBeGreaterThan(0);
    process.kill(bridge?.child_pid ?? 0);
    if (bridge?.pid !== null && bridge?.pid !== undefined && alive(bridge.pid)) process.kill(bridge.pid);
    // the first call after the loss may report it (capability_unavailable, retryable); a retry re-opens
    let result = await call("emu_call", {
      session_id: session,
      address: "mathlib.dll!mf_lerp",
      signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
      args: [1, 3, 0.5],
    });
    if (result.isError === true)
      result = await call("emu_call", {
        session_id: session,
        address: "mathlib.dll!mf_lerp",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        args: [1, 3, 0.5],
      });
    const after = expectToolSuccess(result);
    const view = after["call"] as { ret: { bits: string }; deviations: { kind: string }[] };
    expect(view.ret.bits).toBe(f32(2));
    expect(view.deviations.map((d) => d.kind)).toContain("bridge_restarted_state_reset");
    expect(after["limitations"]).toEqual(
      expect.arrayContaining([expect.stringContaining("1 named snapshot(s) were lost")]),
    );
    const status = await driver?.detail("summary", {
      opId: 2,
      name: "t",
      signal: new AbortController().signal,
      deadline: Deadline.after(5_000),
    });
    expect(status?.ok && status.value).toMatchObject({ generation: 1, lost_snapshots: ["before_kill"] });
    const fresh = (status?.ok ? status.value["bridge"] : null) as { pid: number; child_pid: number } | null;
    if (fresh !== null) pids.push(fresh.pid, fresh.child_pid);
    const lost = await call("emu_call", {
      session_id: session,
      address: "mathlib.dll!mf_lerp",
      signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
      args: [1, 3, 0.5],
      state: { from: "before_kill" },
    });
    expect(lost.isError).toBe(true);
  });
});
