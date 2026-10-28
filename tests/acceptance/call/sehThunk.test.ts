import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { classifyWin64, planToAgent } from "../../../src/domain/callModel/classify.js";
import {
  encodeColumns,
  finalizeVectors,
  typeColumns,
  type BufferInput,
  type ScalarInput,
  type SignatureInput,
} from "../../../src/domain/callModel/normalize.js";
import type { AgentResult, CallFunctionParams, CallFunctionResult } from "../../../src/shared/agentProtocol.js";
import type { PlanWire } from "../../../src/shared/callPlan.js";
import { fixtureArtifact, fridaSkip, gccSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { pidStatus } from "../../support/process/ownedPidLedger.js";
import { compileCallAgent } from "./support/callAgent.js";
import {
  openLocalDevice,
  waitGone,
  type OwnedDevice,
  type RawDevice as Device,
  type RawScript as Script,
  type RawSession as Session,
} from "./support/fridaDevice.js";

/**
 * WP11 acceptance on real Frida with raw agent RPCs (DESIGN §8.4 wave rule): the registered SEH-frame thunk
 * (§5.3.1) and the executor of src/agent/call.ts inside live_fixture.exe, driven by the host call model
 * (classifyWin64 -> planToAgent). The S5 §9.6 12-vector set bit-exact, physics_step vs a JS Math.fround reference,
 * the R1 checks (IsBadReadPtr, C++ catch, 1,000 faults, MXCSR restored, BEA guard and DR traps during calls), thread
 * modes (syscall refusal, expiry with a late no-op run) and NULL faults with the target surviving.
 */
const skip = fridaSkip() || gccSkip();

const f32 = (x: number): string => `0x${(new Uint32Array(new Float32Array([x]).buffer)[0] ?? 0).toString(16)}`;
const carHex = (speed: number, counter: number, p0: number, p1: number, p2: number): string => {
  const b = new DataView(new ArrayBuffer(32));
  b.setFloat32(0, speed, true);
  b.setInt32(4, counter, true);
  b.setFloat64(8, p0, true);
  b.setFloat64(16, p1, true);
  b.setFloat64(24, p2, true);
  return [...new Uint8Array(b.buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
};

let owned: OwnedDevice | null = null;
let device: Device | null = null;
let pidcheck: string | null = null;
let session: Session | null = null;
let script: Script | null = null;
let pid: number | null = null;
let base = 0n;
const exportRva: Record<string, number> = {};
let cxxPath = "";

const rpc = async <T>(name: string, ...args: unknown[]): Promise<T> => {
  if (script === null) throw new Error("script not loaded");
  return (await script.exports[name]?.(...args)) as T;
};

/** Compiles first, then spawns; the pid is recorded before anything else can fail (afterAll kills it). */
const spawnWithScript = async (argv: string[], bundle: string): Promise<{ session: Session; script: Script }> => {
  if (device === null) throw new Error("no device");
  const spawned = await device.spawn(argv, { stdio: "pipe" });
  pid = spawned;
  const attached = await device.attach(spawned);
  session = attached;
  const loaded = await attached.createScript(bundle, { runtime: "qjs" });
  script = loaded;
  const ready = new Promise<void>((resolve, reject) => {
    loaded.message.connect((m) => {
      if (m.type === "send" && (m.payload as { ready?: boolean } | undefined)?.ready === true) resolve();
      else if (m.type === "error") reject(new Error(m.description ?? "agent error"));
    });
  });
  await loaded.load();
  await ready;
  await device.resume(spawned);
  return { session: attached, script: loaded };
};

/** One host-lowered call: classify -> vectors -> planToAgent -> callFunction. */
const callPlan = async (
  fn: string,
  signature: SignatureInput,
  options: {
    readonly buffers?: readonly BufferInput[];
    readonly columns?: Readonly<Record<string, readonly ScalarInput[]>>;
    readonly count?: number;
    readonly fp?: { mxcsr: number; fpcw: number };
    readonly thread?: CallFunctionParams["thread"];
    readonly target?: string;
    readonly maxWallMs?: number;
    readonly coverage?: boolean;
  } = {},
): Promise<{ result: AgentResult<CallFunctionResult>; wire: PlanWire }> => {
  const columns = options.columns ?? {};
  const supplied = new Set(Object.keys(columns));
  const classified = classifyWin64({ signature, buffers: options.buffers ?? [], supplied });
  if (!classified.ok) throw new Error(JSON.stringify(classified.error));
  const count = options.count ?? Object.values(columns)[0]?.length ?? 1;
  const paths = Object.fromEntries(Object.keys(columns).map((k) => [k, k]));
  const typed = typeColumns(
    classified.value.plan,
    { count, columns, paths, indexed: true },
    () => undefined,
    classified.value.arrayDefaults,
  );
  if (!typed.ok) throw new Error(JSON.stringify(typed.error));
  const vectors = finalizeVectors(encodeColumns(classified.value.plan, typed.value), { kind: "inline" });
  const target = options.target ?? `0x${(base + BigInt(exportRva[fn] ?? 0)).toString(16)}`;
  const wire = planToAgent(classified.value.plan, target as `0x${string}`, () => undefined);
  if (!wire.ok) throw new Error(JSON.stringify(wire.error));
  const params: CallFunctionParams = {
    plan: wire.value,
    vectors: { offset: 0, count: vectors.count, columns: vectors.columns as CallFunctionParams["vectors"]["columns"] },
    fp: options.fp ?? { mxcsr: 0x1f80, fpcw: 0x27f },
    thread: options.thread ?? { kind: "agent" },
    chunk: Math.min(1024, vectors.count),
    max_wall_ms: options.maxWallMs ?? 1000,
    coverage:
      options.coverage === true
        ? { mode: "blocks", modules: [], max_blocks: 100_000 }
        : { mode: "none", modules: [], max_blocks: 0 },
    hooks: "suppress",
    overrides: "bypass",
  };
  return { result: await rpc<AgentResult<CallFunctionResult>>("callFunction", params), wire: wire.value };
};

const value = (r: AgentResult<CallFunctionResult>): CallFunctionResult => {
  if (!r.ok) throw new Error(`callFunction failed: ${JSON.stringify(r.error)}`);
  return r.value;
};
const xmm32 = (r: AgentResult<CallFunctionResult>, i = 0): string => {
  const v = value(r);
  expect(v.raw.status[i]).toBe("ok");
  return `0x${(BigInt(v.raw.xmm0lo[i] ?? "0x0") & 0xffffffffn).toString(16)}`;
};
const FOUR = {
  args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }],
  returns: "f32",
  variadic: false,
} as const;
const fourCols = (a: string, b: string, c: string, d: string) => ({ arg0: [a], arg1: [b], arg2: [c], arg3: [d] });

// One fixture process per file (spawned in beforeAll, killed in afterAll), shared by the three groups below.
if (skip === false) {
  beforeAll(async () => {
    const manifest = await loadFixtures();
    const live = fixtureArtifact(manifest, "live_fixture");
    const cxx = fixtureArtifact(manifest, "cxx_catch");
    if (live === null || cxx === null) throw new Error("fixtures unavailable");
    Object.assign(exportRva, live.pe.exportRvas);
    cxxPath = cxx.path;
    pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
    const bundle = await compileCallAgent();
    owned = await openLocalDevice();
    device = owned.device;
    await spawnWithScript([live.path, "--sleep", "16"], bundle);
    const info = await rpc<{ model: string; name: string; base: string }>("info");
    expect(info.model).toBe("seh-frame");
    base = BigInt(info.base);
  }, 120_000);

  afterAll(async () => {
    // kill first: a hung unload must never leak the fixture process
    if (pid !== null) await device?.kill(pid).catch(() => undefined);
    const gone = pid === null || (await waitGone(pidcheck, pid, 5000));
    const bounded = (p: Promise<unknown> | undefined): Promise<unknown> =>
      Promise.race([p?.catch(() => undefined), new Promise((resolve) => setTimeout(resolve, 5000))]);
    await bounded(script?.unload());
    await bounded(session?.detach());
    // the manager deletes its %TEMP%\frida-<id> agent copies only once the target no longer maps them
    await bounded(owned?.close());
    expect(gone).toBe(true);
  }, 30_000);
}

describe.skipIf(skip !== false)(
  `oracle thunk on live_fixture: S5 §9.6 parity and the JS reference${skipNote(skip)}`,
  () => {
    it("the S5 §9.6 four_floats vectors are bit-exact (qNaN payload, sNaN quieting, -0, denormals RN and FTZ/DAZ, RN vs RZ)", async () => {
      const one = f32(1),
        two = f32(2),
        three = f32(3),
        four = f32(4);
      expect(xmm32((await callPlan("four_floats", FOUR, { columns: fourCols(one, two, three, four) })).result)).toBe(
        "0x449a4000",
      );
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: fourCols("0x7fc12345", two, three, four) })).result),
      ).toBe("0x7fc12345");
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: fourCols("0x7fa00001", two, three, four) })).result),
      ).toBe("0x7fe00001");
      expect(xmm32((await callPlan("four_floats", FOUR, { columns: fourCols("-0", "-0", "-0", "-0") })).result)).toBe(
        "0x80000000",
      );
      const denormals = fourCols("0x00000001", "0x00400000", "0x00000003", "0x00000005");
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: denormals, fp: { mxcsr: 0x1f80, fpcw: 0x27f } })).result),
      ).toBe("0x3480020");
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: denormals, fp: { mxcsr: 0x9fc0, fpcw: 0x27f } })).result),
      ).toBe("0x0");
      const rounding = fourCols(f32(1.0000001), f32(0.1), f32(0.3), f32(1e-8));
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: rounding, fp: { mxcsr: 0x1f80, fpcw: 0x27f } })).result),
      ).toBe("0x447d4002");
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: rounding, fp: { mxcsr: 0x7f80, fpcw: 0x27f } })).result),
      ).toBe("0x447d4001");
    });

    it("mix_args passes stack arguments by position (7, 1.5f, 2.25, 3.125f, 11, 0.5)", async () => {
      const sig = {
        args: [{ type: "i32" }, { type: "f32" }, { type: "f64" }, { type: "f32" }, { type: "i32" }, { type: "f64" }],
        returns: "f64",
        variadic: false,
      } as const;
      const { result } = await callPlan("mix_args", sig, {
        columns: { arg0: [7], arg1: [1.5], arg2: [2.25], arg3: [3.125], arg4: [11], arg5: [0.5] },
      });
      expect(value(result).raw.xmm0lo[0]).toBe("0x4039600000000000");
    });

    it("physics_step on scratch struct copies equals a JS Math.fround reference bit for bit (and car_energy)", async () => {
      const sig: SignatureInput = {
        args: [
          { type: "buffer_ptr", buffer: "car" },
          { type: "f32", name: "dt" },
        ],
        returns: "f32",
        variadic: false,
      };
      const cars = [
        { speed: 10, counter: 3, pos: [1, 0, 4], dt: 0.016, ret: "0x412282e8" },
        { speed: 60, counter: 41, pos: [100, 0, 2], dt: 0.5, ret: "0x426c0000" },
      ];
      for (const car of cars) {
        const buffers: BufferInput[] = [
          {
            name: "car",
            size: 32,
            align: 16,
            placement: "scratch",
            init_hex: carHex(car.speed, car.counter, car.pos[0] ?? 0, car.pos[1] ?? 0, car.pos[2] ?? 0),
            fields: [],
            out: true,
          },
        ];
        const { result } = await callPlan("physics_step", sig, { buffers, columns: { dt: [car.dt] } });
        const v = value(result);
        // JS reference of live_fixture.c physics_step (f32 SSE arithmetic, f64 for pos)
        const dt = Math.fround(car.dt);
        const accel = car.speed > 50 ? -2 : Math.fround(9.81);
        const speed = Math.fround(car.speed + Math.fround(accel * dt));
        const out = new DataView(
          new Uint8Array((v.raw.out["car"]?.[0] ?? "").match(/../gu)?.map((h) => Number.parseInt(h, 16)) ?? []).buffer,
        );
        expect(f32(speed)).toBe(car.ret);
        expect(`0x${(BigInt(v.raw.xmm0lo[0] ?? "0x0") & 0xffffffffn).toString(16)}`).toBe(f32(speed));
        expect(out.getUint32(0, true)).toBe(Number(BigInt(f32(speed))));
        expect(out.getInt32(4, true)).toBe(car.counter + 1);
        expect(out.getFloat64(8, true)).toBe((car.pos[0] ?? 0) + speed * dt);
        expect(out.getFloat64(24, true)).toBe((car.pos[2] ?? 0) * 0.5 + 1);
      }
      const energy = await callPlan(
        "car_energy",
        {
          args: [
            { type: "buffer_ptr", buffer: "car" },
            { type: "f64", name: "mass" },
          ],
          returns: "f64",
          variadic: false,
        },
        {
          buffers: [
            {
              name: "car",
              size: 32,
              align: 16,
              placement: "scratch",
              init_hex: carHex(12.5, 0, 0, 0, 3),
              fields: [],
              out: false,
            },
          ],
          columns: { mass: [1200] },
        },
      );
      expect(value(energy.result).raw.xmm0lo[0]).toBe("0x40f6e39000000000");
    });
  },
);

describe.skipIf(skip !== false)(
  `oracle thunk on live_fixture: faults and the callee's own handlers (R1)${skipNote(skip)}`,
  () => {
    it("a NULL argument is a per-vector fault (code, access, address) and the target survives", async () => {
      const sig: SignatureInput = { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32", variadic: false };
      const { result } = await callPlan("physics_step", sig, {
        columns: { arg0: [0], arg1: [0.1] },
        fp: { mxcsr: 0x9fc0, fpcw: 0x27f },
      });
      const v = value(result);
      expect(v.raw.status).toEqual(["fault"]);
      expect(v.exception_model).toBe("seh-frame");
      expect(v.faults[0]).toMatchObject({
        index: 0,
        type: "access-violation",
        code: "0xc0000005",
        memory: { operation: "read", address: "0x0" },
        module: "live_fixture.exe",
      });
      expect(v.faults[0]?.rva).toBe(`0x${(BigInt(v.faults[0]?.address ?? "0x0") - base).toString(16)}`);
      // FaultInfo.registers come from the dispatcher's in-call record of the same exception (rule 3)
      expect(v.faults[0]?.registers["rax"]).toBeDefined();
      expect(v.callee_exceptions).toBe(0);
      const write = value(
        (
          await callPlan(
            "touch_counter",
            { args: [{ type: "ptr" }], returns: "void", variadic: false },
            { columns: { arg0: [0] } },
          )
        ).result,
      );
      expect(write.faults[0]?.memory).toEqual({ operation: "write", address: "0x4" });
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: fourCols(f32(1), f32(2), f32(3), f32(4)) })).result),
      ).toBe("0x449a4000");
    });

    it("R1: the callee's own SEH and C++ handlers run first (IsBadReadPtr(0x10) = 1, cxx_catcher(1) = 43)", async () => {
      const isBad = await rpc<string>("exportAddress", "kernel32.dll", "IsBadReadPtr");
      const sig: SignatureInput = { args: [{ type: "ptr" }, { type: "u64" }], returns: "i32", variadic: false };
      const bad = value((await callPlan("", sig, { columns: { arg0: [16], arg1: [4] }, target: isBad })).result);
      expect(bad.raw.status).toEqual(["ok"]);
      expect(bad.raw.rax[0]).toBe("0x1");
      expect(bad.callee_exceptions).toBeGreaterThanOrEqual(1);
      const lib = await rpc<{ name: string; base: string }>("loadLibrary", cxxPath);
      const catcher = await rpc<string>("exportAddress", lib.name, "cxx_catcher");
      const caught = value(
        (
          await callPlan(
            "",
            { args: [{ type: "i32" }], returns: "i32", variadic: false },
            { columns: { arg0: [1] }, target: catcher },
          )
        ).result,
      );
      expect(caught.raw.status).toEqual(["ok"]);
      expect(caught.raw.rax[0]).toBe("0x2b");
      expect(caught.callee_exceptions).toBeGreaterThanOrEqual(1);
    });

    it("EMU-5: a callee that faults with values on the x87 stack leaves the calling thread's x87 state empty", async () => {
      // x87_add: fld1; fld1; faddp; fstp qword [rsp+8]; movsd xmm0, [rsp+8]; ret (2.0 through xmm0)
      const add = await rpc<string>("code", "d9e8d9e8dec1dd5c2408f20f10442408c3");
      // x87_fault: fld1 x8 (the x87 stack full); mov eax, [rcx] (rcx = 0: access violation); ret
      const fault = await rpc<string>("code", `${"d9e8".repeat(8)}8b01c3`);
      const f64 = { args: [], returns: "f64", variadic: false } as const;
      const first = value((await callPlan("", f64, { target: add })).result);
      expect(first.raw.xmm0lo[0]).toBe("0x4000000000000000");
      const faulted = value(
        (
          await callPlan(
            "",
            { args: [{ type: "ptr" }], returns: "i32", variadic: false },
            { target: fault, columns: { arg0: [0] } },
          )
        ).result,
      );
      expect(faulted.raw.status).toEqual(["fault"]);
      expect(faulted.faults[0]?.type).toBe("access-violation");
      // the recovery label ran fnclex only: the 8 values stayed on the agent thread, the next fld1 overflowed the stack
      // and x87_add "returned" the indefinite NaN 0xfff8000000000000 (review fix EMU-5: fninit)
      for (let i = 0; i < 2; i++) {
        const after = value((await callPlan("", f64, { target: add })).result);
        expect(after.raw.status).toEqual(["ok"]);
        expect(after.raw.xmm0lo[0]).toBe("0x4000000000000000");
      }
    });

    it("R1: 1,000 faulting vectors leave no leak, the thread's MXCSR/FPCW are restored, the fault context is captured", async () => {
      const before = await rpc<{ mxcsr: number; fpcw: number }>("agentEnv");
      const sig: SignatureInput = { args: [{ type: "ptr" }], returns: "void", variadic: false };
      const faultRun = async (): Promise<number> => {
        let faults = 0;
        let offset = 0;
        while (offset < 1000) {
          const remaining = 1000 - offset;
          const { result } = await callPlan("touch_counter", sig, {
            count: remaining,
            columns: { arg0: Array.from({ length: remaining }, () => 0) },
            fp: { mxcsr: 0x9fc0, fpcw: 0x37f },
          });
          const v = value(result);
          faults += v.raw.status.filter((s) => s === "fault").length;
          expect(v.raw.mxcsrOut[0]).toBe("0x9fc0");
          expect(v.raw.fpcwOut[0]).toBe("0x37f");
          offset += v.raw.completed;
        }
        return faults;
      };
      // a warm-up run (lazy allocations of the first faults), then 1,000 measured faults: no handle may leak and
      // private memory may not grow by a per-fault amount (4 MiB over 1,000 faults = < 4 KiB each: a leaked page per
      // fault fails; JS heap noise measured 0..0.4 MB per 1,000 faults here)
      expect(await faultRun()).toBe(1000);
      const memBefore = await rpc<{ handles: number; privateBytes: number }>("memInfo");
      expect(await faultRun()).toBe(1000);
      const memAfter = await rpc<{ handles: number; privateBytes: number }>("memInfo");
      expect(memAfter.handles - memBefore.handles).toBeLessThanOrEqual(2);
      expect(memAfter.privateBytes - memBefore.privateBytes).toBeLessThan(4 * 1024 * 1024);
      const after = await rpc<{ mxcsr: number; fpcw: number }>("agentEnv");
      expect(after.mxcsr & 0xffc0).toBe(before.mxcsr & 0xffc0);
      expect(after.fpcw).toBe(before.fpcw);
      expect(
        xmm32((await callPlan("four_floats", FOUR, { columns: fourCols(f32(1), f32(2), f32(3), f32(4)) })).result),
      ).toBe("0x449a4000");
    });
  },
);

describe.skipIf(skip !== false)(`oracle thunk on live_fixture: per-call coverage${skipNote(skip)}`, () => {
  it("per-call Stalker coverage returns the blocks of each call (one covered vector per RPC; the entry included)", async () => {
    const entry = base + BigInt(exportRva["physics_step"] ?? 0);
    const sig: SignatureInput = {
      args: [
        { type: "buffer_ptr", buffer: "car" },
        { type: "f32", name: "dt" },
      ],
      returns: "f32",
      variadic: false,
    };
    const buffers: BufferInput[] = [
      {
        name: "car",
        size: 32,
        align: 16,
        placement: "scratch",
        init_hex: carHex(10, 3, 1, 0, 4),
        fields: [],
        out: false,
      },
    ];
    const first = value(
      (await callPlan("physics_step", sig, { buffers, columns: { dt: [0.016, 0.5] }, coverage: true })).result,
    );
    expect(first.raw.completed).toBe(1);
    expect(first.next_offset).toBe(1);
    const second = value(
      (await callPlan("physics_step", sig, { buffers, columns: { dt: [0.5] }, coverage: true })).result,
    );
    for (const v of [first, second]) {
      expect(v.raw.status).toEqual(["ok"]);
      expect(v.coverage?.map((c) => c.index)).toEqual([0]);
      const blocks = v.coverage?.[0]?.blocks ?? [];
      expect(blocks.length).toBeGreaterThan(0);
      expect(blocks.some(([start, size]) => BigInt(start) <= entry && entry < BigInt(start) + BigInt(size))).toBe(true);
    }
  });
});

describe.skipIf(skip !== false)(
  `oracle thunk on live_fixture: BEA traps during calls (R1, CT-B2)${skipNote(skip)}`,
  () => {
    it("R1/CT-B2: a call touching a BEA guard-page-watched struct completes and the watch keeps trapping", async () => {
      const struct = await rpc<string>("alloc", 4096, carHex(1, 7, 0, 0, 0));
      await rpc("armGuard", struct);
      const before = await rpc<{ guardTraps: number }>("stats");
      const sig: SignatureInput = { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32", variadic: false };
      const v = value((await callPlan("physics_step", sig, { columns: { arg0: [struct], arg1: [0.5] } })).result);
      // the watch is still armed after the call (every trap re-armed the one-shot guard)
      const stillArmed = await rpc<boolean>("isGuarded", struct);
      await rpc("disarmGuard", struct);
      const after = await rpc<{ guardTraps: number }>("stats");
      expect(v.raw.status).toEqual(["ok"]);
      expect(stillArmed).toBe(true);
      // several accesses trapped one after the other: the watch kept recording during the call
      expect(after.guardTraps - before.guardTraps).toBeGreaterThanOrEqual(2);
      expect(v.bea_traps_during_call).toBe(after.guardTraps - before.guardTraps);
      const bytes = await rpc<string>("read", struct, 8);
      expect(Number.parseInt(bytes.slice(8, 16).match(/../gu)?.reverse().join("") ?? "0", 16)).toBe(8);
    });

    it("R1/CT-B2: a DR-watched call on a thread_id (thread mode) completes and the DR trap is handled", async () => {
      // a user-mode thread (never in a system call), watched by a DR write watch on the struct the call writes
      const spinner = await rpc<number>("spinThread", 0x1f80);
      const struct = await rpc<string>("alloc", 4096, carHex(1, 7, 0, 0, 0));
      await rpc("armDr", spinner, `0x${(BigInt(struct) + 4n).toString(16)}`, 4);
      const before = await rpc<{ drTraps: number }>("stats");
      const v = value(
        (
          await callPlan(
            "physics_step",
            { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32", variadic: false },
            { columns: { arg0: [struct], arg1: [0.5] }, thread: { kind: "thread", tid: spinner, timeout_ms: 5000 } },
          )
        ).result,
      );
      await rpc("disarmDr", spinner);
      const after = await rpc<{ drTraps: number }>("stats");
      expect(v.thread_id).toBe(spinner);
      expect(v.raw.status).toEqual(["ok"]);
      expect(v.bea_traps_during_call).toBeGreaterThanOrEqual(1);
      expect(after.drTraps - before.drTraps).toBeGreaterThanOrEqual(1);
      // physics_step completed: counter 7 -> 8 and speed 1 + 9.81f * 0.5f (f32)
      const bytes = await rpc<string>("read", struct, 8);
      const le32 = (hex: string): number => Number.parseInt(hex.match(/../gu)?.reverse().join("") ?? "0", 16);
      expect(le32(bytes.slice(8, 16))).toBe(8);
      expect(le32(bytes.slice(0, 8))).toBe(Number(BigInt(f32(Math.fround(1 + Math.fround(Math.fround(9.81) * 0.5))))));
    });
  },
);

describe.skipIf(skip !== false)(
  `oracle thunk on live_fixture: thread modes, linked buffers and dispose (CT-I1)${skipNote(skip)}`,
  () => {
    it("CT-I1: a thread blocked in a system call is refused; thread_at runs at a safe point and a DR watch on that thread is handled", async () => {
      const sleeper = await rpc<number>("sleeperThread");
      const sig: SignatureInput = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32", variadic: false };
      // the new thread reaches its wait within moments: poll (25 ms) for the refusal instead of sleeping
      let refused: AgentResult<CallFunctionResult> | null = null;
      for (let i = 0; i < 80 && (refused === null || refused.ok); i++) {
        if (refused !== null) await new Promise((resolve) => setTimeout(resolve, 25));
        refused = (
          await callPlan("add_ints", sig, {
            columns: { arg0: [2], arg1: [3] },
            thread: { kind: "thread", tid: sleeper, timeout_ms: 2000 },
          })
        ).result;
      }
      expect(refused !== null && !refused.ok && refused.error).toMatchObject({
        _tag: "ThreadBusy",
        thread_id: sleeper,
        reason: "in-syscall",
      });
      const main = (await rpc<number[]>("threads"))[0] ?? 0;
      const struct = await rpc<string>("alloc", 4096, carHex(1, 7, 0, 0, 0));
      await rpc("armDr", main, `0x${(BigInt(struct) + 4n).toString(16)}`, 4);
      const before = await rpc<{ drTraps: number }>("stats");
      // safe point: mix_args, which the main loop calls every frame (a different function from the one called)
      const at = `0x${(base + BigInt(exportRva["mix_args"] ?? 0)).toString(16)}`;
      const hooked = value(
        (
          await callPlan(
            "physics_step",
            { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32", variadic: false },
            {
              columns: { arg0: [struct], arg1: [0.5] },
              thread: { kind: "hook", at: at as `0x${string}`, tid: main, timeout_ms: 5000 },
            },
          )
        ).result,
      );
      await rpc("disarmDr", main);
      const after = await rpc<{ drTraps: number }>("stats");
      expect(hooked.thread_id).toBe(main);
      expect(hooked.raw.status).toEqual(["ok"]);
      expect(after.drTraps - before.drTraps).toBeGreaterThanOrEqual(1);
      expect(
        Number.parseInt(
          (await rpc<string>("read", struct, 8)).slice(8, 16).match(/../gu)?.reverse().join("") ?? "0",
          16,
        ),
      ).toBe(8);
    });

    it("CT-I1: an expired thread closure later runs as a no-op (late run) and its allocation leaves quarantine", async () => {
      const spinner = await rpc<number>("spinThread", 0x1f80);
      await rpc("suspend", spinner);
      const sig: SignatureInput = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32", variadic: false };
      const expired = (
        await callPlan("add_ints", sig, {
          columns: { arg0: [2], arg1: [3] },
          thread: { kind: "thread", tid: spinner, timeout_ms: 300 },
        })
      ).result;
      expect(!expired.ok && expired.error._tag).toBe("Timeout");
      const mid = await rpc<{ expired: number; lateRuns: number; quarantined: number }>("stats");
      expect(mid.expired).toBeGreaterThanOrEqual(1);
      expect(mid.quarantined).toBeGreaterThanOrEqual(1);
      await rpc("resume", spinner);
      let late = mid;
      for (let i = 0; i < 80 && late.lateRuns === mid.lateRuns; i++) {
        await new Promise((resolve) => setTimeout(resolve, 25));
        late = await rpc<{ expired: number; lateRuns: number; quarantined: number }>("stats");
      }
      expect(late.lateRuns).toBe(mid.lateRuns + 1);
      expect(late.quarantined).toBe(mid.quarantined - 1);
      // the same thread now runs calls normally (its MXCSR stays its own: the thunk sets the call's per vector)
      const ran = value(
        (
          await callPlan("add_ints", sig, {
            columns: { arg0: [2], arg1: [3] },
            thread: { kind: "thread", tid: spinner, timeout_ms: 5000 },
          })
        ).result,
      );
      expect(ran.raw.rax[0]).toBe("0x5");
      expect(ran.thread_id).toBe(spinner);
    });

    it("ptr_to fields link scratch buffers (bea_vec_sum over a Vec whose begin/end point into a data buffer)", async () => {
      const sig: SignatureInput = { args: [{ type: "buffer_ptr", buffer: "vec" }], returns: "f32", variadic: false };
      const buffers: BufferInput[] = [
        {
          name: "vec",
          size: 24,
          align: 8,
          placement: "scratch",
          fields: [
            { name: "begin", offset: 0, type: "ptr_to", buffer: "data" },
            { name: "end", offset: 8, type: "ptr_to", buffer: "data", plus: 12 },
            { name: "cap", offset: 16, type: "ptr_to", buffer: "data", plus: 16 },
          ],
          out: false,
        },
        {
          name: "data",
          size: 16,
          align: 16,
          placement: "scratch",
          fields: [{ name: "xs", offset: 0, type: "f32[]", count: 4, default: "1.5, 2.25, 4, 100" }],
          out: false,
        },
      ];
      expect(xmm32((await callPlan("bea_vec_sum", sig, { buffers })).result)).toBe(f32(7.75));
    });

    it("the script unloads cleanly after calls, faults and Stalker coverage, also under a call still running on a target thread (AGENT-1)", async () => {
      // a thread-mode call whose callee (kernel32!Sleep 1500 ms) outlives its 300 ms timeout: it STARTED and is still
      // running, so it returns into the thunk page after the unload's dispose. Freeing that page in dispose (attached
      // targets: close_session, detach, host exit) killed the target the moment Sleep returned.
      const spinner = await rpc<number>("spinThread", 0x1f80);
      const sleep = await rpc<string>("exportAddress", "kernel32.dll", "Sleep");
      const slow = (
        await callPlan(
          "",
          { args: [{ type: "u32" }], returns: "void", variadic: false },
          { target: sleep, columns: { arg0: [1500] }, thread: { kind: "thread", tid: spinner, timeout_ms: 300 } },
        )
      ).result;
      expect(!slow.ok && slow.error).toMatchObject({ _tag: "Timeout", started: true });
      const unloaded = await Promise.race([
        (script as Script).unload().then(() => "unloaded"),
        new Promise((resolve) => setTimeout(() => resolve("timed out"), 10_000)),
      ]);
      expect(unloaded).toBe("unloaded");
      script = null;
      // past the callee's return into the thunk page: the target keeps running
      const until = performance.now() + 4000;
      while (performance.now() < until) {
        expect(pid !== null && pidStatus(pidcheck, pid).alive).toBe(true);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    });
  },
);
