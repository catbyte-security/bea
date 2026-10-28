import { existsSync, readFileSync } from "node:fs";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { classifyWin64, planToAgent } from "../../../src/domain/callModel/classify.js";
import {
  encodeColumns,
  finalizeVectors,
  typeColumns,
  type SignatureInput,
} from "../../../src/domain/callModel/normalize.js";
import type {
  AgentResult,
  AgentStatus,
  CallFunctionParams,
  CallFunctionResult,
} from "../../../src/shared/agentProtocol.js";
import { fixtureArtifact, fridaSkip, gccSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { harnessLayout } from "../../support/mcp/stdioSubprocess.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * The BUILT agent bundle (BEA_DIST_DIR snapshot, else dist/) driven by raw RPCs (DESIGN §8.4: raw agent RPCs are
 * allowed) through the core's RawAgent harness (owned DeviceManager, targets fully gone before it closes): hello ->
 * callFunction through the real core — THE dispatcher's in-call branch and the WP3 calls registry count the callee's
 * own handled exceptions (callee_exceptions) and stash the faulting GPRs (FaultInfo.registers); thread mode refuses a
 * thread blocked in a system call (ThreadBusy), and an expired thread closure later runs as a no-op, read through the
 * real status().calls counters (CT-I1). A second, separate script (HELPER) creates and suspends the test's threads.
 */
const skip = fridaSkip() || gccSkip();

/** Test-only helper script (never the BEA agent): threads the tests need inside the target. */
const HELPER = String.raw`
const k32 = Process.getModuleByName("kernel32.dll");
const fn = (name, ret, args) => new NativeFunction(k32.getExportByName(name), ret, args, { scheduling: "exclusive" });
const openThread = fn("OpenThread", "pointer", ["uint32", "int", "uint32"]);
const suspendThread = fn("SuspendThread", "uint32", ["pointer"]);
const resumeThread = fn("ResumeThread", "uint32", ["pointer"]);
const closeHandle = fn("CloseHandle", "int", ["pointer"]);
const createThread = fn("CreateThread", "pointer", ["pointer", "size_t", "pointer", "pointer", "uint32", "pointer"]);
const keep = [];
const withThread = (tid, f) => {
  const h = openThread(0x0002, 0, tid);
  try { return f(h); } finally { closeHandle(h); }
};
const start = (entry, param) => {
  const tidBox = Memory.alloc(8);
  keep.push(tidBox);
  closeHandle(createThread(NULL, 0, entry, param, 0, tidBox));
  return tidBox.readU32();
};
rpc.exports = {
  // a thread spinning in user mode (pause; jmp back): never inside a system call
  spinThread() {
    const page = Memory.alloc(Process.pageSize);
    keep.push(page);
    Memory.protect(page, Process.pageSize, "rwx");
    page.writeByteArray([0xf3, 0x90, 0xeb, 0xfc]);
    return start(page, NULL);
  },
  // a thread blocked for good in a non-alertable kernel wait: CreateThread(start = kernel32!Sleep, param = INFINITE)
  sleeperThread() {
    return start(k32.getExportByName("Sleep"), ptr(0xffffffff));
  },
  suspend(tid) { return withThread(tid, (h) => suspendThread(h)); },
  resume(tid) { return withThread(tid, (h) => resumeThread(h)); },
  loadLibrary(path) { return Module.load(path).name; },
  // handle count and private bytes of the target (leak checks)
  memInfo() {
    const handles = Memory.alloc(4);
    const pmc = Memory.alloc(80);
    const self = fn("GetCurrentProcess", "pointer", [])();
    fn("GetProcessHandleCount", "int", ["pointer", "pointer"])(self, handles);
    pmc.writeU32(80);
    fn("K32GetProcessMemoryInfo", "int", ["pointer", "pointer", "uint32"])(self, pmc, 80);
    return { handles: handles.readU32(), privateBytes: pmc.add(72).readU64().toNumber() };
  },
};
`;

interface HelperScript {
  readonly exports: Record<string, (...args: unknown[]) => Promise<unknown>>;
  load(): Promise<void>;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** File state shared by the describes (each registers the lane hooks with useLane). */
let bundle = "";
let live = "";
let cxx = "";
let ledger: OwnedPidLedger | null = null;
const agents: RawAgent[] = [];
const rvas: Record<string, number> = {};

/** Fixtures, the built bundle and the liveness probe; every agent closed after its test, the manager after the file. */
const useLane = (): void => {
  beforeAll(async () => {
    const bundlePath = harnessLayout().agentBundle;
    if (!existsSync(bundlePath)) throw new Error(`${bundlePath} is missing: run npm run build (and snapshot-dist)`);
    bundle = readFileSync(bundlePath, "utf8");
    const manifest = await loadFixtures();
    const fixture = fixtureArtifact(manifest, "live_fixture");
    const catcher = fixtureArtifact(manifest, "cxx_catch");
    const pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
    if (fixture === null || catcher === null || pidcheck === null) throw new Error("fixtures unavailable");
    live = fixture.path;
    cxx = catcher.path;
    Object.assign(rvas, fixture.pe.exportRvas);
    RawAgent.useLivenessProbe(pidcheck);
    ledger = new OwnedPidLedger(pidcheck);
  }, 120_000);

  afterEach(async () => {
    for (const a of agents.splice(0)) await a.close();
  }, 30_000);

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    await ledger?.assertClean();
  }, 30_000);
};

/** live_fixture with the BUILT agent: ready (feature "call"), hello, resumed; plus the main module base. */
const start = async (): Promise<{ agent: RawAgent; base: bigint }> => {
  const agent = await RawAgent.start({ bundle, program: live, args: ["--sleep", "16"] });
  agents.push(agent);
  ledger?.recordOwned(agent.pid, null, "live_fixture (raw built agent)");
  expect(agent.ready?.["features"]).toContain("call");
  const hello = await agent.hello();
  await agent.resume();
  return { agent, base: BigInt(hello.process.main_module.base) };
};

const helperOf = async (agent: RawAgent): Promise<HelperScript> => {
  const script = (await agent.session.createScript(HELPER, {
    name: "wp11-helper",
    runtime: "qjs",
  })) as unknown as HelperScript;
  await script.load();
  return script;
};

/** One host-lowered call: classify -> vectors -> planToAgent -> the agent's callFunction RPC. */
const call = async (
  agent: RawAgent,
  target: string,
  signature: SignatureInput,
  columns: Record<string, (number | string)[]>,
  thread: CallFunctionParams["thread"] = { kind: "agent" },
): Promise<AgentResult<CallFunctionResult>> => {
  const classified = classifyWin64({ signature, buffers: [], supplied: new Set(Object.keys(columns)) });
  if (!classified.ok) throw new Error(JSON.stringify(classified.error));
  const count = Object.values(columns)[0]?.length ?? 1;
  const typed = typeColumns(
    classified.value.plan,
    { count, columns, paths: {}, indexed: true },
    () => undefined,
    new Map(),
  );
  if (!typed.ok) throw new Error(JSON.stringify(typed.error));
  const vectors = finalizeVectors(encodeColumns(classified.value.plan, typed.value), { kind: "inline" });
  const wire = planToAgent(classified.value.plan, target as `0x${string}`, () => undefined);
  if (!wire.ok) throw new Error("lowering");
  const params: CallFunctionParams = {
    plan: wire.value,
    vectors: { offset: 0, count, columns: vectors.columns as CallFunctionParams["vectors"]["columns"] },
    fp: { mxcsr: 0x1f80, fpcw: 0x27f },
    thread,
    chunk: count,
    max_wall_ms: 50,
    coverage: { mode: "none", modules: [], max_blocks: 0 },
    hooks: "suppress",
    overrides: "bypass",
  };
  return agent.rpc<AgentResult<CallFunctionResult>>("callFunction", params);
};
const value = (r: AgentResult<CallFunctionResult>): CallFunctionResult => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};
const at = (base: bigint, name: string): string => `0x${(base + BigInt(rvas[name] ?? 0)).toString(16)}`;
const ADD: SignatureInput = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32", variadic: false };
const calls = async (agent: RawAgent): Promise<AgentStatus["calls"]> =>
  (await agent.ok<AgentStatus>("status", { detail: "summary" })).calls;

const exportVa = async (agent: RawAgent, module: string, name: string): Promise<string> => {
  const resolved = await agent.ok<{ results: { ok: boolean; target?: { va: string } }[] }>("resolveTargets", {
    targets: [{ module, export: name }],
  });
  const va = resolved.results[0]?.target?.va;
  if (va === undefined) throw new Error(`${module}!${name} did not resolve: ${JSON.stringify(resolved)}`);
  return va;
};

describe.skipIf(skip !== false)(
  `callFunction in the built agent bundle: the real dispatcher (raw RPCs)${skipNote(skip)}`,
  () => {
    useLane();

    it("the real dispatcher + calls registry honour the callee's own handlers (IsBadReadPtr(0x10) = 1, cxx_catcher(1) = 43)", async () => {
      const { agent } = await start();
      const v = value(
        await call(
          agent,
          await exportVa(agent, "kernel32.dll", "IsBadReadPtr"),
          { args: [{ type: "ptr" }, { type: "u64" }], returns: "i32", variadic: false },
          { arg0: [16], arg1: [4] },
        ),
      );
      expect(v.exception_model).toBe("seh-frame");
      expect(v.raw.status).toEqual(["ok"]);
      expect(v.raw.rax[0]).toBe("0x1");
      expect(v.callee_exceptions).toBeGreaterThanOrEqual(1);
      // a C++ throw/catch inside the callee (g++ EH through the thunk's registered frame)
      const helper = await helperOf(agent);
      const name = (await helper.exports["loadLibrary"]?.(cxx)) as string;
      const caught = value(
        await call(
          agent,
          await exportVa(agent, name, "cxx_catcher"),
          { args: [{ type: "i32" }], returns: "i32", variadic: false },
          { arg0: [1] },
        ),
      );
      expect(caught.raw.status).toEqual(["ok"]);
      expect(caught.raw.rax[0]).toBe("0x2b");
      expect(caught.callee_exceptions).toBeGreaterThanOrEqual(1);
    });

    it("an unhandled fault is caught by the thunk frame with the dispatcher's in-call GPRs and the target survives", async () => {
      const { agent, base } = await start();
      const v = value(
        await call(
          agent,
          at(base, "touch_counter"),
          { args: [{ type: "ptr" }], returns: "void", variadic: false },
          { arg0: [0] },
        ),
      );
      expect(v.raw.status).toEqual(["fault"]);
      expect(v.faults[0]).toMatchObject({
        code: "0xc0000005",
        memory: { operation: "write", address: "0x4" },
        module: "live_fixture.exe",
      });
      expect(Object.keys(v.faults[0]?.registers ?? {}).length).toBeGreaterThan(2);
      expect(v.callee_exceptions).toBe(0);
      const four = value(
        await call(
          agent,
          at(base, "four_floats"),
          {
            args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }],
            returns: "f32",
            variadic: false,
          },
          { arg0: [1], arg1: [2], arg2: [3], arg3: [4] },
        ),
      );
      expect(four.raw.xmm0lo[0]).toBe("0x449a4000");
      const status = await agent.ok<AgentStatus>("status", { detail: "summary" });
      // a fresh target: the one in-call exception is touch_counter's fault (four_floats raised none)
      expect(status.exceptions.in_call).toBe(1);
      expect(status.calls.active).toEqual([]);
    });

    it("R1: 1,000 faulting vectors through the real core: each an in-call exception, nothing left active or quarantined, no leak", async () => {
      const { agent, base } = await start();
      const helper = await helperOf(agent);
      const touch: SignatureInput = { args: [{ type: "ptr" }], returns: "void", variadic: false };
      const faultRun = async (): Promise<number> => {
        let faults = 0;
        for (let done = 0; done < 1000;) {
          const zeros = Array.from({ length: 1000 - done }, () => 0);
          const v = value(await call(agent, at(base, "touch_counter"), touch, { arg0: zeros }));
          faults += v.raw.status.filter((status) => status === "fault").length;
          done += v.raw.completed;
        }
        return faults;
      };
      expect(await faultRun()).toBe(1000);
      const memBefore = (await helper.exports["memInfo"]?.()) as { handles: number; privateBytes: number };
      expect(await faultRun()).toBe(1000);
      const memAfter = (await helper.exports["memInfo"]?.()) as { handles: number; privateBytes: number };
      // the second 1,000 faults: no handle leak, and no per-fault memory growth — 4 MiB is < 4 KiB per fault (a leaked
      // page per fault fails); agent heap and exception-row stream noise measured 0..1.05 MB per 1,000 faults here
      expect(memAfter.handles - memBefore.handles).toBeLessThanOrEqual(2);
      expect(memAfter.privateBytes - memBefore.privateBytes).toBeLessThan(4 * 1024 * 1024);
      const status = await agent.ok<AgentStatus>("status", { detail: "summary" });
      expect(status.exceptions.in_call).toBe(2000);
      expect(status.calls).toMatchObject({ active: [], quarantined_blocks: 0, expired_closures: 0 });
      const four = value(
        await call(
          agent,
          at(base, "four_floats"),
          {
            args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }],
            returns: "f32",
            variadic: false,
          },
          { arg0: [1], arg1: [2], arg2: [3], arg3: [4] },
        ),
      );
      expect(four.raw.xmm0lo[0]).toBe("0x449a4000");
    });
  },
);

describe.skipIf(skip !== false)(
  `callFunction in the built agent bundle: thread modes (raw RPCs)${skipNote(skip)}`,
  () => {
    useLane();

    it("CT-I1: thread mode refuses a thread blocked in a system call (ThreadBusy in-syscall) and runs on a user-mode thread", async () => {
      const { agent, base } = await start();
      const helper = await helperOf(agent);
      const sleeper = (await helper.exports["sleeperThread"]?.()) as number;
      const spinner = (await helper.exports["spinThread"]?.()) as number;
      // the sleeper reaches its wait within moments of creation; poll (25 ms) for the refusal instead of sleeping
      let refused: AgentResult<CallFunctionResult> | null = null;
      for (let i = 0; i < 80; i++) {
        refused = await call(
          agent,
          at(base, "add_ints"),
          ADD,
          { arg0: [2], arg1: [3] },
          {
            kind: "thread",
            tid: sleeper,
            timeout_ms: 2000,
          },
        );
        if (!refused.ok) break;
        await sleep(25);
      }
      expect(refused !== null && !refused.ok && refused.error).toMatchObject({
        _tag: "ThreadBusy",
        thread_id: sleeper,
        reason: "in-syscall",
      });
      const ran = value(
        await call(
          agent,
          at(base, "add_ints"),
          ADD,
          { arg0: [40], arg1: [2] },
          {
            kind: "thread",
            tid: spinner,
            timeout_ms: 5000,
          },
        ),
      );
      expect(ran.thread_id).toBe(spinner);
      expect(ran.raw.rax[0]).toBe("0x2a");
    });

    it("CT-I1: an expired thread closure runs later as a no-op (status().calls.late_runs) and leaves quarantine", async () => {
      const { agent, base } = await start();
      const helper = await helperOf(agent);
      const spinner = (await helper.exports["spinThread"]?.()) as number;
      await helper.exports["suspend"]?.(spinner);
      const before = await calls(agent);
      const expired = await call(
        agent,
        at(base, "add_ints"),
        ADD,
        { arg0: [2], arg1: [3] },
        {
          kind: "thread",
          tid: spinner,
          timeout_ms: 300,
        },
      );
      expect(!expired.ok && expired.error._tag).toBe("Timeout");
      const mid = await calls(agent);
      expect(mid.expired_closures).toBe(before.expired_closures + 1);
      expect(mid.quarantined_blocks).toBeGreaterThan(before.quarantined_blocks);
      expect(mid.late_runs).toBe(before.late_runs);
      await helper.exports["resume"]?.(spinner);
      let after = mid;
      for (let i = 0; i < 120 && after.late_runs === mid.late_runs; i++) {
        await sleep(25);
        after = await calls(agent);
      }
      expect(after.late_runs).toBe(mid.late_runs + 1);
      expect(after.quarantined_blocks).toBe(before.quarantined_blocks);
      expect(after.active).toEqual([]);
      // the late run returned without calling: the same thread now runs a call normally
      const ran = value(
        await call(
          agent,
          at(base, "add_ints"),
          ADD,
          { arg0: [2], arg1: [3] },
          {
            kind: "thread",
            tid: spinner,
            timeout_ms: 5000,
          },
        ),
      );
      expect(ran.raw.rax[0]).toBe("0x5");
      expect(ran.thread_id).toBe(spinner);
    });
  },
);
