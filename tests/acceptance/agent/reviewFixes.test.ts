import { basename, dirname } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type {
  AgentResult,
  AgentStatus,
  HelloParams,
  HookInstallParams,
  HookInstallResult,
  InstrumentStopResult,
  ListModulesResult,
  ProfileInstallResult,
  TraceStartParams,
  TraceStartResult,
  WatchInstallResult,
  WriteResult,
} from "../../../src/shared/agentProtocol.js";
import { fixtureArtifact, fridaSkip, gccSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { buildTestAgent } from "../../support/agent/coreAgent.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { buildReviewTarget, type BuiltTarget } from "./support/reviewTarget.js";

/**
 * Partition-A review fixes through the REAL agent (raw Frida, no BEA host): every file under src/agent compiled as
 * `npm run build:agent` does, driven with WP3's RawAgent, against a target this file builds (support/reviewTarget.ts)
 * and spawns (owned, killed on close). Each case fails on the code before its fix:
 *   AGENT-2  a page-guard watch on a page the target re-protects: the stale protection came back (a write then killed
 *            the target) and a stop restored the old protection while reporting reverted:true
 *   AGENT-4  dispose wrote stale "before" bytes over memory the program had changed since write_memory
 *   AGENT-5  every native hook install + stop kept its 5 MiB ring and 1 MiB staging buffer for the session
 *   AGENT-6  every block_counts trace kept its cap x 24 B counting slab (23 MiB at the default max_events)
 *   AGENT-7  trace_api recorded nothing from a thread trace_execution follows (hooks never reached Stalker)
 *   AGENT-8  a second threads-mode trace of a steady loop recorded nothing (the first never let go of the thread)
 *   AGENT-10 a hook capture deref into a page carrying the target's own PAGE_GUARD consumed that guard
 *   AGENT-11 software exceptions (RaiseException, OutputDebugString) were blocking first-chance crash reports
 *   UX-11    an on_call trace that completed its invocations ended with "max_hits"
 */
const SKIP = fridaSkip() !== false ? fridaSkip() : gccSkip();
const MiB = 1024 * 1024;
const hex = (v: bigint): string => `0x${v.toString(16)}`;
const lifetime = (duration_ms: number, max_hits: number) => ({ duration_ms, max_hits, clock: "install" as const });
const capture = { registers: "none" as const, backtrace: 0, values: true };

let bundle = "";
let target: BuiltTarget | null = null;
const agents: RawAgent[] = [];

interface Started {
  readonly a: RawAgent;
  readonly tid: number;
  readonly page: bigint;
  readonly counter: bigint;
}

/** MinGW %p prints bare hex digits (or 0x…, or "(nil)"-like zeros for NULL). */
const pointer = (text: string): bigint =>
  /^(?:0x)?[0-9a-f]+$/iu.test(text) ? BigInt(`0x${text.replace(/^0x/iu, "")}`) : 0n;

const start = async (mode: string, hello: Partial<HelloParams> = {}): Promise<Started> => {
  if (target === null) throw new Error("no target");
  const a = await RawAgent.start({ bundle, program: target.path, args: [mode], cwd: dirname(target.path) });
  agents.push(a);
  await a.hello(hello);
  await a.resume();
  const ready = await a.waitFor(() => /READY pid=\d+ tid=(\d+) page=(\S+) counter=(\S+)/u.exec(a.output()), 10_000);
  if (ready === null) throw new Error(`target did not print READY: ${a.output().slice(0, 300)}`);
  return { a, tid: Number(ready[1]), page: pointer(ready[2] ?? ""), counter: pointer(ready[3] ?? "") };
};

/** One stdin command (Frida device.input), answered by one line matching `re` printed after it was sent. */
const ask = async (a: RawAgent, command: string, re: RegExp, timeoutMs = 5000): Promise<RegExpExecArray | null> => {
  const from = a.output().length;
  await (a.device as unknown as { input(pid: number, data: Buffer): Promise<void> }).input(
    a.pid,
    Buffer.from(`${command}\n`, "utf8"),
  );
  return a.waitFor(() => re.exec(a.output().slice(from)), timeoutMs);
};
const numberOf = async (a: RawAgent, command: string, key: string): Promise<number> => {
  const m = await ask(a, command, new RegExp(`${key}=(-?\\d+)`, "u"));
  if (m === null) throw new Error(`no ${key} answer: ${a.output().slice(-300)}`);
  return Number(m[1]);
};
const protOf = async (a: RawAgent): Promise<number> => {
  const m = await ask(a, "query", /PROT=0x([0-9a-f]+)/u);
  if (m === null) throw new Error(`no PROT answer: ${a.output().slice(-300)}`);
  return Number.parseInt(m[1] ?? "", 16);
};

const endedOf = (a: RawAgent, id: string) =>
  a.messages("instrument").find((m) => m["id"] === id && m["event"] === "ended");

/** block-count/1 records {u64 start, u64 end, u64 count} of a binary stream. */
const blockCounts = (a: RawAgent, stream: string): { start: bigint; count: bigint }[] => {
  const out: { start: bigint; count: bigint }[] = [];
  for (const r of a.records) {
    if (r.payload["bea"] !== "batch" || r.payload["stream"] !== stream || r.data === null) continue;
    for (let i = 0; i + 24 <= r.data.length; i += 24)
      out.push({ start: r.data.readBigUInt64LE(i), count: r.data.readBigUInt64LE(i + 16) });
  }
  return out;
};

/** traceStart, waiting out a thread that is still settling after the previous trace (StalkerBusy settling). */
const traceWhenFree = async (a: RawAgent, params: TraceStartParams): Promise<TraceStartResult> => {
  for (let attempt = 0; attempt < 40; attempt++) {
    const r = await a.rpc<AgentResult<TraceStartResult>>("traceStart", params);
    if (r.ok) return r.value;
    if (r.error._tag !== "StalkerBusy" || r.error.retry_after_ms === 0)
      throw new Error(`traceStart failed: ${JSON.stringify(r.error)}`);
    await new Promise((resolve) =>
      setTimeout(resolve, r.error._tag === "StalkerBusy" ? r.error.retry_after_ms + 25 : 25),
    );
  }
  throw new Error("the thread never became free");
};

const hookParams = (fn: string, engine: "js" | "native", args: HookInstallParams["capture"]["args"]) => ({
  target: { module: "bea_review_target.exe", export: fn },
  engine,
  relocation: "auto" as const,
  capture: { args, ret: null, backtrace: null, registers: "none" as const },
  emit: "enter" as const,
  probe: false,
  hidden_ret_ptr: false,
  lifetime: lifetime(60_000, 1_000_000),
  observe_agent_calls: false,
  force_caution: false,
});

const agent2Verifier = async (): Promise<void> => {
  const { a, page } = await start("pg");
  const r = await a.ok<WatchInstallResult>("watchInstall", {
    method: "page-guard",
    address: hex(page + 8n),
    size: 8,
    access: "write",
    threads: "all",
    capture,
    lifetime: lifetime(30_000, 1000),
  });
  expect(r.pages).toEqual([hex(page)]);
  expect(await protOf(a)).toBe(0x102); // PAGE_READONLY | PAGE_GUARD
  // the target makes the page writable (its VirtualProtect also drops BEA's guard)
  expect(await ask(a, "rw", /PROTECTED ok=1 old=0x102 now=0x4\b/u)).not.toBeNull();
  // the verifier (250 ms) puts the guard back over the TARGET's protection: RW | GUARD, never the stale RO | GUARD
  await vi.waitFor(async () => expect(await protOf(a)).toBe(0x104), { timeout: 5000, interval: 100 });
  // a write: one guard trap, BEA steps it, the write lands (it raised an access violation under a stale RO page)
  expect(await ask(a, "write", /WROTE prot=0x104\b/u)).not.toBeNull();
  expect(await a.waitFor(() => a.rows(r.stream_id).some((row) => row[5] !== null), 5000)).not.toBeNull();
  const stop = await a.ok<InstrumentStopResult>("instrumentStop", { id: r.instrument_id, final_flush: true });
  expect(stop.stopped[0]).toMatchObject({ reverted: true, verification: { kind: "protection", ok: true } });
  expect(await protOf(a)).toBe(0x4); // the target's PAGE_READWRITE stays
  expect(await ask(a, "write", /WROTE prot=0x4\b/u)).not.toBeNull();
  expect(a.detached).toEqual([]);
};

const agent2Stop = async (): Promise<void> => {
  const { a, page } = await start("pg");
  const watch = async (): Promise<WatchInstallResult> =>
    a.ok<WatchInstallResult>("watchInstall", {
      method: "page-guard",
      address: hex(page + 8n),
      size: 8,
      access: "write",
      threads: "all",
      capture,
      lifetime: lifetime(30_000, 1000),
    });
  const first = await watch();
  expect(await ask(a, "rw", /PROTECTED ok=1 old=0x102 now=0x4\b/u)).not.toBeNull();
  const stopped = await a.ok<InstrumentStopResult>("instrumentStop", { id: first.instrument_id, final_flush: true });
  expect(stopped.stopped[0]).toMatchObject({ reverted: true });
  // the stop wrote back the PAGE_READONLY seen at arm time: the target's next write died on it
  expect(await protOf(a)).toBe(0x4);
  expect(await ask(a, "write", /WROTE prot=0x4\b/u)).not.toBeNull();
  // RW -> RX under a second watch: the stop keeps PAGE_EXECUTE_READ, and the page stays readable for the target
  const second = await watch();
  expect(await protOf(a)).toBe(0x104);
  expect(await ask(a, "rx", /PROTECTED ok=1 old=0x104 now=0x20\b/u)).not.toBeNull();
  await a.ok<InstrumentStopResult>("instrumentStop", { id: second.instrument_id, final_flush: true });
  expect(await protOf(a)).toBe(0x20);
  expect(await ask(a, "read", /READ v=\d+ prot=0x20\b/u)).not.toBeNull();
  expect(a.detached).toEqual([]);
};

const agent4Dispose = async (): Promise<void> => {
  const gates = { gates: { write_memory: true, override_function: false, call_function: true } };
  for (const revertFirst of [true, false]) {
    const { a, counter } = await start("loop", gates);
    const written = 1_000_000 * (revertFirst ? 1 : 2);
    const bytes = Buffer.alloc(4);
    bytes.writeInt32LE(written);
    const w = await a.ok<WriteResult>("writeMemory", {
      address: hex(counter),
      mode: "data",
      bytes: bytes.toString("hex"),
      allow_protect_change: false,
    });
    expect(w.verified).toBe(true);
    const original = Buffer.from(w.before, "hex").readInt32LE(0);
    expect(original).toBeLessThan(written);
    // the program keeps counting from the written value: the memory changed after the write
    await vi.waitFor(async () => expect(await numberOf(a, "counter", "COUNTER")).toBeGreaterThan(written), {
      timeout: 5000,
      interval: 50,
    });
    if (revertFirst)
      expect(await a.rpc("revertWrite", { write_id: w.write_id, force: false })).toMatchObject({
        ok: false,
        error: { _tag: "WriteConflict" },
      });
    // rpc.exports.dispose (close_session / detach / host exit on an attached target): revertAll
    await a.script.unload();
    // the stale `before` (the counter at write time) is not written back over the program's value
    expect(await numberOf(a, "counter", "COUNTER")).toBeGreaterThan(written);
    await a.close();
  }
};

const agent5NativeRings = async (): Promise<void> => {
  const { a } = await start("loop");
  const cycle = async (): Promise<void> => {
    const h = await a.ok<HookInstallResult>("hookInstall", hookParams("step", "native", []));
    await a.ok<InstrumentStopResult>("instrumentStop", { id: h.instrument_id, final_flush: true });
  };
  const ringBytes = async (): Promise<number> =>
    (await a.ok<AgentStatus>("status", { detail: "summary" })).memory.ring_bytes;
  await cycle(); // warm-up: the native tier and the first allocations
  await vi.waitFor(async () => expect(await ringBytes()).toBe(0), { timeout: 5000, interval: 100 });
  const before = await numberOf(a, "priv", "PRIV");
  for (let i = 0; i < 8; i++) await cycle();
  // each cycle kept about 6 MiB (5 MiB ring + 1 MiB staging) for the session: +48 MiB
  await vi.waitFor(async () => expect(await ringBytes()).toBe(0), { timeout: 5000, interval: 100 });
  await vi.waitFor(async () => expect((await numberOf(a, "priv", "PRIV")) - before).toBeLessThan(12 * MiB), {
    timeout: 5000,
    interval: 200,
  });
};

const agent6TraceSlabs = async (): Promise<void> => {
  const { a, tid } = await start("loop");
  const trace = async (): Promise<void> => {
    const r = await traceWhenFree(a, {
      threads: [tid],
      mode: "block_counts",
      modules: ["$main"],
      exclude_modules: [],
      lifetime: lifetime(300, 1_000_000),
    });
    expect(await a.waitFor(() => endedOf(a, r.instrument_id), 10_000)).not.toBeUndefined();
  };
  await trace(); // warm-up
  const before = await numberOf(a, "priv", "PRIV");
  for (let i = 0; i < 6; i++) await trace();
  // each trace committed (and kept) a 1,000,000 x 24 B slab: +137 MiB for six
  await vi.waitFor(async () => expect((await numberOf(a, "priv", "PRIV")) - before).toBeLessThan(16 * MiB), {
    timeout: 10_000,
    interval: 250,
  });
};

const agent7ProfileUnderTrace = async (): Promise<void> => {
  const { a, tid } = await start("loop");
  const trace = await traceWhenFree(a, {
    threads: [tid],
    mode: "coverage",
    modules: ["$main"],
    exclude_modules: [],
    lifetime: lifetime(60_000, 1_000_000),
  });
  // followed: the coverage stream has blocks
  expect(
    await a.waitFor(
      () => a.records.some((r) => r.payload["bea"] === "batch" && r.payload["stream"] === trace.stream_id),
      10_000,
    ),
  ).not.toBe(null);
  const profile = await a.ok<ProfileInstallResult>("profileInstall", {
    profiles: ["file"],
    options: {},
    lifetime: lifetime(800, 100_000),
  });
  expect(profile.installed.length).toBeGreaterThan(0);
  // the profile ends by its duration while the thread is still followed (detach under Stalker)
  expect(await a.waitFor(() => endedOf(a, profile.instrument_id), 10_000)).not.toBeUndefined();
  const fromMain = a.rows(profile.stream_id).filter((row) => row[2] === tid);
  expect(fromMain.length).toBeGreaterThan(10); // GetFileAttributesW every 10 ms: ~80; it was 0
  await a.ok<InstrumentStopResult>("instrumentStop", { id: trace.instrument_id, final_flush: true });
  expect(await numberOf(a, "counter", "COUNTER")).toBeGreaterThan(0);
  expect(a.detached).toEqual([]);
};

const agent8BackToBack = async (): Promise<void> => {
  const { a, tid } = await start("steady");
  const exe = basename(target?.path ?? "").toLowerCase();
  const modules = (await a.ok<ListModulesResult>("listModules", { with_pe: false })).modules.map((m) => m.name);
  const exclude = modules.filter((m) => m.toLowerCase() !== exe);
  for (let i = 0; i < 4; i++) {
    const r = await traceWhenFree(a, {
      threads: [tid],
      mode: "block_counts",
      modules: ["$main"],
      exclude_modules: exclude,
      lifetime: lifetime(400, 1_000_000),
    });
    expect(await a.waitFor(() => endedOf(a, r.instrument_id), 10_000)).not.toBeUndefined();
    // the stopped trace's exec context kept the thread (records 4, 0, 0, 0 before the fix)
    expect(blockCounts(a, r.stream_id).length, `trace ${String(i)}`).toBeGreaterThan(0);
  }
  expect(a.detached).toEqual([]);
};

const agent10GuardDeref = async (): Promise<void> => {
  const { a, page } = await start("guard");
  expect(await protOf(a)).toBe(0x104); // PAGE_READWRITE | PAGE_GUARD, the target's
  const h = await a.ok<HookInstallResult>(
    "hookInstall",
    hookParams("touch", "js", [{ slot: 0, type: "u32", deref: [0] }]),
  );
  expect(await a.waitFor(() => a.rows(h.stream_id).length >= 5, 10_000)).not.toBeNull();
  for (const row of a.rows(h.stream_id).slice(0, 5)) expect(row[6]).toEqual([{ e: "guard", a: hex(page + 0x40n) }]);
  // the capture read used to consume the guard: the page was PAGE_READWRITE from then on
  expect(await protOf(a)).toBe(0x104);
  await a.ok<InstrumentStopResult>("instrumentStop", { id: h.instrument_id, final_flush: true });
};

const agent11SoftwareExceptions = async (): Promise<void> => {
  const { a, tid } = await start("loop"); // RawAgent's hello lists "system" in crash_class
  expect(await ask(a, "raise", /RAISED/u)).not.toBeNull();
  expect(await ask(a, "debug", /DEBUGGED/u)).not.toBeNull();
  await a.ok("flush", {});
  const system = await a.waitFor(() => {
    const rows = a.rows("s:exceptions").filter((row) => row[3] === "system" && row[2] !== tid);
    return rows.length > 0 ? rows : null;
  }, 5000);
  expect(system).not.toBeNull();
  for (const row of system ?? []) expect(row[7]).toBe("passed");
  // 40 software exceptions: 8 blocking first-chance reports (no code, the 10 s budget used up) before the fix
  expect(a.messages("crash")).toEqual([]);
  expect(a.detached).toEqual([]);
};

const ux11Invocations = async (): Promise<void> => {
  const { a } = await start("loop");
  const r = await a.ok<TraceStartResult>("traceStart", {
    on_call: { target: { module: "bea_review_target.exe", export: "step" }, invocations: 2 },
    mode: "coverage",
    modules: ["$main"],
    exclude_modules: [],
    lifetime: lifetime(10_000, 1_000_000),
  });
  const ended = await a.waitFor(() => endedOf(a, r.instrument_id), 10_000);
  expect(ended?.["detail"]).toMatchObject({ end_reason: "invocations" });
};

describe.skipIf(SKIP !== false)(`partition-A review fixes through the real agent${skipNote(SKIP)}`, () => {
  beforeAll(async () => {
    const manifest = await loadFixtures();
    const pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
    RawAgent.useLivenessProbe(pidcheck);
    target = await buildReviewTarget();
    bundle = (await buildTestAgent({ mode: "repo" })).bundle;
  }, 300_000);

  afterEach(async () => {
    for (const a of agents.splice(0)) await a.close();
  });

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    await target?.cleanup();
  });

  it(
    "AGENT-2: the verifier re-arms over the protection the target set; a write then succeeds and stop keeps it",
    agent2Verifier,
  );
  it(
    "AGENT-2: a stop right after the target re-protected leaves the target's protection (RW, then RX) in place",
    agent2Stop,
  );
  it(
    "AGENT-4: dispose leaves memory the program changed after write_memory as found (after a conflict and without one)",
    agent4Dispose,
  );
  it("AGENT-5: native hook install + stop cycles give their ring and staging buffers back", agent5NativeRings);
  it("AGENT-6: block_counts traces at the default max_events give their counting slab back", agent6TraceSlabs);
  it(
    "AGENT-7: trace_api records the calls of a thread trace_execution follows, and stops cleanly under it",
    agent7ProfileUnderTrace,
  );
  it(
    "AGENT-8: back-to-back threads-mode traces of a steady loop (every other module excluded) each record",
    agent8BackToBack,
  );
  it(
    "AGENT-10: a hook capture deref into the target's own guard page answers {e:guard} and leaves the guard",
    agent10GuardDeref,
  );
  it(
    "AGENT-11: software exceptions are rows, never blocking crash reports, even when crash_class lists system",
    agent11SoftwareExceptions,
  );
  it("UX-11: an on_call trace that completed its invocations ends with end_reason invocations", ux11Invocations);
});
