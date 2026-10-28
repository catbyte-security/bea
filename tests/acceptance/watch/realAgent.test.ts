import { spawn, type ChildProcess } from "node:child_process";
import { dirname } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type {
  AgentStatus,
  HelloResult,
  InstrumentStopResult,
  TraceStartResult,
  WatchInstallResult,
} from "../../../src/shared/agentProtocol.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { buildTestAgent } from "../../support/agent/coreAgent.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { useLivenessProbe, waitGone } from "./harness/rawFrida.js";

/**
 * WP9 through the REAL agent (raw Frida, no BEA host): every file under src/agent compiled as `npm run build:agent`
 * does, so the engines are bound through WP3's core.watchSeam (watch.ts adaptSeam: external guard pages in BEA's
 * table, the core's dispatcher, instrument registry, streams and Stalker coordinator), driven with WP3's RawAgent
 * harness (hello → resume → RPCs, batches collected per stream). Targets are spawned by Frida for this test (owned,
 * killed on close) or by the test itself (attach case, killed here).
 */
const SKIP = fridaSkip() !== false ? fridaSkip() : gccSkip();
const hex = (v: bigint): string => `0x${v.toString(16)}`;
const lifetime = (duration_ms: number, max_hits: number) => ({ duration_ms, max_hits, clock: "install" as const });
const capture = { registers: "none" as const, backtrace: 0, values: true };

let bundle = "";
let game: FixtureArtifact;
const agents: RawAgent[] = [];
const children: ChildProcess[] = [];

interface Game {
  readonly a: RawAgent;
  readonly base: bigint;
  readonly car: bigint;
}

const rva = (name: string): bigint => BigInt(game.pe.exportRvas[name] ?? -1);
const speedWriterRva = (): number => (game.expectations["speedWriters"] as { rva: number }[])[0]?.rva ?? -1;
/** game_sim prints "READY pid=… world=%p car=%p" (MinGW %p: hex digits, with or without 0x). */
const carOf = (output: string): bigint => {
  const m = /car=(?:0x)?([0-9a-fA-F]+)/u.exec(output);
  if (m?.[1] === undefined) throw new Error(`no car pointer in ${output.slice(0, 200)}`);
  return BigInt(`0x${m[1]}`);
};

const startGame = async (args: readonly string[]): Promise<Game> => {
  const a = await RawAgent.start({ bundle, program: game.path, args, cwd: dirname(game.path) });
  agents.push(a);
  const hello: HelloResult = await a.hello();
  await a.resume();
  if ((await a.waitFor(() => a.output().includes("READY"), 10_000)) === null)
    throw new Error(`fixture did not print READY: ${a.output().slice(0, 300)}`);
  return { a, base: BigInt(hello.process.main_module.base), car: carOf(a.output()) };
};

const endedOf = (a: RawAgent, id: string) =>
  a.messages("instrument").find((m) => m["id"] === id && m["event"] === "ended");

/** block-count/1 records {u64 start, u64 end, u64 count} of a binary stream. */
const blockCounts = (a: RawAgent, stream: string): { start: bigint; end: bigint; count: bigint }[] => {
  const out: { start: bigint; end: bigint; count: bigint }[] = [];
  for (const r of a.records) {
    if (r.payload["bea"] !== "batch" || r.payload["stream"] !== stream || r.data === null) continue;
    for (let i = 0; i + 24 <= r.data.length; i += 24)
      out.push({
        start: r.data.readBigUInt64LE(i),
        end: r.data.readBigUInt64LE(i + 8),
        count: r.data.readBigUInt64LE(i + 16),
      });
  }
  return out;
};

const drWatchThroughCore = async (): Promise<void> => {
  const { a, base, car } = await startGame([]);
  const r = await a.ok<WatchInstallResult>("watchInstall", {
    method: "debug-register",
    address: hex(car + 8n),
    size: 4,
    access: "write",
    threads: "all",
    capture,
    lifetime: lifetime(20_000, 1_000_000),
  });
  expect(r).toMatchObject({ method: "debug-register", slot: 0, arm_errors: [] });
  expect(r.verified?.ok).toBe(r.verified?.threads_checked);
  // the status hooks reach the core: the slot is owned by the watch, no safety net in an owned session
  const status = await a.ok<AgentStatus>("status", { detail: "summary" });
  expect(status.debug_registers[0]?.owner).toBe(r.instrument_id);
  expect(status.exceptions.safety_net).toBe("none");
  expect(await a.waitFor(() => a.rows(r.stream_id).length >= 20, 10_000)).not.toBeNull();
  const stop = await a.ok<InstrumentStopResult>("instrumentStop", { id: r.instrument_id, final_flush: true });
  expect(stop.stopped[0]).toMatchObject({ reverted: true, verification: { kind: "dr7", ok: true } });
  const hits = a.rows(r.stream_id).filter((row) => row[5] !== null);
  expect(hits.length).toBeGreaterThanOrEqual(20);
  for (const row of hits) {
    expect(row[5]).toBe(hex(base + BigInt(speedWriterRva())));
    expect(["exact", "swept"]).toContain(row[6]); // WP3's overlay-aware findAccessInsn
    expect(row[14]).toMatchObject({ base: "rax", disp: 8, base_value: hex(car) });
  }
};

const pageGuardThroughCore = async (): Promise<void> => {
  const { a, base, car } = await startGame(["--no-threads"]);
  const r = await a.ok<WatchInstallResult>("watchInstall", {
    method: "page-guard",
    address: hex(car + 8n),
    size: 4,
    access: "write",
    threads: "all",
    capture,
    rate_limit: { max_per_sec: 20_000, window_ms: 100 },
    lifetime: lifetime(1500, 1_000_000),
  });
  expect(r.pages).toEqual([hex((car + 8n) & ~0xfffn)]);
  const ended = await a.waitFor(() => endedOf(a, r.instrument_id), 10_000);
  expect(ended?.["detail"]).toMatchObject({ reverted: true, verification: { kind: "protection", ok: true } });
  const rows = a.rows(r.stream_id);
  const hits = rows.filter((row) => row[5] !== null);
  expect(hits.length).toBeGreaterThan(20); // ~60 Hz for 1.5 s, the guard faults routed by the core's dispatcher
  for (const row of hits) {
    expect(row[5]).toBe(hex(base + BigInt(speedWriterRva())));
    expect(row[6]).toBe("exact");
  }
  expect(rows.filter((row) => row[5] === null).map((row) => row[8])).toEqual(["bea:watch-final"]);
  // the target keeps running unguarded
  const frames = (a.output().match(/FRAME /gu) ?? []).length;
  expect(await a.waitFor(() => (a.output().match(/FRAME /gu) ?? []).length > frames, 3000)).not.toBeNull();
};

const onCallThroughCore = async (): Promise<void> => {
  const { a, base } = await startGame([]);
  const pdata = game.pe.pdata["physics_step"] ?? { rva: 0, size: 0 };
  const entry = base + rva("physics_step");
  const r = await a.ok<TraceStartResult>("traceStart", {
    on_call: { target: { va: hex(entry) }, invocations: 1 },
    mode: "coverage",
    modules: ["$main"],
    exclude_modules: [],
    lifetime: lifetime(10_000, 100_000),
  });
  expect(r.row_kind).toBe("block-count/1");
  expect(await a.waitFor(() => endedOf(a, r.instrument_id), 15_000)).not.toBeNull();
  const blocks = blockCounts(a, r.stream_id);
  expect(blocks.length).toBeGreaterThanOrEqual(2);
  const lo = base + BigInt(pdata.rva);
  for (const b of blocks) expect(b.start >= lo && b.start < lo + BigInt(pdata.size)).toBe(true);
  expect(blocks.find((b) => b.start === entry)?.count).toBe(1n);
};

const attachedKeepsRecording = async (): Promise<void> => {
  const child = spawn(game.path, [], { stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
  children.push(child);
  let out = "";
  child.stdout?.on("data", (c: Buffer) => (out += c.toString("utf8")));
  const t0 = Date.now();
  while (!out.includes("READY") && Date.now() - t0 < 10_000) await new Promise((res) => setTimeout(res, 25));
  const a = await RawAgent.start({ bundle, attachPid: child.pid ?? 0 });
  agents.push(a);
  await a.hello({
    session: { session_id: "00000000-0000-4000-8000-0000000000a9", instance_id: "pi_wp9", owned: false },
  });
  const r = await a.ok<WatchInstallResult>("watchInstall", {
    method: "debug-register",
    address: hex(carOf(out) + 8n),
    size: 4,
    access: "write",
    threads: "all",
    capture,
    lifetime: lifetime(20_000, 1_000_000),
  });
  const status = await a.ok<AgentStatus>("status", { detail: "summary" });
  expect(status.exceptions.safety_net).toBe("installed");
  // the net is registered after Frida's exceptor: every trap still reaches BEA's dispatcher, hits keep arriving
  const arrived = await a.waitFor(() => a.rows(r.stream_id).length >= 60, 10_000);
  if (arrived === null) {
    const exit = child.exitCode === null ? "alive" : `0x${(child.exitCode >>> 0).toString(16)}`;
    const state = await a.rpc("debugRegisterState", {}).catch((e: unknown) => String(e));
    const after = await a.rpc("status", { detail: "summary" }).catch((e: unknown) => String(e));
    throw new Error(
      `rows=${String(a.rows(r.stream_id).length)} target=${exit} detached=${a.detached.join(",")} ` +
        `install=${JSON.stringify(r).slice(0, 400)} dr=${JSON.stringify(state).slice(0, 1200)} ` +
        `status=${JSON.stringify(after).slice(0, 1500)} errors=${a.errors.join(" | ").slice(0, 600)} ` +
        `crash=${JSON.stringify(a.messages("crash")).slice(0, 1500)}`,
    );
  }
  const stop = await a.ok<InstrumentStopResult>("instrumentStop", { id: r.instrument_id, final_flush: true });
  expect(stop.stopped[0]).toMatchObject({ reverted: true });
  await a.close();
  expect(child.exitCode).toBeNull(); // an attached target outlives the session
};

describe.skipIf(SKIP !== false)(`WP9 engines through the real agent core${skipNote(SKIP)}`, () => {
  beforeAll(async () => {
    const manifest = await loadFixtures();
    const artifact = fixtureArtifact(manifest, "game_sim");
    if (artifact === null) throw new Error("game_sim fixture unavailable");
    game = artifact;
    // close() waits until killed targets are fully gone, so Frida can delete its %TEMP%\frida-<id> agent copies
    const pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
    RawAgent.useLivenessProbe(pidcheck);
    useLivenessProbe(pidcheck);
    bundle = (await buildTestAgent({ mode: "repo" })).bundle;
  }, 300_000);

  afterEach(async () => {
    for (const a of agents.splice(0)) await a.close();
    for (const c of children.splice(0)) {
      if (c.exitCode === null) c.kill();
      if (c.pid !== undefined) await waitGone(c.pid, 5000);
    }
  });

  afterAll(async () => {
    await RawAgent.shutdownFrida();
  });

  it(
    "debug-register watch on car+8: the manifest writer, the slot in status, DR7 verified clear on stop",
    drWatchThroughCore,
  );
  it(
    "page-guard watch on car+8 through BEA's guard table sees every write and restores the page",
    pageGuardThroughCore,
  );
  it(
    "on_call coverage through the core's Stalker coordinator stays in physics_step and has its entry",
    onCallThroughCore,
  );
  it(
    "attached session: the safety net is installed behind Frida's exceptor and hits keep arriving",
    attachedKeepsRecording,
  );
});
