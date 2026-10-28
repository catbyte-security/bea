import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { slotBits } from "../../../src/agent/pure/dr7.js";
import { buildStalkerCoverage, drcovBytes } from "../../../src/application/watch/coverage.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { parseDrcov } from "../../support/drcov.js";
import {
  buildHarness,
  loadFrida,
  shutdownRawFrida,
  spawnHarnessed,
  useLivenessProbe,
  waitGone,
  type Harnessed,
} from "./harness/rawFrida.js";

/**
 * WP9 agent engines on the real target, before the WP3 core exists (raw Frida, no BEA host; DESIGN §8.4 wave rule:
 * raw agent RPCs only). The harness seam (harness/harness-agent.ts.txt) stands in for WP3's dispatcher, instrument
 * registry and streams; the engines are the production files. Rows are S4 watch/1 / poll/1 tuples and block-count/1
 * records. Acceptance rows (WP9 card): DR write watch on car+8 → exactly the manifest writer, struct base = car,
 * insn exact; stop → DR7 clear on every thread; page_guard sees every write; a hot page ends with rate-limit and the
 * target keeps running; on_call coverage lies in physics_step's .pdata range and includes the entry block; drcov
 * parses; a hot DR watch on an attached target survives a hard kill of the host (safety net).
 */
const SKIP = fridaSkip() !== false ? fridaSkip() : gccSkip();
const hex = (v: bigint): string => `0x${v.toString(16)}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type Row = unknown[];
const watchRows = (rows: Row[]) => rows.filter((r) => r[5] !== null);
const markerRows = (rows: Row[]) => rows.filter((r) => r[5] === null && typeof r[8] === "string");

let frida: Awaited<ReturnType<typeof loadFrida>>;
let bundle = "";
let game: FixtureArtifact;
const open: Harnessed[] = [];

const ok = <T>(r: unknown): T => {
  const result = r as { ok: boolean; value?: T; error?: unknown };
  if (!result.ok) throw new Error(`agent error: ${JSON.stringify(result.error)}`);
  return result.value as T;
};
/** One fixture per test, always closed (bounded) when the test ends. */
const withGame = async (args: readonly string[], body: (h: Harnessed) => Promise<void>): Promise<void> => {
  const h = await spawnHarnessed(frida, bundle, game.path, args);
  open.push(h);
  try {
    await body(h);
  } finally {
    open.splice(open.indexOf(h), 1);
    await h.close();
  }
};
const lifetime = (duration_ms: number, max_hits: number) => ({ duration_ms, max_hits, clock: "install" as const });
const capture = { registers: "none" as const, backtrace: 0, values: true };
const speedWriterRva = (): number => (game.expectations["speedWriters"] as { rva: number }[])[0]?.rva ?? -1;
const endedMessage = (h: Harnessed, id: string) => h.messages.find((m) => m.type === "ended" && m["id"] === id);
const waitEnded = (h: Harnessed, id: string, ms: number): Promise<boolean> =>
  h.waitFor(() => endedMessage(h, id) !== undefined, ms);
const frameOf = async (h: Harnessed, car: bigint): Promise<number> =>
  (await h.call("readU32", 10_000, hex(car + 0x38n))) as number;

const drWriterOnCar = (): Promise<void> =>
  withGame([], async (h) => {
    const layout = (await h.call("layout", 10_000)) as { base: string; car: string };
    const base = BigInt(layout.base);
    const car = BigInt(layout.car);
    const installed = ok<{
      instrument_id: string;
      slot: number;
      armed_threads: number;
      verified: { threads_checked: number; ok: number };
    }>(
      await h.call("watchInstall", 15_000, {
        method: "debug-register",
        address: hex(car + 8n),
        size: 4,
        access: "write",
        threads: "all",
        capture,
        lifetime: lifetime(20_000, 1_000_000),
      }),
    );
    expect(installed.slot).toBe(0);
    expect(installed.armed_threads).toBeGreaterThanOrEqual(4);
    expect(installed.verified.ok).toBe(installed.verified.threads_checked);
    expect(await h.waitFor(() => h.rows(installed.instrument_id).length >= 20, 10_000)).toBe(true);
    const stopped = (await h.call("stop", 15_000, installed.instrument_id)) as {
      outcome: { reverted: boolean; verification: { kind: string; ok: boolean } };
    };
    expect(stopped.outcome).toMatchObject({ reverted: true, verification: { kind: "dr7", ok: true } });
    const rows = watchRows(h.rows(installed.instrument_id));
    expect(rows.length).toBeGreaterThanOrEqual(20);
    for (const r of rows) {
      expect(r[4]).toBe("w");
      expect(r[5]).toBe(hex(base + BigInt(speedWriterRva())));
      expect(r[6]).toBe("swept"); // tool insn_confidence "exact"
      expect(r[14]).toMatchObject({ base: "rax", disp: 8, base_value: hex(car), base_written: false });
    }
    const state = ok<{ threads: { tid: number; dr7: string; error: string | null }[] }>(
      await h.call("debugRegisterState", 15_000),
    );
    const sampled = state.threads.filter((t) => t.error === null);
    expect(sampled.length).toBeGreaterThanOrEqual(4);
    for (const t of sampled) expect(BigInt(t.dr7) & slotBits(0)).toBe(0n);
  });

// --no-threads: no other thread touches the car's page. With the helper threads, every foreign access to the page
// opens a window (guard consumed → handler → trap-flag step → re-arm) in which the main thread's store goes unseen
// (WATCH_PAGE_GUARD_CONCURRENT; measured 40–90 % misses in the WP9 lab), which is why auto prefers a DR.
const pageGuardSingleWriter = (): Promise<void> =>
  withGame(["--no-threads"], async (h) => {
    const layout = (await h.call("layout", 10_000)) as { base: string; car: string };
    const base = BigInt(layout.base);
    const car = BigInt(layout.car);
    const frame0 = await frameOf(h, car);
    const installed = ok<{ instrument_id: string; pages: string[] }>(
      await h.call("watchInstall", 15_000, {
        method: "page-guard",
        address: hex(car + 8n),
        size: 4,
        access: "write",
        threads: "all",
        capture,
        rate_limit: { max_per_sec: 20_000, window_ms: 100 },
        lifetime: lifetime(1500, 1_000_000),
      }),
    );
    expect(installed.pages).toEqual([hex((car + 8n) & ~0xfffn)]);
    expect(await waitEnded(h, installed.instrument_id, 10_000)).toBe(true);
    const frame1 = await frameOf(h, car);
    const all = h.rows(installed.instrument_id);
    const hits = watchRows(all);
    // one speed store per frame; the frames read before arming and after the stop bracket the watched window
    expect(hits.length).toBeGreaterThan(20);
    expect(hits.length).toBeLessThanOrEqual(frame1 - frame0);
    expect(hits.length).toBeGreaterThanOrEqual(frame1 - frame0 - 4);
    for (const r of hits) {
      expect(r[5]).toBe(hex(base + BigInt(speedWriterRva())));
      expect(r[6]).toBe("exact");
      expect(typeof r[10]).toBe("string");
      expect(typeof r[11]).toBe("string");
      expect(r[14]).toMatchObject({ base: "rax", disp: 8, base_value: hex(car) });
    }
    expect(markerRows(all).map((r) => r[8])).toEqual(["bea:watch-final"]);
    expect(endedMessage(h, installed.instrument_id)?.["outcome"]).toMatchObject({
      reverted: true,
      verification: { kind: "protection", ok: true },
    });
  });

const pageGuardHotPage = (): Promise<void> =>
  withGame(["--hot", "20000"], async (h) => {
    const layout = (await h.call("layout", 10_000)) as { car: string; hotSink: string };
    const car = BigInt(layout.car);
    const installed = ok<{ instrument_id: string }>(
      await h.call("watchInstall", 15_000, {
        method: "page-guard",
        address: hex(BigInt(layout.hotSink)),
        size: 8,
        access: "write",
        threads: "all",
        capture,
        rate_limit: { max_per_sec: 20_000, window_ms: 100 },
        lifetime: lifetime(10_000, 10_000_000),
      }),
    );
    expect(await waitEnded(h, installed.instrument_id, 10_000)).toBe(true);
    expect(endedMessage(h, installed.instrument_id)?.["reason"]).toBe("rate-limit");
    const trip = markerRows(h.rows(installed.instrument_id)).find((r) => r[8] === "bea:rate-limit");
    // the valve's counters (hex): either the trap rate passed the limit, or handling the traps held the target for
    // more than half of a window (≈ 55 µs per access here caps the rate near the 20,000/s limit)
    const n = (k: string): number => Number((trip?.[12] as Record<string, string> | undefined)?.[k] ?? -1);
    if (n("busy_trip") === 1) expect(n("busy_pct"), JSON.stringify(trip)).toBeGreaterThan(n("busy_limit_pct"));
    else expect(n("peak_per_sec"), JSON.stringify(trip)).toBeGreaterThan(n("limit_per_sec"));
    expect(n("busy_limit_pct")).toBe(50);
    const f0 = await frameOf(h, car);
    await sleep(500);
    expect(await frameOf(h, car)).toBeGreaterThan(f0);
  });

const pollCarStruct = (): Promise<void> =>
  withGame([], async (h) => {
    const layout = (await h.call("layout", 10_000)) as { car: string };
    const installed = ok<{ instrument_id: string; initial_value: string }>(
      await h.call("watchInstall", 15_000, {
        method: "poll",
        address: hex(BigInt(layout.car)),
        size: 0x80,
        interval_ms: 16,
        access: "write",
        threads: "all",
        capture,
        lifetime: lifetime(1500, 1_000_000),
      }),
    );
    expect(installed.initial_value).toHaveLength(0x100);
    expect(await waitEnded(h, installed.instrument_id, 10_000)).toBe(true);
    const offsets = new Set(h.rows(installed.instrument_id).map((r) => r[2] as number));
    expect(offsets.has(0x8)).toBe(true); // speed (+0x8) / throttle (+0xc)
    expect(offsets.has(0x10)).toBe(true); // steer (+0x10) / rpm (+0x14)
    expect(offsets.has(0x48)).toBe(false); // mass / drag: never written after init
  });

/** block-count/1 records {u64 start, u64 end, u64 count} of one instrument. */
const blockCounts = (h: Harnessed, id: string): { start: bigint; end: bigint; count: bigint }[] =>
  h.bins
    .filter((b) => b.id === id)
    .flatMap((b) => {
      const out: { start: bigint; end: bigint; count: bigint }[] = [];
      for (let i = 0; i + 24 <= b.data.length; i += 24)
        out.push({
          start: b.data.readBigUInt64LE(i),
          end: b.data.readBigUInt64LE(i + 8),
          count: b.data.readBigUInt64LE(i + 16),
        });
      return out;
    });

const onCallCoverage = (): Promise<void> =>
  withGame([], async (h) => {
    const layout = (await h.call("layout", 10_000)) as { base: string; physicsStep: string };
    const base = BigInt(layout.base);
    const entry = BigInt(layout.physicsStep);
    const pdata = game.pe.pdata["physics_step"] ?? { rva: 0, size: 0 };
    const started = ok<{ instrument_id: string; row_kind: string }>(
      await h.call("traceStart", 15_000, {
        on_call: { target: { va: hex(entry) }, invocations: 1 },
        mode: "coverage",
        modules: ["$main"],
        exclude_modules: [],
        lifetime: lifetime(10_000, 100_000),
      }),
    );
    expect(started.row_kind).toBe("block-count/1");
    expect(await waitEnded(h, started.instrument_id, 15_000)).toBe(true);
    const blocks = blockCounts(h, started.instrument_id);
    expect(blocks.length).toBeGreaterThanOrEqual(2);
    const lo = base + BigInt(pdata.rva);
    const hi = lo + BigInt(pdata.size);
    for (const b of blocks) {
      expect(b.start >= lo && b.start < hi, `block ${hex(b.start)} outside physics_step`).toBe(true);
      expect(b.count).toBeGreaterThan(0n);
    }
    const entryBlock = blocks.find((b) => b.start === entry);
    expect(entryBlock).toBeDefined();
    expect(entryBlock?.count).toBe(1n);
    const module = {
      name: game.file,
      path: game.path,
      base,
      size: game.pe.sizeOfImage,
      fileSha256: null,
      preferredBase: null,
      entryRva: null,
      timestamp: null,
    };
    const cov = buildStalkerCoverage(
      { sessionId: "raw", evidenceId: null, threads: [] },
      [module],
      blocks.map((b) => ({ va: b.start, size: Number(b.end - b.start), hits: Number(b.count) })),
      false,
    );
    const parsed = parseDrcov(drcovBytes(cov));
    expect(parsed.modules[0]?.path).toBe(game.path);
    expect(parsed.blocks.length).toBe(blocks.length);
    for (const b of parsed.blocks) expect(b.start >= pdata.rva && b.start < pdata.rva + pdata.size).toBe(true);
    expect(parsed.blocks.some((b) => b.start === pdata.rva)).toBe(true);
  });

const until = async (done: () => boolean, ms: number): Promise<void> => {
  const t0 = Date.now();
  while (!done() && Date.now() - t0 < ms) await sleep(25);
};
const killTree = (pid: number | undefined): void => {
  spawnSync("taskkill", ["/F", "/PID", String(pid)], { windowsHide: true });
};

interface HardKill {
  readonly alive: boolean;
  readonly exitCode: number | null;
  readonly armed: string;
  readonly diedBeforeKill: boolean;
  /** traps BEA's dispatcher handled during 500 ms with the agent loaded */
  readonly liveTraps: number | null;
  /** the safety net's DR count at that point ("none" without a net): 0 = it stayed behind Frida's exceptor */
  readonly netTrapsWhileLoaded: string | null;
}
/**
 * A hot DR watch (~20k traps/s) on a target attached by a separate host; the host is killed with taskkill /F. Frida
 * then unloads the script, calling rpc.exports.dispose (the engines' synchronous disarm, as WP3's core does) unless
 * `dispose` is false.
 */
const hardKillRun = async (attached: boolean, dispose: boolean): Promise<HardKill> => {
  const target: ChildProcess = spawn(game.path, ["--hot", "2000"], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let out = "";
  target.stdout?.on("data", (c: Buffer) => (out += c.toString("utf8")));
  // the host is hard-killed and never closes its DeviceManager: its own TEMP keeps Frida's agent copies (~45 MB) here,
  // removed once host and target are gone
  const dir = mkdtempSync(join(tmpdir(), "bea-wp9-net-"));
  let host: ChildProcess | null = null;
  try {
    await until(() => out.includes("READY"), 10_000);
    const bundlePath = join(dir, "harness.js");
    writeFileSync(bundlePath, bundle);
    const hostScript = join(import.meta.dirname, "harness", "attachHost.mjs");
    const flags = [attached ? "1" : "0", dispose ? "1" : "0"];
    host = spawn(process.execPath, [hostScript, String(target.pid), bundlePath, ...flags], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      env: { ...process.env, TEMP: dir, TMP: dir },
    });
    let hostOut = "";
    host.stdout?.on("data", (c: Buffer) => (hostOut += c.toString("utf8")));
    host.stderr?.on("data", (c: Buffer) => (hostOut += c.toString("utf8")));
    await until(() => hostOut.includes("READY") && hostOut.includes("LIVE"), 20_000);
    const armed =
      /ARMED .*/u.exec(hostOut)?.[0] ?? `not armed (target exit ${String(target.exitCode)}): ${hostOut.slice(0, 1500)}`;
    const diedBeforeKill = target.exitCode !== null;
    const live = /LIVE traps0=(\d+) traps=(\d+) netdr=(\w+)/u.exec(hostOut);
    killTree(host.pid);
    const frames = (out.match(/FRAME /gu) ?? []).length;
    await sleep(4000);
    const alive = target.exitCode === null && (out.match(/FRAME /gu) ?? []).length > frames;
    return {
      alive,
      exitCode: target.exitCode,
      armed,
      diedBeforeKill,
      liveTraps: live === null ? null : Number(live[2]) - Number(live[1]),
      netTrapsWhileLoaded: live?.[3] ?? null,
    };
  } finally {
    if (host !== null && host.exitCode === null) killTree(host.pid);
    if (target.exitCode === null) target.kill();
    // the agent copies in `dir` can be deleted only once no process maps them
    for (const pid of [host?.pid, target.pid]) if (pid !== undefined) await waitGone(pid, 5000);
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
};

const safetyNetSurvivesHostKill = async (): Promise<void> => {
  // Control: no safety net and no dispose disarm, so the armed watch outlives the script: CT-lab E4 saw 0x80000004
  // (a stray BEA trap nobody claims), this lab also 0xC0000005 (Frida's unload racing the trap stream; 5/5 deaths).
  // Any death proves the setup. Lab matrix (WP9, 6-8 runs each): dispose alone kept every target alive; the net
  // without dispose kept 7/8 (the 8th: that same unload race, an access violation no vectored handler can absorb).
  const control = await hardKillRun(false, false);
  const code = control.exitCode === null ? "alive" : `0x${(control.exitCode >>> 0).toString(16)}`;
  expect(
    control.alive,
    `control ${code}, died before the kill: ${String(control.diedBeforeKill)}, ${control.armed}`,
  ).toBe(false);
  // The production configuration of an attached session: safety net (registered after Frida's exceptor) + dispose.
  const guarded = await hardKillRun(true, true);
  expect(guarded.armed).toContain("ok=true net=true");
  // registered last, the net never sees a BEA trap while the agent is loaded: the watch keeps recording
  expect(guarded.netTrapsWhileLoaded, guarded.armed).toBe("0");
  expect(guarded.liveTraps).toBeGreaterThan(100);
  expect(guarded.diedBeforeKill).toBe(false);
  expect(guarded.alive, `protected target exit ${String(guarded.exitCode)}`).toBe(true);
};

describe.skipIf(SKIP !== false)(`WP9 agent engines on game_sim (raw Frida)${skipNote(SKIP)}`, () => {
  beforeAll(async () => {
    const manifest = await loadFixtures();
    const artifact = fixtureArtifact(manifest, "game_sim");
    if (artifact === null) throw new Error("game_sim fixture unavailable");
    game = artifact;
    useLivenessProbe(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
    frida = await loadFrida();
    bundle = await buildHarness(frida);
  }, 180_000);

  afterAll(async () => {
    for (const h of open.splice(0)) await h.close();
    await shutdownRawFrida();
  });

  it(
    "debug-register write watch on car+8: exactly the manifest speed writer, struct base = car, then DR7 clear everywhere",
    drWriterOnCar,
  );
  it(
    "page-guard watch on car+8 sees every physics_step write with the exact instruction (single-writer world)",
    pageGuardSingleWriter,
  );
  it("page-guard watch on a hot page ends with rate-limit and the target keeps running", pageGuardHotPage);
  it("poll on the car struct reports the changing cells and never the constant tunables", pollCarStruct);
  it(
    "on_call coverage of one physics_step call lies in its .pdata range, includes the entry block and exports as drcov",
    onCallCoverage,
  );
  it(
    "safety net: a hot DR watch on an attached target survives a hard kill of the host (the unprotected control dies)",
    safetyNetSurvivesHostKill,
    90_000,
  );
});
