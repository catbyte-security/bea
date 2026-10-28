import { spawn, type ChildProcess } from "node:child_process";
import { readFile } from "node:fs/promises";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { parseDrcov } from "../../support/drcov.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * Tool-level acceptance of the watch area (S6 §10.8 rows, DESIGN §8.4 edits; WP9 card). Wave rule (CI-I1): besides
 * watch_memory / trace_execution / export_coverage only earlier-wave tools are used (spawn/attach/resume/close of
 * WP4, read_memory of WP6, stop_instrumentation/query_events of WP7). Runs against the BUILT server
 * (BEA_DIST_DIR snapshot); every target is spawned by BEA (owned, killed at close) or by this test (attach target,
 * killed here). Assertions are pointer-free: RVAs from the fixture manifest.
 */
const SKIP = fridaSkip() !== false ? fridaSkip() : jobhostSkip();
const hex = (v: bigint): string => `0x${v.toString(16)}`;
const out = (r: unknown): Readonly<Record<string, unknown>> => expectToolSuccess(r as Record<string, unknown>);

let game: FixtureArtifact;
let ledger: OwnedPidLedger;
let bea: BeaConnection;
const speedWriterRva = (): number => (game.expectations["speedWriters"] as { rva: number }[])[0]?.rva ?? -1;
/** The manifest's speed reader inside one function (objdump-derived). */
const speedReaderRva = (fn: string): number =>
  (game.expectations["speedReaders"] as { fn: string; rva: number }[]).find((r) => r.fn === fn)?.rva ?? -1;
/** car->frame (+0x38): incremented once per frame by physics_step, read by nothing else. */
const frameOffset = (): bigint =>
  BigInt((game.expectations["structOffsets"] as { frame: number } | undefined)?.frame ?? 0x38);
const exportVa = (t: Target, name: string): bigint => t.base + BigInt(game.pe.exportRvas[name] ?? -1);

interface Target {
  readonly session: string;
  readonly base: bigint;
  readonly car: bigint;
}

/** The car pointer through [[game_sim.exe!g_world]+8] (read_memory). */
const carOf = async (session: string): Promise<bigint> => {
  const read = out(
    await bea.call("read_memory", {
      session_id: session,
      address: "game_sim.exe!g_world",
      deref: [8],
      size: 8,
      view: "ptr",
    }),
  );
  return BigInt(String((read["values"] as unknown[])[0]));
};

/** spawn_process + resume_process + READY + the car pointer. */
const spawnGame = async (args: readonly string[]): Promise<Target> => {
  const spawned = out(await bea.call("spawn_process", { program: game.path, args: [...args] }));
  const session = String(spawned["session_id"]);
  const base = BigInt(String((spawned["main_module"] as { base: string }).base));
  out(await bea.call("resume_process", { session_id: session }));
  out(await bea.call("wait", { session_id: session, until: "output", output_contains: "READY", timeout_ms: 10_000 }));
  return { session, base, car: await carOf(session) };
};
const closeGame = async (t: Target): Promise<void> => {
  out(await bea.call("close_session", { session_id: t.session }));
};
/** car->frame now (read_memory u32). */
const frameOf = async (t: Target): Promise<number> => {
  const read = out(
    await bea.call("read_memory", { session_id: t.session, address: hex(t.car + frameOffset()), size: 4, view: "u32" }),
  );
  return Number((read["values"] as unknown[])[0]);
};

const writersOf = (watch: Readonly<Record<string, unknown>>) =>
  ((watch["instrument"] as { summary?: { writers?: unknown[] } }).summary?.writers ?? []) as {
    insn: { va: string; at: string | null; text: string };
    access: string;
    count: number;
    threads: number[];
    struct_bases: { base: string; disp: string }[];
    values: { first: unknown; last: unknown; distinct: number };
  }[];
const recordingOf = (r: Readonly<Record<string, unknown>>): string =>
  (r["instrument"] as { recording_id: string }).recording_id;
/** Fields of a watch hit row read back through query_events (S6 §5.4; the kind's field dictionary). */
const HIT_FIELDS = ["access", "insn_va", "insn_confidence", "struct_base", "disp", "value", "value_when"] as const;
type HitRow = Readonly<Record<(typeof HIT_FIELDS)[number], unknown>>;
/**
 * Write-hit rows of a watch recording (newest first by default). query_events pages are columnar (`columns` + one
 * cell array per row) and project at most 16 columns, so the fields are named explicitly; marker rows (no `access`;
 * `ne` would match their null) are filtered out by `access eq "w"`. At least one row is required, so the per-row
 * assertions cannot pass vacuously.
 */
const hitRowsOf = async (recording: string, limit: number, order: "asc" | "desc" = "desc"): Promise<HitRow[]> => {
  const page = out(
    await bea.call("query_events", {
      recording_id: recording,
      view: "rows",
      fields: [...HIT_FIELDS],
      where: [{ field: "access", op: "eq", value: "w" }],
      order,
      limit,
    }),
  );
  const columns = page["columns"] as string[];
  expect(columns).toEqual(["seq", ...HIT_FIELDS]);
  const rows = (page["rows"] as unknown[][]).map(
    (cells) => Object.fromEntries(columns.map((c, i) => [c, cells[i]])) as HitRow,
  );
  expect(rows.length, JSON.stringify(page).slice(0, 1500)).toBeGreaterThan(0);
  return rows;
};

const drSpeedWriter = async (): Promise<void> => {
  const t = await spawnGame([]);
  const watch = out(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: hex(t.car + 8n),
      size: 4,
      access: "write",
      view: "f32",
      duration_ms: 1500,
      wait_ms: 3000,
    }),
  );
  expect(watch["method"]).toBe("debug_register");
  const writers = writersOf(watch);
  expect(
    writers.map((w) => w.insn.va),
    JSON.stringify(watch).slice(0, 3000),
  ).toEqual([hex(t.base + BigInt(speedWriterRva()))]);
  expect(writers[0]?.struct_bases[0]).toEqual({ base: hex(t.car), disp: "0x8", count: expect.any(Number) as number });
  // the recorded rows themselves: the writer, its struct base and the exact instruction (DR traps after the store)
  for (const e of await hitRowsOf(recordingOf(watch), 5))
    expect(e).toEqual({
      seq: expect.any(Number) as number,
      access: "w",
      insn_va: hex(t.base + BigInt(speedWriterRva())),
      insn_confidence: "exact",
      struct_base: hex(t.car),
      disp: "0x8",
      value: expect.any(Number) as number, // f32 view: the speed just stored
      value_when: "after",
    });
  await closeGame(t);
};

const readWriteAndPoll = async (): Promise<void> => {
  const t = await spawnGame([]);
  const rw = out(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: hex(t.car + 8n),
      size: 4,
      access: "read_write",
      duration_ms: 1500,
      wait_ms: 3000,
    }),
  );
  // the speed store on the main thread, and telemetry_sample's read of car->speed on the telemetry thread
  const accessors = writersOf(rw);
  const detail = JSON.stringify(accessors).slice(0, 2000);
  const writer = accessors.find((w) => w.access === "w" && w.insn.va === hex(t.base + BigInt(speedWriterRva())));
  const reader = accessors.find(
    (w) => w.access === "r" && w.insn.va === hex(t.base + BigInt(speedReaderRva("telemetry_sample"))),
  );
  expect(writer, detail).toBeDefined();
  expect(reader, detail).toBeDefined();
  expect(reader?.threads.filter((tid) => !(writer?.threads ?? []).includes(tid)).length, detail).toBeGreaterThan(0);
  // the handler reads the watched bytes without tripping its own read/write slot: values are present on every
  // accessor, and the slot keeps trapping (a frame's store and reads, the telemetry thread every 50 ms)
  for (const a of [writer, reader]) {
    expect(a?.values.first, detail).toMatch(/^[0-9a-f]{8}$/u);
    expect(a?.values.last, detail).toMatch(/^[0-9a-f]{8}$/u);
    expect(a?.count, detail).toBeGreaterThanOrEqual(10);
  }
  const poll = out(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: hex(t.car),
      size: 0x80,
      method: "poll",
      view: "f32",
      interval_ms: 16,
      duration_ms: 1500,
      wait_ms: 3000,
    }),
  );
  const fields = ((poll["instrument"] as { summary: { fields: { offset: string }[] } }).summary.fields ?? []).map(
    (f) => f.offset,
  );
  expect(fields).toEqual(expect.arrayContaining(["0x8", "0x14"]));
  expect(fields).not.toContain("0x48");
  await closeGame(t);
};

const rpmTwoThreads = async (): Promise<void> => {
  const t = await spawnGame(["--engine-start-ms", "1000"]);
  const watch = out(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: hex(t.car + 0x14n),
      size: 4,
      access: "write",
      duration_ms: 2500,
      wait_ms: 5000,
    }),
  );
  // physics_step (main thread) and engine_update (the engine thread, created after arming) write rpm; which of
  // physics_step's two compiled stores runs depends on the branch taken, so the writers are matched by function
  const rpm = game.expectations["rpmWriters"] as { fn: string; rva: number }[];
  const seen = new Set(writersOf(watch).map((w) => Number(BigInt(w.insn.va) - t.base)));
  const fns = [...new Set(rpm.filter((w) => seen.has(w.rva)).map((w) => w.fn))].sort();
  expect(fns, JSON.stringify(writersOf(watch)).slice(0, 2000)).toEqual(["engine_update", "physics_step"]);
  expect(new Set(writersOf(watch).flatMap((w) => w.threads)).size).toBeGreaterThanOrEqual(2);
  await closeGame(t);
};

const pageGuardThenSlots = async (): Promise<void> => {
  const t = await spawnGame(["--no-threads"]);
  const pg = out(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: hex(t.car + 8n),
      size: 4,
      method: "page_guard",
      duration_ms: 1000,
      wait_ms: 3000,
    }),
  );
  expect(writersOf(pg).map((w) => w.insn.va)).toEqual([hex(t.base + BigInt(speedWriterRva()))]);
  for (const e of await hitRowsOf(recordingOf(pg), 3))
    expect(e).toMatchObject({ access: "w", insn_va: hex(t.base + BigInt(speedWriterRva())), value_when: "before" });
  // §8.4 edit: no missed hits at the frame rate (S4 engine, not a 43 hits/s ceiling). physics_step bumps car->frame
  // (+0x38, `add dword [rax+0x38],1`, a read-modify-write) exactly once per frame and nothing else touches it, so the
  // values seen before each write must be consecutive frame numbers.
  const frames = out(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: hex(t.car + 0x38n),
      size: 4,
      access: "write",
      method: "page_guard",
      view: "u32",
      duration_ms: 1000,
      wait_ms: 3000,
    }),
  );
  const counter = (await hitRowsOf(recordingOf(frames), 500, "asc")).map((e) => e.value as number);
  expect(counter.length, JSON.stringify(frames).slice(0, 1500)).toBeGreaterThanOrEqual(20);
  const gaps = counter.flatMap((v, i) =>
    i > 0 && v !== (counter[i - 1] ?? 0) + 1 ? [`${String(counter[i - 1])}→${String(v)}`] : [],
  );
  expect(gaps, `missed frames between consecutive hits (${String(counter.length)} hits)`).toEqual([]);
  const ids: string[] = [];
  for (const off of [0x0n, 0x4n, 0x8n, 0xcn]) {
    const dr = out(
      await bea.call("watch_memory", {
        session_id: t.session,
        address: hex(t.car + off),
        size: 4,
        method: "debug_register",
        duration_ms: 60_000,
      }),
    );
    ids.push(recordingOf(dr));
  }
  const fifth = parseToolError(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: hex(t.car + 0x10n),
      size: 4,
      method: "debug_register",
    }),
  );
  expect(fifth.code).toBe("instrumentation_failed");
  const auto = out(
    await bea.call("watch_memory", { session_id: t.session, address: hex(t.car + 0x10n), size: 4, duration_ms: 500 }),
  );
  expect(auto["method"]).toBe("page_guard");
  // moved row (§8.4): stop_instrumentation of a DR watch disarms it (the agent verifies DR7 on every thread)
  const stopped = out(await bea.call("stop_instrumentation", { session_id: t.session, ids }));
  for (const s of stopped["stopped"] as { status: string }[]) expect(s.status).toBe("reverted");
  await closeGame(t);
};

/**
 * CT-I4 at tool level: a page_guard watch on game_sim's hot page (g_hot_sink, 20,000 read-modify-writes per frame)
 * trips the valve long before its 10 s duration; the result explains which criterion tripped, and the target keeps
 * running on an unguarded page.
 */
const hotPageValve = async (): Promise<void> => {
  const t = await spawnGame(["--hot", "20000"]);
  const watch = out(
    await bea.call("watch_memory", {
      session_id: t.session,
      address: "game_sim.exe!g_hot_sink",
      size: 8,
      method: "page_guard",
      duration_ms: 10_000,
      wait_ms: 12_000,
    }),
  );
  const detail = JSON.stringify(watch).slice(0, 2500);
  const instrument = watch["instrument"] as {
    state: string;
    end_reason: string | null;
    summary?: { rate_limited?: { cause: string; limit_per_sec: number; peak_per_sec: number; busy_pct: number } };
  };
  expect(instrument.state, detail).toBe("finished");
  expect(instrument.end_reason, detail).toBe("rate-limit"); // the agent's valve end (CT-I4, D-INT-20)
  const trip = instrument.summary?.rate_limited;
  expect(trip, detail).toBeTruthy();
  if (trip?.cause === "busy") {
    expect(trip.busy_pct, detail).toBeGreaterThan(50);
    expect(watch["limitations"]).toContain(LIMITATIONS.WATCH_RATE_LIMIT_BUSY(trip.busy_pct));
  } else {
    expect(trip?.peak_per_sec, detail).toBeGreaterThan(20_000);
    expect(watch["limitations"]).toContain(LIMITATIONS.WATCH_RATE_LIMIT(20_000));
  }
  expect(watch["coverage"]).toMatchObject({ status: "partial", reasons: expect.arrayContaining(["watch_rate_limit"]) });
  const f0 = await frameOf(t);
  await vi.waitFor(async () => expect(await frameOf(t)).toBeGreaterThan(f0 + 10), { timeout: 5000, interval: 25 });
  await closeGame(t);
};

/** The attach target stays running past the session (the ledger checks it in afterAll, then ends it). */
const autoOnAttached = async (): Promise<void> => {
  const child: ChildProcess = spawn(game.path, [], { stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
  ledger.recordAttachTarget(child.pid ?? 0, null, "attach game_sim");
  const attached = out(await bea.call("attach_process", { pid: child.pid }));
  const session = String(attached["session_id"]);
  const car = await carOf(session);
  const watch = out(
    await bea.call("watch_memory", {
      session_id: session,
      address: hex(car + 8n),
      size: 4,
      duration_ms: 500,
      wait_ms: 2000,
    }),
  );
  expect(watch["method"]).toBe("debug_register");
  out(await bea.call("close_session", { session_id: session }));
  expect(child.exitCode).toBeNull(); // attached targets survive
};

/**
 * WP9 card at server level: a hot debug-register watch on an attached game_sim (--hot 2000: every one of ~2,000
 * writes per frame to g_hot_sink traps), then the SERVER is hard-killed (TerminateProcess: no shutdown handler runs).
 * Frida unloads the script, dispose disarms the slot and the leaked safety net absorbs stray traps: the target keeps
 * running. The raw-Frida lab (agentEngines.test.ts) shows the unprotected control dying.
 */
const hardKillWithHotDr = async (): Promise<void> => {
  const child: ChildProcess = spawn(game.path, ["--hot", "2000"], {
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
  ledger.recordAttachTarget(child.pid ?? 0, null, "attach game_sim --hot 2000");
  let output = "";
  child.stdout?.on("data", (c: Buffer) => (output += c.toString("utf8")));
  const frames = (): number => (output.match(/FRAME /gu) ?? []).length;
  await vi.waitFor(() => expect(output).toContain("READY"), { timeout: 10_000, interval: 25 });
  const session = String(out(await bea.call("attach_process", { pid: child.pid }))["session_id"]);
  const watch = out(
    await bea.call("watch_memory", {
      session_id: session,
      address: "game_sim.exe!g_hot_sink",
      size: 8,
      duration_ms: 60_000,
    }),
  );
  expect(watch["method"]).toBe("debug_register");
  await vi.waitFor(
    async () => {
      const page = out(
        await bea.call("query_events", {
          recording_id: recordingOf(watch),
          view: "rows",
          fields: ["access"],
          limit: 1,
        }),
      );
      expect((page["page"] as { total: number }).total).toBeGreaterThan(2000);
    },
    { timeout: 10_000, interval: 100 },
  );
  const before = frames();
  process.kill(bea.pid ?? 0, "SIGKILL");
  await vi.waitFor(() => expect(frames(), `target exit ${String(child.exitCode)}`).toBeGreaterThan(before + 2), {
    timeout: 15_000,
    interval: 100,
  });
  expect(child.exitCode).toBeNull();
};

const onCallExports = async (): Promise<void> => {
  const t = await spawnGame([]);
  const pdata = game.pe.pdata["physics_step"] ?? { rva: 0, size: 0 };
  const trace = out(
    await bea.call("trace_execution", {
      session_id: t.session,
      on_call: "game_sim.exe!physics_step",
      invocations: 1,
      wait_ms: 5000,
    }),
  );
  const recording = recordingOf(trace);
  expect((trace["instrument"] as { state: string }).state).toBe("finished");
  expect(trace["limitations"]).toEqual(expect.arrayContaining([expect.stringContaining("entry block was added")]));
  const drcov = out(await bea.call("export_coverage", { recording_id: recording }));
  const parsed = parseDrcov(new Uint8Array(await readFile(String(drcov["path"]))));
  expect(parsed.modules.some((m) => m.path.toLowerCase().endsWith("game_sim.exe"))).toBe(true);
  expect(parsed.blocks.length).toBeGreaterThanOrEqual(2);
  for (const b of parsed.blocks) expect(b.start >= pdata.rva && b.start < pdata.rva + pdata.size).toBe(true);
  expect(parsed.blocks.some((b) => b.start === pdata.rva)).toBe(true);
  const modoff = out(await bea.call("export_coverage", { recording_id: recording, format: "modoff" }));
  expect(await readFile(String(modoff["path"]), "utf8")).toContain(`game_sim.exe+0x${pdata.rva.toString(16)}`);
  expect(parseToolError(await bea.call("export_coverage", { recording_id: recording })).code).toBe(
    "file_operation_failed",
  );
  await closeGame(t);
};

/**
 * export_coverage of call evidence (S6 §10.8 "trace, call and emu evidence": emu evidence moved to WP14, call_function
 * is a wave-4 tool). One physics_step call on a scratch copy of the live car with coverage:true; the call's evidence
 * exports as drcov whose game_sim.exe blocks lie in physics_step's .pdata range (it calls nothing) and include its
 * entry, and as modoff.
 */
const callEvidenceExport = async (): Promise<void> => {
  const t = await spawnGame(["--no-threads", "--speed", "20", "--throttle", "0.125"]);
  const pdata = game.pe.pdata["physics_step"] ?? { rva: 0, size: 0 };
  const call = out(
    await bea.call("call_function", {
      session_id: t.session,
      address: "game_sim.exe!physics_step",
      signature: { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f32" }], returns: "f32" },
      buffers: [{ name: "car", size: 128, init_from: hex(t.car) }],
      args: [null, 1 / 60],
      coverage: true,
    }),
  );
  const detail = JSON.stringify(call).slice(0, 2500);
  expect((call["block_coverage"] as { blocks: number } | null)?.blocks, detail).toBeGreaterThanOrEqual(2);
  const evidence = String(call["evidence_id"]);
  const drcov = out(await bea.call("export_coverage", { evidence_id: evidence }));
  const parsed = parseDrcov(new Uint8Array(await readFile(String(drcov["path"]))));
  const main = parsed.modules.find((m) => m.path.toLowerCase().endsWith("game_sim.exe"));
  expect(main, parsed.modules.map((m) => m.path).join(", ")).toBeDefined();
  const blocks = parsed.blocks.filter((b) => b.moduleId === main?.id);
  expect(blocks.length, JSON.stringify(parsed.blocks).slice(0, 1500)).toBeGreaterThanOrEqual(2);
  for (const b of blocks)
    expect(b.start >= pdata.rva && b.start < pdata.rva + pdata.size, `0x${b.start.toString(16)}`).toBe(true);
  expect(blocks.some((b) => b.start === pdata.rva)).toBe(true);
  const modoff = out(await bea.call("export_coverage", { evidence_id: evidence, format: "modoff" }));
  expect(await readFile(String(modoff["path"]), "utf8")).toContain(`game_sim.exe+0x${pdata.rva.toString(16)}`);
  await closeGame(t);
};

const traceMain = (session: string, tid: number, mode: string, duration_ms: number) =>
  bea.call("trace_execution", { session_id: session, thread_ids: [tid], mode, duration_ms, wait_ms: 3000 });

/** A block's hits in a block_counts recording (summed: the agent may flush one block in several deltas). */
const blockHits = async (recording: string, va: bigint): Promise<number> => {
  const page = out(
    await bea.call("query_events", {
      recording_id: recording,
      view: "rows",
      fields: ["va", "hits"],
      where: [{ field: "va", op: "eq", value: hex(va) }],
      limit: 500,
    }),
  );
  expect(page["columns"]).toEqual(["seq", "va", "hits"]);
  return (page["rows"] as unknown[][]).reduce((n, r) => n + Number(r[2]), 0);
};

const traceModesOnMain = async (): Promise<void> => {
  const t = await spawnGame(["--hot", "1000"]);
  const threads = out(await bea.call("list_threads", { session_id: t.session }));
  const mainTid = (threads["rows"] as { tid: number; main: boolean }[]).find((row) => row.main)?.tid ?? 0;
  // block_counts: physics_step's entry block runs once per frame. The frames inside the trace window are counted by
  // the other once-per-frame functions of the main loop (mix_args, car_energy: one block each) in the same trace,
  // and bounded above by car->frame read before and after it.
  const frame0 = await frameOf(t);
  const counts = out(await traceMain(t.session, mainTid, "block_counts", 1000));
  const frame1 = await frameOf(t);
  expect((counts["instrument"] as { dropped: number }).dropped).toBe(0);
  const entry = await blockHits(recordingOf(counts), exportVa(t, "physics_step"));
  const perFrame = [
    await blockHits(recordingOf(counts), exportVa(t, "mix_args")),
    await blockHits(recordingOf(counts), exportVa(t, "car_energy")),
  ];
  const detail = `physics_step ${String(entry)}, mix_args/car_energy ${perFrame.join("/")}, frames ${String(frame0)}→${String(frame1)}`;
  expect(entry, detail).toBeGreaterThanOrEqual(10);
  expect(entry, detail).toBeLessThanOrEqual(frame1 - frame0);
  for (const frames of perFrame) expect(Math.abs(entry - frames), detail).toBeLessThanOrEqual(2);
  // calls: an edge from main's call site (game_sim.exe, outside physics_step) to physics_step's entry
  const calls = out(await traceMain(t.session, mainTid, "calls", 500));
  const edges = (calls["instrument"] as { summary: { calls?: { from: string; to: string | null }[] } }).summary.calls;
  const pdata = game.pe.pdata["physics_step"] ?? { rva: 0, size: 0 };
  const rvaIn = (at: string): number => Number.parseInt(/^game_sim\.exe\+0x([0-9a-f]+)$/iu.exec(at)?.[1] ?? "-1", 16);
  const toPhysics = (edges ?? []).filter((c) => c.to !== null && rvaIn(c.to) === pdata.rva);
  expect(toPhysics.length, JSON.stringify(edges).slice(0, 2000)).toBeGreaterThan(0);
  for (const c of toPhysics) {
    expect(rvaIn(c.from), c.from).toBeGreaterThan(0);
    expect(rvaIn(c.from) >= pdata.rva && rvaIn(c.from) < pdata.rva + pdata.size, c.from).toBe(false);
  }
  const coverage = out(await traceMain(t.session, mainTid, "coverage", 1000));
  expect((coverage["instrument"] as { dropped: number }).dropped).toBe(0);
  await closeGame(t);
};

describe.skipIf(SKIP !== false)(`watch_memory / trace_execution / export_coverage on game_sim${skipNote(SKIP)}`, () => {
  beforeAll(async () => {
    const manifest = await loadFixtures();
    const artifact = fixtureArtifact(manifest, "game_sim");
    if (artifact === null) throw new Error("game_sim fixture unavailable");
    game = artifact;
    ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
  }, 120_000);

  // a server per test: at most 3 spawned targets per server (S6 §10.7)
  beforeEach(async () => {
    bea = await connectBea({ ledger });
  }, 120_000);
  afterEach(async () => {
    await bea.close();
  });

  afterAll(async () => {
    try {
      await ledger.assertClean();
    } finally {
      await ledger.killAttachTargets();
    }
  });

  it(
    "debug_register write on car+8: exactly the manifest speed writer, struct_base = car, insn_confidence exact",
    drSpeedWriter,
  );
  it(
    "read_write also reports telemetry_sample's reader on another thread; poll finds the changing fields",
    readWriteAndPoll,
  );
  it("rpm writers on two threads, the engine thread created after arming (new-thread arming)", rpmTwoThreads);
  it(
    "page_guard reports the same writer with value_when before; a 5th explicit DR fails and auto falls back",
    pageGuardThenSlots,
  );
  it("a page_guard watch on a hot page ends with the rate valve and the target keeps running (CT-I4)", hotPageValve);
  it("auto picks a debug register on an attached target (CT-I4)", autoOnAttached);
  it(
    "a hot debug-register watch on an attached target survives a hard kill of the server (dispose + safety net)",
    hardKillWithHotDr,
    60_000,
  );
  it(
    "trace_execution on_call: blocks inside physics_step's .pdata range plus the entry block; drcov and modoff export",
    onCallExports,
  );
  it(
    "block_counts on the main thread ≈ frames, calls has main → physics_step, coverage under --hot drops nothing",
    traceModesOnMain,
  );
  it(
    "export_coverage of call_function coverage evidence: drcov inside physics_step with its entry, and modoff",
    callEvidenceExport,
  );
});
