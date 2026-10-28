import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * S6 §10.8 acceptance rows of scan_memory, scan_next and scan_results (WP10) against the BUILT server over stdio
 * (BEA_DIST_DIR snapshot), plus the rows moved here by DESIGN §8.4: `wait` on a scan id and `stop_instrumentation`
 * releasing a scan. Wave rule: besides the scan tools only earlier-wave session tools (spawn_process, resume_process,
 * session_status for READY/RAMP via output_tail — the in-test stand-in for LiveSession.waitFor —, close_session) and
 * the moved WP7 rows. Oracles: the READY line's car/world pointers and manifest RVAs; no sleeps.
 * The page-guard row ("a value on a page-guard-watched page is found and the watch keeps recording") chains WP9's
 * watch_memory (wave 5); it lives in the last describe and runs once WP9 has landed.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();
type Obj = Readonly<Record<string, unknown>>;
const EQUILIBRIUM = ["--no-threads", "--speed", "20", "--throttle", "0.125"] as const;

interface Started {
  readonly id: string;
  readonly car: bigint;
  readonly world: bigint;
}

describe.skipIf(skip !== false)(`scan tools on game_sim${skipNote(skip)}`, () => {
  let game: FixtureArtifact | undefined;
  let bea: BeaConnection | undefined;
  let ledger: OwnedPidLedger | undefined;
  const sessions: string[] = [];
  const conn = (): BeaConnection => {
    if (bea === undefined) throw new Error("server not started");
    return bea;
  };
  const ok = async (name: string, args: Obj): Promise<Obj> => expectToolSuccess(await conn().call(name, args));
  const rva = (name: string): bigint => BigInt(game?.pe.exportRvas[name] ?? Number.NaN);
  const tail = async (id: string): Promise<string> =>
    ((await ok("session_status", { session_id: id }))["output_tail"] as string | null) ?? "";
  const start = async (argv: readonly string[]): Promise<Started> => {
    const spawned = await ok("spawn_process", { program: game?.path, args: [...argv] });
    const id = spawned["session_id"] as string;
    sessions.push(id);
    await ok("resume_process", { session_id: id });
    const ready = await vi.waitFor(
      async () => {
        const m = /READY pid=\d+ world=(?:0x)?([0-9a-fA-F]+) car=(?:0x)?([0-9a-fA-F]+)/u.exec(await tail(id));
        if (m === null) throw new Error("no READY yet");
        return m;
      },
      { timeout: 15_000, interval: 25 },
    );
    return { id, world: BigInt(`0x${ready[1] ?? "0"}`), car: BigInt(`0x${ready[2] ?? "0"}`) };
  };
  const rows = async (scanId: string, extra: Obj = {}): Promise<Obj[]> =>
    (await ok("scan_results", { scan_id: scanId, limit: 500, ...extra }))["rows"] as Obj[];

  beforeAll(async () => {
    const loaded = await loadFixtures();
    if ("unavailable" in loaded) throw new Error(loaded.unavailable);
    game = fixtureArtifact(loaded, "game_sim") ?? undefined;
    ledger = new OwnedPidLedger(fixtureArtifact(loaded, "pidcheck")?.path ?? null);
    bea = await connectBea({ ledger });
  }, 60_000);
  afterAll(async () => {
    for (const id of sessions) await bea?.call("close_session", { session_id: id }).catch(() => undefined);
    await bea?.close();
    expect((await ledger?.audit())?.leaks ?? []).toEqual([]);
  }, 60_000);

  it("scan_memory on the f32 equilibrium: 20.0 hits include car+8; markers; static World pointer; errors", async () => {
    const t = await start(EQUILIBRIUM);
    const speed = await ok("scan_memory", { session_id: t.id, value_type: "f32", value: 20 });
    expect(speed).toMatchObject({ state: "done", truncated: false, predicate_type: "bea.scan.result" });
    expect(speed["evidence_id"]).toMatch(/^ev_/u);
    const speedRows = await rows(speed["scan_id"] as string);
    // values decode in the agent's QJS from their bits: 20, never "Infinity" (QJS has no infinities)
    expect(speedRows.find((r) => BigInt(r["va"] as string) === t.car + 8n)).toMatchObject({ value: 20, prev: 20 });

    const utf8 = await ok("scan_memory", {
      session_id: t.id,
      value_type: "utf8",
      value: "BEA_GAME_SIM_MARKER_v1",
      protection: "r--",
    });
    const utf8Rows = await rows(utf8["scan_id"] as string);
    expect(utf8Rows.map((r) => r["at"])).toContain(`game_sim.exe+0x${rva("g_marker").toString(16)}`);
    const utf16 = await ok("scan_memory", {
      session_id: t.id,
      value_type: "utf16",
      value: "BEA_GAME_SIM_WIDE_v1",
      protection: "r--",
    });
    expect((await rows(utf16["scan_id"] as string)).map((r) => r["at"])).toContain(
      `game_sim.exe+0x${rva("g_wmarker").toString(16)}`,
    );

    const statics = await ok("scan_memory", {
      session_id: t.id,
      value_type: "ptr",
      compare: "pointer_to",
      value: `0x${t.world.toString(16)}`,
      kind: "image",
    });
    const hit = await rows(statics["scan_id"] as string);
    expect(hit).toEqual([
      expect.objectContaining({
        at: `game_sim.exe+0x${rva("g_world").toString(16)}`,
        static: `game_sim.exe:0x${(BigInt(game?.pe.imageBase ?? "0") + rva("g_world")).toString(16)}`,
        value: `0x${t.world.toString(16)}`,
      }),
    ]);

    expect(
      parseToolError(await conn().call("scan_memory", { session_id: t.id, value_type: "bytes", value: "zz 00" })),
    ).toMatchObject({
      code: "invalid_request",
    });
    // 4 scans are open; 4 more fill the session's 8, the 9th is refused
    for (let i = 0; i < 4; i++)
      await ok("scan_memory", { session_id: t.id, value_type: "u32", value: 0x1234_5678, wait_ms: 0 });
    expect(
      parseToolError(await conn().call("scan_memory", { session_id: t.id, value_type: "u32", value: 1 })),
    ).toMatchObject({
      code: "resource_constraint",
    });
  }, 120_000);

  it("scan_next increased after RAMP keeps car+8 and the count drops; scan_results address forms and paging", async () => {
    const t = await start([...EQUILIBRIUM, "--ramp-at-ms", "1500"]);
    const first = await ok("scan_memory", { session_id: t.id, value_type: "f32", value: 20 });
    const scanId = first["scan_id"] as string;
    await vi.waitFor(
      async () => {
        if (!/RAMP frame=\d+[\s\S]*FRAME \d+/u.test(await tail(t.id))) throw new Error("no RAMP yet");
      },
      { timeout: 15_000, interval: 25 },
    );
    const up = await ok("scan_next", { scan_id: scanId, compare: "increased" });
    expect(up).toMatchObject({ state: "done", iteration: 1, previous_count: first["count"] });
    expect(up["count"] as number).toBeLessThan(first["count"] as number);
    const narrowed = await rows(scanId);
    const car = narrowed.find((r) => BigInt(r["va"] as string) === t.car + 8n);
    expect(car).toMatchObject({ at: null, static: null });
    expect(car?.["value"] as number).toBeGreaterThan(20);
    expect(car?.["prev"] as number).toBeGreaterThan(20);
    const page1 = await ok("scan_results", { scan_id: scanId, limit: 1 });
    expect(page1["page"]).toMatchObject({ offset: 0, limit: 1, total: up["count"] });
  }, 120_000);

  it("moved rows: wait on a scan id; stop_instrumentation releases a scan; a released scan is reference_not_found", async () => {
    const t = await start(EQUILIBRIUM);
    const running = await ok("scan_memory", { session_id: t.id, value_type: "f32", compare: "unknown", wait_ms: 0 });
    const scanId = running["scan_id"] as string;
    const waited = await ok("wait", { session_id: t.id, ids: [scanId], timeout_ms: 60_000 });
    expect(waited).toMatchObject({ satisfied: true, reason: "condition" });
    expect(waited["scans"]).toEqual([expect.objectContaining({ scan_id: scanId, state: "ready" })]);
    const status = await ok("session_status", { session_id: t.id });
    expect(status["scans"]).toEqual([expect.objectContaining({ scan_id: scanId, value_type: "f32", iteration: 0 })]);
    const stopped = await ok("stop_instrumentation", { session_id: t.id, ids: [scanId] });
    expect(stopped["stopped"]).toEqual([expect.objectContaining({ id: scanId, kind: "scan", status: "released" })]);
    expect(parseToolError(await conn().call("scan_results", { scan_id: scanId }))).toMatchObject({
      code: "reference_not_found",
    });
  }, 120_000);
});

describe.skipIf(skip !== false)(`scan + page-guard watch (needs WP9 watch_memory)${skipNote(skip)}`, () => {
  it("a value on a page-guard-watched page is found and the watch keeps recording", async () => {
    const loaded = await loadFixtures();
    if ("unavailable" in loaded) throw new Error(loaded.unavailable);
    const game = fixtureArtifact(loaded, "game_sim");
    const ledger = new OwnedPidLedger(fixtureArtifact(loaded, "pidcheck")?.path ?? null);
    const bea = await connectBea({ ledger });
    try {
      const ok = async (name: string, args: Obj): Promise<Obj> => expectToolSuccess(await bea.call(name, args));
      const spawned = await ok("spawn_process", { program: game?.path, args: [...EQUILIBRIUM] });
      const id = spawned["session_id"] as string;
      await ok("resume_process", { session_id: id });
      const ready = await vi.waitFor(
        async () => {
          const out = ((await ok("session_status", { session_id: id }))["output_tail"] as string | null) ?? "";
          const m = /car=(?:0x)?([0-9a-fA-F]+)/u.exec(out);
          if (m === null) throw new Error("no READY yet");
          return BigInt(`0x${m[1] ?? "0"}`);
        },
        { timeout: 15_000, interval: 25 },
      );
      const watch = await ok("watch_memory", {
        session_id: id,
        address: `0x${(ready + 8n).toString(16)}`,
        size: 4,
        access: "write",
        method: "page_guard",
        duration_ms: 20_000,
      });
      const recId = (watch["instrument"] as Obj)["recording_id"] as string;
      const scan = await ok("scan_memory", { session_id: id, value_type: "f32", value: 20 });
      const hits = (
        (await ok("scan_results", { scan_id: scan["scan_id"] as string, limit: 500 }))["rows"] as Obj[]
      ).map((r) => BigInt(r["va"] as string));
      expect(hits).toContain(ready + 8n);
      const before = ((await ok("query_events", { recording_id: recId }))["recording"] as Obj)["events"] as number;
      await vi.waitFor(
        async () => {
          const now = ((await ok("query_events", { recording_id: recId }))["recording"] as Obj)["events"] as number;
          if (now <= before) throw new Error("watch not recording");
        },
        { timeout: 10_000, interval: 50 },
      );
      await ok("close_session", { session_id: id });
    } finally {
      await bea.close();
      expect((await ledger.audit()).leaks).toEqual([]);
    }
  }, 120_000);
});

describe.skipIf(skip !== false)(`scan job slicing through the built server${skipNote(skip)}`, () => {
  it("a 1 GiB scan (--ballast-mb 1024) keeps agent RPCs (read_memory round trips) ≤ 50 ms while it runs", async () => {
    const loaded = await loadFixtures();
    if ("unavailable" in loaded) throw new Error(loaded.unavailable);
    const game = fixtureArtifact(loaded, "game_sim");
    const ledger = new OwnedPidLedger(fixtureArtifact(loaded, "pidcheck")?.path ?? null);
    const bea = await connectBea({ ledger });
    try {
      const ok = async (name: string, args: Obj): Promise<Obj> => expectToolSuccess(await bea.call(name, args));
      const spawned = await ok("spawn_process", {
        program: game?.path,
        args: [...EQUILIBRIUM, "--ballast-mb", "1024"],
      });
      const id = spawned["session_id"] as string;
      await ok("resume_process", { session_id: id });
      const car = await vi.waitFor(
        async () => {
          const out = ((await ok("session_status", { session_id: id }))["output_tail"] as string | null) ?? "";
          const m = /READY pid=\d+ world=(?:0x)?[0-9a-fA-F]+ car=(?:0x)?([0-9a-fA-F]+)/u.exec(out);
          if (m === null) throw new Error("no READY yet");
          return BigInt(`0x${m[1] ?? "0"}`);
        },
        { timeout: 30_000, interval: 25 },
      );
      const ping = { session_id: id, address: `0x${(car + 8n).toString(16)}`, size: 4, view: "f32" };
      await ok("read_memory", ping); // warm-up (first evidence write of the session)
      let done = false;
      const scan = ok("scan_memory", {
        session_id: id,
        value_type: "f32",
        compare: "between",
        value: 19.99,
        value2: 20.01,
        wait_ms: 60_000,
      }).finally(() => {
        done = true;
      });
      const rtts: number[] = [];
      while (!done) {
        const t0 = performance.now();
        await ok("read_memory", ping);
        rtts.push(performance.now() - t0);
      }
      const result = await scan;
      expect(result).toMatchObject({ state: "done", truncated: false });
      expect(result["scanned_bytes"] as number).toBeGreaterThan(1024 * 1024 * 1024);
      const hits = (
        (await ok("scan_results", { scan_id: result["scan_id"] as string, limit: 500 }))["rows"] as Obj[]
      ).map((r) => BigInt(r["va"] as string));
      expect(hits).toContain(car + 8n);
      rtts.sort((a, b) => a - b);
      if (process.env["BEA_TEST_VERBOSE"] === "1")
        process.stderr.write(
          `[scan latency via server] reads=${String(rtts.length)} p50=${String(rtts[rtts.length >> 1])} max=${String(rtts.at(-1))} scanned=${String(result["scanned_bytes"])} elapsed_ms=${String(result["elapsed_ms"])}\n`,
        );
      expect(rtts.length).toBeGreaterThan(5);
      expect(rtts.at(-1), `read_memory max of ${String(rtts.length)} round trips`).toBeLessThanOrEqual(50);
      await ok("close_session", { session_id: id });
    } finally {
      await bea.close();
      expect((await ledger.audit()).leaks).toEqual([]);
    }
  }, 180_000);
});
