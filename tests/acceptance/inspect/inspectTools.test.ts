import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
  type FixtureManifest,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * S6 §10.8 acceptance rows of the five inspect tools (WP6), against the BUILT server over stdio (BEA_DIST_DIR
 * snapshot). Wave rule (DESIGN §8.4): only earlier-wave tools (spawn_process, resume_process, close_session) plus the
 * tools under test; readiness is polled with read_memory (vi.waitFor at 25 ms), never slept on. Expectations come
 * from the fixture manifest; assertions are pointer-free (RVAs, module-relative text). The hooked-disassembly row
 * moved to WP7.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();
type Obj = Readonly<Record<string, unknown>>;

const normalizeInsn = (text: string): string =>
  text
    .toLowerCase()
    .replace(/0x([0-9a-f]+)/gu, (_m, hex: string) => String(Number.parseInt(hex, 16)))
    .replace(/\s+/gu, "");

interface Server {
  readonly game: () => FixtureArtifact;
  readonly bea: () => BeaConnection;
  readonly ok: (name: string, args: Obj) => Promise<Obj>;
  /** spawn + resume game_sim, then wait until g_world points at a World (the fixture's READY state). */
  readonly start: (argv: readonly string[]) => Promise<string>;
  readonly exportRva: (name: string) => number;
}

/** One built server per describe (≤ 3 spawned targets each, S6 §10.7), sessions closed and the PID ledger audited. */
const useServer = (): Server => {
  let game: FixtureArtifact | undefined;
  let bea: BeaConnection | undefined;
  let ledger: OwnedPidLedger | undefined;
  const sessions: string[] = [];
  const conn = (): BeaConnection => {
    if (bea === undefined) throw new Error("server not started");
    return bea;
  };
  const art = (): FixtureArtifact => {
    if (game === undefined) throw new Error("fixtures not loaded");
    return game;
  };
  const ok = async (name: string, args: Obj): Promise<Obj> => expectToolSuccess(await conn().call(name, args));

  beforeAll(async () => {
    const loaded: FixtureManifest | { unavailable: string } = await loadFixtures();
    if ("unavailable" in loaded) throw new Error(loaded.unavailable);
    game = fixtureArtifact(loaded, "game_sim") ?? undefined;
    ledger = new OwnedPidLedger(fixtureArtifact(loaded, "pidcheck")?.path ?? null);
    bea = await connectBea({ ledger });
  }, 60_000);

  afterAll(async () => {
    for (const id of sessions) await bea?.call("close_session", { session_id: id }).catch(() => undefined);
    await bea?.close();
    const audit = await ledger?.audit();
    expect(audit?.leaks ?? []).toEqual([]);
  }, 60_000);

  return {
    game: art,
    bea: conn,
    ok,
    exportRva: (name) => {
      const rva = art().pe.exportRvas[name];
      if (rva === undefined) throw new Error(`manifest lacks export ${name}`);
      return rva;
    },
    start: async (argv) => {
      const spawned = await ok("spawn_process", { program: art().path, args: [...argv] });
      const id = spawned["session_id"] as string;
      sessions.push(id);
      await ok("resume_process", { session_id: id });
      await vi.waitFor(
        async () => {
          const read = await ok("read_memory", {
            session_id: id,
            address: "game_sim.exe!g_world",
            size: 8,
            view: "ptr",
          });
          expect((read["values"] as string[])[0]).not.toBe("0x0");
        },
        { timeout: 15_000, interval: 25 },
      );
      return id;
    },
  };
};

describe.skipIf(skip !== false)(`inspect listings on game_sim${skipNote(skip)}`, () => {
  const { ok, start, game, exportRva } = useServer();

  it("list_modules: main row, file sha256, and a later mathlib.dll load with its preferred base", async () => {
    const id = await start(["--load-mathlib-at", "120", "--hz", "60"]);
    const first = await ok("list_modules", { session_id: id, filter: "game_sim", hash: true });
    const rows = first["rows"] as Obj[];
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      name: "game_sim.exe",
      main: true,
      preferred_base: `0x${BigInt(game().pe.imageBase).toString(16)}`,
      sha256: game().artifactSha256,
      size: game().pe.sizeOfImage,
    });
    expect(first["module_map_id"]).toMatch(/^mm_[a-f0-9]{64}$/u);
    const epoch = first["epoch"] as number;
    await vi.waitFor(
      async () => {
        const later = await ok("list_modules", { session_id: id, filter: "mathlib" });
        expect(later["rows"]).toMatchObject([{ name: "mathlib.dll", preferred_base: "0x180000000", main: false }]);
        expect(later["epoch"] as number).toBeGreaterThan(epoch);
      },
      { timeout: 15_000, interval: 25 },
    );
  });

  it("list_memory_ranges: image rows, the car in a private rw- range, totals equal the paging sum", async () => {
    const id = await start(["--hz", "60"]);
    const images = await ok("list_memory_ranges", { session_id: id, kind: "image", module: "game_sim.exe" });
    expect((images["rows"] as Obj[]).length).toBeGreaterThan(0);
    for (const row of images["rows"] as Obj[]) expect(row).toMatchObject({ module: "game_sim.exe", kind: "image" });

    const car = await ok("read_memory", {
      session_id: id,
      address: "game_sim.exe!g_world",
      deref: [8],
      size: 8,
      view: "ptr",
    });
    const carVa = BigInt((car["values"] as string[])[0] ?? "0x0");
    let offset = 0;
    let sum = 0;
    let count = 0;
    let total = -1;
    let totalBytes = -1;
    let carRow: Obj | undefined;
    for (;;) {
      const page = await ok("list_memory_ranges", { session_id: id, protection: "rw-", limit: 100, offset });
      totalBytes = page["total_bytes"] as number;
      const p = page["page"] as { total: number; next_offset: number | null };
      total = p.total;
      for (const row of page["rows"] as Obj[]) {
        sum += row["size"] as number;
        count += 1;
        const base = BigInt(row["base"] as string);
        if (carVa >= base && carVa < base + BigInt(row["size"] as number)) carRow = row;
      }
      if (p.next_offset === null) break;
      offset = p.next_offset;
    }
    expect(count).toBe(total);
    expect(sum).toBe(totalBytes);
    expect(carRow).toMatchObject({ kind: "private", prot: "rw-", module: null });
  });

  it("list_threads: the worker threads, one main thread, GPRs, and the late engine thread at the starter's target", async () => {
    const id = await start(["--hz", "60", "--engine-start-ms", "1500"]);
    const entryAt = (row: Obj): string => String((row["entry"] as Obj | null)?.["at"] ?? "");
    const inGame = (rows: readonly Obj[]): Obj[] => rows.filter((r) => entryAt(r).startsWith("game_sim.exe+"));
    /** Every `ref` in the disassembly of the .pdata function that contains `at`. */
    const refsOf = async (at: string): Promise<string[]> => {
      const out = await ok("disassemble", { session_id: id, address: at, function: true });
      return (out["rows"] as { ref: string | null }[]).flatMap((r) => (r.ref === null ? [] : [r.ref]));
    };

    // before the engine starts: main (CRT entry) + input + telemetry + engine_starter, exactly one main, GPRs
    const before = inGame((await ok("list_threads", { session_id: id, registers: true }))["rows"] as Obj[]);
    expect(before.length).toBeGreaterThanOrEqual(4);
    expect(before.filter((r) => r["main"] === true)).toHaveLength(1);
    for (const row of before)
      expect(row["registers"]).toMatchObject({
        rip: expect.stringMatching(/^0x/u),
        rsp: expect.stringMatching(/^0x/u),
      });

    // the engine thread is the one whose entry routine calls engine_update; it appears only after the start delay
    const engineUpdate = `game_sim.exe+0x${exportRva("engine_update").toString(16)} `;
    const callsEngineUpdate = async (row: Obj): Promise<boolean> =>
      (await refsOf(entryAt(row))).some((ref) => ref.startsWith(engineUpdate));
    for (const row of before) expect(await callsEngineUpdate(row), entryAt(row)).toBe(false);
    let engine: Obj | undefined;
    await vi.waitFor(
      async () => {
        const rows = inGame((await ok("list_threads", { session_id: id }))["rows"] as Obj[]);
        const fresh = rows.filter((r) => !before.some((b) => b["tid"] === r["tid"]));
        for (const row of fresh) if (await callsEngineUpdate(row)) engine = row;
        expect(engine).toBeDefined();
      },
      { timeout: 15_000, interval: 25 },
    );
    // entry func = the starter's target: some pre-engine thread's routine references the engine entry address
    if (engine === undefined) throw new Error("engine thread not found");
    const engineEntry = engine["entry"] as Obj;
    const target = `${entryAt(engine)} `;
    const starters: string[] = [];
    for (const row of before)
      if ((await refsOf(entryAt(row))).some((ref) => ref.startsWith(target))) starters.push(entryAt(row));
    expect(starters).toHaveLength(1);
    expect(engineEntry["func"]).toEqual(expect.stringMatching(/^game_sim\.exe/u));
  });
});

describe.skipIf(skip !== false)(`inspect reads and disassembly on game_sim${skipNote(skip)}`, () => {
  const { ok, start, game, bea, exportRva } = useServer();

  it("read_memory: the marker, the [[g_world]+8]+8 speed chain, 0x10 and a read into an unmapped page", async () => {
    const eq = game().expectations["equilibrium"] as { args: string[]; speed: number };
    const markers = game().expectations["markers"] as { ascii: string };
    const chainSpec = game().expectations["chain"] as { root: string; offsets: number[] };
    const id = await start([...eq.args, "--hz", "60"]);
    const marker = await ok("read_memory", {
      session_id: id,
      address: "game_sim.exe!g_marker",
      size: 64,
      view: "utf8",
    });
    expect(marker["text"]).toBe(markers.ascii);
    expect(marker["address"]).toMatchObject({ module: "game_sim.exe", rva: `0x${exportRva("g_marker").toString(16)}` });

    const speed = await ok("read_memory", {
      session_id: id,
      address: `game_sim.exe!${chainSpec.root}`,
      deref: chainSpec.offsets,
      size: 4,
      view: "f32",
    });
    expect(speed["values"]).toEqual([eq.speed]);
    const chain = speed["chain"] as { address: string; value: string }[];
    expect(chain).toHaveLength(2);
    const base = BigInt((marker["address"] as Obj)["va"] as string) - BigInt(exportRva("g_marker"));
    expect(BigInt(chain[0]?.address ?? "0x0") - base).toBe(BigInt(exportRva(chainSpec.root)));
    expect(BigInt(chain[1]?.address ?? "0x0")).toBe(BigInt(chain[0]?.value ?? "0x0") + 8n);
    expect(BigInt((speed["address"] as Obj)["va"] as string)).toBe(BigInt(chain[1]?.value ?? "0x0") + 8n);
    // the chain's pointers are the READY world and car (g_world, then world->cars[0] at +8), read independently
    const world = await ok("read_memory", { session_id: id, address: "game_sim.exe!g_world", size: 8, view: "ptr" });
    const car = await ok("read_memory", {
      session_id: id,
      address: "game_sim.exe!g_world",
      deref: [8],
      size: 8,
      view: "ptr",
    });
    expect(BigInt(chain[0]?.value ?? "0x1")).toBe(BigInt((world["values"] as string[])[0] ?? "0x0"));
    expect(BigInt(chain[1]?.value ?? "0x1")).toBe(BigInt((car["values"] as string[])[0] ?? "0x0"));

    expect(parseToolError(await bea().call("read_memory", { session_id: id, address: "0x10", size: 4 })).code).toBe(
      "memory_access_failed",
    );

    // a readable range followed by no committed range at all (protection "---" lists every committed range, so the
    // next page is reserved or free, i.e. unmapped): read across that end
    const rows: { base: string; size: number; prot: string }[] = [];
    for (let offset: number | null = 0; offset !== null;) {
      const page = await ok("list_memory_ranges", { session_id: id, protection: "---", limit: 1000, offset });
      rows.push(...(page["rows"] as { base: string; size: number; prot: string }[]));
      offset = (page["page"] as { next_offset: number | null }).next_offset;
    }
    const starts = new Set(rows.map((r) => BigInt(r.base)));
    const edge = rows.find((r) => r.prot.startsWith("r") && !starts.has(BigInt(r.base) + BigInt(r.size)));
    if (edge === undefined) throw new Error("no range edge found");
    const across = await ok("read_memory", {
      session_id: id,
      address: `0x${(BigInt(edge.base) + BigInt(edge.size) - 16n).toString(16)}`,
      size: 64,
    });
    expect(across).toMatchObject({ requested: 64, returned: 16, complete: false, coverage: { status: "partial" } });
  });

  it("disassemble: function:true includes the manifest speed writer, RIP-relative refs are resolved", async () => {
    const id = await start(["--hz", "60"]);
    const physics = game().pe.pdata["physics_step"];
    if (physics === undefined) throw new Error("manifest lacks physics_step .pdata");
    const out = await ok("disassemble", { session_id: id, address: "game_sim.exe!physics_step", function: true });
    expect(out).toMatchObject({
      module: "game_sim.exe",
      func: { size: physics.size },
      hooked_bytes_restored: false,
      coverage: { status: "complete" },
    });
    const rows = out["rows"] as { rva: string | null; t: string; ref: string | null }[];
    expect(rows[0]?.rva).toBe(`0x${physics.rva.toString(16)}`);
    for (const w of game().expectations["speedWriters"] as { rva: number; text: string }[]) {
      const row = rows.find((r) => r.rva === `0x${w.rva.toString(16)}`);
      expect(normalizeInsn(row?.t ?? "")).toBe(normalizeInsn(w.text));
    }
    expect(rows.some((r) => /^game_sim\.exe\+0x[0-9a-f]+ game_sim\.exe:0x14[0-9a-f]+$/u.test(r.ref ?? ""))).toBe(true);
    const count = await ok("disassemble", { session_id: id, address: "game_sim.exe!physics_step", count: 3 });
    expect((count["rows"] as unknown[]).length).toBe(3);
  });
});
