import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { evidenceIdOf } from "../../../src/domain/evidence/authenticate.js";
import type { BeaEvidence } from "../../../src/domain/evidence/record.js";
import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  emuSkip,
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { parseDrcov } from "../../support/drcov.js";
import { realPython } from "../../support/emu/python.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { harnessLayout, minimalEnv } from "../../support/mcp/stdioSubprocess.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * The cross-wave rows the DESIGN §8.4 wave rule moved to WP18 (tests/acceptance/integration/), on the BUILT server
 * (BEA_DIST_DIR) with real Frida and the real emulator bridge:
 *   - WP1's chained evidence rows: get_evidence "after read and diff", record_unknown "after a diff" (the diff's
 *     auto-unknown listed), export_evidence "after the above" (dir + zip verified by import_evidence validate_only and
 *     by the separate `bea evidence verify` CLI), and A.4 #6 (a cancelled recording tool leaves findable evidence);
 *   - query_events paging of the host row streams: a live call-batch stream (WP11), and the instance-less emu-batch and
 *     diff streams (WP14; they cite their producer records since the integrator fix);
 *   - export_coverage of emulation evidence (WP9 → WP14 row);
 *   - the inspect tools on a real emulation session (WP6: list_modules, read_memory, disassemble);
 *   - call_function while BEA's own watch engines are armed on memory the callee writes (WP11 R1 t11/t12 at tool level:
 *     the traps are handled inside the call, the call completes, the watch records the hit).
 * One server for the file (≤ 3 targets): game_sim at its f32 equilibrium and an emulation capture of it.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip() || emuSkip();
type Obj = Readonly<Record<string, unknown>>;
const EQUILIBRIUM = ["--no-threads", "--speed", "20", "--throttle", "0.125"];

let home: TempHome;
let bea: BeaConnection;
let ledger: OwnedPidLedger;
let game: FixtureArtifact;
let live = "";
let emu = "";
let car = 0n;

const ok = async (name: string, args: Obj): Promise<Obj> => expectToolSuccess(await bea.call(name, args));
const hex = (v: bigint | number): string => `0x${v.toString(16)}`;
const f32 = (v: number): string => `0x${(new Uint32Array(new Float32Array([v]).buffer)[0] ?? 0).toString(16)}`;
const columnsOf = (page: Obj): Record<string, unknown>[] => {
  const columns = page["columns"] as string[];
  return (page["rows"] as unknown[][]).map((cells) => Object.fromEntries(columns.map((c, i) => [c, cells[i]])));
};
/** Every page of a stream through query_events; the pages agree on the total. */
const pageStream = async (
  streamId: string,
  limit: number,
): Promise<{ rows: number; total: number; evidence: Obj[] }> => {
  let offset: number | null = 0;
  let rows = 0;
  let total = -1;
  const evidence: Obj[] = [];
  while (offset !== null) {
    const page = await ok("query_events", { stream_id: streamId, view: "rows", offset, limit });
    const meta = page["page"] as { total: number; next_offset: number | null };
    if (total === -1) total = meta.total;
    expect(meta.total).toBe(total);
    rows += (page["rows"] as unknown[]).length;
    evidence.push(page);
    offset = meta.next_offset;
  }
  return { rows, total, evidence };
};

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const sim = fixtureArtifact(manifest, "game_sim");
  if (sim === null) throw new Error("game_sim fixture unavailable");
  game = sim;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
  home = await createTempHome("wp18-integration");
  const python = realPython();
  bea = await connectBea({ home, ledger, ...(python === null ? {} : { env: { BEA_PYTHON: python } }) });
  live = String((await ok("spawn_process", { program: game.path, args: EQUILIBRIUM }))["session_id"]);
  await ok("resume_process", { session_id: live });
  await ok("wait", { session_id: live, until: "output", output_contains: "READY", timeout_ms: 15_000 });
  const read = await ok("read_memory", {
    session_id: live,
    address: "game_sim.exe!g_world",
    deref: [8],
    size: 8,
    view: "ptr",
  });
  car = BigInt(String((read["values"] as unknown[])[0]));
  const opened = await ok("emu_open", { live_session_id: live, capture_regions: [{ address: hex(car), size: 0x80 }] });
  emu = String(opened["session_id"]);
  const bridge = opened["bridge"] as { pid: number; child_pid: number };
  for (const pid of new Set([bridge.pid, bridge.child_pid]))
    ledger.recordOwned(pid, null, "integration emulation bridge");
}, 120_000);

afterAll(async () => {
  if (skip !== false) return;
  for (const id of [emu, live]) if (id !== "") await bea.call("close_session", { session_id: id });
  const outcome = await bea.close();
  expect(outcome.exitCode).toBe(0);
  await ledger.assertClean();
  await home.cleanup();
}, 60_000);

const crossWaveRow1 = async (): Promise<void> => {
  // a diff with one wrong expected value: differ + an auto-unknown, and no live call
  const diff = await ok("diff_function", {
    live_session_id: live,
    emu_session_id: emu,
    legs: ["emulation", "expected"],
    address: "game_sim.exe!tiny_add",
    signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
    vectors: { columns: { arg0: [1, 2, 3], arg1: [10, 20, 30] } },
    expected: { columns: { ret: [11, 22, 34] } },
  });
  expect(diff["verdict"]).toBe("differ");
  const autoUnknown = String(diff["unknown_id"]);
  expect(autoUnknown).toMatch(/^unk_/u);
  // A.4 #6: a recording tool whose blocking wait the client cancelled still left its install record
  await expect(
    bea.call(
      "hook_function",
      { session_id: live, address: "game_sim.exe!car_energy", duration_ms: 20_000, wait_ms: 20_000 },
      { signal: AbortSignal.timeout(500) },
    ),
  ).rejects.toThrow();
  // get_evidence after read and diff: rows by predicate, and every complete record recomputes its own id
  const summary = (await ok("get_evidence", { limit: 500 }))["summary"] as {
    rows: { evidence_id: string; predicate_type: string }[];
  };
  const predicates = new Set(summary.rows.map((r) => r.predicate_type));
  for (const p of ["bea.memory.read", "bea.diff", "bea.emu.session", "bea.instrument.install"])
    expect(predicates).toContain(p);
  const installs = summary.rows.filter((r) => r.predicate_type === "bea.instrument.install");
  expect(installs.length).toBeGreaterThanOrEqual(1);
  for (const row of summary.rows.filter((r) =>
    ["bea.memory.read", "bea.diff", "bea.instrument.install"].includes(r.predicate_type),
  )) {
    const complete = await ok("get_evidence", { detail: "complete", id: row.evidence_id });
    const record = (complete["record"] as { value: unknown }).value as BeaEvidence;
    const { evidence_id: _id, ...body } = record;
    expect(evidenceIdOf(body), row.predicate_type).toBe(row.evidence_id);
  }
  // record_unknown after a diff: the diff's auto-unknown is listed; create / update / stale / unsupported resolve
  const unknowns = (
    (await ok("get_evidence", { entity: "unknowns", limit: 100 }))["summary"] as {
      rows: { unknown_id?: string; id?: string }[];
    }
  ).rows;
  expect(JSON.stringify(unknowns)).toContain(autoUnknown);
  const created = await ok("record_unknown", {
    question: "Is tiny_add's emulated result what the game computes?",
    session_id: live,
    severity: "medium",
    supporting: [String(diff["evidence_id"])],
  });
  expect(created).toMatchObject({ revision: 1, status: "open", predicate_type: "bea.unknown.mutation" });
  const id = String(created["unknown_id"]);
  expect(await ok("record_unknown", { unknown_id: id, expected_revision: 1, status: "investigating" })).toMatchObject({
    revision: 2,
  });
  expect(
    parseToolError(await bea.call("record_unknown", { unknown_id: id, expected_revision: 1, status: "blocked" })),
  ).toMatchObject({
    code: "revision_conflict",
  });
  expect(
    parseToolError(
      await bea.call("record_unknown", {
        unknown_id: id,
        expected_revision: 2,
        status: "resolved",
        resolution: "tiny_add",
      }),
    ).code,
  ).toBe("invalid_request");
  // export_evidence after the above: a zip and a directory, each verified twice (server and an independent CLI process)
  const zip = await ok("export_evidence", { format: "zip", streams: "all" });
  const dir = await ok("export_evidence", { streams: "all" });
  for (const bundle of [zip, dir]) {
    expect(bundle["streams"] as number).toBeGreaterThanOrEqual(3);
    expect(await ok("import_evidence", { path: String(bundle["path"]), validate_only: true })).toMatchObject({
      valid: true,
      records: bundle["records"],
    });
    const verifyHome = await createTempHome("wp18-verify");
    try {
      const cli = spawnSync(
        process.execPath,
        [harnessLayout().dispatcher, "evidence", "verify", String(bundle["path"]), "--json"],
        { encoding: "utf8", env: minimalEnv(verifyHome), cwd: verifyHome.work, windowsHide: true, timeout: 60_000 },
      );
      expect(cli.status, cli.stderr).toBe(0);
      expect(JSON.parse(cli.stdout)).toMatchObject({ valid: true, records: bundle["records"] });
    } finally {
      await verifyHome.cleanup();
    }
  }
  expect(parseToolError(await bea.call("export_evidence", { format: "zip", out_path: String(zip["path"]) })).code).toBe(
    "file_operation_failed",
  );
};

const crossWaveRow2 = async (): Promise<void> => {
  const n = 300;
  const columns = { arg0: Array.from({ length: n }, (_, i) => i), arg1: Array.from({ length: n }, (_, i) => 3 * i) };
  const signature = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" };
  const called = await ok("call_function", {
    session_id: live,
    address: "game_sim.exe!tiny_add",
    signature,
    vectors: { columns },
    inline_limit: 0,
  });
  const callStream = String((called["batch"] as { stream_id: string }).stream_id);
  const emulated = await ok("emu_call", {
    session_id: emu,
    address: "game_sim.exe!tiny_add",
    signature,
    vectors: { columns },
    inline_limit: 0,
  });
  const emuStream = String((emulated["batch"] as { stream_id: string }).stream_id);
  const diffed = await ok("diff_function", {
    live_session_id: live,
    emu_session_id: emu,
    address: "game_sim.exe!tiny_add",
    signature,
    vectors: { columns },
    inline_limit: 0,
  });
  expect(diffed["verdict"]).toBe("equivalent-on-tested-inputs");
  const diffStream = String(diffed["stream_id"]);
  for (const stream of [callStream, emuStream, diffStream]) expect(stream).toMatch(/^st_[0-9a-f]{64}$/u);
  for (const [label, stream] of [
    ["call-batch", callStream],
    ["emu-batch", emuStream],
    ["diff", diffStream],
  ] as const) {
    const paged = await pageStream(stream, 128);
    expect(paged.total, label).toBe(n);
    expect(paged.rows, label).toBe(n);
    for (const page of paged.evidence) {
      expect(page["predicate_type"], label).toBe("bea.events.query");
      expect(String(page["evidence_id"]), label).toMatch(/^ev_/u);
    }
  }
  // the rows are the vectors: tiny_add(i, 3i) = 4i, in the emulator as live
  const first = columnsOf(await ok("query_events", { stream_id: emuStream, view: "rows", limit: 4 }));
  expect(first).toHaveLength(4);
  expect(first.map((r) => BigInt(String(r["r"])))).toEqual([0n, 4n, 8n, 12n]);
};

const crossWaveRow3 = async (): Promise<void> => {
  const extent = game.pe.pdata["physics_step"];
  if (extent === undefined) throw new Error("no .pdata extent for physics_step");
  const run = await ok("emu_call", {
    session_id: emu,
    address: "game_sim.exe!physics_step",
    signature: { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32" },
    args: [hex(car), 1 / 60],
    trace: { coverage: true },
  });
  expect((run["call"] as { status: string }).status).toBe("returned");
  const exported = await ok("export_coverage", { evidence_id: String(run["evidence_id"]) });
  const drcov = parseDrcov(new Uint8Array(await readFile(String(exported["path"]))));
  const module = drcov.modules.find((m) => m.path.toLowerCase().endsWith("game_sim.exe"));
  expect(module).toBeDefined();
  const blocks = drcov.blocks.filter((b) => b.moduleId === module?.id);
  expect(blocks.length).toBeGreaterThanOrEqual(2);
  for (const block of blocks) {
    expect(block.start).toBeGreaterThanOrEqual(extent.rva);
    expect(block.start).toBeLessThan(extent.rva + extent.size);
  }
};

const crossWaveRow4 = async (): Promise<void> => {
  const modules = await ok("list_modules", { session_id: emu });
  expect(modules["rows"]).toContainEqual(expect.objectContaining({ name: "game_sim.exe" }));
  const read = await ok("read_memory", { session_id: emu, address: hex(car), size: 0x80 });
  expect(read).toMatchObject({ complete: true, authority: "emulation" });
  const bytes = Buffer.from(String(read["data"]), "hex");
  expect(bytes.readUInt32LE(0)).toBe(0x31524143); // 'CAR1'
  expect(bytes.readFloatLE(0x08)).toBe(20);
  const speedWriter = (game.expectations["speedWriters"] as { rva: number; text: string }[])[0];
  const disasm = await ok("disassemble", { session_id: emu, address: "game_sim.exe!physics_step", function: true });
  const rows = disasm["rows"] as { rva: string | null; t: string }[];
  // the rows come from the captured image (module-relative rva); the writer is the manifest's speed store
  const writer = rows.find((r) => r.rva === hex(speedWriter?.rva ?? -1));
  expect(writer, JSON.stringify(rows.slice(0, 4))).toBeDefined();
  expect(writer?.t).toBe("movss dword ptr [rax + 8], xmm0");
};

const crossWaveRow5 = async (): Promise<void> => {
  const speed = hex(car + 8n);
  const signature = { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32" };
  // DR slots are per thread: the call runs on the game's main thread at a per-frame safe point (thread_at, R1 t12);
  // a guard page is per page: the call runs on the agent's own thread (R1 t11)
  for (const [method, where] of [
    ["debug_register", { thread_at: "game_sim.exe!mix_args" }],
    ["page_guard", {}],
  ] as const) {
    const watch = await ok("watch_memory", {
      session_id: live,
      address: speed,
      size: 4,
      access: "write",
      method,
      duration_ms: 30_000,
    });
    expect(watch["method"], method).toBe(method);
    const recording = (watch["instrument"] as { recording_id: string }).recording_id;
    // physics_step(&live car, dt = 0) writes the same 20.0 back: a write the armed watch traps inside the call
    const called = await ok("call_function", {
      session_id: live,
      address: "game_sim.exe!physics_step",
      signature,
      args: [hex(car), 0],
      ...where,
    });
    const call = called["call"] as { status: string; ret: { bits: string } };
    expect(call.status, method).toBe("returned");
    expect(call.ret.bits, method).toBe(f32(20));
    // the call's evidence counts the BEA traps the dispatcher handled while the callee ran (bea_traps_during_call)
    const complete = await ok("get_evidence", { detail: "complete", id: String(called["evidence_id"]) });
    const raw =
      (complete["record"] as { value: { raw_result?: { bea_traps_during_call?: number } } }).value.raw_result ?? {};
    expect(raw.bea_traps_during_call, method).toBeGreaterThanOrEqual(1);
    // and the watch is still armed and recording afterwards
    const stopped = await ok("stop_instrumentation", { session_id: live, ids: [recording] });
    expect(stopped["stopped"], method).toEqual([expect.objectContaining({ id: recording })]);
    const writers = (
      (await ok("query_events", { recording_id: recording, view: "summary" })) as {
        summary: { writers?: { insn: { at: string | null } }[] };
      }
    ).summary.writers;
    const writerAt = `game_sim.exe+${hex((game.expectations["speedWriters"] as { rva: number }[])[0]?.rva ?? -1)}`;
    expect(
      writers?.map((w) => w.insn.at),
      method,
    ).toContain(writerAt);
  }
};

describe.skipIf(skip !== false)(`cross-wave rows on the built server (DESIGN §8.4)${skipNote(skip)}`, () => {
  it(
    "WP1 chained: get_evidence after read and diff; record_unknown after a diff; export_evidence after the above",
    crossWaveRow1,
    180_000,
  );
  it("query_events pages host row streams: a live call-batch, an emu-batch and a diff stream", crossWaveRow2, 180_000);
  it("export_coverage of emulation evidence: an emulated physics_step call as drcov", crossWaveRow3, 120_000);
  it(
    "inspect tools on the emulation session: list_modules, read_memory of the captured car, disassemble physics_step",
    crossWaveRow4,
    120_000,
  );
  it(
    "call_function while BEA's watch engines are armed on memory the callee writes: the traps are handled inside the call and the call completes",
    crossWaveRow5,
    180_000,
  );
});
