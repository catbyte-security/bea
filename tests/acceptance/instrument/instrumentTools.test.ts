import { afterAll, describe, expect, it } from "vitest";

import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * S6 §10.8 rows of hook_function, wait, stop_instrumentation and query_events through the BUILT server (run with
 * BEA_DIST_DIR from `node scripts/snapshot-dist.mjs <id>`), plus the rows the wave rule moved to WP7 (DESIGN §8.4):
 * resume_process "hook installed before resume → frame 0", map_address "after hooking still match", disassemble
 * "with a hook shows hooked_bytes_restored". Only earlier-wave tools (WP4 sessions, WP5 map_address) and this area's
 * tools (plus disassemble, which the table moved here) are used. Needs WP1 + WP4 + WP5 (+ WP6) merged.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();

type Out = Readonly<Record<string, unknown>>;
interface Page {
  readonly columns: string[];
  readonly rows: unknown[][];
  readonly page: { total: number };
}
const col = (p: Page, name: string): unknown[] => p.rows.map((r) => r[p.columns.indexOf(name)]);

const homes: TempHome[] = [];
const servers: BeaConnection[] = [];
afterAll(async () => {
  for (const s of servers) await s.close();
  for (const h of homes) await h.cleanup();
});
const server = async (name: string) => {
  const manifest = await loadFixtures();
  const game = fixtureArtifact(manifest, "game_sim");
  const crashy = fixtureArtifact(manifest, "crashy");
  const pidcheck = fixtureArtifact(manifest, "pidcheck");
  if (game === null || crashy === null) throw new Error("fixtures unavailable");
  const home = await createTempHome(`wp7-${name}`);
  homes.push(home);
  const bea = await connectBea({ home, ledger: new OwnedPidLedger(pidcheck?.path ?? null) });
  servers.push(bea);
  return { bea, game, crashy, manifest };
};
const ok = async (bea: BeaConnection, tool: string, args: Record<string, unknown>): Promise<Out> =>
  expectToolSuccess(await bea.call(tool, args));
const spawn = async (bea: BeaConnection, program: string, args: string[]): Promise<string> =>
  (await ok(bea, "spawn_process", { program, args })).session_id as string;

describe.skipIf(skip !== false)(
  `hook_function and query_events on physics_step (MCP, game_sim)${skipNote(skip)}`,
  () => {
    it(
      "hook_function physics_step: ret == speed@leave, dt is 1/60 f32, query views, stop restores the file bytes",
      { timeout: 120_000 },
      async () => {
        const { bea, game } = await server("physics");
        const sid = await spawn(bea, game.path, ["--no-threads"]);
        await ok(bea, "resume_process", { session_id: sid });
        const hooked = await ok(bea, "hook_function", {
          session_id: sid,
          address: "game_sim.exe!physics_step",
          capture: [
            { name: "car", arg: 0, type: "ptr" },
            { name: "dt", arg: 1, type: "f32" },
            { name: "speed", arg: 0, type: "f32", deref: [8], when: "both" },
          ],
          returns: "f32",
          duration_ms: 1500,
          wait_ms: 3000,
        });
        expect(hooked).toMatchObject({
          function_start: true,
          bytes_match_file: true,
          relocation: "default",
          instrument: { kind: "hook", state: "finished", end_reason: "duration" },
        });
        const rec = (hooked.instrument as { recording_id: string }).recording_id;
        const rows = (await ok(bea, "query_events", {
          recording_id: rec,
          view: "rows",
          fields: ["ret:bits", "speed@leave:bits", "dt:bits"],
          order: "desc",
          limit: 500,
        })) as unknown as Page & Out;
        expect(rows.page.total).toBeGreaterThan(30);
        expect(col(rows, "ret:bits")).toEqual(col(rows, "speed@leave:bits"));
        expect(new Set(col(rows, "dt:bits"))).toEqual(new Set(["0x3c888889"]));
        expect((rows.fields as { name: string }[]).map((f) => f.name)).toEqual(
          expect.arrayContaining(["car", "dt", "speed", "speed@leave", "ret"]),
        );
        const group = (await ok(bea, "query_events", {
          recording_id: rec,
          view: "group",
          group_by: ["dt"],
        })) as unknown as Page;
        expect(group.rows).toHaveLength(1);
        expect(group.rows[0]?.[1]).toBe(rows.page.total);
        const stats = await ok(bea, "query_events", { recording_id: rec, view: "stats", fields: ["speed@leave"] });
        expect((stats.stats as { min: number; max: number }[])[0]?.max).toBeGreaterThanOrEqual(
          (stats.stats as { min: number }[])[0]?.min ?? 0,
        );
        const filtered = (await ok(bea, "query_events", {
          recording_id: rec,
          view: "rows",
          where: [{ field: "seq", op: "le", value: 3 }],
        })) as unknown as Page;
        expect(filtered.page.total).toBe(3);
        const unknown = parseToolError(
          await bea.call("query_events", { recording_id: rec, view: "rows", fields: ["nope"] }),
        );
        expect(unknown.code).toBe("invalid_request");
        expect(JSON.stringify(unknown.details)).toContain("speed@leave");
        // an active recording is partial; stopping restores the bytes (map_address verification, moved WP5 row)
        const live = await ok(bea, "hook_function", {
          session_id: sid,
          address: "game_sim.exe!physics_step",
          capture: [{ arg: 1, type: "f32" }],
          duration_ms: 60_000,
        });
        const liveId = (live.instrument as { recording_id: string }).recording_id;
        const partial = await ok(bea, "query_events", { recording_id: liveId });
        expect(partial.coverage).toMatchObject({
          status: "partial",
          reasons: expect.arrayContaining(["recording_active"]),
        });
        const mapped = await ok(bea, "map_address", { session_id: sid, addresses: ["game_sim.exe!physics_step"] });
        expect((mapped.rows as { verify: { status: string } }[])[0]?.verify.status).toBe("match");
        const dis = await ok(bea, "disassemble", { session_id: sid, address: "game_sim.exe!physics_step", count: 4 });
        expect(dis.hooked_bytes_restored).toBe(true);
        const stopped = await ok(bea, "stop_instrumentation", { session_id: sid, ids: [liveId] });
        expect(stopped.stopped).toMatchObject([{ id: liveId, kind: "hook", status: "reverted" }]);
        expect((stopped.stopped as { manifest_evidence_id: string }[])[0]?.manifest_evidence_id).toMatch(/^ev_/u);
        const after = await ok(bea, "map_address", { session_id: sid, addresses: ["game_sim.exe!physics_step"] });
        expect((after.rows as { verify: { status: string; own_effects_restored: number } }[])[0]?.verify).toMatchObject(
          {
            status: "match",
            own_effects_restored: 0,
          },
        );
        const n = (await ok(bea, "query_events", { recording_id: liveId })).recording as { events: number };
        const again = await ok(bea, "wait", { session_id: sid, until: "exit", timeout_ms: 300 });
        expect(again).toMatchObject({ satisfied: false, reason: "timeout" });
        expect(((await ok(bea, "query_events", { recording_id: liveId })).recording as { events: number }).events).toBe(
          n.events,
        );
        expect((await ok(bea, "stop_instrumentation", { session_id: sid, ids: [liveId] })).stopped).toMatchObject([
          { status: "already_ended" },
        ]);
        await ok(bea, "close_session", { session_id: sid });
      },
    );
  },
);

describe.skipIf(skip !== false)(
  `hook_function argument classes, relocation and probes (MCP, game_sim)${skipNote(skip)}`,
  () => {
    it(
      "mix_args stack floats exact, tiny_add forced relocation, probe rax == car, max_events ends at 50",
      { timeout: 120_000 },
      async () => {
        const { bea, game, manifest } = await server("args");
        const sid = await spawn(bea, game.path, ["--no-threads"]);
        await ok(bea, "resume_process", { session_id: sid });
        const writers = fixtureArtifact(manifest, "game_sim")?.expectations["speedWriters"] as
          | { rva: number; base: string }[]
          | undefined;
        const writer = writers?.[0];
        expect(writer).toBeDefined();
        const mix = await ok(bea, "hook_function", {
          session_id: sid,
          address: "game_sim.exe!mix_args",
          capture: [
            { name: "b", arg: 1, type: "f32" },
            { name: "c", arg: 2, type: "f64" },
            { name: "d", arg: 3, type: "f32" },
            { name: "e", arg: 4, type: "i32" },
            { name: "f", arg: 5, type: "f64" },
          ],
          returns: "f64",
          max_events: 20,
          wait_ms: 5000,
        });
        const mixRows = (await ok(bea, "query_events", {
          recording_id: (mix.instrument as { recording_id: string }).recording_id,
          view: "rows",
          fields: ["b", "c", "d", "e", "f"],
        })) as unknown as Page;
        expect(mixRows.rows.length).toBeGreaterThan(0);
        for (const r of mixRows.rows) expect(r.slice(1)).toEqual([1.5, 2.25, 3.125, 7, 0.5]);
        const tiny = await ok(bea, "hook_function", {
          session_id: sid,
          address: "game_sim.exe!tiny_add",
          capture: [
            { name: "a", arg: 0, type: "i32" },
            { name: "b", arg: 1, type: "i32" },
          ],
          returns: "i32",
          max_events: 10,
          wait_ms: 5000,
        });
        expect(tiny.relocation).toBe("forced");
        expect(tiny.limitations).toEqual(expect.arrayContaining([expect.stringContaining("forced relocation")]));
        const tinyRows = (await ok(bea, "query_events", {
          recording_id: (tiny.instrument as { recording_id: string }).recording_id,
          view: "rows",
          fields: ["a", "b", "ret"],
        })) as unknown as Page;
        expect(tinyRows.rows.length).toBeGreaterThan(0);
        for (const r of tinyRows.rows) expect(r[3]).toBe((r[1] as number) + (r[2] as number));
        const car = await ok(bea, "hook_function", {
          session_id: sid,
          address: "game_sim.exe!physics_step",
          capture: [{ name: "car", arg: 0, type: "ptr" }],
          max_events: 50,
          wait_ms: 10_000,
        });
        expect(car.instrument).toMatchObject({ state: "finished", end_reason: "max_events", events: 50 });
        const carRows = (await ok(bea, "query_events", {
          recording_id: (car.instrument as { recording_id: string }).recording_id,
          view: "rows",
          fields: ["car"],
          limit: 1,
        })) as unknown as Page;
        const probe = await ok(bea, "hook_function", {
          session_id: sid,
          address: `game_sim.exe+0x${(writer?.rva ?? 0).toString(16)}`,
          probe: true,
          capture: [{ name: "base", reg: writer?.base ?? "rax", type: "ptr" }],
          max_events: 5,
          wait_ms: 5000,
        });
        const probeRows = (await ok(bea, "query_events", {
          recording_id: (probe.instrument as { recording_id: string }).recording_id,
          view: "rows",
          fields: ["base"],
        })) as unknown as Page;
        expect(new Set(col(probeRows, "base"))).toEqual(new Set([carRows.rows[0]?.[1]]));
        await ok(bea, "close_session", { session_id: sid });
      },
    );
  },
);

describe.skipIf(skip !== false)(
  `resume_process, wait and stop_instrumentation (MCP, game_sim)${skipNote(skip)}`,
  () => {
    it(
      "resume_process: a hook installed before resume sees frame 0; wait for events, output and exit",
      { timeout: 120_000 },
      async () => {
        const { bea, game, crashy } = await server("resume");
        const spawned = await ok(bea, "spawn_process", { program: game.path, args: ["--no-threads"] });
        const sid = spawned.session_id as string;
        const hooked = await ok(bea, "hook_function", {
          session_id: sid,
          address: "game_sim.exe!physics_step",
          capture: [{ name: "frame", arg: 0, type: "u32", deref: [0x38] }],
          duration_ms: 3000,
        });
        const rec = (hooked.instrument as { recording_id: string }).recording_id;
        await ok(bea, "resume_process", { session_id: sid });
        const events = await ok(bea, "wait", {
          session_id: sid,
          until: "events",
          ids: [rec],
          min_events: 10,
          timeout_ms: 20_000,
        });
        expect(events).toMatchObject({ satisfied: true, reason: "condition", evidence_id: null });
        const first = (await ok(bea, "query_events", {
          recording_id: rec,
          view: "rows",
          fields: ["frame"],
          limit: 1,
        })) as unknown as Page;
        expect(first.rows[0]?.[1]).toBe(0);
        const output = await ok(bea, "wait", {
          session_id: sid,
          until: "output",
          output_contains: "FRAME 60",
          timeout_ms: 20_000,
        });
        expect(output.satisfied).toBe(true);
        const timeout = await ok(bea, "wait", {
          session_id: sid,
          until: "output",
          output_contains: "never-printed",
          timeout_ms: 200,
        });
        const repeat = await ok(bea, "wait", {
          session_id: sid,
          until: "output",
          output_contains: "never-printed",
          timeout_ms: 200,
        });
        expect([timeout.reason, repeat.reason]).toEqual(["timeout", "timeout"]);
        const all = await ok(bea, "stop_instrumentation", { session_id: sid, all: true });
        expect(all.active_remaining).toBe(0);
        // built-in recordings are listed by spawn_process (session_status lists them under `instruments`)
        const builtin = spawned.recordings as { recording_id: string; kind: string }[];
        const exceptions = builtin.find((r) => r.kind === "exceptions");
        expect(exceptions).toBeDefined();
        expect(
          parseToolError(
            await bea.call("stop_instrumentation", {
              session_id: sid,
              ids: [exceptions?.recording_id ?? "rec_missing"],
            }),
          ).code,
        ).toBe("invalid_request");
        // all:true stops instruments only: the built-in recordings stay active until the session ends
        const status = (await ok(bea, "session_status", { session_id: sid })).instruments as {
          recording_id: string;
          state: string;
        }[];
        expect(status.find((r) => r.recording_id === exceptions?.recording_id)?.state).toBe("active");
        await ok(bea, "close_session", { session_id: sid });
        const csid = await spawn(bea, crashy.path, ["av-write"]);
        await ok(bea, "resume_process", { session_id: csid });
        const exit = await ok(bea, "wait", { session_id: csid, until: "exit", timeout_ms: 20_000 });
        expect(exit).toMatchObject({ satisfied: true, reason: "condition", target: { state: "exited" } });
        expect(String((exit.target as { exit: { code_hex: string } }).exit.code_hex).toLowerCase()).toBe("0xc0000005");
        expect((exit.target as { crash: unknown }).crash).not.toBeNull();
        await ok(bea, "close_session", { session_id: csid });
      },
    );
  },
);
