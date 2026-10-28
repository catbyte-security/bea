import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { listModuleSymbolsOutputSchema, mapAddressOutputSchema } from "../../../src/contracts/areas/address.js";
import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * S6 §10.8 rows for map_address and list_module_symbols over the BUILT server (DESIGN §8.4 with its edits: static
 * addresses written `game_sim.exe:0x…`, rows assert status:"mapped", func.is_start, verify.status:"match"). The
 * hook and gated-write variants of the map_address row moved to WP7 and WP12 by the wave rule; the raw-RPC versions
 * live in rawFridaAddress.test.ts. Needs WP4's spawn_process/close_session (wave 2): run with a snapshot
 * (BEA_DIST_DIR, docs/testing.md).
 */
const skipReason = gccSkip() || fridaSkip() || jobhostSkip();

let bea: BeaConnection;
let ledger: OwnedPidLedger;
let game: FixtureArtifact;
let sessionId: string;
let base: bigint;
/** KERNEL32.dll!Sleep's IAT slot from the pe_path listing (the live listing must agree) */
let sleepSlotRva: string | null = null;

const hex = (n: number | bigint) => `0x${n.toString(16)}`;
const rvaOf = (name: string): number => game.pe.exportRvas[name] ?? -1;

beforeAll(async () => {
  if (skipReason !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "game_sim");
  const pidcheck = fixtureArtifact(manifest, "pidcheck");
  if (artifact === null) throw new Error("fixtures unavailable");
  game = artifact;
  ledger = new OwnedPidLedger(pidcheck?.path ?? null);
  bea = await connectBea({ ledger });
  const spawned = expectToolSuccess(await bea.call("spawn_process", { program: game.path, args: ["--no-threads"] }));
  sessionId = spawned["session_id"] as string;
  base = BigInt((spawned["main_module"] as { base: string }).base);
}, 120_000);

afterAll(async () => {
  if (skipReason !== false) return;
  if (sessionId !== undefined) await bea.call("close_session", { session_id: sessionId });
  await bea.close();
  await ledger.assertClean();
});

describe.skipIf(skipReason !== false)(`map_address (S6 §10.8)${skipNote(skipReason)}`, () => {
  it("maps the Ghidra static VA of physics_step: va = base + rva, is_start, bytes match", async () => {
    const rva = rvaOf("physics_step");
    const out = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await bea.call("map_address", {
          session_id: sessionId,
          addresses: [`game_sim.exe:${hex(0x140000000 + rva)}`, `game_sim.exe:${hex(0x140000000 + rva + 0x10)}`],
          verify_bytes: 16,
          expected_image_sha256: game.artifactSha256,
        }),
      ),
    );
    expect(out.rows[0]).toMatchObject({
      status: "mapped",
      address: { va: hex(base + BigInt(rva)), rva: hex(rva), static_va: hex(0x140000000 + rva) },
      func: { is_start: true, name: "physics_step" },
      image_check: "match",
      verify: { status: "match" },
    });
    expect(out.rows[1]).toMatchObject({ status: "mapped", func: { is_start: false } });
    expect(out.modules[0]).toMatchObject({
      preferred_base: "0x140000000",
      runtime_base: hex(base),
      runtime_matches_file: true,
    });
    expect(out.confidence).toBe("derived");
  });

  it("reports a row note beyond SizeOfImage without failing, and honours an explicit /0x base", async () => {
    const rva = rvaOf("physics_step");
    const out = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await bea.call("map_address", {
          session_id: sessionId,
          addresses: [`+${hex(game.pe.sizeOfImage + 0x10)}`, `game_sim.exe:${hex(0x150000000 + rva)}/0x150000000`],
        }),
      ),
    );
    expect(out.rows[0]).toMatchObject({ status: "error", issue: { code: "invalid_request" } });
    expect(out.rows[1]).toMatchObject({
      status: "mapped",
      address: { va: hex(base + BigInt(rva)), static_base_source: "caller" },
    });
    expect(out.coverage.reasons).toContain("entry_errors");
  });

  it("maps offline with pe_path + runtime_base (pure arithmetic, no session)", async () => {
    const rva = rvaOf("physics_step");
    const out = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await bea.call("map_address", {
          pe_path: game.path,
          runtime_base: hex(base),
          addresses: [`game_sim.exe:${hex(0x140000000 + rva)}`],
        }),
      ),
    );
    expect(out.rows[0]).toMatchObject({ status: "mapped", address: { va: hex(base + BigInt(rva)) }, verify: null });
    expect(out.authority).toBe("static-artifact");
    expect(parseToolError(await bea.call("map_address", { pe_path: game.path, addresses: ["1234"] })).code).toBe(
      "invalid_request",
    );
  });
});

describe.skipIf(skipReason !== false)(`list_module_symbols (S6 §10.8)${skipNote(skipReason)}`, () => {
  it("pe_path: physics_step export rva and .pdata extent equal the manifest; imports carry KERNEL32.dll!Sleep with slot_rva", async () => {
    const exports = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(await bea.call("list_module_symbols", { pe_path: game.path, filter: "physics_step" })),
    );
    expect(exports.rows).toContainEqual(
      expect.objectContaining({ name: "physics_step", rva: hex(rvaOf("physics_step")) }),
    );
    const functions = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(
        await bea.call("list_module_symbols", { pe_path: game.path, kind: "functions", filter: "physics_step" }),
      ),
    );
    const extent = game.pe.pdata["physics_step"];
    expect(functions.rows).toEqual([{ rva: hex(extent?.rva ?? 0), size: extent?.size, name: "physics_step" }]);
    const imports = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(
        await bea.call("list_module_symbols", { pe_path: game.path, kind: "imports", filter: "Sleep" }),
      ),
    );
    const sleep = (imports.rows as { module: string; name: string; slot_rva: string; slot_va: string | null }[]).find(
      (r) => r.module === "KERNEL32.dll" && r.name === "Sleep",
    );
    // the IAT slot lies inside the image (the reader's slot RVAs equal pefile's: tests/unit/pe/peReader.test.ts)
    expect(sleep?.slot_rva).toMatch(/^0x[0-9a-f]+$/u);
    expect(Number(BigInt(sleep?.slot_rva ?? "0x0"))).toBeGreaterThan(0);
    expect(Number(BigInt(sleep?.slot_rva ?? "0x0"))).toBeLessThan(game.pe.sizeOfImage);
    expect(sleep?.slot_va).toBeNull();
    sleepSlotRva = sleep?.slot_rva ?? null;
  });

  it("live: rows have va = base + rva and imports resolve to Locs", async () => {
    const exports = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(await bea.call("list_module_symbols", { session_id: sessionId, filter: "physics_step" })),
    );
    expect(exports.rows[0]).toMatchObject({ va: hex(base + BigInt(rvaOf("physics_step"))) });
    const imports = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(
        await bea.call("list_module_symbols", { session_id: sessionId, kind: "imports", filter: "!Sleep" }),
      ),
    );
    expect(imports.rows[0]).toMatchObject({ resolved: { sym: "Sleep" }, slot_rva: sleepSlotRva });
    expect((imports.rows[0] as { slot_va: string }).slot_va).toBe(hex(base + BigInt(sleepSlotRva ?? "0x0")));
  });
});
