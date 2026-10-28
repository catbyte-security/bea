import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { BeaCore } from "../../../../src/application/BeaApplication.js";
import { createAddressService } from "../../../../src/application/address/createAddressService.js";
import { listModuleSymbolsOutputSchema, mapAddressOutputSchema } from "../../../../src/contracts/areas/address.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import { LIMITATIONS } from "../../../../src/domain/evidence/limitations.js";
import type { EmuPort } from "../../../../src/ports/emu.js";
import type { DynamicSessionPort, OperationContext } from "../../../../src/ports/sessions.js";
import { createPeServices } from "../../../../src/providers/pe/createPeServices.js";
import { fixtureArtifact, gccSkip, loadFixtures, type FixtureArtifact } from "../../../support/acceptance/fixtures.js";
import { fakeServices } from "../../../support/fakes/fakeServices.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import {
  fakeEmu,
  fakeEvidence,
  fakeProcess,
  type FakeEvidence,
  type FakeProcess,
} from "../../../unit/address/support/fakes.js";

/**
 * map_address and list_module_symbols over the production MCP server (createMcpServer + invokeTool + Delivery) with
 * the REAL PE services and AddressService, fake evidence/session/emulator ports and a modelled live process built
 * from the fixture files (S6 §10.6 boundary layer; DESIGN §6.2 #13–#14).
 */
const windows = process.platform === "win32";
const skip = !windows || gccSkip() !== false;
const SYS = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
const LIVE = "3f2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b";
const EMU = "9b2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b";
const GAME_BASE = 0x7ff6_a000_0000n;
const KERNEL32_BASE = 0x7ffa_1000_0000n;

let game: FixtureArtifact;
let bea: InMemoryBea;
let ev: FakeEvidence;
let proc: FakeProcess;

/** Sessions port: one live session, one emulation session (admission and the FIFO collapse to direct calls). */
const fakeSessions = (getProc: () => FakeProcess): DynamicSessionPort => {
  const op = (name: string, signal?: AbortSignal): OperationContext => ({
    opId: 7,
    name,
    signal: signal ?? new AbortController().signal,
    deadline: Deadline.after(30_000),
  });
  return new Proxy({} as DynamicSessionPort, {
    get: (_t, prop) => {
      if (prop === "admit")
        return (name: string, req: { signal?: AbortSignal }, fn: (o: OperationContext) => unknown) =>
          fn(op(name, req.signal));
      if (prop === "kindOf") return (id: string) => (id === LIVE ? "live" : id === EMU ? "emulation" : null);
      if (prop === "withSession")
        return (_id: string, o: OperationContext, _mode: string, fn: (s: unknown) => unknown) => fn(getProc().session);
      if (prop === "then") return undefined;
      return () => {
        throw new Error(`fake sessions.${String(prop)}`);
      };
    },
  });
};

beforeAll(async () => {
  if (skip) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "game_sim");
  if (artifact === null) throw new Error("fixtures unavailable");
  game = artifact;
  ev = fakeEvidence();
  let emu: EmuPort | null = null;
  bea = await connectInMemoryBea({
    services: async (core: BeaCore) => {
      const pe = createPeServices(core);
      proc = await fakeProcess(
        pe.images,
        [
          { path: game.path, base: GAME_BASE },
          { path: join(SYS, "kernel32.dll"), base: KERNEL32_BASE, name: "KERNEL32.DLL" },
        ],
        ev,
      );
      const address = createAddressService(core, {
        evidence: ev.runtime,
        pe,
        emulator: () => {
          if (emu === null) throw new Error("late-bound emulator used during construction");
          return emu;
        },
      });
      emu = fakeEmu(EMU, [
        {
          name: "game_sim.exe",
          path: game.path,
          sha256: game.artifactSha256,
          base: "0x140000000",
          size: game.pe.sizeOfImage,
          preferredBase: "0x140000000",
          primary: true,
        },
      ]);
      return fakeServices({ evidence: ev.runtime, pe, address, sessions: fakeSessions(() => proc), emulator: emu })(
        core,
      );
    },
  });
}, 600_000);
afterAll(async () => {
  if (!skip) await bea.close();
});
afterEach(() => {
  if (!skip) ev.drafts.length = 0;
});

const call = async (name: string, args: Record<string, unknown>) => bea.client.callTool({ name, arguments: args });
const exportRva = (name: string): number => game.pe.exportRvas[name] ?? -1;
const hex = (n: number | bigint) => `0x${n.toString(16)}`;

describe.skipIf(skip)("map_address over MCP", () => {
  it("is advertised read-only and idempotent with both tools in the address area", async () => {
    const tools = (await bea.client.listTools()).tools.filter(
      (t) => t.name === "map_address" || t.name === "list_module_symbols",
    );
    expect(tools.map((t) => t.name)).toEqual(["list_module_symbols", "map_address"]);
    for (const tool of tools)
      expect(tool.annotations).toMatchObject({ readOnlyHint: true, idempotentHint: true, destructiveHint: false });
  });

  it("maps offline against a PE file with runtime_base (pure arithmetic), per-row errors are rows", async () => {
    const physics = exportRva("physics_step");
    const result = expectToolSuccess(
      await call("map_address", {
        pe_path: game.path,
        runtime_base: "0x7ff600000000",
        addresses: [
          `$main:${hex(0x140000000 + physics)}`,
          `+${hex(physics + 0x10)}`,
          "game_sim.exe!physics_step",
          hex(0x7ff600000000n + BigInt(physics)),
          `+${hex(game.pe.sizeOfImage + 0x100)}`,
        ],
      }),
    );
    const out = mapAddressOutputSchema.parse(result);
    expect(out.rows.map((r) => r.status)).toEqual(["mapped", "mapped", "mapped", "mapped", "error"]);
    expect(out.rows[0]?.address).toMatchObject({
      va: hex(0x7ff600000000n + BigInt(physics)),
      module: "game_sim.exe",
      image_sha256: game.artifactSha256,
    });
    expect(out.rows[0]?.func).toMatchObject({
      start: `game_sim.exe+${hex(physics)}`,
      is_start: true,
      name: "physics_step",
    });
    expect(out.rows[0]?.func?.size).toBe(game.pe.pdata["physics_step"]?.size);
    expect(out.rows[1]?.func?.is_start).toBe(false);
    expect(out.rows[0]?.region).toBe("game_sim.exe:.text");
    expect(out.rows[0]?.verify).toBeNull();
    expect(out.rows[4]?.issue).toMatchObject({ code: "invalid_request" });
    expect(out.modules).toEqual([
      {
        name: "game_sim.exe",
        path: game.path,
        sha256: game.artifactSha256,
        preferred_base: "0x140000000",
        runtime_base: "0x7ff600000000",
        base_source: "pe-header",
        runtime_matches_file: null,
      },
    ]);
    expect(out.coverage).toEqual({ status: "partial", truncated: false, dropped: 1, reasons: ["entry_errors"] });
    expect(out.limitations).toEqual(
      expect.arrayContaining([LIMITATIONS.STATIC_UNBOUND, LIMITATIONS.PURE_ARITHMETIC, LIMITATIONS.BATCH_ERRORS(1)]),
    );
    expect(out).toMatchObject({
      predicate_type: "bea.address.map",
      confidence: "derived",
      authority: "static-artifact",
    });
    const draft = ev.drafts.at(-1);
    expect(draft?.subject).toMatchObject({ kind: "image", image_sha256: game.artifactSha256, format: "pe32+" });
    expect(draft?.capture).toBeUndefined();
    // a derived map cites what it was computed from (S2 invariant 6): the PE summary of the image (bea.image.pe,
    // observed, static-artifact, unanchored so the same image dedups to one record)
    const record = ev.records.find((r) => r.evidence_id === out.evidence_id);
    const summary = ev.records.find((r) => r.evidence_id === record?.evidence_links[0]);
    expect(record?.evidence_links).toHaveLength(1);
    expect(summary).toMatchObject({
      predicate_type: "bea.image.pe",
      subject: { kind: "image", image_sha256: game.artifactSha256 },
      confidence: "observed",
      authority: "static-artifact",
      observed_at: null,
      result: { name: "game_sim.exe", image_base: "0x140000000", size_of_image: game.pe.sizeOfImage },
    });
    // without runtime_base the preferred base stands in
    const noBase = mapAddressOutputSchema.parse(
      expectToolSuccess(await call("map_address", { pe_path: game.path, addresses: [`+${hex(physics)}`] })),
    );
    expect(noBase.rows[0]?.address?.va).toBe(hex(0x140000000 + physics));
    // a pe_path space takes its static base from the PE header, never "emulation" (WP15 report)
    expect(noBase.rows[0]?.address?.static_base_source).toBe("pe-header");
    expect(noBase.modules[0]?.runtime_base).toBeNull();
    expect(noBase.limitations).toContain(LIMITATIONS.PREFERRED_BASE_ASSUMED);
    expect(ev.records.find((r) => r.evidence_id === noBase.evidence_id)?.evidence_links).toEqual([
      summary?.evidence_id,
    ]);
    // every row an error: the pe_path image itself is still the parent
    const allErrors = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await call("map_address", { pe_path: game.path, addresses: [`+${hex(game.pe.sizeOfImage + 0x100)}`] }),
      ),
    );
    expect(allErrors.rows[0]?.status).toBe("error");
    expect(ev.records.find((r) => r.evidence_id === allErrors.evidence_id)?.evidence_links).toEqual([
      summary?.evidence_id,
    ]);
  });

  it("fails the whole call on grammar errors, listing every bad index, and enforces the refines", async () => {
    const error = parseToolError(await call("map_address", { pe_path: game.path, addresses: ["+0x10", "1234", "x!"] }));
    expect(error.code).toBe("invalid_request");
    expect((error.details["issues"] as { path: string }[]).map((i) => i.path)).toEqual([
      "addresses[1]",
      "addresses[2]",
    ]);
    expect(parseToolError(await call("map_address", { addresses: ["+0x10"] })).code).toBe("invalid_request");
    expect(
      parseToolError(await call("map_address", { session_id: LIVE, pe_path: game.path, addresses: ["+0x10"] })).code,
    ).toBe("invalid_request");
    expect(
      parseToolError(await call("map_address", { session_id: LIVE, runtime_base: "0x1", addresses: ["+0x10"] })).code,
    ).toBe("invalid_request");
    expect(
      parseToolError(await call("map_address", { pe_path: game.path, addresses: ["+0x10"], symbols: [{ name: "x" }] }))
        .code,
    ).toBe("invalid_request");
  });
});

describe.skipIf(skip)("map_address on sessions over MCP", () => {
  it("verifies live bytes, reports regions, records an anchored derived map linked to the module map", async () => {
    const physics = exportRva("physics_step");
    const data = game.pe.sections.find((s) => s.name === ".data");
    const out = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await call("map_address", {
          session_id: LIVE,
          addresses: [
            `game_sim.exe:${hex(0x140000000 + physics)}`,
            `+${hex(physics + 0x10)}`,
            `+${hex(data?.rva ?? 0)}`,
            "0x10000000",
            "nosuch.dll+0x10",
          ],
          verify_bytes: 16,
          expected_image_sha256: game.artifactSha256,
        }),
      ),
    );
    expect(out.rows[0]).toMatchObject({
      status: "mapped",
      image_check: "match",
      address: { va: hex(GAME_BASE + BigInt(physics)) },
      func: { is_start: true },
      verify: { status: "match", compared: 16, equal: 16, own_effects_restored: 0, differences: [] },
    });
    expect(out.rows[1]?.func?.is_start).toBe(false);
    expect(out.rows[2]).toMatchObject({ verify: { status: "not-applicable" } });
    expect(out.rows[3]).toMatchObject({ status: "non-image", region: "private", address: { module: null } });
    expect(out.rows[4]).toMatchObject({ status: "error", issue: { code: "address_unmapped" } });
    expect(out.modules[0]).toMatchObject({
      runtime_base: hex(GAME_BASE),
      base_source: "pe-header",
      runtime_matches_file: true,
    });
    expect(out).toMatchObject({ confidence: "derived", authority: "live-process" });
    const draft = ev.drafts.at(-1);
    expect(draft?.capture).toBeDefined();
    expect(draft?.subject).toMatchObject({ kind: "process-instance" });
    expect(draft?.evidence_links).toEqual([`ev_${"9".repeat(64)}`]);
    expect(draft?.locations).toHaveLength(3);
  });

  it("downgrades to inferred on an image digest mismatch or unexplained bytes and records an auto-unknown", async () => {
    const physics = exportRva("physics_step");
    const before = ev.autoUnknowns.length;
    const out = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await call("map_address", {
          session_id: LIVE,
          addresses: [`+${hex(physics)}`],
          expected_image_sha256: "0".repeat(64),
        }),
      ),
    );
    expect(out.rows[0]?.image_check).toBe("mismatch");
    expect(out.confidence).toBe("inferred");
    expect(out.limitations).toContain(LIMITATIONS.IMAGE_MISMATCH);
    expect(ev.autoUnknowns.length).toBe(before + 1);
    // a patched .rdata byte (outside the code footprint) is unexplained
    const rdata = game.pe.sections.find((s) => s.name === ".rdata");
    proc.write(GAME_BASE + BigInt((rdata?.rva ?? 0) + 0x20), Uint8Array.from([0x99]));
    const bytes = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await call("map_address", { session_id: LIVE, addresses: [`+${hex((rdata?.rva ?? 0) + 0x20)}`] }),
      ),
    );
    expect(bytes.rows[0]?.verify).toMatchObject({
      status: "mismatch",
      differences: [{ size: 1, class: "unexplained" }],
    });
    expect(bytes.confidence).toBe("inferred");
    expect(bytes.limitations).toContain(LIMITATIONS.BYTES_MISMATCH);
    expect(bytes.modules[0]?.runtime_matches_file).toBe(false);
    // the record keeps the differing bytes (a byte field), the inline result does not
    const recorded = ev.drafts.at(-1)?.result as { rows: { verify: { differences: { live_hex: string }[] } }[] };
    expect(recorded.rows[0]?.verify.differences[0]?.live_hex).toBe("99");
    expect(JSON.stringify(bytes)).not.toContain("live_hex");
  });

  it("registers caller symbols (Ghidra) first and names rows with them", async () => {
    const exported = new Set(Object.values(game.pe.exportRvas));
    const hidden = await firstHiddenFunction(exported);
    const out = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await call("map_address", {
          session_id: LIVE,
          addresses: [`+${hex(hidden + 2)}`],
          symbols: [{ static_va: hex(0x140000000 + hidden), name: "Car::integrate" }],
          symbols_module: "game_sim.exe",
          symbols_source: "ghidra",
          verify_bytes: 0,
        }),
      ),
    );
    expect(out.symbols_registered).toBe(1);
    expect(out.rows[0]?.address?.symbol).toMatchObject({ name: "Car::integrate", kind: "caller", offset: "0x2" });
    expect(out.rows[0]?.func?.name).toBe("Car::integrate");
    expect(out.authority).toBe("imported");
    expect(out.limitations).toContain(LIMITATIONS.CALLER_SYMBOL_NAMES);
    const [caller, map] = ev.drafts.slice(-2);
    expect(caller?.predicate_type).toBe("bea.symbols.caller");
    expect(caller).toMatchObject({
      confidence: "inferred",
      authority: "imported",
      subject: { kind: "image", image_sha256: game.artifactSha256 },
    });
    expect(map?.evidence_links).toContain(out.rows[0]?.address?.symbol?.evidence_id);
    expect(ev.blobs.at(-1) === undefined ? "" : Buffer.from(ev.blobs.at(-1) ?? []).toString()).toContain(
      "Car::integrate",
    );
  });

  it("maps against an emulation session's images without byte verification", async () => {
    const out = mapAddressOutputSchema.parse(
      expectToolSuccess(
        await call("map_address", {
          session_id: EMU,
          addresses: [`$main:${hex(0x140000000 + exportRva("physics_step"))}`],
        }),
      ),
    );
    expect(out.rows[0]).toMatchObject({
      status: "mapped",
      verify: null,
      address: { va: hex(0x140000000 + exportRva("physics_step")), static_base_source: "emulation" },
    });
    expect(out.modules[0]).toMatchObject({ base_source: "emulation" });
    // The rows are computed from the emulated image's PE facts, so the map cites that image's bea.image.pe summary
    // (S2 invariant 6) and weakest-parent authority is static-artifact (S2 §18.2 allows only live-process or
    // static-artifact for a map); the space itself is flagged by base_source "emulation" and EMULATED_IMAGE_SPACE.
    expect(out.authority).toBe("static-artifact");
    expect(out.confidence).toBe("derived");
    const summary = ev.records.findLast((r) => r.predicate_type === "bea.image.pe");
    expect(ev.records.find((r) => r.evidence_id === out.evidence_id)?.evidence_links).toEqual([summary?.evidence_id]);
    expect(out.limitations).toContain(LIMITATIONS.EMULATED_IMAGE_SPACE);
    expect(
      parseToolError(
        await call("map_address", { session_id: "00000000-0000-4000-8000-000000000000", addresses: ["+0x1"] }),
      ).code,
    ).toBe("session_not_found");
  });
});

describe.skipIf(skip)("list_module_symbols over MCP", () => {
  it("lists exports, .pdata functions and imports of a file on disk, paged with a total", async () => {
    const exports = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(await call("list_module_symbols", { pe_path: game.path, filter: "physics" })),
    );
    expect(exports.rows).toContainEqual(
      expect.objectContaining({
        name: "physics_step",
        rva: hex(exportRva("physics_step")),
        kind: "function",
        va: null,
        forwarder: null,
      }),
    );
    expect(exports).toMatchObject({
      module: "game_sim.exe",
      image_sha256: game.artifactSha256,
      preferred_base: "0x140000000",
      kind: "exports",
    });
    expect(exports).toMatchObject({
      predicate_type: "bea.symbols.module",
      confidence: "observed",
      authority: "static-artifact",
    });
    const functions = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(
        await call("list_module_symbols", { pe_path: game.path, kind: "functions", filter: "physics_step" }),
      ),
    );
    expect(functions.rows).toEqual([
      {
        rva: hex(game.pe.pdata["physics_step"]?.rva ?? 0),
        size: game.pe.pdata["physics_step"]?.size,
        name: "physics_step",
      },
    ]);
    const imports = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(await call("list_module_symbols", { pe_path: game.path, kind: "imports", limit: 2 })),
    );
    expect(imports.rows).toHaveLength(2);
    expect(imports.page).toMatchObject({ offset: 0, limit: 2, next_offset: 2 });
    expect(imports.page.total).toBeGreaterThan(2);
    expect(imports.limitations).toContain(LIMITATIONS.IMPORTS_NOT_RESOLVED);
    const sleep = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(await call("list_module_symbols", { pe_path: game.path, kind: "imports", filter: "!Sleep" })),
    );
    expect(sleep.rows[0]).toMatchObject({ module: "KERNEL32.dll", name: "Sleep", slot_va: null, resolved: null });
  });

  it("lists a live module with runtime VAs and resolves IAT slots to Locs", async () => {
    const pe = await bea.app.services.pe.images.open(game.path);
    if (!pe.ok) throw new Error("open");
    const sleepSlot = (await pe.value.imports()).find((i) => i.name === "Sleep")?.slot_rva ?? 0;
    const k32 = await bea.app.services.pe.images.open(join(SYS, "kernel32.dll"));
    if (!k32.ok) throw new Error("open");
    const sleepRva = (await k32.value.exports()).find((e) => e.name === "Sleep")?.rva ?? 0;
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(KERNEL32_BASE + BigInt(sleepRva));
    proc.write(GAME_BASE + BigInt(sleepSlot), value);
    const out = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(await call("list_module_symbols", { session_id: LIVE, kind: "imports", filter: "!Sleep" })),
    );
    expect(out.rows[0]).toMatchObject({
      slot_va: hex(GAME_BASE + BigInt(sleepSlot)),
      resolved: { at: `KERNEL32.DLL+${hex(sleepRva)}`, sym: "Sleep" },
    });
    expect(out.confidence).toBe("derived");
    const exports = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(
        await call("list_module_symbols", { session_id: LIVE, module: "game_sim", filter: "physics_step" }),
      ),
    );
    expect(exports.rows[0]).toMatchObject({ va: hex(GAME_BASE + BigInt(exportRva("physics_step"))) });
    const missing = parseToolError(await call("list_module_symbols", { session_id: LIVE, module: "nosuch.dll" }));
    expect(missing).toMatchObject({ code: "address_unmapped", recovery: { kind: "refresh_module_map" } });
  });

  it("lists an emulated module at its emulated base, derived from the image's PE summary", async () => {
    const out = listModuleSymbolsOutputSchema.parse(
      expectToolSuccess(await call("list_module_symbols", { session_id: EMU, filter: "physics_step" })),
    );
    expect(out.rows[0]).toMatchObject({
      name: "physics_step",
      va: hex(0x140000000 + exportRva("physics_step")),
    });
    expect(out).toMatchObject({ confidence: "derived", authority: "static-artifact" });
    const links = ev.records.find((r) => r.evidence_id === out.evidence_id)?.evidence_links ?? [];
    expect(links).toHaveLength(1);
    expect(ev.records.find((r) => r.evidence_id === links[0])).toMatchObject({
      predicate_type: "bea.image.pe",
      subject: { kind: "image", image_sha256: game.artifactSha256 },
    });
  });
});

/** The first .pdata function of game_sim that is not exported (a "static" function only Ghidra names). */
const firstHiddenFunction = async (exported: ReadonlySet<number>): Promise<number> => {
  const pe = await bea.app.services.pe.images.open(game.path);
  if (!pe.ok) throw new Error("open");
  for (const entry of (await pe.value.functions()).entries())
    if (entry.primary_begin === entry.begin && !exported.has(entry.begin) && entry.end - entry.begin > 8)
      return entry.begin;
  throw new Error("no unexported function");
};
