import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { captureDumpBundle, type BundleDeps } from "../../../src/application/dump/captureBundle.js";
import { dumpModuleImage, dumpRawRange, moduleExpr, type DumpDeps } from "../../../src/application/dump/dumpMemory.js";
import { verifyDumpBundle } from "../../../src/application/dump/verifyDumpBundle.js";
import { sha256Hex } from "../../../src/domain/canonical.js";
import { DUMP_LIMITATIONS } from "../../../src/domain/evidence/limitations/dump.js";
import type { OutputPathPolicy } from "../../../src/domain/outputPaths.js";
import { formatHex } from "../../../src/shared/hex.js";
import {
  createEvidenceLog,
  disposeEvidenceLog,
  FakeTarget,
  fakeAddress,
  fakeEvidence,
  fakeLiveSession,
  fakePe,
  GAME_BASE,
  HEAP,
  PI,
  TEB,
  TLS_BLOCK,
  testOp,
  type EvidenceLog,
} from "./dumpFakes.js";
import { fileSectionBytes, mapPe } from "./peBuilder.js";

let root: string;
let policy: OutputPathPolicy;
let log: EvidenceLog;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "bea-wp13-svc-"));
  policy = {
    platform: process.platform === "win32" ? "win32" : "linux",
    exportsDir: join(root, "runs", "run_x", "exports"),
    allowedRoots: [join(root, "allowed")],
    systemRoots: [],
  };
  log = await createEvidenceLog();
});
afterEach(async () => {
  await disposeEvidenceLog(log);
  await rm(root, { recursive: true, force: true });
});

const setup = (patches: Parameters<typeof fakeAddress>[1]["patches"] = [], withPe = true) => {
  const target = new FakeTarget();
  const live = fakeLiveSession(target, log);
  const address = fakeAddress(target, { patches });
  const deps: DumpDeps = { evidence: fakeEvidence(log), address, pe: withPe ? fakePe(target) : null, policy };
  return { target, live, address, deps };
};
const peInput = { session_id: "s", module: "game_sim.exe" };

describe("dump_memory format pe (S6 §4.15, D-INT-45)", () => {
  it("realigned + preferred: BEA and foreign patches restored, unexplained bytes kept, .text equals the file, gaps zero-filled", async () => {
    const { target, live, deps, address } = setup([
      { rva: 0x1200, size: 4, class: "foreign-or-agent-patch" },
      { rva: 0x1300, size: 2, class: "unexplained" },
    ]);
    target.hook(GAME_BASE + 0x1760n);
    target.write(GAME_BASE + 0x1200n, Uint8Array.from([0xff, 0x25, 0, 0]));
    target.write(GAME_BASE + 0x1300n, Uint8Array.from([0xcc, 0xcc]));
    const res = await dumpModuleImage(
      deps,
      live.session,
      { module: "game_sim.exe", layout: "pe_realigned", rebaseTo: "preferred", liveBytes: false, input: peInput },
      testOp(),
    );
    if (!res.ok) throw new Error(JSON.stringify(res.error));
    const out = res.value;
    expect(out).toMatchObject({
      format: "pe",
      base: formatHex(GAME_BASE),
      layout: "pe_realigned",
      image_base_in_file: "0x140000000",
      module: {
        name: "game_sim.exe",
        file_sha256: sha256Hex(target.pe.file),
        rebased_to: "preferred",
        relocations_reverted: 3,
      },
      gaps: [{ va: formatHex(GAME_BASE + 0x5000n), size: 0x1000 }],
      restored_patches: [
        { rva: "0x1200", size: 4, source: "file-image" },
        { rva: "0x1760", size: 5, source: "bea-original" },
      ],
      predicate_type: "bea.memory.dump",
      instance_id: PI,
      coverage: { status: "partial", reasons: ["unreadable_ranges"] },
    });
    expect(out.limitations).toEqual(
      expect.arrayContaining([
        DUMP_LIMITATIONS.LIVE_PATCHES_RESTORED(2),
        DUMP_LIMITATIONS.DUMP_IAT_NOT_REBUILT,
        DUMP_LIMITATIONS.DUMP_REBASE_RUNTIME_WRITES,
        DUMP_LIMITATIONS.DUMP_GAPS(1),
      ]),
    );
    expect(out.path).toBe(join(policy.exportsDir, `game_sim.exe-${out.sha256.slice(0, 8)}.pe`));
    const file = new Uint8Array(await readFile(out.path));
    expect(sha256Hex(file)).toBe(out.sha256);
    expect(file.length).toBe(target.pe.sizeOfImage);
    const expected = fileSectionBytes(target.pe.file, 0x1000).slice();
    expected.set([0xcc, 0xcc], 0x300);
    expect(file.subarray(0x1000, 0x1000 + expected.length)).toEqual(expected);
    expect(file.subarray(0x5000, 0x6000).every((b) => b === 0)).toBe(true);
    // only non-writable sections are compared with the file
    expect(address.verified.map((v) => Number(v.va - GAME_BASE))).toEqual([0x1000, 0x3000, 0x6000]);
    expect(live.agent.calls.find((c) => c.method === "dumpStart")?.params).toMatchObject({
      items: [{ kind: "module", module: formatHex(GAME_BASE) }],
      suspend: "none",
      original_bytes: true,
    });
    const draft = log.drafts[0];
    expect(draft).toMatchObject({
      predicate_type: "bea.memory.dump",
      operation: "dump_memory",
      subject: { kind: "process-instance", instance_id: PI },
      blobs: [{ role: "dump.region" }],
    });
    expect(draft?.capture).toBeDefined();
    expect(draft?.locations?.[0]).toMatchObject({ kind: "address", va: formatHex(GAME_BASE) });
  });

  it("the same dump twice reuses the content-named default file; a caller out_path must not exist", async () => {
    const { live, deps } = setup();
    const req = {
      module: "game_sim.exe",
      layout: "mapped" as const,
      rebaseTo: "runtime" as const,
      liveBytes: false,
      input: peInput,
    };
    const first = await dumpModuleImage(deps, live.session, req, testOp());
    const second = await dumpModuleImage(deps, live.session, req, testOp());
    if (!first.ok || !second.ok) throw new Error("dump failed");
    expect(second.value.path).toBe(first.value.path);
    expect(second.value.image_base_in_file).toBe(formatHex(GAME_BASE));
    expect(second.value.module?.relocations_reverted).toBeNull();
    const taken = join(policy.exportsDir, "taken.pe");
    await writeFile(taken, "x");
    const third = await dumpModuleImage(deps, live.session, { ...req, outPath: taken }, testOp());
    expect(third.ok ? null : third.error).toMatchObject({ _tag: "FileOperationFailed", reason: "exists" });
    expect(await readFile(taken, "utf8")).toBe("x");
    const refused = await dumpModuleImage(
      deps,
      live.session,
      { ...req, outPath: join(root, "allowed", "x.cmd") },
      testOp(),
    );
    expect(refused.ok ? null : refused.error).toMatchObject({ _tag: "AccessDenied", reason: "policy" });
    await mkdir(join(root, "allowed"), { recursive: true });
    const allowed = await dumpModuleImage(
      deps,
      live.session,
      { ...req, outPath: join(root, "allowed", "game.bin") },
      testOp(),
    );
    expect(allowed.ok ? allowed.value.path : allowed.error).toBe(join(root, "allowed", "game.bin"));
  });
});

describe("dump_memory format pe: live bytes, degraded PE access, refusals", () => {
  it("live_bytes:true keeps the hook jump and skips every restore", async () => {
    const { target, live, deps, address } = setup([{ rva: 0x1200, size: 4, class: "foreign-or-agent-patch" }]);
    target.hook(GAME_BASE + 0x1760n);
    const res = await dumpModuleImage(
      deps,
      live.session,
      { module: "$main", layout: "mapped", rebaseTo: "runtime", liveBytes: true, input: peInput },
      testOp(),
    );
    if (!res.ok) throw new Error(JSON.stringify(res.error));
    expect(res.value.restored_patches).toEqual([]);
    expect(res.value.limitations).toContain(DUMP_LIMITATIONS.LIVE_BYTES_RAW);
    // GHIDRA-1: a mapped dump says it is a raw memory image, and points no loader at a COFF symbol table
    expect(res.value.limitations).toContain(DUMP_LIMITATIONS.DUMP_MAPPED_NOT_A_PE_FILE);
    expect(address.verified).toEqual([]);
    const file = new Uint8Array(await readFile(res.value.path));
    const lfanew = new DataView(file.buffer, file.byteOffset).getUint32(0x3c, true);
    expect(new DataView(file.buffer, file.byteOffset).getUint32(lfanew + 4 + 8, true)).toBe(0);
    expect(Array.from(file.subarray(0x1760, 0x1765))).toEqual([0xe9, 0x01, 0x02, 0x03, 0x04]);
    expect(live.agent.calls.find((c) => c.method === "dumpStart")?.params).toMatchObject({ original_bytes: false });
  });

  it("without the PE reader: mapped/runtime still works (BEA originals only); preferred is refused", async () => {
    const { target, live, deps } = setup([], false);
    target.hook(GAME_BASE + 0x1760n);
    const ok1 = await dumpModuleImage(
      deps,
      live.session,
      { module: "game_sim.exe", layout: "pe_realigned", rebaseTo: "runtime", liveBytes: false, input: peInput },
      testOp(),
    );
    if (!ok1.ok) throw new Error(JSON.stringify(ok1.error));
    expect(ok1.value.module?.file_sha256).toBeNull();
    expect(ok1.value.limitations).toContain(DUMP_LIMITATIONS.DUMP_FILE_IMAGE_UNAVAILABLE);
    expect(ok1.value.restored_patches).toEqual([{ rva: "0x1760", size: 5, source: "bea-original" }]);
    const refused = await dumpModuleImage(
      deps,
      live.session,
      { module: "game_sim.exe", layout: "mapped", rebaseTo: "preferred", liveBytes: false, input: peInput },
      testOp(),
    );
    expect(refused.ok ? null : refused.error._tag).toBe("CapabilityUnavailable");
  });

  it("an unknown module is address_unmapped; bytes holding a sensitive value are never written", async () => {
    const { live, deps } = setup();
    const missing = await dumpModuleImage(
      deps,
      live.session,
      { module: "nope.dll", layout: "mapped", rebaseTo: "runtime", liveBytes: false, input: peInput },
      testOp(),
    );
    expect(missing.ok ? null : missing.error._tag).toBe("AddressUnmapped");
    await disposeEvidenceLog(log);
    log = await createEvidenceLog("\u0011\u0011\u0011\u0011");
    const s2 = setup();
    const redacted = await dumpModuleImage(
      s2.deps,
      s2.live.session,
      { module: "game_sim.exe", layout: "mapped", rebaseTo: "runtime", liveBytes: false, input: peInput },
      testOp(),
    );
    expect(redacted.ok ? null : redacted.error).toMatchObject({ _tag: "AccessDenied", reason: "policy" });
  });

  it("moduleExpr quotes tokens with grammar characters", () => {
    expect(moduleExpr("game.exe")).toBe("game.exe+0x0");
    expect(moduleExpr("game.exe@0x7ff6a0000000")).toBe("game.exe@0x7ff6a0000000+0x0");
    expect(moduleExpr("my game+.exe")).toBe('"my game+.exe"+0x0');
  });
});

describe("dump_memory format raw", () => {
  it("streams the range with zero-filled gaps and records the region blob", async () => {
    const { live, deps } = setup();
    const res = await dumpRawRange(
      deps,
      live.session,
      { address: formatHex(HEAP), size: 0x3000, input: { session_id: "s", format: "raw" } },
      testOp(),
    );
    if (!res.ok) throw new Error(JSON.stringify(res.error));
    expect(res.value).toMatchObject({
      format: "raw",
      bytes: 0x3000,
      base: formatHex(HEAP),
      layout: null,
      module: null,
      gaps: [{ va: formatHex(HEAP + 0x2000n), size: 0x1000 }],
      restored_patches: [],
    });
    const file = new Uint8Array(await readFile(res.value.path));
    expect(file[0x123]).toBe(0x23);
    expect(file.subarray(0x2000).every((b) => b === 0)).toBe(true);
    expect(res.value.path.startsWith(policy.exportsDir)).toBe(true);
    expect(log.drafts[0]?.blobs?.[0]?.sha256).toBe(res.value.sha256);
  });

  it("nothing readable → memory_access_failed", async () => {
    const { live, deps } = setup();
    const res = await dumpRawRange(deps, live.session, { address: "0x900000", size: 0x2000, input: {} }, testOp());
    expect(res.ok ? null : res.error).toMatchObject({ _tag: "MemoryAccessFailed", access: "read" });
  });
});

describe("bea.dump/1 capture (S5 §10.2 R1–R11)", () => {
  const bundleDeps = (deps: DumpDeps, maxTotalBytes = 2048 * 1024 * 1024): BundleDeps => ({
    ...deps,
    version: "0.1.0",
    maxTotalBytes,
    now: () => 0,
    wallIso: () => "2026-10-28T00:00:00.000Z",
  });

  it("writes a verifiable bundle: TEB of the primary thread, real FPCW/MXCSR, static TLS, imports, readable map", async () => {
    const { target, live, deps } = setup([{ rva: 0x1200, size: 4, class: "foreign-or-agent-patch" }]);
    target.hook(GAME_BASE + 0x1760n);
    const res = await captureDumpBundle(
      bundleDeps(deps),
      live.session,
      { modules: ["$main"], regions: [{ address: formatHex(HEAP + 0x10n), size: 0x20 }], mode: "suspended" },
      testOp(),
    );
    if (!res.ok) throw new Error(JSON.stringify(res.error));
    expect(res.value.bundlePath).toBe(join(policy.exportsDir, res.value.bundleId));
    const verified = await verifyDumpBundle(res.value.bundlePath, { maxTotalBytes: 1 << 30 });
    if (!verified.ok) throw new Error(JSON.stringify(verified.error));
    const m = verified.value.manifest;
    expect(m.producer.evidence_id).toBe(res.value.evidenceId);
    expect(m.capture).toMatchObject({
      mode: "suspended",
      time_anchor: { seq: 9, effect_epoch: 2, module_map_epoch: 3 },
    });
    expect(m.threads.map((t) => [t.tid, t.primary])).toEqual([
      [100, true],
      [200, false],
    ]);
    const primary = m.threads[0]!;
    expect(primary.teb).toBe(formatHex(TEB));
    expect(primary.context).toMatchObject({ mxcsr: "0x1fa0", fpcw: "0x37f", rflags: "0x246", rsp: "0x1f8100" });
    expect(primary.tls.static_blocks).toEqual([
      { module: "game_sim.exe", index: 1, address: formatHex(TLS_BLOCK), size: 0x20 },
    ]);
    const tags = new Set(m.regions.map((r) => r.tag));
    for (const tag of ["module", "teb", "peb", "stack", "tls", "kuser_shared_data", "range"])
      expect(tags.has(tag as never), tag).toBe(true);
    expect(m.regions.some((r) => BigInt(r.base) <= TEB && TEB < BigInt(r.base) + BigInt(r.size))).toBe(true);
    expect(m.memory_map.every((r) => r.protection.startsWith("r"))).toBe(true);
    expect(m.imports).toEqual([
      {
        importer: "game_sim.exe",
        slot: formatHex(GAME_BASE + 0x3080n),
        name: "Sleep",
        ordinal: null,
        dll: "KERNEL32.dll",
        target: "0x7ffd00012340",
      },
    ]);
    expect(m.modules.find((x) => x.name === "game_sim.exe")).toMatchObject({
      captured: "partial",
      preferred_base: "0x140000000",
      file_sha256: sha256Hex(target.pe.file),
    });
    expect(m.modules.find((x) => x.name === "ntdll.dll")?.captured).toBe("none");
    // the module image regions carry original bytes: the hook and the foreign patch are gone
    const text = m.regions.find((r) => r.tag === "module" && r.protection === "r-x")!;
    const bytes = new Uint8Array(await readFile(join(res.value.bundlePath, "regions", `${text.sha256}.bin`)));
    // = the relocated on-disk .text (what the loader mapped before anything patched it)
    expect(bytes.subarray(0, 0x1800)).toEqual(mapPe(target.pe.file, GAME_BASE).subarray(0x1000, 0x2800));
    expect(res.value.detail.restoredPatches).toEqual([
      { rva: "0x1200", size: 4, source: "file-image" },
      { rva: "0x1760", size: 5, source: "bea-original" },
    ]);
    expect(m.limitations).toEqual(
      expect.arrayContaining([DUMP_LIMITATIONS.DUMP_SUSPENDED_PARTIAL, DUMP_LIMITATIONS.LIVE_PATCHES_RESTORED(2)]),
    );
    expect(log.drafts.at(-1)).toMatchObject({ predicate_type: "bea.dump.capture", subject: { instance_id: PI } });
    expect(res.value.detail.envelope.evidence_id).toBe(res.value.evidenceId);
    expect(live.agent.calls.find((c) => c.method === "dumpStart")?.params).toMatchObject({
      suspend: "all",
      original_bytes: true,
    });
  });

  it("refuses an unknown thread_id and a capture over emu.dump_max_mb; out_dir follows the policy", async () => {
    const { live, deps } = setup();
    const badThread = await captureDumpBundle(
      bundleDeps(deps),
      live.session,
      { modules: ["$main"], regions: [], mode: "running", threadId: 999 },
      testOp(),
    );
    expect(badThread.ok ? null : badThread.error).toMatchObject({
      _tag: "InputError",
      issues: [{ path: "bundle.thread_id" }],
    });
    const agentThread = await captureDumpBundle(
      bundleDeps(deps),
      live.session,
      { modules: ["$main"], regions: [], mode: "running", threadId: 300 },
      testOp(),
    );
    expect(agentThread.ok ? null : agentThread.error._tag).toBe("InputError");
    const big = await captureDumpBundle(
      bundleDeps(deps, 0x4000),
      live.session,
      { modules: ["$main"], regions: [], mode: "running" },
      testOp(),
    );
    expect(big.ok ? null : big.error).toMatchObject({ _tag: "ResourceConstraint", resource: "memory" });
    const refused = await captureDumpBundle(
      bundleDeps(deps),
      live.session,
      { modules: ["$main"], regions: [], mode: "running", outDir: join(root, "elsewhere", "b") },
      testOp(),
    );
    expect(refused.ok ? null : refused.error).toMatchObject({ _tag: "AccessDenied", reason: "policy" });
    const chosen = join(root, "allowed", "bundle1");
    await mkdir(join(root, "allowed"), { recursive: true });
    const placed = await captureDumpBundle(
      bundleDeps(deps),
      live.session,
      { modules: ["$main"], regions: [], mode: "running", outDir: chosen },
      testOp(),
    );
    if (!placed.ok) throw new Error(JSON.stringify(placed.error));
    expect(placed.value.bundlePath).toBe(chosen);
    expect(placed.value.limitations).toContain(DUMP_LIMITATIONS.DUMP_RUNNING_TORN);
    const again = await captureDumpBundle(
      bundleDeps(deps),
      live.session,
      { modules: ["$main"], regions: [], mode: "running", outDir: chosen },
      testOp(),
    );
    expect(again.ok ? null : again.error).toMatchObject({ _tag: "FileOperationFailed", reason: "exists" });
  });
});
