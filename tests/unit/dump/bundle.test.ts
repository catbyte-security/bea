import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  composeRegion,
  planBundleRegions,
  writeDumpBundle,
  type CapturedRegion,
  type ManifestDraft,
} from "../../../src/application/dump/DumpBundleWriter.js";
import { verifyDumpBundle } from "../../../src/application/dump/verifyDumpBundle.js";
import { canonicalJson, sha256Hex } from "../../../src/domain/canonical.js";
import {
  asDumpManifestV1,
  dumpManifestIssues,
  dumpManifestSchema,
  type DumpManifest,
} from "../../../src/domain/dumpBundle.js";
import { ok } from "../../../src/domain/result.js";
import type { Hex } from "../../../src/shared/hex.js";

const PAGE = 0x1000;
const fill = (size: number, seed: number) => new Uint8Array(size).map((_, i) => (i * 31 + seed) & 0xff);
const region = (over: Partial<CapturedRegion> & { base: bigint; size: number; bytes?: Uint8Array }): CapturedRegion => {
  const bytes = over.bytes ?? fill(over.size, Number(over.base & 0xffn));
  return {
    tag: "range",
    protection: "rw-",
    module: null,
    holes: [],
    load: async () => ok(bytes),
    ...over,
  };
};

const ZERO_CTX = Object.fromEntries(
  [
    "rip",
    "rsp",
    "rbp",
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
  ].map((k) => [k, "0x0"]),
) as unknown as DumpManifest["threads"][number]["context"];

const draft = (teb: Hex): ManifestDraft => ({
  schema: "bea.dump/1",
  created_at: "2026-10-28T00:00:00.000Z",
  producer: {
    tool: "bea",
    version: "0.1.0",
    operation: "dump_memory",
    evidence_id: `ev_${"e".repeat(64)}`,
    instance_id: `pi_${"a".repeat(64)}`,
  },
  process: {
    pid: 4242,
    image_path: "C:\\games\\game.exe",
    image_sha256: "c".repeat(64),
    arch: "x64",
    os: { platform: "windows", version: "10.0.26200" },
  },
  capture: { mode: "suspended", time_anchor: { seq: 7, effect_epoch: 0, module_map_epoch: 1 }, duration_ms: 12 },
  modules: [
    {
      name: "game.exe",
      path: "C:\\games\\game.exe",
      base: "0x140000000",
      size: 0x6000,
      file_sha256: "c".repeat(64),
      preferred_base: "0x140000000",
      timestamp: 0,
      captured: "full",
    },
  ],
  memory_map: [
    { base: "0x140000000", size: 0x1000, protection: "r--", module: "game.exe" },
    { base: "0x140001000", size: 0x2000, protection: "r-x", module: "game.exe" },
    { base: "0x140003000", size: 0x3000, protection: "rw-", module: "game.exe" },
    { base: "0x30000", size: 0x2000, protection: "rw-", module: null },
  ],
  threads: [
    {
      tid: 100,
      primary: true,
      teb,
      context: { ...ZERO_CTX, mxcsr: "0x1fa0", fpcw: "0x37f", rflags: "0x246" },
      stack: { base: "0x200000", limit: "0x1f0000" },
      tls: { slots_array: null, static_blocks: [] },
    },
  ],
  peb: "0x50000",
  imports: [],
  limitations: [],
});

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "bea-wp13-bundle-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("planBundleRegions (S5 §10.1 layout)", () => {
  it("splits a module image at the readable map's protection runs and drops unmapped parts", () => {
    const image = region({ base: 0x1_4000_0000n, size: 0x7000, tag: "module", module: "game.exe", protection: "r-x" });
    const planned = planBundleRegions(
      [image],
      [
        { base: 0x1_4000_0000n, size: 0x1000, protection: "r--", module: "game.exe" },
        { base: 0x1_4000_1000n, size: 0x2000, protection: "r-x", module: "game.exe" },
        { base: 0x1_4000_3000n, size: 0x3000, protection: "rw-", module: "game.exe" },
      ],
    );
    expect(planned.map((r) => [r.base.toString(16), r.size, r.protection, r.tag])).toEqual([
      ["140000000", 0x1000, "r--", "module"],
      ["140001000", 0x2000, "r-x", "module"],
      ["140003000", 0x3000, "rw-", "module"],
    ]);
    expect(planned.every((r) => r.unreadable.length === 0)).toBe(true);
  });

  it("never gives a straddling range's pages another protection: .data stays writable (DATA-6)", () => {
    const map = [
      { base: 0x1_4000_0000n, size: 0x1000, protection: "r--", module: "game.exe" },
      { base: 0x1_4000_1000n, size: 0x1000, protection: "r-x", module: "game.exe" },
      { base: 0x1_4000_2000n, size: 0x1000, protection: "r--", module: "game.exe" },
      { base: 0x1_4000_3000n, size: 0x1000, protection: "rw-", module: "game.exe" },
    ];
    const image = region({ base: 0x1_4000_0000n, size: 0x4000, tag: "module", module: "game.exe", protection: "r-x" });
    // a range from the last .rdata page into .data (its own protection is its first page's: r--)
    const straddle = region({ base: 0x1_4000_2800n, size: 0x1000, tag: "range", protection: "r--" });
    const rows = (planned: ReturnType<typeof planBundleRegions>) =>
      planned.map((r) => [r.base.toString(16), r.size, r.protection, r.tag, r.module]);
    expect(rows(planBundleRegions([image, straddle], map))).toEqual([
      ["140000000", 0x1000, "r--", "module", "game.exe"],
      ["140001000", 0x1000, "r-x", "module", "game.exe"],
      ["140002000", 0x1000, "r--", "module", "game.exe"],
      ["140003000", 0x1000, "rw-", "module", "game.exe"],
    ]);
    // a range alone over code, rodata and data takes the map's protection per run
    const span = region({ base: 0x1_4000_1000n, size: 0x3000, tag: "range", protection: "r-x" });
    expect(rows(planBundleRegions([span], map)).map((r) => r[2])).toEqual(["r-x", "r--", "rw-"]);
  });

  it("aligns to pages, merges overlapping captures and lists pages no capture read", async () => {
    const tls = region({ base: 0x30010n, size: 0x40, tag: "tls" });
    const teb = region({ base: 0x30000n, size: 0x2000, tag: "teb", holes: [{ offset: 0x1000, size: 0x1000 }] });
    const planned = planBundleRegions([tls, teb], []);
    expect(planned).toHaveLength(1);
    expect(planned[0]).toMatchObject({ base: 0x30000n, size: 0x2000, tag: "tls" });
    // page 0x30000: the tls capture covers only 0x40 bytes of it, the teb capture all of it → readable
    // page 0x31000: inside the teb's hole and outside the tls capture → unreadable
    expect(planned[0]?.unreadable).toEqual([0x31000n]);
    const bytes = await composeRegion(planned[0]!, (src) => src.load());
    if (!bytes.ok) throw new Error("compose failed");
    expect(bytes.value.subarray(0, 0x1000)).toEqual((await teb.load()).ok ? fill(0x2000, 0).subarray(0, 0x1000) : null);
    expect(bytes.value.subarray(0x1000).every((b) => b === 0)).toBe(true);
  });
});

describe("writeDumpBundle + verifyDumpBundle", () => {
  const regions = () =>
    planBundleRegions(
      [
        region({ base: 0x1_4000_0000n, size: 0x6000, tag: "module", module: "game.exe", protection: "r-x" }),
        region({ base: 0x30000n, size: 0x2000, tag: "teb" }),
        region({ base: 0x7ffe0000n, size: PAGE, tag: "kuser_shared_data", protection: "r--" }),
      ],
      [
        { base: 0x1_4000_0000n, size: 0x1000, protection: "r--", module: "game.exe" },
        { base: 0x1_4000_1000n, size: 0x2000, protection: "r-x", module: "game.exe" },
        { base: 0x1_4000_3000n, size: 0x3000, protection: "rw-", module: "game.exe" },
      ],
    );

  it("writes a JCS manifest whose bundle_id is its own digest, content-addressed regions, and verifies", async () => {
    const target = join(dir, "bundle");
    const written = await writeDumpBundle("dump_memory", draft("0x30000"), regions(), target, dir);
    if (!written.ok) throw new Error(JSON.stringify(written.error));
    expect(written.value.path).toBe(target);
    const text = await readFile(join(target, "manifest.json"), "utf8");
    expect(text).toBe(canonicalJson(JSON.parse(text)));
    const { bundle_id: id, ...rest } = JSON.parse(text) as DumpManifest;
    expect(id).toBe(`dump_${sha256Hex(canonicalJson(rest as never))}`);
    expect(written.value.manifestSha256).toBe(sha256Hex(text));
    const files = await readdir(join(target, "regions"));
    // identical regions are stored once (the sample pattern repeats every page)
    expect(files.sort()).toEqual([...new Set(written.value.manifest.regions.map((r) => `${r.sha256}.bin`))].sort());
    expect((await readdir(dir)).filter((n) => n.includes("staging"))).toEqual([]);
    const verified = await verifyDumpBundle(target, { maxTotalBytes: 2048 * 1024 * 1024 });
    if (!verified.ok) throw new Error(JSON.stringify(verified.error));
    expect(verified.value.manifest.regions.map((r) => r.tag)).toEqual([
      "teb",
      "kuser_shared_data",
      "module",
      "module",
      "module",
    ]);
    expect(verified.value.manifest.threads[0]?.context).toMatchObject({ mxcsr: "0x1fa0", fpcw: "0x37f" });
    expect(asDumpManifestV1(verified.value.manifest).schema).toBe("bea.dump/1");
  });

  it("derives the default directory from the bundle id and never replaces an existing target", async () => {
    const first = await writeDumpBundle("dump_memory", draft("0x30000"), regions(), (id) => join(dir, id), dir);
    if (!first.ok) throw new Error("write failed");
    expect(first.value.path).toBe(join(dir, first.value.bundleId));
    const again = await writeDumpBundle("dump_memory", draft("0x30000"), regions(), first.value.path, dir);
    expect(again.ok ? null : again.error).toMatchObject({ _tag: "FileOperationFailed", reason: "exists" });
    expect((await readdir(dir)).filter((n) => n.includes("staging"))).toEqual([]);
  });

  it("rejects tampering: region bytes, non-canonical text, a foreign bundle_id, missing files", async () => {
    const target = join(dir, "b");
    const written = await writeDumpBundle("dump_memory", draft("0x30000"), regions(), target, dir);
    if (!written.ok) throw new Error("write failed");
    const opts = { maxTotalBytes: 1 << 30 };
    const regionFile = join(target, "regions", `${written.value.manifest.regions[0]!.sha256}.bin`);
    const original = await readFile(regionFile);
    const tampered = Buffer.from(original);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    await writeFile(regionFile, tampered);
    expect((await verifyDumpBundle(target, opts)).ok ? null : "x").toBe("x");
    const res = await verifyDumpBundle(target, opts);
    expect(res.ok ? null : res.error).toMatchObject({ _tag: "EvidenceIntegrity", reason: "id-mismatch" });
    await writeFile(regionFile, original);
    const manifestFile = join(target, "manifest.json");
    const text = await readFile(manifestFile, "utf8");
    await writeFile(manifestFile, JSON.stringify(JSON.parse(text), null, 1));
    expect(await verifyDumpBundle(target, opts)).toMatchObject({ ok: false, error: { _tag: "InputError" } });
    const changed = { ...(JSON.parse(text) as DumpManifest), peb: "0x60000" };
    await writeFile(manifestFile, canonicalJson(changed as never));
    expect(await verifyDumpBundle(target, opts)).toMatchObject({ ok: false, error: { _tag: "EvidenceIntegrity" } });
    await writeFile(manifestFile, text);
    await rm(regionFile);
    expect(await verifyDumpBundle(target, opts)).toMatchObject({ ok: false, error: { _tag: "InputError" } });
    expect(await verifyDumpBundle(join(dir, "missing"), opts)).toMatchObject({
      ok: false,
      error: { _tag: "FileOperationFailed", reason: "missing" },
    });
  });

  it("refuses a bundle without the chosen thread's TEB, or over emu.dump_max_mb", async () => {
    const target = join(dir, "noteb");
    const written = await writeDumpBundle("dump_memory", draft("0x90000"), regions(), target, dir);
    if (!written.ok) throw new Error("write failed");
    const res = await verifyDumpBundle(target, { maxTotalBytes: 1 << 30 });
    expect(res.ok ? null : res.error).toMatchObject({ _tag: "InputError", issues: [{ path: "dump_path" }] });
    const ok2 = join(dir, "big");
    const w2 = await writeDumpBundle("dump_memory", draft("0x30000"), regions(), ok2, dir);
    if (!w2.ok) throw new Error("write failed");
    expect(await verifyDumpBundle(ok2, { maxTotalBytes: 0x4000 })).toMatchObject({
      ok: false,
      error: { _tag: "ResourceConstraint", resource: "memory" },
    });
  });
});

describe("dumpManifestIssues (pure constraints)", () => {
  const base = (): DumpManifest => ({
    ...draft("0x30000"),
    bundle_id: `dump_${"0".repeat(64)}`,
    regions: [
      {
        base: "0x30000",
        size: 0x2000,
        protection: "rw-",
        tag: "teb",
        module: null,
        sha256: "a".repeat(64),
        complete: true,
        unreadable_pages: [],
      },
    ],
  });
  it("accepts a well-formed manifest and flags each violated rule", () => {
    expect(dumpManifestSchema.safeParse(base()).success).toBe(true);
    expect(dumpManifestIssues(base(), { maxTotalBytes: 1 << 20 })).toEqual([]);
    const m = base();
    const bad: DumpManifest = {
      ...m,
      regions: [...m.regions, { ...m.regions[0]!, base: "0x31000", size: 0x1800, unreadable_pages: ["0x90000"] }],
      memory_map: [{ base: "0x10000", size: 0x1000, protection: "---", module: null }],
      threads: [],
    };
    const problems = dumpManifestIssues(bad, { maxTotalBytes: 0x1000, memoryLimitBytes: 256 * 1024 * 1024 }).map(
      (i) => i.problem,
    );
    expect(problems).toEqual(
      expect.arrayContaining([
        "region is not a non-empty run of 4 KiB pages",
        "unreadable page outside its region",
        "region overlaps another region",
        "memory_map lists only readable ranges",
        "exactly one primary thread is required",
        "total region bytes exceed emu.dump_max_mb",
        "total region bytes leave less than 256 MiB of the emulator memory limit",
      ]),
    );
    expect(dumpManifestIssues(base(), { maxTotalBytes: 1 << 20, threadId: 7 }).map((i) => i.problem)).toEqual([
      "the requested thread is not in the bundle",
    ]);
  });

  it("the strict schema refuses unknown keys and non-canonical hex", () => {
    expect(dumpManifestSchema.safeParse({ ...base(), extra: 1 }).success).toBe(false);
    expect(dumpManifestSchema.safeParse({ ...base(), peb: "0x0050000" }).success).toBe(false);
  });
});
