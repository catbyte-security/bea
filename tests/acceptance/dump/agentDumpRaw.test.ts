import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import type {
  BlobMessage,
  DumpManifest,
  DumpStartParams,
  JobMessage,
  ThreadState,
} from "../../../src/shared/agentProtocol.js";
import {
  fixtureArtifact,
  fridaSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { pidStatus } from "../../support/process/ownedPidLedger.js";
import { fileFacts, mapPe } from "../../unit/dump/peBuilder.js";

/**
 * WP13 raw-agent acceptance (wave rule CI-I1: raw agent RPCs only). The REAL feature file src/agent/dump.ts and its
 * pure helpers are bundled by frida.Compiler with a test entry that gives them the day-0 core plus a stand-in
 * originals overlay (the WP-AGENT seam dump.ts looks up at runtime), loaded into a game_sim this test spawns, and
 * driven through rpc.exports; blob and job messages are collected exactly as AgentChannel would. Everything spawned
 * here is killed in afterAll.
 */
const REPO = resolve(import.meta.dirname, "../../..");
const SKIP = fridaSkip();

const HARNESS = `
import { createCore } from "./state.js";
import { wrapAll } from "./rpc.js";
import * as dump from "./dump.js";

const c: any = createCore();
const originals: { address: NativePointer; bytes: number[] }[] = [];
c.originals = {
  overlay: (buf: ArrayBuffer, base: NativePointer) => {
    const u = new Uint8Array(buf);
    for (const o of originals) {
      const off = o.address.sub(base).toInt32();
      if (off >= 0 && off + o.bytes.length <= u.length) u.set(o.bytes, off);
    }
  },
};
c.phase = "ready";
dump.init(c);
const wrapped = wrapAll(c, { ...dump.rpc } as any);
const main = Process.mainModule;
rpc.exports = {
  ...wrapped,
  base: () => main.base.toString(),
  size: () => main.size,
  jsTid: () => c.jsTid,
  features: () => c.features,
  mainTid: () => {
    const end = main.base.add(main.size);
    const t = Process.enumerateThreads().find(
      (x) => x.entrypoint !== undefined && x.entrypoint.routine.compare(main.base) >= 0 && x.entrypoint.routine.compare(end) < 0,
    );
    return (t ?? Process.enumerateThreads()[0]).id;
  },
  registerOriginal: (rva: number, hex: string) => {
    const bytes = hex.match(/../g)!.map((b) => parseInt(b, 16));
    originals.push({ address: main.base.add(rva), bytes });
  },
  frame: () => {
    const w = main.getExportByName("g_world").readPointer();
    return w.isNull() ? -1 : w.add(8).readPointer().add(0x38).readU32();
  },
};
`;

interface Rpc {
  [method: string]: (...args: unknown[]) => Promise<unknown>;
}
type Reply<T> = { ok: true; value: T } | { ok: false; error: Record<string, unknown> };

let stage = "";
let frida: typeof import("frida");
/** This file's own DeviceManager (never the singleton): closing it lets Frida delete its %TEMP% agent copies. */
let dm: InstanceType<(typeof import("frida"))["DeviceManager"]> | undefined;
let device: Awaited<ReturnType<(typeof import("frida"))["getLocalDevice"]>>;
let pidcheck: string | null = null;
let pid = 0;
let session: Awaited<ReturnType<typeof device.attach>> | null = null;
let rpc: Rpc;
let game: FixtureArtifact;
let base = 0n;
const blobs = new Map<string, { parts: BlobMessage[]; data: Buffer[] }>();
const jobs = new Map<string, JobMessage>();

const run = async (params: DumpStartParams): Promise<{ manifest: DumpManifest; bytes: Map<string, Buffer> }> => {
  const started = (await rpc["dumpStart"]?.(params)) as Reply<{ job_id: string; planned_blobs: number }>;
  if (!started.ok) throw new Error(`dumpStart failed: ${JSON.stringify(started.error)}`);
  const job = await vi.waitFor(
    () => {
      const done = jobs.get(started.value.job_id);
      if (done === undefined) throw new Error("job not finished");
      return done;
    },
    { timeout: 20_000, interval: 25 },
  );
  expect(job.state, JSON.stringify(job.error)).toBe("done");
  const manifest = job.result as DumpManifest;
  const bytes = new Map<string, Buffer>();
  for (const region of manifest.regions) {
    const got = blobs.get(region.blob);
    expect(got, region.blob).toBeDefined();
    expect(got?.parts.at(-1)?.last).toBe(true);
    expect(got?.parts.every((p) => p.job === started.value.job_id && p.total === region.size)).toBe(true);
    bytes.set(region.blob, Buffer.concat(got?.data ?? []));
  }
  return { manifest, bytes };
};

const startOnce = async (): Promise<void> => {
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "game_sim");
  if (artifact === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
  game = artifact;
  pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
  frida = (await import("frida")).default as unknown as typeof import("frida");
  stage = await mkdtemp(join(tmpdir(), "bea-wp13-agent-"));
  await cp(join(REPO, "src", "agent"), join(stage, "agent"), { recursive: true });
  await cp(join(REPO, "src", "shared"), join(stage, "shared"), { recursive: true });
  await writeFile(join(stage, "agent", "wp13Harness.ts"), HARNESS);
  const compiler = new frida.Compiler();
  const bundle = await compiler.build(join(stage, "agent", "wp13Harness.ts"), {
    projectRoot: stage,
    bundleFormat: "esm",
    typeCheck: "none",
    sourceMaps: "omitted",
    compression: "none",
  });
  dm = new frida.DeviceManager();
  device = await dm.getDeviceById("local", 5000);
  pid = await device.spawn([game.path], { cwd: game.path.replace(/[\\/][^\\/]+$/u, ""), stdio: frida.Stdio.Pipe });
  session = await device.attach(pid);
  const script = await session.createScript(bundle, { runtime: frida.ScriptRuntime.QJS });
  script.message.connect((message, data) => {
    if (message.type !== "send") return;
    const payload = message.payload as { bea?: string };
    if (payload.bea === "blob") {
      const blob = payload as BlobMessage;
      const entry = blobs.get(blob.blob) ?? { parts: [], data: [] };
      entry.parts.push(blob);
      entry.data.push(data ?? Buffer.alloc(0));
      blobs.set(blob.blob, entry);
    } else if (payload.bea === "job") jobs.set((payload as JobMessage).job, payload as JobMessage);
  });
  await script.load();
  rpc = script.exports as unknown as Rpc;
  await device.resume(pid);
  base = BigInt((await rpc["base"]?.()) as string);
  await vi.waitFor(
    async () => {
      if (((await rpc["frame"]?.()) as number) < 2) throw new Error("game loop not running yet");
    },
    { timeout: 10_000, interval: 25 },
  );
};
let started: Promise<void> | null = null;
const start = (): Promise<void> => (started ??= startOnce());

afterAll(async () => {
  try {
    await session?.detach();
  } catch {
    // the process may already be gone
  }
  if (pid !== 0) {
    try {
      await device.kill(pid);
    } catch {
      // already exited
    }
    // DeviceManager.close() deletes Frida's %TEMP%\frida-<id> agent copies (~45 MB) only once no target maps them;
    // process.kill(pid, 0) reports the exit ~10 ms too early, so wait for the process object itself (pidcheck)
    await vi.waitFor(() => expect(pidStatus(pidcheck, pid).alive).toBe(false), { interval: 25, timeout: 5000 });
  }
  await dm?.close();
  if (stage !== "") await rm(stage, { recursive: true, force: true });
});

describe.skipIf(SKIP !== false)(`raw agent: dump jobs on game_sim${skipNote(SKIP)}`, () => {
  beforeAll(start, 120_000);

  it("registers the dump feature", async () => {
    expect(await rpc["features"]?.()).toContain("dump");
  });

  it("dumps the main image in mapped layout: .text equals the relocated file, BEA originals spliced and reported", async () => {
    const physics = game.pe.exportRvas["physics_step"] ?? 0;
    const live = (await rpc["size"]?.()) as number;
    await rpc["registerOriginal"]?.(physics, "cccccccccc");
    const { manifest, bytes } = await run({
      items: [{ kind: "module", module: `0x${base.toString(16)}` }],
      suspend: "none",
      max_total_bytes: 64 * 1024 * 1024,
      original_bytes: true,
      chunk_bytes: 64 * 1024,
    });
    expect(manifest).toMatchObject({ format: "bea-dump/1", pid, truncated: false });
    expect(manifest.modules).toEqual([
      {
        name: "game_sim.exe",
        path: expect.any(String),
        base: `0x${base.toString(16)}`,
        size: live,
        blob: manifest.regions[0]?.blob,
      },
    ]);
    const region = manifest.regions[0]!;
    expect(region).toMatchObject({ kind: "module", size: live, module: "game_sim.exe" });
    expect(region.bea_patches_restored).toEqual([{ offset: physics, size: 5 }]);
    expect(blobs.get(region.blob)!.parts.length).toBeGreaterThan(1);
    const image = bytes.get(region.blob)!;
    expect(image.length).toBe(live);
    const file = new Uint8Array(await readFile(game.path));
    const expected = Buffer.from(mapPe(file, base));
    expected.fill(0xcc, physics, physics + 5);
    const text = fileFacts(file).sections.find((s) => (s.characteristics & 0x20000000) !== 0)!;
    const n = Math.min(text.virtualSize, text.rawSize);
    expect(image.subarray(text.rva, text.rva + n).equals(expected.subarray(text.rva, text.rva + n))).toBe(true);
    // without original_bytes the live bytes come back
    const raw = await run({
      items: [{ kind: "module", module: "game_sim.exe" }],
      suspend: "none",
      max_total_bytes: 64 * 1024 * 1024,
      original_bytes: false,
    });
    const rawImage = raw.bytes.get(raw.manifest.regions[0]!.blob)!;
    expect(raw.manifest.regions[0]?.bea_patches_restored).toEqual([]);
    expect(rawImage[physics]).not.toBe(0xcc);
  });

  it("suspend:all captures the main thread's real FPCW/MXCSR, TEB, PEB, TLS and stack; the game keeps running", async () => {
    const tid = (await rpc["mainTid"]?.()) as number;
    const { manifest, bytes } = await run({
      items: [
        { kind: "thread", tid, stack_bytes: 0x4000, teb: true, tls: true, xmm: true },
        { kind: "range", base: "0x7ffe0000", size: 0x1000 },
      ],
      suspend: "all",
      max_total_bytes: 64 * 1024 * 1024,
      original_bytes: true,
    });
    expect(manifest.taken.suspended).toBe(true);
    const state = manifest.threads[0] as ThreadState;
    expect(state.tid).toBe(tid);
    expect(state.fpcw).toBe("0x37f"); // gcc/msvcrt fixtures run with FPCW 0x37F (S4 F14), not 0x27F
    expect(Number(state.mxcsr) & 0xffc0).toBe(0x1f80);
    expect(state.xmm).toHaveLength(16);
    expect(Object.keys(state.registers).sort()).toEqual(
      [
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "r8",
        "r9",
        "rax",
        "rbp",
        "rbx",
        "rcx",
        "rdi",
        "rdx",
        "rip",
        "rsi",
        "rsp",
      ].sort(),
    );
    const teb = manifest.regions.find((r) => r.kind === "teb")!;
    expect(teb.base).toBe(state.teb);
    expect(teb.size).toBe(0x2000);
    const tebBytes = bytes.get(teb.blob)!;
    expect(`0x${tebBytes.readBigUInt64LE(0x30).toString(16)}`).toBe(state.teb); // NT_TIB.Self
    expect(`0x${tebBytes.readBigUInt64LE(0x60).toString(16)}`).toBe(state.peb);
    expect(manifest.regions.some((r) => r.kind === "peb")).toBe(true);
    expect(manifest.regions.some((r) => r.kind === "stack")).toBe(true);
    const rsp = BigInt(state.registers["rsp"] ?? "0x0");
    const stack = manifest.regions.find((r) => r.kind === "stack")!;
    expect(BigInt(stack.base) <= rsp && rsp < BigInt(stack.base) + BigInt(stack.size)).toBe(true);
    const kusd = manifest.regions.find((r) => r.base === "0x7ffe0000")!;
    expect(kusd.holes).toEqual([]);
    expect(bytes.get(kusd.blob)!.readUInt32LE(0x26c)).toBe(10); // NtMajorVersion
    const f0 = (await rpc["frame"]?.()) as number;
    await vi.waitFor(async () => expect((await rpc["frame"]?.()) as number).toBeGreaterThan(f0), {
      timeout: 5000,
      interval: 25,
    });
  });
});

describe.skipIf(SKIP !== false)(`raw agent: unreadable tails and thread state on game_sim${skipNote(SKIP)}`, () => {
  beforeAll(start, 120_000);

  it("a range running off the image reports the unreadable tail as a zero-filled hole", async () => {
    const size = (await rpc["size"]?.()) as number;
    const start = base + BigInt(size) - 0x1000n;
    const { manifest, bytes } = await run({
      items: [{ kind: "range", base: `0x${start.toString(16)}`, size: 0x2000 }],
      suspend: "none",
      max_total_bytes: 0x2000,
      original_bytes: false,
    });
    const region = manifest.regions[0]!;
    expect(region.holes).toEqual([{ offset: 0x1000, size: 0x1000, reason: "unreadable" }]);
    expect(
      bytes
        .get(region.blob)!
        .subarray(0x1000)
        .every((b) => b === 0),
    ).toBe(true);
  });

  it("captureThreadState: the agent's own thread is refused, an unknown thread is NotFound, a live thread answers", async () => {
    const own = (await rpc["captureThreadState"]?.({
      tid: (await rpc["jsTid"]?.()) as number,
      xmm: false,
      teb: true,
      tls: false,
    })) as Reply<ThreadState>;
    expect(own.ok ? null : own.error["_tag"]).toBe("BadParams");
    const unknown = (await rpc["captureThreadState"]?.({
      tid: 4,
      xmm: false,
      teb: true,
      tls: false,
    })) as Reply<ThreadState>;
    expect(unknown.ok ? null : unknown.error).toMatchObject({ _tag: "NotFound", what: "thread" });
    const tid = (await rpc["mainTid"]?.()) as number;
    const state = (await rpc["captureThreadState"]?.({ tid, xmm: true, teb: true, tls: true })) as Reply<ThreadState>;
    if (!state.ok) throw new Error(JSON.stringify(state.error));
    expect(state.value).toMatchObject({ tid, fpcw: "0x37f" });
    expect(state.value.tls?.tls_slots).toHaveLength(64);
    expect(state.value.stack).not.toBeNull();
  });
});
