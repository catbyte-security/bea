import { spawn, type ChildProcess } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import type { DisassembleParams, DisassembleResult, InsnRow } from "../../../src/shared/agentProtocol.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { pidStatus } from "../../support/process/ownedPidLedger.js";

/**
 * WP6 raw-Frida acceptance of the agent `disassemble` RPC (no BEA host; DESIGN §8.4 wave rule: raw agent RPCs only).
 * A test bundle is compiled by frida.Compiler from the REAL src/agent/code.ts + its pure helpers, with a minimal core
 * whose `originals` service records the bytes under a real Interceptor hook (the S4 §8.4 OriginalBytes contract), and
 * is loaded into a game_sim.exe this test spawns itself. Expectations come from the fixture file bytes and the
 * fixture manifest (never from documents); assertions are pointer-free (RVAs).
 */
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const skip = fridaSkip() || gccSkip();

const TEST_ENTRY = `
import * as code from "./agent/code.js";
import { AGENT_LIMIT_DEFAULTS } from "./shared/agentLimits.js";

// OriginalBytes as S4 §8.4 describes it: bytes saved before each BEA patch, overlaid on request.
const saved: { base: NativePointer; bytes: Uint8Array }[] = [];
const keep: unknown[] = [];
const originals = {
  isPatched: (r: { base: NativePointer; size: number }): boolean =>
    saved.some((s) => s.base.compare(r.base.add(r.size)) < 0 && s.base.add(s.bytes.length).compare(r.base) > 0),
  overlay: (buf: ArrayBuffer, base: NativePointer): number => {
    const view = new Uint8Array(buf);
    let n = 0;
    for (const s of saved)
      for (let i = 0; i < s.bytes.length; i++) {
        const off = Number(BigInt(s.base.add(i).toString()) - BigInt(base.toString()));
        if (off >= 0 && off < view.length) { view[off] = s.bytes[i] as number; n++; }
      }
    return n;
  },
};
const core = { limits: { ...AGENT_LIMIT_DEFAULTS }, originals };
code.init(core as never);
rpc.exports = {
  disassemble: (p: never) => code.rpc.disassemble(p),
  mainBase: () => Process.mainModule.base.toString(),
  hook: (rva: number) => {
    const at = Process.mainModule.base.add(rva);
    saved.push({ base: at, bytes: new Uint8Array(at.readByteArray(32) as ArrayBuffer) });
    keep.push(Interceptor.attach(at, { onEnter() {} }));
    Interceptor.flush();
    return true;
  },
  edgePage: (): string => {
    // two pages: nops at the end of the first, the second made inaccessible
    const page = Process.pageSize;
    const mem = Memory.alloc(2 * page);
    keep.push(mem);
    mem.add(page - 4).writeByteArray([0x90, 0x90, 0x90, 0x90]);
    Memory.protect(mem.add(page), page, "---");
    return mem.add(page - 4).toString();
  },
  badBytes: (): string => {
    const mem = Memory.alloc(Process.pageSize);
    keep.push(mem);
    mem.writeByteArray([0x90, 0x06, 0x90, 0x90]); // 0x06 (push es) is invalid in 64-bit mode
    return mem.toString();
  },
};
`;

interface Agent {
  disassemble(p: DisassembleParams): Promise<{ ok: true; value: DisassembleResult } | { ok: false; error: unknown }>;
  mainBase(): Promise<string>;
  hook(rva: number): Promise<boolean>;
  edgePage(): Promise<string>;
  badBytes(): Promise<string>;
}

/** objdump `DWORD PTR [rax+0x8],xmm0` and Capstone `dword ptr [rax + 8], xmm0` compare equal. */
const normalizeInsn = (text: string): string =>
  text
    .toLowerCase()
    .replace(/0x([0-9a-f]+)/gu, (_m, hex: string) => String(Number.parseInt(hex, 16)))
    .replace(/\s+/gu, "");

/** File bytes at an RVA through the manifest's section table. */
const fileBytesAt = (file: Buffer, art: FixtureArtifact, rva: number, size: number): Buffer => {
  const section = art.pe.sections.find((s) => rva >= s.rva && rva + size <= s.rva + s.virtualSize);
  if (section === undefined) throw new Error(`rva 0x${rva.toString(16)} is in no section`);
  const header = file.readUInt32LE(0x3c);
  const sectionTable = header + 24 + file.readUInt16LE(header + 20);
  for (let i = 0; i < file.readUInt16LE(header + 6); i++) {
    const at = sectionTable + 40 * i;
    if (file.readUInt32LE(at + 12) === section.rva) {
      const raw = file.readUInt32LE(at + 20);
      return file.subarray(raw + rva - section.rva, raw + rva - section.rva + size);
    }
  }
  throw new Error("section header not found");
};

const rel = (va: string, base: bigint): number => Number(BigInt(va) - base);

type Frida = typeof import("frida");
const loadFrida = async (): Promise<Frida> => {
  const fridaModule = (await import("frida")) as unknown as { default?: unknown };
  return (fridaModule.default ?? fridaModule) as Frida;
};

/** Stage the REAL agent sources + the test entry and compile them with frida.Compiler (only entry.ts is reachable). */
const compileTestAgent = async (frida: Frida, stage: string): Promise<string> => {
  await cp(join(ROOT, "src", "agent"), join(stage, "agent"), { recursive: true });
  await mkdir(join(stage, "shared"), { recursive: true });
  await cp(join(ROOT, "src", "shared"), join(stage, "shared"), { recursive: true });
  await writeFile(
    join(stage, "agent", "buildInfo.ts"),
    'export const AGENT_VERSION = "0.0.0";\nexport const AGENT_BUILD_ID = "test";\n',
  );
  await writeFile(join(stage, "entry.ts"), TEST_ENTRY);
  const tsconfig = JSON.parse(await readFile(join(ROOT, "src", "agent", "tsconfig.json"), "utf8")) as Record<
    string,
    unknown
  >;
  await writeFile(join(stage, "tsconfig.json"), JSON.stringify({ ...tsconfig, include: ["entry.ts"] }));
  return new frida.Compiler().build(join(stage, "entry.ts"), {
    projectRoot: stage,
    bundleFormat: "esm",
    typeCheck: "none",
    sourceMaps: "omitted",
  });
};

/** game_sim without worker threads, owned by this test, once it printed READY. */
const spawnReady = async (exe: string): Promise<ChildProcess> => {
  const proc = spawn(exe, ["--no-threads", "--hz", "60"], { cwd: dirname(exe), stdio: "pipe" });
  await new Promise<void>((done, failed) => {
    let text = "";
    const timer = setTimeout(() => failed(new Error(`game_sim never printed READY: ${text}`)), 15_000);
    proc.stdout?.on("data", (chunk: Buffer) => {
      text += chunk.toString("utf8");
      if (text.includes("READY")) {
        clearTimeout(timer);
        done();
      }
    });
    proc.once("exit", (code) => failed(new Error(`game_sim exited early (${String(code)})`)));
  });
  return proc;
};

const params = (address: string, extra: Partial<DisassembleParams>): DisassembleParams => ({
  address: address as DisassembleParams["address"],
  mode: "count",
  original_bytes: true,
  operands: false,
  cfg: false,
  ...extra,
});

describe.skipIf(skip !== false)(`agent disassemble on game_sim (raw Frida)${skipNote(skip)}`, () => {
  let child: ChildProcess | null = null;
  let stage: string | null = null;
  let session: { detach(): Promise<void> } | null = null;
  /** This file's own DeviceManager (never Frida's singleton): closing it lets Frida delete its %TEMP% agent copies. */
  let dm: InstanceType<Frida["DeviceManager"]> | null = null;
  let pidcheck: string | null = null;
  let agent: Agent;
  let base: bigint;
  let art: FixtureArtifact;
  let fileBytes: Buffer;
  let physics: { readonly rva: number; readonly size: number };

  beforeAll(async () => {
    const manifest = await loadFixtures();
    const found = fixtureArtifact(manifest, "game_sim");
    if (found === null) throw new Error("game_sim fixture unavailable although gcc is present");
    art = found;
    pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
    fileBytes = await readFile(art.path);
    const range = art.pe.pdata["physics_step"];
    if (range === undefined) throw new Error("manifest lacks physics_step .pdata");
    physics = range;

    stage = await mkdtemp(join(tmpdir(), "bea-wp6-agent-"));
    const frida = await loadFrida();
    const bundle = await compileTestAgent(frida, stage);
    const proc = await spawnReady(art.path);
    child = proc;
    if (proc.pid === undefined) throw new Error("no pid");
    dm = new frida.DeviceManager();
    const device = await dm.getDeviceById("local", 5000);
    const attached = await device.attach(proc.pid);
    session = attached;
    const script = await attached.createScript(bundle, { runtime: frida.ScriptRuntime.QJS });
    await script.load();
    agent = script.exports as unknown as Agent;
    base = BigInt(await agent.mainBase());
  }, 60_000);

  afterAll(async () => {
    await session?.detach().catch(() => undefined);
    if (child !== null && child.exitCode === null) {
      child.kill();
      await new Promise((done) => child?.once("exit", done));
    }
    // DeviceManager.close() deletes %TEMP%\frida-<id> only once no target maps the agent DLLs any more; Node's exit
    // event can precede the process object being signaled, so wait for pidcheck to report the target gone
    const pid = child?.pid;
    if (pid !== undefined)
      await vi.waitFor(() => expect(pidStatus(pidcheck, pid).alive).toBe(false), { interval: 25, timeout: 5000 });
    await dm?.close();
    if (stage !== null) await rm(stage, { recursive: true, force: true });
  });

  const call = async (p: DisassembleParams): Promise<DisassembleResult> => {
    const reply = await agent.disassemble(p);
    if (!reply.ok) throw new Error(`disassemble failed: ${JSON.stringify(reply.error)}`);
    return reply.value;
  };
  const at = (rva: number): string => `0x${(base + BigInt(rva)).toString(16)}`;

  it("function mode covers the whole .pdata function, byte-exact with the file, with the speed writer text", async () => {
    const result = await call(params(at(physics.rva + 0x10), { mode: "function", cfg: true }));
    expect(result.function).toEqual({ base: at(physics.rva), size: physics.size, source: "pdata" });
    expect(rel(result.start, base)).toBe(physics.rva);
    expect(result.stop).toBeNull();
    expect(result.truncated).toBe(false);
    expect(result.overlay_used).toBe(false);
    const rows = result.instructions;
    expect(rel(rows[0]?.address ?? "0x0", base)).toBe(physics.rva);
    const last = rows.at(-1) as InsnRow;
    expect(rel(last.address, base) + last.size).toBe(physics.rva + physics.size);
    const joined = Buffer.from(rows.map((r) => r.bytes).join(""), "hex");
    expect(joined.equals(fileBytesAt(fileBytes, art, physics.rva, physics.size))).toBe(true);
    const writers = (art.expectations["speedWriters"] ?? []) as readonly { rva: number; text: string }[];
    expect(writers.length).toBeGreaterThan(0);
    for (const w of writers) {
      const row = rows.find((r) => rel(r.address, base) === w.rva);
      expect(row, `row at the speed writer rva ${w.rva}`).toBeDefined();
      expect(normalizeInsn(`${row?.mnemonic ?? ""} ${row?.op_str ?? ""}`)).toBe(normalizeInsn(w.text));
    }
    expect(result.blocks?.length ?? 0).toBeGreaterThan(1);
  });

  it("resolves relative branch targets and RIP-relative operands against the real addresses", async () => {
    const result = await call(params(at(physics.rva), { mode: "function" }));
    let branches = 0;
    let ripOps = 0;
    for (const row of result.instructions) {
      const b = Buffer.from(row.bytes, "hex");
      const rva = rel(row.address, base);
      const end = rva + row.size;
      let expected: number | null = null;
      if (b[0] === 0xe9 || b[0] === 0xe8) expected = end + b.readInt32LE(1);
      else if (b[0] === 0x0f && ((b[1] ?? 0) & 0xf0) === 0x80) expected = end + b.readInt32LE(2);
      else if (((b[0] ?? 0) & 0xf0) === 0x70 || b[0] === 0xeb) expected = end + b.readInt8(1);
      if (expected !== null) {
        branches += 1;
        expect(row.branch_target, `branch at rva ${rva}`).not.toBeNull();
        expect(rel(row.branch_target ?? "0x0", base)).toBe(expected);
        expect(row.op_str).toBe(`0x${(base + BigInt(expected)).toString(16)}`);
      }
      // SSE loads/compares with a RIP-relative operand and no immediate: the disp32 is the last 4 bytes
      if (row.mem_targets.length > 0 && /^(?:movss|comiss|addss|mulss)$/u.test(row.mnemonic)) {
        ripOps += 1;
        expect(rel(row.mem_targets[0] ?? "0x0", base)).toBe(end + b.readInt32LE(b.length - 4));
      }
    }
    expect(branches).toBeGreaterThanOrEqual(2);
    expect(ripOps).toBeGreaterThanOrEqual(2);
  });

  it("shows the original bytes under a hook (overlay) and the hook's jmp without it", async () => {
    expect(await agent.hook(physics.rva)).toBe(true);
    const restored = await call(params(at(physics.rva), { count: 8 }));
    expect(restored.overlay_used).toBe(true);
    expect(restored.instructions[0]?.overlay).toBe(true);
    const shown = Buffer.from(restored.instructions.map((r) => r.bytes).join(""), "hex");
    expect(shown.equals(fileBytesAt(fileBytes, art, physics.rva, shown.length))).toBe(true);
    const live = await call(params(at(physics.rva), { count: 1, original_bytes: false }));
    expect(live.overlay_used).toBe(false);
    expect(live.instructions[0]?.mnemonic).toBe("jmp");
    expect(live.instructions[0]?.bytes).not.toBe(restored.instructions[0]?.bytes);
  });

  it("stops at an unreadable page with access-violation and at undecodable bytes with decode-error", async () => {
    const edge = await agent.edgePage();
    const cut = await call(params(edge, { count: 32 }));
    expect(cut.instructions.map((r) => r.mnemonic)).toEqual(["nop", "nop", "nop", "nop"]);
    expect(cut.stop?.reason).toBe("access-violation");
    expect(BigInt(cut.stop?.at ?? "0x0")).toBe(BigInt(edge) + 4n);

    const bad = await call(params(await agent.badBytes(), { count: 4 }));
    expect(bad.instructions.map((r) => r.mnemonic)).toEqual(["nop"]);
    expect(bad.stop?.reason).toBe("decode-error");

    const unreadable = await agent.disassemble(params("0x10", { count: 4 }));
    expect(unreadable).toMatchObject({ ok: false, error: { _tag: "AccessViolation", partial_bytes: 0 } });
  });

  it("refuses function mode outside any .pdata function", async () => {
    const reply = await agent.disassemble(params(await agent.badBytes(), { mode: "function" }));
    expect(reply).toMatchObject({ ok: false, error: { _tag: "NoFunctionRange" } });
  });
});
