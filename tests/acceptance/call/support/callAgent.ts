import { cp, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Raw-Frida harness for the oracle executor (WP11; DESIGN §8.4 wave rule: raw agent RPCs, no BEA host). Stages ONLY
 * the call feature (src/agent/{call,callThunk}.ts, src/agent/pure/call*.ts and pure/coreErrors.ts) with day-0
 * stand-ins for state.ts and errors.ts and src/shared, plus the entry below, and compiles it with frida.Compiler (typeCheck full). The entry stands in for the
 * agent core: a calls registry (enter/exit/activeOn) and a dispatcher mimic with the DESIGN §5.3 routing order
 * (BEA guard/TF and DR traps handled -> in-call exceptions counted, GPRs stashed, passed on), as in [REV-lab R1].
 */
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const AGENT_FILES = ["call.ts", "callThunk.ts", "pure/callBlock.ts", "pure/callMaterialize.ts", "pure/coreErrors.ts"];

/**
 * Day-0 stand-ins (WP0 §4 text) for the two core files call.ts imports, so this harness never depends on the agent
 * core's in-progress state: call.ts uses only `features` and `limits` of AgentCore plus structurally bound services.
 */
const STATE_STANDIN = String.raw`
import type { AgentFeature, AgentLimits, FatalMessage, GateName, ReadyMessage, ThreadId } from "../shared/agentProtocol.js";
import { AGENT_LIMIT_DEFAULTS } from "../shared/agentLimits.js";
export type Phase = "loaded" | "ready" | "shutting-down";
export interface AgentCore {
  readonly t0Wall: number;
  readonly jsTid: ThreadId;
  phase: Phase;
  bootStage: FatalMessage["stage"];
  features: AgentFeature[];
  early: ReadyMessage["early"];
  gates: Record<GateName, boolean>;
  limits: AgentLimits;
}
export function createCore(): AgentCore {
  return {
    t0Wall: Date.now(),
    jsTid: Process.getCurrentThreadId(),
    phase: "loaded",
    bootStage: "platform",
    features: [],
    early: { exception_handler: true, exit_hook: false, last_chance_hook: false, module_observer: false },
    gates: { write_memory: false, override_function: false, call_function: false },
    limits: { ...AGENT_LIMIT_DEFAULTS },
  };
}
`;
const ERRORS_STANDIN = String.raw`
import type { AgentError, AgentResult } from "../shared/agentProtocol.js";
export const ok = <T>(value: T): AgentResult<T> => ({ ok: true, value });
export const fail = (error: AgentError): AgentResult<never> => ({ ok: false, error });
`;

const HARNESS_ENTRY = String.raw`
import type { CallFunctionParams } from "../shared/agentProtocol.js";
import * as call from "./call.js";
import { createCore } from "./state.js";

const core = createCore();
core.phase = "ready";
core.gates.call_function = true;
// the WP3 CallRegistry record shape (src/agent/pure/coreCalls.ts ActiveCall)
type Entry = { tid: number; token: number; exceptions: number; beaTraps: number; faults: { address: string; registers: Record<string, string> }[] };
const active = new Map<number, Entry>();
const seen = { inCall: 0, guardTraps: 0, drTraps: 0, outside: 0 };
(core as unknown as Record<string, unknown>)["calls"] = {
  enter(tid: number, token: number): Entry {
    const e = { tid, token, exceptions: 0, beaTraps: 0, faults: [] };
    active.set(tid, e);
    return e;
  },
  exit(tid: number): Entry | null {
    const e = active.get(tid) ?? null;
    active.delete(tid);
    return e;
  },
  activeOn(tid: number): Entry | null {
    return active.get(tid) ?? null;
  },
};
const keep: NativePointer[] = [];
const k32 = Process.getModuleByName("kernel32.dll");
const fn = <R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(name: string, ret: R, args: A) =>
  new NativeFunction(k32.getExportByName(name), ret, args, { scheduling: "exclusive" });
const virtualProtect = fn("VirtualProtect", "int", ["pointer", "size_t", "uint32", "pointer"]);
const openThread = fn("OpenThread", "pointer", ["uint32", "int", "uint32"]);
const suspendThread = fn("SuspendThread", "uint32", ["pointer"]);
const resumeThread = fn("ResumeThread", "uint32", ["pointer"]);
const closeHandle = fn("CloseHandle", "int", ["pointer"]);
const createThread = fn("CreateThread", "pointer", ["pointer", "size_t", "pointer", "pointer", "uint32", "pointer"]);
const virtualAlloc = fn("VirtualAlloc", "pointer", ["pointer", "size_t", "uint32", "uint32"]);
const virtualQuery = fn("VirtualQuery", "size_t", ["pointer", "pointer", "size_t"]);
const getCurrentProcess = fn("GetCurrentProcess", "pointer", []);
const getProcessHandleCount = fn("GetProcessHandleCount", "int", ["pointer", "pointer"]);
const getProcessMemoryInfo = fn("K32GetProcessMemoryInfo", "int", ["pointer", "pointer", "uint32"]);
const oldProtect = Memory.alloc(4);
keep.push(oldProtect);
// MEMORY_BASIC_INFORMATION (48 bytes, Protect at +0x24); PROCESS_MEMORY_COUNTERS_EX (80 bytes, PrivateUsage at +72)
const mbi = Memory.alloc(48);
const pmc = Memory.alloc(80);
const handleBox = Memory.alloc(4);
keep.push(mbi, pmc, handleBox);
const guarded = new Set<string>();
const rearm = new Map<number, NativePointer>();
const pageOf = (p: NativePointer): NativePointer => p.and(ptr(Process.pageSize - 1).not());

Process.setExceptionHandler((d) => {
  const tid = Process.getCurrentThreadId();
  const entry = active.get(tid);
  const nc = d.nativeContext;
  if (d.type === "guard-page" && d.memory !== undefined) {
    const page = pageOf(d.memory.address);
    if (guarded.has(page.toString())) {
      seen.guardTraps++;
      if (entry !== undefined) entry.beaTraps++;
      rearm.set(tid, page);
      nc.add(0x44).writeU32(nc.add(0x44).readU32() | 0x100);
      return true;
    }
  }
  if (d.type === "single-step") {
    const page = rearm.get(tid);
    if (page !== undefined) {
      rearm.delete(tid);
      virtualProtect(page, Process.pageSize, 0x104, oldProtect);
      nc.add(0x44).writeU32(nc.add(0x44).readU32() & ~0x100);
      return true;
    }
    if (nc.add(0x68).readU64().and(0xf).toNumber() !== 0) {
      seen.drTraps++;
      if (entry !== undefined) entry.beaTraps++;
      nc.add(0x70).writeU64(0);
      nc.add(0x48).writeU64(0);
      nc.add(0x68).writeU64(0);
      return true;
    }
  }
  if (entry !== undefined) {
    entry.exceptions++;
    seen.inCall++;
    entry.faults.push({ address: d.address.toString(), registers: { rip: d.context.pc.toString(), rsp: d.context.sp.toString(), rax: (d.context as X64CpuContext).rax.toString() } });
    if (entry.faults.length > 8) entry.faults.shift();
  } else seen.outside++;
  return false;
});

// the core's dispose seam (state.ts hooks.onDispose, run by rpc.ts disposeAll from rpc.exports.dispose at unload)
const onDispose: (() => void)[] = [];
(core as unknown as Record<string, unknown>)["hooks"] = { onDispose };
call.init(core);

const hex = (bytes: ArrayBuffer | null): string => {
  let out = "";
  for (const b of new Uint8Array(bytes ?? new ArrayBuffer(0))) out += b.toString(16).padStart(2, "0");
  return out;
};
const bytesOf = (h: string): number[] => {
  const out: number[] = [];
  for (let i = 0; i < h.length; i += 2) out.push(Number.parseInt(h.slice(i, i + 2), 16));
  return out;
};
const envPage = Memory.alloc(Process.pageSize);
keep.push(envPage);
Memory.protect(envPage, Process.pageSize, "rwx");
envPage.writeByteArray(bytesOf("0fae19d97904c3"));
const readEnv = new NativeFunction(envPage, "void", ["pointer"]);
const envBuf = Memory.alloc(16);
keep.push(envBuf);
const withThread = <T>(tid: number, f: (h: NativePointer) => T): T => {
  const h = openThread(0x0002, 0, tid);
  try {
    return f(h);
  } finally {
    closeHandle(h);
  }
};

rpc.exports = {
  /** Frida calls it on script unload (the core's disposeAll: every disposer, newest first, never throwing) */
  dispose() {
    for (const hook of [...onDispose].reverse()) {
      try {
        hook();
      } catch {
        // keep disposing
      }
    }
  },
  info() {
    const main = Process.mainModule;
    return { model: call.exceptionModel(), name: main.name, base: main.base.toString(), jsTid: Process.getCurrentThreadId() };
  },
  callFunction(p: CallFunctionParams) {
    return call.rpc.callFunction(p);
  },
  exportAddress(module: string, name: string) {
    return Process.getModuleByName(module).getExportByName(name).toString();
  },
  loadLibrary(path: string) {
    const m = Module.load(path);
    return { name: m.name, base: m.base.toString() };
  },
  agentEnv() {
    readEnv(envBuf);
    return { mxcsr: envBuf.readU32(), fpcw: envBuf.add(4).readU16() };
  },
  alloc(size: number, init: string) {
    const p = Memory.alloc(Math.max(size, Process.pageSize));
    keep.push(p);
    if (init.length > 0) p.writeByteArray(bytesOf(init));
    return p.toString();
  },
  read(address: string, size: number) {
    return hex(ptr(address).readByteArray(size));
  },
  armGuard(address: string) {
    const page = pageOf(ptr(address));
    guarded.add(page.toString());
    virtualProtect(page, Process.pageSize, 0x104, oldProtect);
  },
  disarmGuard(address: string) {
    const page = pageOf(ptr(address));
    guarded.delete(page.toString());
    virtualProtect(page, Process.pageSize, 0x04, oldProtect);
  },
  /** PAGE_GUARD is set on the page right now (the watch is armed) */
  isGuarded(address: string) {
    if (virtualQuery(pageOf(ptr(address)), mbi, 48).toNumber() === 0) return false;
    return (mbi.add(0x24).readU32() & 0x100) !== 0;
  },
  /** the target's handle count and private bytes (leak checks) */
  memInfo() {
    getProcessHandleCount(getCurrentProcess(), handleBox);
    pmc.writeU32(80);
    getProcessMemoryInfo(getCurrentProcess(), pmc, 80);
    return { handles: handleBox.readU32(), privateBytes: pmc.add(72).readU64().toNumber() };
  },
  armDr(tid: number, address: string, size: number) {
    const t = Process.enumerateThreads().find((x) => x.id === tid);
    if (t === undefined) throw new Error("no such thread");
    t.setHardwareWatchpoint(0, ptr(address), size, "w");
  },
  disarmDr(tid: number) {
    Process.enumerateThreads().find((x) => x.id === tid)?.unsetHardwareWatchpoint(0);
  },
  threads() {
    return Process.enumerateThreads().map((t) => t.id);
  },
  /**
   * a thread spinning in user mode (pause; jmp back) whose MXCSR is set to the given value first. Its code page comes
   * from VirtualAlloc, not Memory.alloc: Frida frees its heap at script unload, and the thread must keep spinning after
   * the dispose test's unload (a freed spin loop would kill the target for an unrelated reason).
   */
  spinThread(mxcsr: number) {
    const page = virtualAlloc(NULL, Process.pageSize, 0x3000, 0x40);
    const imm = [mxcsr & 0xff, (mxcsr >> 8) & 0xff, (mxcsr >> 16) & 0xff, (mxcsr >> 24) & 0xff];
    // mov dword [rsp-8], imm32 ; ldmxcsr [rsp-8] ; pause ; jmp pause
    page.writeByteArray([0xc7, 0x44, 0x24, 0xf8, ...imm, 0x0f, 0xae, 0x54, 0x24, 0xf8, 0xf3, 0x90, 0xeb, 0xfc]);
    const tidBox = Memory.alloc(8);
    keep.push(tidBox);
    const h = createThread(NULL, 0, page, NULL, 0, tidBox);
    closeHandle(h);
    return tidBox.readU32();
  },
  /** a thread blocked for good in a non-alertable kernel wait: CreateThread(start = kernel32!Sleep, param = INFINITE) */
  sleeperThread() {
    const tidBox = Memory.alloc(8);
    keep.push(tidBox);
    const h = createThread(NULL, 0, k32.getExportByName("Sleep"), ptr(0xffffffff), 0, tidBox);
    closeHandle(h);
    return tidBox.readU32();
  },
  suspend(tid: number) {
    return withThread(tid, (h) => suspendThread(h));
  },
  resume(tid: number) {
    return withThread(tid, (h) => resumeThread(h));
  },
  stats() {
    return { ...seen, expired: call.callCounters.expiredClosures, lateRuns: call.callCounters.lateRuns, quarantined: call.callCounters.quarantinedBlocks() };
  },
  /** a fresh executable page holding the given machine code (hex): callees the fixtures do not have */
  code(hexCode: string) {
    const page = Memory.alloc(Process.pageSize);
    keep.push(page);
    Memory.protect(page, Process.pageSize, "rwx");
    page.writeByteArray(bytesOf(hexCode));
    return page.toString();
  },
};
send({ ready: true });
`;

const listTs = async (dir: string): Promise<string[]> =>
  (await readdir(dir, { recursive: true, withFileTypes: true }))
    .filter((e) => e.isFile() && e.name.endsWith(".ts"))
    .map((e) => join(e.parentPath, e.name));

interface CompilerDiagnostic {
  readonly category: string;
  readonly code: number;
  readonly text: string;
  readonly file?: { readonly path: string; readonly line: number };
}

/** Compiles the harness bundle; throws with every diagnostic on failure. */
export const compileCallAgent = async (): Promise<string> => {
  const base = join(ROOT, "build", "tmp");
  await mkdir(base, { recursive: true });
  const stage = await mkdtemp(join(base, `wp11-call-agent-${String(process.pid)}-`));
  try {
    await mkdir(join(stage, "agent", "pure"), { recursive: true });
    for (const file of AGENT_FILES) await cp(join(ROOT, "src", "agent", file), join(stage, "agent", file));
    for (const file of await listTs(join(ROOT, "src", "shared"))) {
      const target = join(stage, "shared", relative(join(ROOT, "src", "shared"), file));
      await mkdir(dirname(target), { recursive: true });
      await cp(file, target);
    }
    await writeFile(join(stage, "agent", "state.ts"), STATE_STANDIN);
    await writeFile(join(stage, "agent", "errors.ts"), ERRORS_STANDIN);
    await writeFile(join(stage, "agent", "harness.ts"), HARNESS_ENTRY);
    const tsconfig = JSON.parse(await readFile(join(ROOT, "src", "agent", "tsconfig.json"), "utf8")) as Record<
      string,
      unknown
    >;
    tsconfig["include"] = ["agent/**/*.ts", "shared/**/*.ts"];
    await writeFile(join(stage, "tsconfig.json"), JSON.stringify(tsconfig, null, 2));
    const fridaModule = (await import("frida")) as unknown as { default?: unknown };
    const frida = (fridaModule.default ?? fridaModule) as {
      Compiler: new () => {
        diagnostics: { connect: (handler: (batch: unknown) => void) => void };
        build: (entry: string, options: Record<string, unknown>) => Promise<string>;
      };
    };
    const compiler = new frida.Compiler();
    const diagnostics: CompilerDiagnostic[] = [];
    compiler.diagnostics.connect((batch) =>
      diagnostics.push(
        ...(JSON.parse(
          JSON.stringify(batch, (_key, v: unknown) => (typeof v === "bigint" ? Number(v) : v)),
        ) as CompilerDiagnostic[]),
      ),
    );
    let bundle: string;
    try {
      bundle = await compiler.build(join(stage, "agent", "harness.ts"), {
        projectRoot: stage,
        bundleFormat: "esm",
        typeCheck: "full",
        sourceMaps: "omitted",
        compression: "none",
      });
    } catch (cause) {
      throw new Error(
        `call agent harness failed to compile: ${String(cause)}\n${diagnostics.map((d) => `${d.file?.path ?? "?"}:${String((d.file?.line ?? 0) + 1)} TS${String(d.code)} ${d.text}`).join("\n")}`,
      );
    }
    if (diagnostics.length > 0)
      throw new Error(
        diagnostics
          .map((d) => `${d.file?.path ?? "?"}:${String((d.file?.line ?? 0) + 1)} TS${String(d.code)} ${d.text}`)
          .join("\n"),
      );
    return bundle;
  } finally {
    await rm(stage, { recursive: true, force: true, maxRetries: 3 }).catch(() => undefined);
  }
};
