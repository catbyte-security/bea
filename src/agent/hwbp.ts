// =================================================================================================
// src/agent/hwbp.ts — debug-register watches (S4 §11.2, DESIGN §5.3; WP9-WATCH) and the GumJS helpers the other
// watch engines share (Win32 bindings, CONTEXT offsets, access-instruction recovery, operand decoding).
// Imported only by watch.ts, pageguard.ts, poll.ts and watchSafetyNet.ts (features never import each other).
// =================================================================================================
import type { FrameRef, Hex, InstrumentId, WatchMemOperand } from "../shared/agentProtocol.js";
import {
  clearDr6Hits,
  clearSlot,
  DR6_CAUSE_BITS,
  DR_SLOTS,
  firedSlots,
  inferStepSlots,
  pickSlot,
  verifySlot,
  type DrRw,
  type DrSize,
  type DrSlot,
} from "./pure/dr7.js";
import { memoryOperandAccess, rwAccessOf } from "./pure/watchAccess.js";

// ---------------------------------------------------------------- conversions

export const hexOf = (p: NativePointer | UInt64 | bigint | number): Hex => {
  if (typeof p === "bigint") return `0x${BigInt.asUintN(64, p).toString(16)}`;
  if (typeof p === "number") return `0x${p.toString(16)}`;
  const text = p.toString(16);
  return `0x${text.replace(/^0x/u, "").replace(/^0+(?=.)/u, "")}`;
};
export const bigOf = (p: NativePointer | UInt64 | Int64): bigint => BigInt(p.toString());
export const bytesHex = (ab: ArrayBuffer | null): string | null => {
  if (ab === null) return null;
  let out = "";
  for (const b of new Uint8Array(ab)) out += b.toString(16).padStart(2, "0");
  return out;
};
const u8 = (ab: ArrayBuffer | null): Uint8Array | null => (ab === null ? null : new Uint8Array(ab));
/** Never throws: a read that faults (unmapped, guard) gives null. */
export const readBytes = (address: NativePointer, size: number): ArrayBuffer | null => {
  try {
    return address.readByteArray(size);
  } catch {
    return null;
  }
};

// ---------------------------------------------------------------- Win32 (lazy, exclusive: callers may hold the JS lock)

export const CONTEXT = {
  size: 0x4d0,
  flags: 0x30,
  eflags: 0x44,
  dr0: 0x48,
  dr6: 0x68,
  dr7: 0x70,
  flagsDebugRegisters: 0x00100010,
} as const;
const THREAD_ACCESS = 0x0008 | 0x0002 | 0x0800; // GET_CONTEXT | SUSPEND_RESUME | QUERY_LIMITED_INFORMATION

type Fn = NativeFunction<number | NativePointer | UInt64, (number | NativePointerValue)[]>;
interface Win32 {
  OpenThread: Fn;
  SuspendThread: Fn;
  ResumeThread: Fn;
  GetThreadContext: Fn;
  CloseHandle: Fn;
  VirtualQuery: Fn;
  VirtualProtect: Fn;
  NtQueryInformationThread: Fn;
  ReadProcessMemory: Fn;
}
let win32: Win32 | null = null;
const bind = (module: string, name: string, ret: NativeFunctionReturnType, args: NativeFunctionArgumentType[]): Fn =>
  new NativeFunction(Process.getModuleByName(module).getExportByName(name), ret, args, {
    scheduling: "exclusive",
  }) as unknown as Fn;
const w32 = (): Win32 =>
  (win32 ??= {
    OpenThread: bind("kernelbase.dll", "OpenThread", "pointer", ["uint32", "int", "uint32"]),
    SuspendThread: bind("kernelbase.dll", "SuspendThread", "uint32", ["pointer"]),
    ResumeThread: bind("kernelbase.dll", "ResumeThread", "uint32", ["pointer"]),
    GetThreadContext: bind("kernelbase.dll", "GetThreadContext", "int", ["pointer", "pointer"]),
    CloseHandle: bind("kernelbase.dll", "CloseHandle", "int", ["pointer"]),
    VirtualQuery: bind("kernelbase.dll", "VirtualQuery", "uint64", ["pointer", "pointer", "uint64"]),
    VirtualProtect: bind("kernelbase.dll", "VirtualProtect", "int", ["pointer", "uint64", "uint32", "pointer"]),
    NtQueryInformationThread: bind("ntdll.dll", "NtQueryInformationThread", "uint32", [
      "pointer",
      "uint32",
      "pointer",
      "uint32",
      "pointer",
    ]),
    ReadProcessMemory: bind("kernelbase.dll", "ReadProcessMemory", "int", [
      "pointer",
      "pointer",
      "pointer",
      "uint64",
      "pointer",
    ]),
  });

const OWN_PROCESS = ptr("0xffffffffffffffff"); // GetCurrentProcess()
const KERNEL_BUF = 64; // debug-register ranges (≤ 8 bytes) reuse one buffer; page-guard ranges (≤ 64 KiB) allocate
const kernelBuf = { mem: null as NativePointer | null };
/**
 * Read without a user-mode access: ReadProcessMemory on the own process copies in the kernel, where the thread's
 * user debug registers are not loaded. Inside a trap handler a plain read of bytes that a read/write slot covers
 * trips that slot again on the trapping thread (debug registers stay live during exception dispatch); Frida's
 * guarded read then fails and gives null (WP9 acceptance). The shared buffer is safe: handlers run under the JS lock
 * and the call is exclusive. Never throws; null when the range is not readable.
 */
export const readBytesKernel = (address: NativePointer, size: number): ArrayBuffer | null => {
  if (size < 1 || size > 65_536) return null;
  try {
    const buf = size <= KERNEL_BUF ? (kernelBuf.mem ??= Memory.alloc(KERNEL_BUF + 8)) : Memory.alloc(size + 8);
    const done = buf.add(size <= KERNEL_BUF ? KERNEL_BUF : size);
    done.writeU64(0);
    if ((w32().ReadProcessMemory(OWN_PROCESS, address, buf, size, done) as number) === 0) return null;
    return done.readU64().toNumber() === size ? buf.readByteArray(size) : null;
  } catch {
    return null;
  }
};

export interface DebugRegisters {
  readonly dr: [bigint, bigint, bigint, bigint];
  readonly dr6: bigint;
  readonly dr7: bigint;
}
const ctxBuf = { mem: null as NativePointer | null };
/** OpenThread → SuspendThread → GetThreadContext(CONTEXT_DEBUG_REGISTERS) → ResumeThread (VERIFIED a6e). */
export const readDebugRegisters = (tid: number): DebugRegisters | { readonly error: string } => {
  const api = w32();
  const handle = api.OpenThread(THREAD_ACCESS, 0, tid) as NativePointer;
  if (handle.isNull()) return { error: "open-failed" };
  try {
    if ((api.SuspendThread(handle) as number) === 0xffffffff) return { error: "suspend-failed" };
    try {
      const raw = (ctxBuf.mem ??= Memory.alloc(CONTEXT.size + 16));
      const ctx = raw.add(15).and(ptr("0xfffffffffffffff0")); // CONTEXT must be 16-byte aligned
      ctx.add(CONTEXT.flags).writeU32(CONTEXT.flagsDebugRegisters);
      if ((api.GetThreadContext(handle, ctx) as number) === 0) return { error: "context-failed" };
      const dr = DR_SLOTS.map((s) => bigOf(ctx.add(CONTEXT.dr0 + 8 * s).readU64())) as [bigint, bigint, bigint, bigint];
      return { dr, dr6: bigOf(ctx.add(CONTEXT.dr6).readU64()), dr7: bigOf(ctx.add(CONTEXT.dr7).readU64()) };
    } finally {
      api.ResumeThread(handle);
    }
  } finally {
    api.CloseHandle(handle);
  }
};

export interface RegionInfo {
  readonly base: NativePointer;
  readonly state: number;
  readonly protect: number;
  readonly type: number;
}
const mbiBuf = { mem: null as NativePointer | null };
/** VirtualQuery (MEMORY_BASIC_INFORMATION x64: BaseAddress +0, RegionSize +0x18, State +0x20, Protect +0x24, Type +0x28). */
export const queryRegion = (address: NativePointer): RegionInfo | null => {
  const mbi = (mbiBuf.mem ??= Memory.alloc(0x30));
  const n = w32().VirtualQuery(address, mbi, 0x30) as UInt64;
  if (bigOf(n) === 0n) return null;
  return {
    base: mbi.readPointer(),
    state: mbi.add(0x20).readU32(),
    protect: mbi.add(0x24).readU32(),
    type: mbi.add(0x28).readU32(),
  };
};
const oldProt = { mem: null as NativePointer | null };
export const protect = (page: NativePointer, size: number, protection: number): boolean =>
  (w32().VirtualProtect(page, size, protection, (oldProt.mem ??= Memory.alloc(4))) as number) !== 0;

/** [StackLimit, StackBase) from the TEB (NtQueryInformationThread class 0, TebBaseAddress at +8). */
export const threadStack = (tid: number): { readonly limit: bigint; readonly base: bigint } | null => {
  const api = w32();
  const handle = api.OpenThread(0x0800, 0, tid) as NativePointer;
  if (handle.isNull()) return null;
  try {
    const tbi = Memory.alloc(0x30);
    if ((api.NtQueryInformationThread(handle, 0, tbi, 0x30, NULL) as number) !== 0) return null;
    const teb = tbi.add(8).readPointer();
    if (teb.isNull()) return null;
    return { base: bigOf(teb.add(8).readPointer()), limit: bigOf(teb.add(0x10).readPointer()) };
  } catch {
    return null;
  } finally {
    api.CloseHandle(handle);
  }
};

// ---------------------------------------------------------------- instructions and registers

export const GPR_NAMES = [
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "rbp",
  "rsp",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "rip",
] as const;
type Gpr = (typeof GPR_NAMES)[number];

/** Capstone sub-register → its 64-bit register (operand bases are usually 64-bit already). */
const fullRegister = (name: string): Gpr | null => {
  const n = name.toLowerCase();
  if ((GPR_NAMES as readonly string[]).includes(n)) return n as Gpr;
  const legacy: Readonly<Record<string, Gpr>> = {
    eax: "rax", ax: "rax", al: "rax", ah: "rax",
    ebx: "rbx", bx: "rbx", bl: "rbx", bh: "rbx",
    ecx: "rcx", cx: "rcx", cl: "rcx", ch: "rcx",
    edx: "rdx", dx: "rdx", dl: "rdx", dh: "rdx",
    esi: "rsi", si: "rsi", sil: "rsi",
    edi: "rdi", di: "rdi", dil: "rdi",
    ebp: "rbp", bp: "rbp", bpl: "rbp",
    esp: "rsp", sp: "rsp", spl: "rsp",
    eip: "rip",
  }; // prettier-ignore
  const hit = legacy[n];
  if (hit !== undefined) return hit;
  const m = /^(r(?:[89]|1[0-5]))(?:d|w|b)$/u.exec(n);
  return m?.[1] !== undefined ? (m[1] as Gpr) : null;
};

const registerValue = (context: CpuContext, name: Gpr): bigint | null => {
  const value = (context as unknown as Record<string, NativePointer | undefined>)[name === "rip" ? "pc" : name];
  return value === undefined ? null : bigOf(value);
};

/** Explicit name list: QJS context objects have no own keys [ext-frida §3.6]. */
export const captureRegisters = (context: CpuContext, names: readonly string[]): Record<string, Hex> => {
  const out: Record<string, Hex> = {};
  for (const name of names) {
    const full = fullRegister(name);
    if (full === null) continue;
    const v = registerValue(context, full);
    if (v !== null) out[full] = hexOf(v);
  }
  return out;
};

export interface AccessInsn {
  readonly insn: NativePointer | null;
  readonly conf: "exact" | "swept" | "heuristic" | "unknown";
  readonly text: string | null;
}
const insnCache = new Map<string, AccessInsn>();
const parseAt = (p: NativePointer): X86Instruction | null => {
  try {
    return Instruction.parse(p) as X86Instruction;
  } catch {
    return null;
  }
};
const hasMemOperand = (insn: X86Instruction): boolean => insn.operands.some((o) => o.type === "mem");

/**
 * Live-bytes fallback of WP3's overlay-aware disasm.findAccessInsn (S4 §8.4): sweep from the .pdata function start
 * until next == pcAfter ("swept"); else back-scan 1..15 bytes and accept a unique memory-operand candidate
 * ("heuristic"). Code inside Stalker's cache or other cloaked memory is "unknown". LRU-ish cache of 4096 entries.
 */
export const findAccessInsnLocal = (pcAfter: NativePointer): AccessInsn => {
  const key = pcAfter.toString();
  const cached = insnCache.get(key);
  if (cached !== undefined) return cached;
  let out: AccessInsn = { insn: null, conf: "unknown", text: null };
  if (!Cloak.hasRangeContaining(pcAfter)) {
    const fr = Process.findFunctionRange(pcAfter);
    if (fr !== null && pcAfter.compare(fr.base) > 0) {
      let p = fr.base;
      for (let i = 0; i < 4096 && p.compare(pcAfter) < 0; i++) {
        const insn = parseAt(p);
        if (insn === null) break;
        if (insn.next.equals(pcAfter)) {
          out = { insn: insn.address, conf: "swept", text: insn.toString() };
          break;
        }
        p = insn.next;
      }
    }
    if (out.insn === null) {
      const candidates: X86Instruction[] = [];
      for (let k = 1; k <= 15; k++) {
        const insn = parseAt(pcAfter.sub(k));
        if (insn !== null && insn.size === k && hasMemOperand(insn)) candidates.push(insn);
      }
      const only = candidates.length === 1 ? candidates[0] : undefined;
      if (only !== undefined) out = { insn: only.address, conf: "heuristic", text: only.toString() };
    }
  }
  if (insnCache.size >= 4096) insnCache.clear();
  insnCache.set(key, out);
  return out;
};

interface DecodedInsn {
  readonly text: string;
  readonly next: NativePointer;
  /** read or write by the only memory operand (Capstone access); null when the decoder cannot tell */
  readonly memAccess: "r" | "w" | null;
  readonly mem: {
    readonly base: string | null;
    readonly index: string | null;
    readonly scale: 1 | 2 | 4 | 8;
    readonly disp: number;
    readonly size: number;
    readonly writesBase: boolean;
  } | null;
}
const decodeCache = new Map<string, DecodedInsn | null>();
/** Instruction.parse once per address (watch traps repeat at the same instructions; hot pages need cheap hits). */
export const decodeInsn = (at: NativePointer): DecodedInsn | null => {
  const key = at.toString();
  const known = decodeCache.get(key);
  if (known !== undefined) return known;
  const insn = parseAt(at);
  let out: DecodedInsn | null = null;
  if (insn !== null) {
    const m = insn.operands.find((o): o is X86MemOperand => o.type === "mem");
    const base = m?.value.base === undefined ? null : (fullRegister(m.value.base) ?? m.value.base);
    const written = insn.regsAccessed.written.map((r) => fullRegister(r) ?? r);
    out = {
      text: insn.toString(),
      next: insn.next,
      memAccess: memoryOperandAccess(insn.operands),
      mem:
        m === undefined
          ? null
          : {
              base,
              index: m.value.index === undefined ? null : (fullRegister(m.value.index) ?? m.value.index),
              scale: [1, 2, 4, 8].includes(m.value.scale) ? (m.value.scale as 1 | 2 | 4 | 8) : 1,
              disp: m.value.disp,
              size: m.size,
              writesBase: base !== null && written.includes(base),
            },
    };
  }
  if (decodeCache.size >= 4096) decodeCache.clear();
  decodeCache.set(key, out);
  return out;
};

/**
 * CI-M12: the memory operand of the accessing instruction (Instruction.parse, cached), with the base register's
 * value from `context`. For debug-register traps the context is from AFTER the access, so a base the instruction
 * also writes is unreliable: `base_written` reports it (page-guard callers override it, their context is before).
 */
export const memOperandOf = (insnAt: NativePointer | null, context: CpuContext): WatchMemOperand | null => {
  if (insnAt === null) return null;
  const decoded = decodeInsn(insnAt);
  const mem = decoded?.mem ?? null;
  if (decoded === null || mem === null) return null;
  let baseValue: bigint | null = null;
  if (mem.base === "rip") baseValue = bigOf(decoded.next);
  else if (mem.base !== null && fullRegister(mem.base) !== null)
    baseValue = registerValue(context, fullRegister(mem.base) as Gpr);
  return {
    base: mem.base,
    index: mem.index,
    scale: mem.scale,
    disp: mem.disp,
    size: mem.size,
    base_value: baseValue === null ? null : hexOf(baseValue),
    base_written: mem.writesBase,
  };
};

const legend = { map: null as ModuleMap | null };
/** "<module>+0x<rva>" when inside a module (ModuleMap at capture time), else the bare VA. */
const frameRef = (address: NativePointer): FrameRef => {
  const map = (legend.map ??= new ModuleMap());
  let m = map.find(address);
  if (m === null) {
    map.update();
    m = map.find(address);
  }
  return m === null ? hexOf(address) : `${m.name}+${hexOf(address.sub(m.base))}`;
};
export const backtraceOf = (context: CpuContext, depth: number): FrameRef[] | null =>
  depth <= 0 ? null : Thread.backtrace(context, Backtracer.ACCURATE).slice(0, depth).map(frameRef);

// ---------------------------------------------------------------- the debug-register manager

/** One watch or execute breakpoint hit, before it becomes a WatchRow (watch.ts adds g/t and the instrument id). */
export interface WatchHit {
  readonly tid: number;
  readonly access: "r" | "w" | "x";
  readonly insn: NativePointer | null;
  readonly conf: AccessInsn["conf"];
  readonly pcAfter: NativePointer | null;
  readonly text: string | null;
  readonly addr: NativePointer;
  readonly before: ArrayBuffer | null;
  readonly after: ArrayBuffer | null;
  readonly regs: Record<string, Hex> | null;
  readonly bt: FrameRef[] | null;
  readonly mem: WatchMemOperand | null;
}
/** "stop": the instrument reached max_hits; the slot is disarmed in the handler from now on. */
export type HitVerdict = "continue" | "stop";
export interface HitSink {
  hit(h: WatchHit): HitVerdict;
}
export interface DrCapture {
  readonly registers: "none" | "gpr";
  readonly backtrace: number;
}
export interface DrArmSpec {
  readonly owner: InstrumentId;
  readonly address: NativePointer;
  readonly size: DrSize;
  readonly rw: DrRw;
  readonly slot?: DrSlot;
  readonly threads: "all" | readonly number[];
  readonly capture: DrCapture;
  readonly sink: HitSink;
}
interface Slot {
  state: "free" | "armed" | "disarming" | "quarantined";
  spec: DrArmSpec | null;
  shadow: ArrayBuffer | null;
  /** hits attributed without a DR6 cause bit since the slot was armed (inferStepSlots) */
  inferred: number;
}
export interface DrArmResult {
  readonly slot: DrSlot;
  readonly armedThreads: number;
  readonly armErrors: { tid: number; message: string }[];
  readonly verified: { threads_checked: number; ok: number };
  readonly initial: ArrayBuffer | null;
}
export interface DrHostHooks {
  /** threads that may be armed (cloaked Frida threads and the agent thread are already excluded) */
  threads(): ThreadDetails[];
  readDebugRegisters(tid: number): DebugRegisters | { readonly error: string };
  findAccessInsn(pcAfter: NativePointer): AccessInsn;
  /**
   * The watched bytes now, with BEA's own guard pages on the range suspended (CT-I5). `kernel`: copy them in the
   * kernel (readBytesKernel), because a user-mode read would trip a read/write slot that covers them.
   */
  readWatched(address: NativePointer, size: number, kernel: boolean): ArrayBuffer | null;
  verifyThreads(): number;
  /** the slot set changed (safety-net tables) */
  onSlotsChanged(mask: number): void;
  fault(where: string, e: unknown): void;
}

/** How long a verified-disarmed slot keeps claiming its late traps before it is free again. */
const DR_RELEASE_GRACE_MS = 1000;

export class DebugRegisters4 {
  readonly #slots: Slot[] = DR_SLOTS.map(() => ({ state: "free", spec: null, shadow: null, inferred: 0 }));
  #observer: ThreadObserver | null = null;
  constructor(private readonly host: DrHostHooks) {}

  /** Bits 0..3: slots armed, disarming or quarantined (their traps are BEA's). */
  get ownedMask(): number {
    let m = 0;
    DR_SLOTS.forEach((s) => {
      if (this.#slots[s]?.state !== "free") m |= 1 << s;
    });
    return m;
  }
  busy(): boolean[] {
    return this.#slots.map((s) => s.state !== "free");
  }
  slotInfo(): {
    slot: number;
    owner: InstrumentId | "quarantined" | null;
    kind: "watch" | "exec" | null;
    address: Hex | null;
  }[] {
    return this.#slots.map((s, i) => ({
      slot: i,
      owner: s.state === "quarantined" ? "quarantined" : (s.spec?.owner ?? null),
      kind: s.spec === null ? null : s.spec.rw === "x" ? "exec" : "watch",
      address: s.spec === null ? null : hexOf(s.spec.address),
    }));
  }
  /** Armed slots that cover every thread (the fingerprint expects their DR7 bits on each one). */
  armedAllThreads(): { slot: DrSlot; rw: DrRw; size: DrSize }[] {
    const out: { slot: DrSlot; rw: DrRw; size: DrSize }[] = [];
    DR_SLOTS.forEach((s) => {
      const e = this.#slots[s];
      if (e?.state === "armed" && e.spec !== null && e.spec.threads === "all")
        out.push({ slot: s, rw: e.spec.rw, size: e.spec.rw === "x" ? 1 : e.spec.size });
    });
    return out;
  }
  inUse(): { slot: number; owner: InstrumentId | "quarantined"; kind: "watch" | "exec" }[] {
    return this.slotInfo()
      .filter((s) => s.owner !== null)
      .map((s) => ({ slot: s.slot, owner: s.owner as InstrumentId | "quarantined", kind: s.kind ?? "watch" }));
  }

  arm(spec: DrArmSpec): DrArmResult | null {
    const slot = pickSlot(this.busy(), spec.slot);
    if (slot === null) return null;
    const entry = this.#slots[slot] as Slot;
    entry.spec = spec;
    // the agent thread is never armed: a user-mode read is safe here, only BEA's guards need suspending
    entry.shadow = spec.rw === "x" ? null : this.host.readWatched(spec.address, spec.size, false);
    entry.inferred = 0;
    entry.state = "armed";
    this.host.onSlotsChanged(this.ownedMask); // published before the first thread can trap (safety net)
    const errors: { tid: number; message: string }[] = [];
    let armed = 0;
    const wanted = spec.threads === "all" ? null : new Set(spec.threads);
    for (const t of this.host.threads()) {
      if (wanted !== null && !wanted.has(t.id)) continue;
      const failure = this.#armOn(t, slot, spec);
      if (failure === null) armed += 1;
      else errors.push({ tid: t.id, message: failure });
    }
    if (spec.threads === "all") this.#ensureObserver();
    return { slot, armedThreads: armed, armErrors: errors, verified: this.verify(slot), initial: entry.shadow };
  }

  #armOn(t: StableThreadDetails, slot: DrSlot, spec: DrArmSpec): string | null {
    try {
      if (spec.rw === "x") t.setHardwareBreakpoint(slot, spec.address);
      else t.setHardwareWatchpoint(slot, spec.address, spec.size, spec.rw);
      return null;
    } catch (e) {
      return e instanceof Error ? e.message.slice(0, 120) : "arm-failed";
    }
  }

  /**
   * New threads: onAdded runs ON the new thread before its start routine (VERIFIED [ext-frida §3.9]). Attaching also
   * replays every existing thread of Frida's registry on the calling thread (gumquickprocess.c), Frida's own threads
   * included: those are skipped like in threads() (re-arming an armed thread is idempotent).
   */
  #ensureObserver(): void {
    if (this.#observer !== null) return;
    this.#observer = Process.attachThreadObserver({
      onAdded: (t) => {
        if (Cloak.hasThread(t.id)) return;
        DR_SLOTS.forEach((s) => {
          const e = this.#slots[s];
          if (e?.state === "armed" && e.spec !== null && e.spec.threads === "all") this.#armOn(t, s, e.spec);
        });
      },
    });
  }
  #dropObserverIfIdle(): void {
    const anyAll = this.#slots.some((s) => s.state === "armed" && s.spec?.threads === "all");
    if (!anyAll && this.#observer !== null) {
      this.#observer.detach();
      this.#observer = null;
    }
  }

  /** Read DR0–3/DR7 back on up to verifyThreads() threads (S4 §11.2 step 4). */
  verify(slot: DrSlot): { threads_checked: number; ok: number } {
    const e = this.#slots[slot] as Slot;
    const spec = e.spec;
    let checked = 0;
    let ok = 0;
    if (spec === null) return { threads_checked: 0, ok: 0 };
    const wanted = spec.threads === "all" ? null : new Set(spec.threads);
    for (const t of this.host.threads()) {
      if (checked >= this.host.verifyThreads()) break;
      if (wanted !== null && !wanted.has(t.id)) continue;
      const regs = this.host.readDebugRegisters(t.id);
      if ("error" in regs) continue;
      checked += 1;
      const expected = { address: bigOf(spec.address), rw: spec.rw, size: spec.rw === "x" ? (1 as const) : spec.size };
      if (verifySlot(regs.dr7, regs.dr[slot], slot, expected) === "armed") ok += 1;
    }
    return { threads_checked: checked, ok };
  }

  /**
   * The owned slots (armed, disarming or quarantined) this single step fired: DR6 B0..B3, or, when DR6 names no cause
   * at all, the owned slots the trapping context's DR7 enables at their own address (pure/dr7.ts inferStepSlots).
   */
  #firedOwned(nc: NativePointer, dr6: bigint): DrSlot[] {
    const named = firedSlots(dr6).filter((s) => (this.#slots[s]?.state ?? "free") !== "free");
    if (named.length > 0 || (dr6 & DR6_CAUSE_BITS) !== 0n) return named;
    const owned: { slot: DrSlot; address: bigint }[] = [];
    DR_SLOTS.forEach((s) => {
      const e = this.#slots[s];
      if (e !== undefined && e.state !== "free" && e.spec !== null)
        owned.push({ slot: s, address: bigOf(e.spec.address) });
    });
    if (owned.length === 0) return [];
    const dr7 = bigOf(nc.add(CONTEXT.dr7).readU64());
    const dr = DR_SLOTS.map((s) => bigOf(nc.add(CONTEXT.dr0 + 8 * s).readU64()));
    const inferred = inferStepSlots(dr6, dr7, dr, owned);
    for (const s of inferred) (this.#slots[s] as Slot).inferred += 1;
    return inferred;
  }

  /** Dispatcher hook: false when the step is not BEA's (no owned slot fired); every claimed hit is recorded. */
  onTrap(d: ExceptionDetails, tid: number): boolean {
    const nc = d.nativeContext;
    const dr6 = bigOf(nc.add(CONTEXT.dr6).readU64());
    const fired = this.#firedOwned(nc, dr6);
    if (fired.length === 0) return false;
    for (const s of fired) {
      const e = this.#slots[s] as Slot;
      if (e.state !== "armed" || e.spec === null) {
        this.#clearInContext(nc, s);
        continue;
      }
      let verdict: HitVerdict = "continue";
      try {
        verdict = e.spec.rw === "x" ? this.#onExec(d, tid, e) : this.#onWatch(d, tid, e);
      } catch (err) {
        this.host.fault("hwbp.onTrap", err); // that hit is lost; the trap is still BEA's and is claimed
      }
      if (verdict === "stop") {
        e.state = "disarming";
        this.#clearInContext(nc, s);
      } else if (e.spec.rw === "x") {
        nc.add(CONTEXT.eflags).writeU32(nc.add(CONTEXT.eflags).readU32() | 0x10000); // RF: run it once [V a6b]
      }
    }
    nc.add(CONTEXT.dr6).writeU64(uint64(clearDr6Hits(dr6).toString()));
    return true;
  }

  #onExec(d: ExceptionDetails, tid: number, e: Slot): HitVerdict {
    const spec = e.spec as DrArmSpec;
    return spec.sink.hit({
      tid,
      access: "x",
      insn: d.address,
      conf: "exact",
      pcAfter: null,
      text: decodeInsn(d.address)?.text ?? null,
      addr: spec.address,
      before: null,
      after: null,
      regs: spec.capture.registers === "gpr" ? captureRegisters(d.context, GPR_NAMES) : null,
      bt: backtraceOf(d.context, spec.capture.backtrace),
      mem: null,
    });
  }

  /** True when an owned read/write slot covers part of [address, address + size): a user-mode read would trip it. */
  readTrips(address: NativePointer, size: number): boolean {
    const lo = bigOf(address);
    const hi = lo + BigInt(size);
    return this.#slots.some((e) => {
      if (e.state === "free" || e.spec === null || e.spec.rw !== "rw") return false;
      const a = bigOf(e.spec.address);
      return a < hi && lo < a + BigInt(e.spec.size);
    });
  }

  #onWatch(d: ExceptionDetails, tid: number, e: Slot): HitVerdict {
    const spec = e.spec as DrArmSpec;
    const pcAfter = d.context.pc;
    const found = this.host.findAccessInsn(pcAfter);
    const after = this.host.readWatched(spec.address, spec.size, this.readTrips(spec.address, spec.size));
    const before = e.shadow;
    e.shadow = after;
    // an rw slot cannot tell a read from a write: the accessing instruction's memory operand does (WP9 acceptance)
    const operand = found.insn === null ? null : (decodeInsn(found.insn)?.memAccess ?? null);
    const access = spec.rw === "w" ? "w" : rwAccessOf(operand, u8(before), u8(after));
    return spec.sink.hit({
      tid,
      access,
      insn: found.insn,
      conf: found.conf,
      pcAfter,
      text: found.text,
      addr: spec.address,
      before,
      after,
      regs: spec.capture.registers === "gpr" ? captureRegisters(d.context, GPR_NAMES) : null,
      bt: backtraceOf(d.context, spec.capture.backtrace),
      mem: memOperandOf(found.insn, d.context),
    });
  }

  /** Handler-side disarm on the CONTEXT that will be restored (the VERIFIED reliable half, a6d). */
  #clearInContext(nc: NativePointer, s: DrSlot): void {
    const dr7 = bigOf(nc.add(CONTEXT.dr7).readU64());
    nc.add(CONTEXT.dr7).writeU64(uint64(clearSlot(dr7, s).toString()));
    nc.add(CONTEXT.dr0 + 8 * s).writeU64(0);
  }

  #unsetEverywhere(s: DrSlot, rw: DrRw): void {
    for (const t of this.host.threads()) {
      try {
        if (rw === "x") t.unsetHardwareBreakpoint(s);
        else t.unsetHardwareWatchpoint(s);
      } catch {
        // the thread exited
      }
    }
  }

  #stillSet(s: DrSlot): number {
    let found = 0;
    let checked = 0;
    for (const t of this.host.threads()) {
      if (checked >= this.host.verifyThreads()) break;
      const regs = this.host.readDebugRegisters(t.id);
      if ("error" in regs) continue;
      checked += 1;
      if (verifySlot(regs.dr7, regs.dr[s], s, null) !== "cleared") found += 1;
    }
    return found;
  }

  /**
   * S4 §11.2 disarm: disarming state (traps clear in the handler) → unset on every thread → verify after 150 ms,
   * up to 3 rounds → free, or quarantined (never reused; its traps stay swallowed).
   */
  async disarm(owner: InstrumentId): Promise<{ slot: DrSlot | null; ok: boolean; detail: string }> {
    const s = DR_SLOTS.find((k) => this.#slots[k]?.spec?.owner === owner);
    if (s === undefined) return { slot: null, ok: true, detail: "not armed" };
    const e = this.#slots[s] as Slot;
    const rw = e.spec?.rw ?? "w";
    e.state = "disarming";
    this.#dropObserverIfIdle();
    let left = 0;
    for (let round = 0; round < 3; round++) {
      this.#unsetEverywhere(s, rw);
      await new Promise<void>((resolve) => setTimeout(resolve, 150));
      left = this.#stillSet(s);
      if (left === 0) break;
    }
    if (left > 0) {
      e.state = "quarantined";
      this.host.onSlotsChanged(this.ownedMask);
      return { slot: s, ok: false, detail: `dr${String(s)} still set on ${String(left)} thread(s); slot quarantined` };
    }
    this.#releaseLater(s, e.spec);
    const inferred = e.inferred > 0 ? `; ${String(e.inferred)} hit(s) had no DR6 cause bit (attributed by DR7)` : "";
    return { slot: s, ok: true, detail: `dr7 slot ${String(s)} clear on every sampled thread${inferred}` };
  }

  /**
   * The slot stays BEA's (disarming: traps are cleared in the handler) for DR_RELEASE_GRACE_MS after the verified
   * disarm. A thread that trapped just before the unset and waited past the verification (a starved thread, or one
   * blocked on the JS lock) resumes from its exception context, whose DR7 still has the slot: that late trap must
   * still be claimed and cleared, not passed on as a stranger's single step (which kills the target).
   */
  #releaseLater(s: DrSlot, spec: DrArmSpec | null): void {
    const e = this.#slots[s] as Slot;
    setTimeout(() => {
      if (e.state !== "disarming" || e.spec !== spec) return;
      e.state = "free";
      e.spec = null;
      e.shadow = null;
      this.host.onSlotsChanged(this.ownedMask);
    }, DR_RELEASE_GRACE_MS);
  }

  /** dispose (unload): synchronous unset everywhere, no verification (A-36 VERIFIED: keeps the target alive). */
  disarmAllSync(): void {
    DR_SLOTS.forEach((s) => {
      const e = this.#slots[s];
      if (e === undefined || e.state === "free" || e.spec === null) return;
      e.state = "disarming";
      this.#unsetEverywhere(s, e.spec.rw);
    });
    if (this.#observer !== null) {
      this.#observer.detach();
      this.#observer = null;
    }
  }
}
