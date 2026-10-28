// =================================================================================================
// src/agent/dump.ts — dump jobs and thread state (S4 §15; S5 §10.2 R1–R9; DESIGN §5.3, D-INT-44, D-INT-45; WP-DUMP).
//
// dumpStart plans on the JS thread (enumeration may take the loader lock), then runs a sliced job: one region at a
// time, chunks of ≤ dump_chunk_bytes sent as `blob` messages, a `job` message with the bea-dump/1 manifest at the end.
// suspend:"all" copies thread state and the thread/range items into agent memory while every other thread is
// suspended (no enumeration and no send while suspended, A-32), resumes in `finally` (cooperative 2 s watchdog), then
// sends the copies. Module images are always read live; with original_bytes (default) BEA's own patches are replaced
// by the original bytes (CT-I6) and reported per region as bea_patches_restored.
//
// Core services this feature uses when WP-AGENT provides them (looked up at runtime so this file builds against the
// day-0 AgentCore; the integrator wires them, see `coreServices`): `guards.withBeaGuardsSuspended(ranges, fn)`
// (D-INT-44), `originals.overlay(buf, base)` (S4 §8.4) and `modules.epoch`. Without them reads are plain Frida reads
// (a BEA guard page then reads as a hole) and nothing is spliced. Dump jobs run on this file's own slicer; their ids
// ("j<n>", n ≥ 1000001) and blob ids ("b<n>", same base) never collide with the core JobRunner's.
// =================================================================================================
import type {
  AgentError,
  AgentResult,
  AgentRpcImpl,
  BlobMessage,
  CaptureThreadStateParams,
  DumpItem,
  DumpManifest,
  DumpRegion,
  DumpStartParams,
  DumpStartResult,
  JobMessage,
  ThreadState,
} from "../shared/agentProtocol.js";
import { AGENT_LIMIT_HARD } from "../shared/agentLimits.js";
import { formatHex, type Hex } from "../shared/hex.js";
import { fail, mapThrown, ok } from "./errors.js";
import {
  CONTEXT_ALL,
  CONTEXT_BYTES,
  CONTEXT_FLAGS_OFFSET,
  DIR_TLS,
  PEB_BYTES,
  TEB_BYTES,
  TEB_PEB,
  TEB_STACK_BASE,
  TEB_STACK_LIMIT,
  TEB_TLS_POINTER,
  TEB_TLS_SLOT_COUNT,
  TEB_TLS_SLOTS,
  TLS_DIRECTORY_BYTES,
  changedRanges,
  chunksOf,
  coalesce,
  holesOf,
  intersect,
  moduleSelector,
  pageSpan,
  parseContext,
  parseTlsDirectory,
  peDirectory,
  readableParts,
  stackSpan,
  tlsBlockSize,
  type Rel,
  type Span,
} from "./pure/dumpPlan.js";
import type { AgentCore } from "./state.js";

const ID_BASE = 1_000_000;
const MAX_ITEMS = 256;
const MAX_SUSPENDED_BYTES = 64 * 1024 * 1024;
const SUSPEND_WATCHDOG_MS = 2000;
const THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
const THREAD_CONTEXT_ACCESS = 0x0008 | 0x0002 | 0x0800; // GET_CONTEXT | SUSPEND_RESUME | QUERY_LIMITED_INFORMATION
const SUSPEND_FAILED = 0xffffffff;

// ---------------------------------------------------------------- core services (duck-typed, see header)
type GuardRange = { base: NativePointer; size: number };
interface CoreServices {
  guarded<T>(base: NativePointer, size: number, fn: () => T): T;
  overlay: ((buf: ArrayBuffer, base: NativePointer) => void) | null;
  moduleEpoch(): number;
}
const fnAt = (holder: unknown, name: string): ((...args: unknown[]) => unknown) | null => {
  if (typeof holder !== "object" || holder === null) return null;
  const value: unknown = Reflect.get(holder, name);
  return typeof value === "function" ? (...args: unknown[]) => Reflect.apply(value, holder, args) : null;
};
function coreServices(core: AgentCore): CoreServices {
  const guards: unknown = Reflect.get(core, "guards");
  const suspend = fnAt(guards, "withBeaGuardsSuspended") ?? fnAt(core, "withBeaGuardsSuspended");
  const overlay = fnAt(Reflect.get(core, "originals"), "overlay");
  const modules: unknown = Reflect.get(core, "modules");
  return {
    guarded: <T>(base: NativePointer, size: number, fn: () => T): T =>
      suspend === null ? fn() : (suspend([{ base, size } satisfies GuardRange], fn) as T),
    overlay: overlay === null ? null : (buf, base) => void overlay(buf, base),
    moduleEpoch: () => {
      const epoch: unknown = typeof modules === "object" && modules !== null ? Reflect.get(modules, "epoch") : 0;
      return typeof epoch === "number" ? epoch : 0;
    },
  };
}

// ---------------------------------------------------------------- Win32 bindings (S4 §5.5; exclusive scheduling)
interface Win32 {
  readonly openThread: NativeFunction<NativePointer, [number, number, number]>;
  readonly closeHandle: NativeFunction<number, [NativePointerValue]>;
  readonly suspendThread: NativeFunction<number, [NativePointerValue]>;
  readonly resumeThread: NativeFunction<number, [NativePointerValue]>;
  readonly getThreadContext: NativeFunction<number, [NativePointerValue, NativePointerValue]>;
  readonly ntQueryInformationThread: NativeFunction<
    number,
    [NativePointerValue, number, NativePointerValue, number, NativePointerValue]
  >;
}
let win: Win32 | null = null;
function win32(): Win32 {
  if (win !== null) return win;
  const kb = Process.getModuleByName("kernelbase.dll");
  const nt = Process.getModuleByName("ntdll.dll");
  const ex = { scheduling: "exclusive" } as const;
  win = {
    openThread: new NativeFunction(kb.getExportByName("OpenThread"), "pointer", ["uint32", "int", "uint32"], ex),
    closeHandle: new NativeFunction(kb.getExportByName("CloseHandle"), "int", ["pointer"], ex),
    suspendThread: new NativeFunction(kb.getExportByName("SuspendThread"), "uint32", ["pointer"], ex),
    resumeThread: new NativeFunction(kb.getExportByName("ResumeThread"), "uint32", ["pointer"], ex),
    getThreadContext: new NativeFunction(kb.getExportByName("GetThreadContext"), "int", ["pointer", "pointer"], ex),
    ntQueryInformationThread: new NativeFunction(
      nt.getExportByName("NtQueryInformationThread"),
      "uint32",
      ["pointer", "uint32", "pointer", "uint32", "pointer"],
      ex,
    ),
  };
  return win;
}

const big = (p: NativePointer): bigint => BigInt(p.toString());
const at = (v: bigint): NativePointer => ptr(`0x${v.toString(16)}`);
const hex = (p: NativePointer): Hex => formatHex(big(p));
const notFoundThread = (tid: number): AgentResult<never> =>
  fail({ _tag: "NotFound", message: "thread not found", what: "thread", id: String(tid) });

/** TEB via OpenThread(QUERY_LIMITED) + NtQueryInformationThread(ThreadBasicInformation) → TebBaseAddress (+8). */
function tebOf(tid: number): NativePointer | null {
  const w = win32();
  const h = w.openThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid);
  if (h.isNull()) return null;
  try {
    const info = Memory.alloc(48);
    if (w.ntQueryInformationThread(h, 0, info, 48, NULL) !== 0) return null;
    const teb = info.add(8).readPointer();
    return teb.isNull() ? null : teb;
  } finally {
    w.closeHandle(h);
  }
}

/** GetThreadContext(CONTEXT_ALL); suspends around the call unless the caller already suspended the thread. */
function contextBytes(tid: number, alreadySuspended: boolean): Uint8Array | null {
  const w = win32();
  const raw = Memory.alloc(CONTEXT_BYTES + 16);
  const ctx = raw.add((16 - (raw.toUInt32() & 15)) & 15);
  ctx.writeU32(CONTEXT_ALL, CONTEXT_FLAGS_OFFSET);
  const h = w.openThread(THREAD_CONTEXT_ACCESS, 0, tid);
  if (h.isNull()) return null;
  try {
    if (!alreadySuspended && w.suspendThread(h) === SUSPEND_FAILED) return null;
    try {
      if (w.getThreadContext(h, ctx) === 0) return null;
    } finally {
      if (!alreadySuspended) w.resumeThread(h);
    }
    const out = ctx.readByteArray(CONTEXT_BYTES);
    return out === null ? null : new Uint8Array(out);
  } finally {
    w.closeHandle(h);
  }
}

// ---------------------------------------------------------------- planning
type RegionKind = DumpRegion["kind"];
interface PlannedRegion {
  readonly blob: string;
  readonly kind: RegionKind;
  readonly span: Span;
  readonly protection: string;
  readonly module: string | null;
  /** plan-time readable spans (absolute), used by the slow per-range read path */
  readonly readable: readonly Span[];
  readonly splice: boolean;
  /** suspend:"all": bytes copied under suspension (agent memory) + their holes */
  copy: { buf: NativePointer; holes: Rel[] } | null;
  copyCandidate: boolean;
}
interface PlannedThread {
  readonly tid: number;
  readonly xmm: boolean;
  readonly tls: boolean;
  readonly teb: NativePointer | null;
  state: ThreadState | null;
}
interface TlsModule {
  readonly module: string;
  readonly indexAddress: NativePointer;
  readonly size: number;
}

function readableIn(span: Span, snapshot: readonly Span[]): Span[] {
  return snapshot.map((r) => intersect(span, r)).filter((r): r is Span => r !== null);
}
function protectionOf(span: Span): string {
  try {
    return Process.findRangeByAddress(at(span.start))?.protection ?? "---";
  } catch {
    return "---";
  }
}
function tlsModules(): TlsModule[] {
  const out: TlsModule[] = [];
  for (const m of Process.enumerateModules()) {
    try {
      const header = m.base.readByteArray(0x1000);
      const dir = header === null ? null : peDirectory(new Uint8Array(header), DIR_TLS);
      if (dir === null || dir.size < TLS_DIRECTORY_BYTES) continue;
      const raw = m.base.add(dir.rva).readByteArray(TLS_DIRECTORY_BYTES);
      const tls = raw === null ? null : parseTlsDirectory(new Uint8Array(raw));
      const size = tls === null ? 0 : tlsBlockSize(tls);
      if (tls !== null && size > 0 && tls.indexAddress !== 0n)
        out.push({ module: m.name, indexAddress: at(tls.indexAddress), size });
    } catch {
      // unreadable header: no static TLS facts for this module
    }
  }
  return out;
}

class Planner {
  readonly regions: PlannedRegion[] = [];
  readonly threads: PlannedThread[] = [];
  readonly modules: DumpManifest["modules"] = [];
  readonly #seen = new Set<string>();
  readonly #snapshot: Span[];
  #tls: TlsModule[] | null = null;
  #live: Map<number, NativePointer> | null = null;
  #blob: () => string;
  constructor(blob: () => string) {
    this.#blob = blob;
    this.#snapshot = Process.enumerateRanges("r--").map((r) => ({ start: big(r.base), size: r.size }));
  }
  add(kind: RegionKind, span: Span, module: string | null, splice: boolean, copyCandidate: boolean): string | null {
    if (span.size <= 0) return null;
    const key = `${kind}:${span.start.toString(16)}:${String(span.size)}`;
    if (this.#seen.has(key)) return null;
    this.#seen.add(key);
    const blob = this.#blob();
    this.regions.push({
      blob,
      kind,
      span,
      protection: kind === "module" ? "r-x" : protectionOf(span),
      module,
      readable: readableIn(span, this.#snapshot),
      splice,
      copy: null,
      copyCandidate,
    });
    return blob;
  }
  item(item: DumpItem, original: boolean): AgentError | null {
    switch (item.kind) {
      case "module":
        return this.#module(item.module, original);
      case "range":
        this.add("range", { start: BigInt(item.base), size: item.size }, null, false, true);
        return null;
      case "ranges":
        this.#ranges(item);
        return null;
      case "thread":
        return this.#thread(item);
    }
  }
  #module(selector: string, original: boolean): AgentError | null {
    const sel = moduleSelector(selector);
    const m = Process.enumerateModules().find((x) =>
      sel.kind === "base" ? big(x.base) === sel.base : x.name.toLowerCase() === sel.name,
    );
    if (m === undefined) return { _tag: "ModuleNotFound", message: "module not loaded", module: selector };
    const blob = this.add("module", { start: big(m.base), size: m.size }, m.name, original, false);
    this.modules.push({ name: m.name, path: m.path, base: hex(m.base), size: m.size, blob });
    return null;
  }
  #ranges(item: Extract<DumpItem, { kind: "ranges" }>): void {
    const f = item.filter;
    const include = f.modules?.map((n) => n.toLowerCase());
    const exclude = new Set(f.exclude_modules?.map((n) => n.toLowerCase()) ?? []);
    let total = 0;
    for (const r of Process.enumerateRanges(f.protection)) {
      const owner = Process.findModuleByAddress(r.base);
      const name = owner?.name.toLowerCase() ?? null;
      if (f.private_only === true && owner !== null) continue;
      if (include !== undefined && (name === null || !include.includes(name))) continue;
      if (name !== null && exclude.has(name)) continue;
      if (f.min !== undefined && big(r.base) < BigInt(f.min)) continue;
      if (f.max !== undefined && big(r.base) >= BigInt(f.max)) continue;
      if (f.max_region_bytes !== undefined && r.size > f.max_region_bytes) continue;
      if (total + r.size > item.max_total_bytes) break;
      total += r.size;
      this.add("range", { start: big(r.base), size: r.size }, owner?.name ?? null, false, false);
    }
  }
  #thread(item: Extract<DumpItem, { kind: "thread" }>): AgentError | null {
    const teb = tebOf(item.tid);
    if (teb === null) return { _tag: "NotFound", message: "thread not found", what: "thread", id: String(item.tid) };
    this.threads.push({ tid: item.tid, xmm: item.xmm, tls: item.tls, teb, state: null });
    if (item.teb) this.add("teb", { start: big(teb), size: TEB_BYTES }, null, false, true);
    const peb = teb.add(TEB_PEB).readPointer();
    if (!peb.isNull()) this.add("peb", pageSpan(big(peb), PEB_BYTES), null, false, true);
    if (item.stack_bytes > 0) {
      this.#live ??= new Map(Process.enumerateThreads().map((t) => [t.id, t.context.sp]));
      const sp = this.#live.get(item.tid);
      const rsp = sp === undefined ? null : big(sp);
      const base = big(teb.add(TEB_STACK_BASE).readPointer());
      // suspend:"all" may capture a deeper rsp than this snapshot: keep 64 KiB of margin below it
      const span = rsp === null ? null : stackSpan(rsp - 0x10000n, base, item.stack_bytes + 0x10000);
      if (span !== null) this.add("stack", span, null, false, true);
    }
    if (item.tls) this.#threadTls(teb);
    return null;
  }
  #threadTls(teb: NativePointer): void {
    const array = teb.add(TEB_TLS_POINTER).readPointer();
    if (array.isNull()) return;
    this.#tls ??= tlsModules();
    let count = 0;
    while (
      count < 64 &&
      !array
        .add(8 * count)
        .readPointer()
        .isNull()
    )
      count++;
    this.add("tls", pageSpan(big(array), Math.max(8, 8 * count)), null, false, true);
    for (const t of this.#tls) {
      try {
        const index = t.indexAddress.readU32();
        if (index >= 64) continue;
        const block = array.add(8 * index).readPointer();
        if (!block.isNull()) this.add("tls", pageSpan(big(block), t.size), t.module, false, true);
      } catch {
        // index or slot unreadable: this module's static block is not captured
      }
    }
  }
}

// ---------------------------------------------------------------- thread state
function threadState(
  tid: number,
  ctx: Uint8Array,
  want: { xmm: boolean; tls: boolean },
  teb: NativePointer | null,
): ThreadState {
  const parsed = parseContext(ctx, want.xmm);
  let peb: Hex | null = null;
  let stack: ThreadState["stack"] = null;
  let tls: ThreadState["tls"] = null;
  if (teb !== null) {
    try {
      peb = hex(teb.add(TEB_PEB).readPointer());
      stack = { base: hex(teb.add(TEB_STACK_BASE).readPointer()), limit: hex(teb.add(TEB_STACK_LIMIT).readPointer()) };
      if (want.tls) {
        const array = teb.add(TEB_TLS_POINTER).readPointer();
        const slots: Hex[] = [];
        for (let i = 0; i < TEB_TLS_SLOT_COUNT; i++) slots.push(hex(teb.add(TEB_TLS_SLOTS + 8 * i).readPointer()));
        tls = { static_tls_array: array.isNull() ? null : hex(array), tls_slots: slots };
      }
    } catch {
      // TEB fields unreadable: keep what was read
    }
  }
  return {
    tid,
    registers: parsed.registers,
    eflags: parsed.eflags,
    mxcsr: parsed.mxcsr,
    fpcw: parsed.fpcw,
    xmm: parsed.xmm,
    teb: teb === null ? null : hex(teb),
    peb,
    stack,
    tls,
  };
}

// ---------------------------------------------------------------- reads
/** Copies the readable parts of [off, off+size) of a region into `out` (at 0); returns the holes it hit. */
function readSlow(region: PlannedRegion, off: number, size: number, out: Uint8Array, svc: CoreServices): Rel[] {
  const planned = holesOf(region.span, region.readable);
  const holes: Rel[] = [];
  for (const part of readableParts(off, size, planned))
    for (let p = part.offset; p < part.offset + part.size;) {
      const n = Math.min(0x1000 - Number((region.span.start + BigInt(p)) & 0xfffn), part.offset + part.size - p);
      const addr = at(region.span.start + BigInt(p));
      try {
        const buf = svc.guarded(addr, n, () => addr.readByteArray(n));
        if (buf === null) throw new Error("unreadable");
        out.set(new Uint8Array(buf), p - off);
      } catch {
        holes.push({ offset: p, size: n });
      }
      p += n;
    }
  for (const h of planned) {
    const s = Math.max(h.offset, off);
    const e = Math.min(h.offset + h.size, off + size);
    if (e > s) holes.push({ offset: s, size: e - s });
  }
  return holes;
}

/** One chunk of a region: fast whole read first, then the per-page fallback. */
function readChunk(
  region: PlannedRegion,
  off: number,
  size: number,
  svc: CoreServices,
): { bytes: Uint8Array; holes: Rel[] } {
  if (region.copy !== null) {
    const raw = region.copy.buf.add(off).readByteArray(size);
    const bytes = raw === null ? new Uint8Array(size) : new Uint8Array(raw);
    const holes = region.copy.holes
      .map((h) => ({
        offset: Math.max(h.offset, off),
        size: Math.min(h.offset + h.size, off + size) - Math.max(h.offset, off),
      }))
      .filter((h) => h.size > 0);
    return { bytes, holes };
  }
  const addr = at(region.span.start + BigInt(off));
  try {
    const raw = svc.guarded(addr, size, () => addr.readByteArray(size));
    if (raw !== null) return { bytes: new Uint8Array(raw), holes: [] };
  } catch {
    // fall through to the per-page path
  }
  const bytes = new Uint8Array(size);
  return { bytes, holes: readSlow(region, off, size, bytes, svc) };
}

// ---------------------------------------------------------------- suspend:"all" capture (S4 §15.1 steps 1–4)
function suspendedCapture(plan: Planner, core: AgentCore, svc: CoreServices): void {
  let budget = MAX_SUSPENDED_BYTES;
  const copies: PlannedRegion[] = [];
  for (const r of plan.regions)
    if (r.copyCandidate && r.span.size <= budget) {
      budget -= r.span.size;
      r.copy = { buf: Memory.alloc(r.span.size), holes: [] };
      copies.push(r);
    }
  // keep every allocation referenced (QJS frees a Memory.alloc block as soon as its own pointer is unreachable; a
  // derived pointer does not keep it alive, VERIFIED: GetThreadContext then wrote into freed memory)
  const contexts = plan.threads.map(() => {
    const raw = Memory.alloc(CONTEXT_BYTES + 16);
    return { raw, ctx: raw.add((16 - (raw.toUInt32() & 15)) & 15) };
  });
  const w = win32();
  const self = Process.getCurrentThreadId();
  const handles: NativePointer[] = [];
  const t0 = Date.now();
  try {
    for (const t of Process.enumerateThreads()) {
      if (t.id === self || t.id === core.jsTid) continue;
      const h = w.openThread(THREAD_CONTEXT_ACCESS, 0, t.id);
      if (h.isNull()) continue;
      if (w.suspendThread(h) === SUSPEND_FAILED) w.closeHandle(h);
      else handles.push(h);
    }
    plan.threads.forEach((t, i) => {
      const ctx = contexts[i]?.ctx;
      if (ctx === undefined) return;
      ctx.writeU32(CONTEXT_ALL, CONTEXT_FLAGS_OFFSET);
      const h = w.openThread(THREAD_CONTEXT_ACCESS, 0, t.tid);
      if (h.isNull()) return;
      try {
        if (w.getThreadContext(h, ctx) !== 0) {
          const bytes = ctx.readByteArray(CONTEXT_BYTES);
          if (bytes !== null) t.state = threadState(t.tid, new Uint8Array(bytes), t, t.teb);
        }
      } finally {
        w.closeHandle(h);
      }
    });
    for (const r of copies) {
      const copy = r.copy;
      if (copy === null) continue;
      if (Date.now() - t0 > SUSPEND_WATCHDOG_MS) {
        r.copy = null; // watchdog: the rest is read live after the resume
        continue;
      }
      const planned = holesOf(r.span, r.readable);
      for (const part of readableParts(0, r.span.size, planned)) {
        const src = at(r.span.start + BigInt(part.offset));
        try {
          svc.guarded(src, part.size, () => Memory.copy(copy.buf.add(part.offset), src, part.size));
        } catch {
          copy.holes.push(part);
        }
      }
      copy.holes.push(...planned);
    }
  } finally {
    for (const h of handles) {
      w.resumeThread(h);
      w.closeHandle(h);
    }
  }
  for (const r of copies)
    if (r.copy !== null)
      for (const h of coalesce(r.copy.holes)) r.copy.buf.add(h.offset).writeByteArray(new Uint8Array(h.size).buffer);
}

// ---------------------------------------------------------------- the job
interface RegionProgress {
  part: number;
  holes: Rel[];
  restored: Rel[];
}
interface DumpJob {
  readonly id: string;
  readonly plan: Planner;
  readonly chunk: number;
  readonly suspended: boolean;
  readonly t0: number;
  readonly total: number;
  readonly truncated: boolean;
  ri: number;
  ci: number;
  done: number;
  progress: RegionProgress;
  readonly regions: DumpRegion[];
}

let core: AgentCore | null = null;
let services: CoreServices | null = null;
let nextId = ID_BASE;
let running = 0;

const nowUs = (c: AgentCore): number => (Date.now() - c.t0Wall) * 1000;

function sendJob(job: DumpJob, c: AgentCore, msg: Pick<JobMessage, "state" | "result" | "error">): void {
  const message: JobMessage = {
    bea: "job",
    job: job.id,
    kind: "dump",
    progress: { done: job.done, total: job.total, unit: "bytes" },
    ...msg,
  };
  if (message.result === undefined) delete message.result;
  if (message.error === undefined) delete message.error;
  send(message);
  void c;
}

function finishRegion(job: DumpJob, region: PlannedRegion): void {
  job.regions.push({
    blob: region.blob,
    kind: region.kind,
    base: formatHex(region.span.start),
    size: region.span.size,
    protection: region.protection,
    module: region.module,
    holes: coalesce(job.progress.holes).map((h) => ({ offset: h.offset, size: h.size, reason: "unreadable" })),
    bea_patches_restored: coalesce(job.progress.restored),
    sha256: null,
  });
  job.ri++;
  job.ci = 0;
  job.progress = { part: 0, holes: [], restored: [] };
}

/** Sends one chunk; returns false when every region is done. */
function stepChunk(job: DumpJob, svc: CoreServices): boolean {
  const region = job.plan.regions[job.ri];
  if (region === undefined) return false;
  const chunks = chunksOf(region.span.size, job.chunk);
  const chunk = chunks[job.ci];
  if (chunk === undefined) {
    finishRegion(job, region);
    return true;
  }
  const { bytes, holes } = readChunk(region, chunk.offset, chunk.size, svc);
  job.progress.holes.push(...holes);
  if (region.splice && svc.overlay !== null) {
    const before = bytes.slice();
    try {
      svc.overlay(bytes.buffer as ArrayBuffer, at(region.span.start + BigInt(chunk.offset)));
      for (const r of changedRanges(before, bytes))
        job.progress.restored.push({ offset: r.offset + chunk.offset, size: r.size });
    } catch {
      bytes.set(before);
    }
  }
  const last = job.ci === chunks.length - 1;
  const message: BlobMessage = {
    bea: "blob",
    blob: region.blob,
    job: job.id,
    part: job.progress.part++,
    offset: chunk.offset,
    bytes: chunk.size,
    last,
    total: region.span.size,
  };
  send(message, bytes.buffer as ArrayBuffer);
  job.done += chunk.size;
  job.ci++;
  if (last) finishRegion(job, region);
  return true;
}

function manifestOf(job: DumpJob, c: AgentCore, svc: CoreServices): DumpManifest {
  return {
    format: "bea-dump/1",
    pid: Process.id,
    taken: { t0: job.t0, t1: nowUs(c), suspended: job.suspended },
    modules: job.plan.modules,
    regions: job.regions,
    threads: job.plan.threads.map((t) => t.state).filter((s): s is ThreadState => s !== null),
    module_map_epoch: svc.moduleEpoch(),
    truncated: job.truncated,
  };
}

function runSlice(job: DumpJob, c: AgentCore, svc: CoreServices): void {
  const budget = Math.max(1, c.limits.job_slice_ms);
  const start = Date.now();
  try {
    while (Date.now() - start < budget) {
      if (!stepChunk(job, svc)) {
        running--;
        sendJob(job, c, { state: "done", result: manifestOf(job, c, svc) });
        return;
      }
      // one chunk per slice when chunks are large (bounds the queued send() bytes)
      if (job.chunk >= 1024 * 1024) break;
    }
  } catch (e) {
    running--;
    sendJob(job, c, { state: "failed", error: mapThrown(e, "dump") });
    return;
  }
  setImmediate(() => runSlice(job, c, svc));
}

// ---------------------------------------------------------------- RPCs
function badParams(path: string, problem: string): AgentResult<never> {
  return fail({ _tag: "BadParams", message: "invalid dump parameters", issues: [{ path, problem }] });
}

function validate(p: DumpStartParams, c: AgentCore): AgentResult<never> | null {
  if (!Array.isArray(p.items) || p.items.length === 0 || p.items.length > MAX_ITEMS)
    return badParams("items", `1..${String(MAX_ITEMS)} items required`);
  if (p.suspend !== "none" && p.suspend !== "all") return badParams("suspend", "none or all");
  if (!Number.isInteger(p.max_total_bytes) || p.max_total_bytes < 1)
    return badParams("max_total_bytes", "a positive integer is required");
  if (running >= c.limits.dump_max_concurrent)
    return fail({
      _tag: "ResourceLimit",
      message: "too many dump jobs",
      resource: "jobs",
      limit: c.limits.dump_max_concurrent,
    });
  return null;
}

function dumpStart(p: DumpStartParams): AgentResult<DumpStartResult> {
  const c = core;
  const svc = services;
  if (c === null || svc === null) return fail({ _tag: "NotReady", message: "dump feature not initialized" });
  const invalid = validate(p, c);
  if (invalid !== null) return invalid;
  const plan = new Planner(() => `b${String(++nextId)}`);
  for (const item of p.items) {
    const error = plan.item(item, p.original_bytes !== false);
    if (error !== null) return fail(error);
  }
  const maxTotal = Math.min(p.max_total_bytes, c.limits.dump_max_bytes, AGENT_LIMIT_HARD.dump_max_bytes);
  let total = 0;
  let truncated = false;
  const kept = plan.regions.filter((r) => {
    if (total + r.span.size > maxTotal) {
      truncated = true;
      return false;
    }
    total += r.span.size;
    return true;
  });
  plan.regions.splice(0, plan.regions.length, ...kept);
  for (const m of plan.modules) if (m.blob !== null && !kept.some((r) => r.blob === m.blob)) m.blob = null;
  if (p.suspend === "all") suspendedCapture(plan, c, svc);
  for (const t of plan.threads)
    if (t.state === null) {
      const ctx = contextBytes(t.tid, false);
      if (ctx !== null) t.state = threadState(t.tid, ctx, t, t.teb);
    }
  const chunkCap = Math.min(c.limits.dump_chunk_bytes, AGENT_LIMIT_HARD.dump_chunk_bytes);
  const job: DumpJob = {
    id: `j${String(++nextId)}`,
    plan,
    chunk: Math.max(0x1000, Math.min(p.chunk_bytes ?? chunkCap, chunkCap)),
    suspended: p.suspend === "all",
    t0: nowUs(c),
    total,
    truncated,
    ri: 0,
    ci: 0,
    done: 0,
    progress: { part: 0, holes: [], restored: [] },
    regions: [],
  };
  running++;
  setImmediate(() => runSlice(job, c, svc));
  return ok({ job_id: job.id, planned_bytes: total, planned_blobs: plan.regions.length });
}

function captureThreadState(p: CaptureThreadStateParams): AgentResult<ThreadState> {
  const c = core;
  if (c === null) return fail({ _tag: "NotReady", message: "dump feature not initialized" });
  if (!Number.isInteger(p.tid) || p.tid <= 0) return badParams("tid", "a thread id is required");
  if (p.tid === c.jsTid || p.tid === Process.getCurrentThreadId())
    return badParams("tid", "the agent thread cannot capture its own state");
  const teb = tebOf(p.tid);
  if (teb === null) return notFoundThread(p.tid);
  const ctx = contextBytes(p.tid, false);
  if (ctx === null) return notFoundThread(p.tid);
  const state = threadState(p.tid, ctx, { xmm: p.xmm, tls: p.tls }, teb);
  return ok(p.teb ? state : { ...state, teb: null });
}

export function init(c: AgentCore): void {
  core = c;
  services = coreServices(c);
  if (!c.features.includes("dump")) c.features.push("dump");
}
export const rpc = {
  dumpStart,
  captureThreadState,
} satisfies Partial<AgentRpcImpl>;
