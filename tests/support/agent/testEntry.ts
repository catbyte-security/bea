// =================================================================================================
// tests/support/agent/testEntry.ts — the agent-side TEST entry of the WP3 raw-Frida acceptance lane. The source below
// is staged next to index.ts (as agent/__beaTest.ts) and compiled by frida.Compiler with the core; it imports the real
// boot ("./index.js") and adds test-only RPCs that need the core singleton: an in-call bracket (`core.calls`), BEA
// guard pages, stolen guards, a test hook stream through the instrument registry and the event pipeline, and the
// core's own fallback trap engine on a page the target writes (dispose tests). Never part of the shipped bundle.
// =================================================================================================

export const TEST_ENTRY_NAME = "__beaTest";

export const TEST_ENTRY_SOURCE = String.raw`
import "./index.js";
import { currentCore } from "./state.js";
import { Stream } from "./events.js";
import { Instrument } from "./instruments.js";
import { hex } from "./encode.js";
import { captureArg } from "./capture.js";
import { decodeAt, findAccessInsn } from "./disasm.js";
import type { ArgCapture, ValueCell } from "../shared/agentProtocol.js";

const core = currentCore()!;
const keep: unknown[] = [];
const PAGE_GUARD = 0x100;

const isBadReadPtrAddress = Process.getModuleByName("kernelbase.dll").findExportByName("IsBadReadPtr")
  ?? Process.getModuleByName("kernel32.dll").getExportByName("IsBadReadPtr");
const isBadReadPtr = new NativeFunction(isBadReadPtrAddress, "int", ["pointer", "size_t"], { exceptions: "propagate" });
const virtualQueryProtect = (p: NativePointer): number => core.guards.query(p)?.protect ?? -1;

/** One "BEA call" on the current thread: calls.enter → IsBadReadPtr(0x10) under exceptions:"propagate" → exit. */
const inCallOnce = (bracket: boolean): { result: number; exited: unknown; tid: number } => {
  const tid = Process.getCurrentThreadId();
  const token = core.calls.newToken();
  if (bracket) core.calls.enter(tid, token);
  let result = -1;
  let exited: unknown = null;
  try {
    result = isBadReadPtr(ptr(0x10), 4) as number;
  } finally {
    if (bracket) exited = core.calls.exit(tid);
  }
  return { result, exited, tid };
};

const guardPages = new Map<string, NativePointer>();
let seamReverts = 0;

const extra = {
  testInCallAgentThread(): unknown {
    return inCallOnce(true);
  },
  testInCallOnThread(p: { tid: number; bracket: boolean }): Promise<unknown> {
    return Process.runOnThread(p.tid, () => inCallOnce(p.bracket));
  },
  testMainThread(): number {
    return Process.enumerateThreads()[0]!.id;
  },
  /** A target-like page (VirtualAlloc, not Frida's heap) holding a marker, registered and armed as a BEA guard page. */
  testGuardPage(p: { marker: number }): unknown {
    const page = core.win.VirtualAlloc(NULL, Process.pageSize, 0x3000, 0x04);
    keep.push(page);
    page.add(0x100).writeU32(p.marker >>> 0);
    const entry = core.guards.add(page, "test");
    if ("_tag" in entry) return { error: entry };
    const armed = core.guards.arm(entry);
    guardPages.set(page.toString(), page);
    return { page: hex(page), armed, protect: virtualQueryProtect(page) };
  },
  /** Arm the core fallback engine on the page containing a target address (the target keeps touching it). */
  testGuardAddress(p: { address: string }): unknown {
    const entry = core.guards.add(ptr(p.address), "test");
    if ("_tag" in entry) return { error: entry };
    const armed = core.guards.arm(entry);
    return { page: hex(entry.base), armed, protect: virtualQueryProtect(entry.base) };
  },
  testGuardState(p: { page: string }): unknown {
    const entry = core.guards.find(ptr(p.page));
    return entry === null
      ? null
      : { protect: virtualQueryProtect(entry.base), guarded: core.guards.isGuardedNow(entry), windows: entry.windows,
          stolen: entry.stolen, fallbackTraps: entry.fallbackTraps };
  },
  /** scanSync over a BEA page through withBeaGuardsSuspended (the CT-I5 primitive). */
  testScanSuspended(p: { page: string; pattern: string }): unknown {
    const page = ptr(p.page);
    const hits = core.guards.withBeaGuardsSuspended([{ base: page, size: Process.pageSize }], () =>
      Memory.scanSync(page, Process.pageSize, p.pattern).map((h) => hex(h.address)));
    return { hits, protectAfter: virtualQueryProtect(page) };
  },
  /** scanSync WITHOUT suspension: Frida's try-scope consumes the guard (CT-lab E16b); the core re-arms (stolen). */
  testScanUnsuspended(p: { page: string; pattern: string }): unknown {
    const page = ptr(p.page);
    let threw: string | null = null;
    try {
      Memory.scanSync(page, Process.pageSize, p.pattern);
    } catch (e) {
      threw = e instanceof Error ? e.message : String(e);
      core.guards.noteThrown(e);
    }
    return { threw, protectAfter: virtualQueryProtect(page) };
  },
  /** A JS listener emitting hook/1-shaped rows through a registered instrument and its stream. */
  testHookRows(p: { module: string; export: string; lifetime?: { duration_ms: number; max_hits: number; clock?: "install" | "resume" } }): unknown {
    const target = Process.getModuleByName(p.module).getExportByName(p.export);
    const id = core.instruments.nextId("hook");
    const stream = core.streams.open({ instrument: id, kind: "hook/1", enc: "json" });
    if (!(stream instanceof Stream)) return { error: stream };
    let listener: InvocationListener | null = null;
    const inst = core.instruments.register({
      id, kind: "hook", label: "test", lifetime: p.lifetime ?? { duration_ms: 60000, max_hits: 100000 }, targets: [hex(target)],
      stream, sites: [target],
      revert: () => { listener?.detach(); return { reverted: true, verification: null }; },
    });
    if (!(inst instanceof Instrument)) return { error: inst };
    core.originals.save(target, 32, id);
    listener = Interceptor.attach(target, {
      onEnter(args) {
        if (!inst.active || core.calls.suppresses(Process.getCurrentThreadId())) return;
        if (inst.hit() === "ignore") return;
        const row = [core.native.nextG(), core.native.nowUs(), Process.getCurrentThreadId(), 1, this.depth,
          hex(this.returnAddress), [hex(args[0]!)], null, null, null];
        if (core.streams.emit(stream, row)) inst.counters.recorded++;
      },
    });
    Interceptor.flush();
    core.originals.markPatched(target);
    keep.push(listener);
    return { instrument_id: id, stream_id: stream.id };
  },
  testHooksCount(): unknown {
    return { onDispose: core.hooks.onDispose.length, guards: core.guards.size };
  },
  /** WP9 seam: an instrument through core.watchSeam.openInstrument; two rows, max_hits 2 → ends with max_hits. */
  testSeamInstrument(): unknown {
    const handle = core.watchSeam.openInstrument({
      kind: "watch", rowKind: "watch/1", layout: null, lifetime: { duration_ms: 60000, max_hits: 2 }, targets: ["0x1000"],
      label: "seam", revert: () => { seamReverts++; return { reverted: true, verification: { kind: "dr7", ok: true, detail: "test" } }; },
    });
    if ("_tag" in handle) return { error: handle };
    const row = (n: number) => [core.native.nextG(), core.native.nowUs(), Process.getCurrentThreadId(), handle.id, "w",
      null, "unknown", null, "bea:test", null, null, null, null, null, { n }];
    const hits: boolean[] = [];
    for (let i = 0; i < 3; i++) {
      const recorded = handle.hit();
      hits.push(recorded);
      if (recorded) handle.emitJson(row(i), 64);
    }
    handle.count("filtered", 5);
    return { id: handle.id, stream: handle.streamId, hits, active: handle.isActive() };
  },
  testSeamReverts(): number {
    return seamReverts;
  },
  /** Capture readers (capture.ts) on the first call of an export of the main module; the listener detaches after it. */
  testCapture(p: { export: string; specs: ArgCapture[] }): Promise<ValueCell[]> {
    const target = Process.mainModule.getExportByName(p.export);
    return new Promise((resolve) => {
      let done = false;
      const listener = Interceptor.attach(target, {
        onEnter(args) {
          if (done) return;
          done = true;
          const cells = p.specs.map((spec) => captureArg(core, this.context, args, spec, false));
          setImmediate(() => { listener.detach(); resolve(cells); });
        },
      });
      keep.push(listener);
    });
  },
  /** The overlay-aware decoder (disasm.ts) at an address. */
  testDecode(p: { address: string; overlay: boolean }): unknown {
    const row = decodeAt(core, ptr(p.address), p.overlay);
    return row === null ? null : { text: row.text, bytes: row.bytes, overlay: row.overlay, size: row.size,
      branchTarget: row.branchTarget };
  },
  /** findAccessInsn of a trap-after pc. */
  testAccessInsn(p: { pcAfter: string }): unknown {
    return findAccessInsn(core, ptr(p.pcAfter));
  },
  /** WP7/WP8 (feature sends its own ended) and WP12 (registry sends it) external instruments. */
  testExternalInstruments(): unknown {
    const info = (id: string, state: "active" | "ended") => ({
      id, kind: "hook" as const, label: null, state, stream: null, created_t: 0, deadline_t: null, max_hits: 1,
      counters: { hits: 0, recorded: 0, sampled_out: 0, filtered: 0, agent_calls_suppressed: 0, unreturned: 0, errors: 0,
        dropped: {}, bea_guard_suspended: 0 },
      targets: [],
    });
    const summary = (id: string) => ({ ...info(id, "ended"), end_reason: "requested" as const, ended_t: 1, reverted: true,
      verification: null });
    const ownId = core.instruments.nextId("hook");
    let ownState: "active" | "ended" = "active";
    core.instruments.registerExternal({ id: ownId, kind: "hook", info: () => info(ownId, ownState),
      stop: () => { ownState = "ended"; send({ bea: "instrument", id: ownId, event: "ended", detail: summary(ownId) });
        return summary(ownId); } });
    const regId = core.instruments.allocate("override");
    core.instruments.register(regId, { info: () => info(regId, "active"), stop: async () => summary(regId) });
    return { ownId, regId };
  },
};

Object.assign(rpc.exports, extra);
`;
