import type {
  AgentResult,
  AgentRpcImpl,
  EndReason,
  Hex,
  InstrumentCounters,
  InstrumentSummary,
  OverrideInstallParams,
  OverrideInstallResult,
  ResolvedTarget,
  ValueCell,
} from "../shared/agentProtocol.js";
import { fail, ok } from "./errors.js";
import {
  ApplicationGate,
  planOverride,
  stackArgOffset,
  type ArgPatch,
  type OverridePlan,
  type RetPatch,
} from "./pure/modifyOverride.js";
import {
  bindModifySeam,
  LocalIds,
  type ModifyCoreSeam,
  type OverrideRegistration,
  type RegisteredOverride,
  type RevertResult,
} from "./pure/modifySeam.js";
import { cellOf, hexOf, replaceLowLane, toHexBytes } from "./pure/modifyValues.js";
import { replaceStubBytes } from "./pure/modifyStub.js";
import { sameBytes } from "./pure/modifyWrites.js";
import type { AgentCore } from "./state.js";

/**
 * override_function (WP12-MODIFY; S4 §14, gate `override_function` enforced by rpc.ts wrapAll). Feature file.
 * - rewrite args: onEnter writes `args[slot]` (int), the low lane of `xmm<slot>` (float slot < 4, upper lanes kept)
 *   or the stack slot `rsp+8+8*slot` (float slot ≥ 4); rewrite ret: onLeave `retval.replace` or xmm0 low lane;
 * - replace: `Interceptor.replaceFast` to a native stub (pure/modifyStub.ts) that asks a pinned `decide` NativeCallback
 *   per call and either returns the constant or tail-jumps to the original with the caller's registers and stack, so
 *   the agent-call bypass (S4 §13.4), `when` filters and an ended lifetime reach the original without argument
 *   types; stub page and callback stay pinned until after revert + settle; a second replace of one function throws
 *   "already replaced" → HookConflict;
 * - install retries with relocation "forced" when the default relocation fails (S4 §10.2); flush + Stalker invalidate;
 * - the core InstrumentRegistry (through pure/modifySeam.ts) owns the id, the lifetime (duration, clock "resume",
 *   max_hits counted per APPLICATION), the stop protocol and the ended message; `when` filters stay here;
 *   `record` emits override/1 rows with the original values;
 * - revert: detach/revert synchronously, then verify the patch-site bytes against the head saved before patching,
 *   re-checking for up to 500 ms (Frida restores the site only after a thread inside the trampoline left it).
 * Without the core registry a local one keeps ids, timers and the ended message (no rows).
 */
interface ActiveOverride {
  readonly plan: OverridePlan;
  readonly target: NativePointer;
  readonly owner: string;
  readonly head: Uint8Array;
  readonly gate: ApplicationGate;
  reg: RegisteredOverride | null;
  listener: InvocationListener | null;
  callback: NativeCallback<NativeCallbackReturnType, []> | null;
  /** the replace stub's page (mode replace) */
  stub: NativePointer | null;
  reverting: Promise<RevertResult> | null;
}

const SETTLE_MS = 1000;
const HEAD_BYTES = 32;
const VERIFY_TRIES = 50;
const VERIFY_INTERVAL_MS = 10;
const ALTERNATIVES = ["watch_memory execute", "trace_execution on_call", "override the caller"];

let core: AgentCore | null = null;
let seam: ModifyCoreSeam<NativePointer> = bindModifySeam<NativePointer>({});
/** live overrides by patch site (one per function: HookConflict otherwise) */
const live = new Map<string, ActiveOverride>();
/** NativeCallbacks and stub pages referenced from module scope until after revert + settle (QJS frees them) */
const pinned = new Set<NativeCallback<NativeCallbackReturnType, []> | NativePointer>();

export function init(c: AgentCore): void {
  core = c;
  seam = bindModifySeam<NativePointer>(c);
  if (!c.features.includes("override")) c.features.push("override");
  seam.onDispose?.(() => {
    for (const o of live.values()) disarm(o);
  });
}

const nowUs = (): number => (Date.now() - (core?.t0Wall ?? 0)) * 1000;

// ------------------------------------------------------------------------------------------- local registry
/** Fallback when the core has no InstrumentRegistry: ids "o<n>", timers at install, max_hits, ended message. */
const localIds = new LocalIds("o");
function registerLocally(r: OverrideRegistration<NativePointer>): RegisteredOverride {
  const id = localIds.allocate();
  const createdT = nowUs();
  const counters: InstrumentCounters = {
    hits: 0,
    recorded: 0,
    sampled_out: 0,
    filtered: 0,
    agent_calls_suppressed: 0,
    unreturned: 0,
    errors: 0,
    dropped: {},
    bea_guard_suspended: 0,
  };
  const maxHits = r.lifetime.max_hits > 0 ? r.lifetime.max_hits : 10_000;
  const durationMs = r.lifetime.duration_ms > 0 ? r.lifetime.duration_ms : 30_000;
  let state: "active" | "stopping" | "ended" = "active";
  const stop = async (reason: EndReason): Promise<void> => {
    if (state !== "active") return;
    state = "stopping";
    clearTimeout(timer);
    const outcome = await r.revert(reason);
    state = "ended";
    const summary: InstrumentSummary = {
      id,
      kind: "override",
      label: r.label,
      state,
      stream: null,
      created_t: createdT,
      deadline_t: createdT + durationMs * 1000,
      max_hits: maxHits,
      counters: { ...counters, dropped: {} },
      targets: [...r.targets],
      end_reason: reason,
      ended_t: nowUs(),
      reverted: outcome.reverted,
      verification: outcome.verification,
    };
    send({ bea: "instrument", id, event: "ended", detail: summary });
  };
  const timer = setTimeout(() => void stop("duration"), durationMs);
  return {
    id,
    streamId: null,
    get active() {
      return state === "active";
    },
    counters,
    hit: () => {
      if (state !== "active" || counters.hits >= maxHits) return false;
      counters.hits += 1;
      if (counters.hits === maxHits) setImmediate(() => void stop("max_hits"));
      return true;
    },
    emit: () => undefined,
    discard: () => void stop("error"),
  };
}

// ------------------------------------------------------------------------------------------- patching
const bitsOfPointer = (value: NativePointer): bigint => BigInt(value.toString());

/** Apply one argument patch; returns the original value cell. */
function applyArg(ctx: InvocationContext, args: InvocationArguments, a: ArgPatch): ValueCell {
  const cpu = ctx.context as X64CpuContext;
  if (a.location === "int") {
    const original = args[a.slot];
    args[a.slot] = ptr(hexOf(a.bits));
    return cellOf(a.type, original === undefined ? 0n : bitsOfPointer(original));
  }
  if (a.location === "xmm") {
    const regs = cpu as unknown as Record<string, ArrayBuffer>;
    const current = new Uint8Array(regs[`xmm${String(a.slot)}`] ?? new ArrayBuffer(16));
    const width = a.width === 4 ? 4 : 8;
    const view = new DataView(current.buffer, current.byteOffset, 16);
    const bits = width === 4 ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);
    regs[`xmm${String(a.slot)}`] = replaceLowLane(current, a.bits, width).buffer as ArrayBuffer;
    return cellOf(a.type, bits);
  }
  const slot = cpu.rsp.add(stackArgOffset(a.slot));
  if (a.width === 4) {
    const bits = BigInt(slot.readU32());
    slot.writeU32(Number(a.bits));
    return cellOf(a.type, bits);
  }
  const bits = BigInt(slot.readU64().toString());
  slot.writeU64(uint64(a.bits.toString()));
  return cellOf(a.type, bits);
}

/** Apply the return patch in onLeave; returns the original return cell. */
function applyRet(ctx: InvocationContext, retval: InvocationReturnValue, r: RetPatch): ValueCell {
  if (r.float) {
    const cpu = ctx.context as X64CpuContext;
    const current = new Uint8Array(cpu.xmm0);
    const view = new DataView(current.buffer, current.byteOffset, 16);
    const bits = r.width === 4 ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);
    cpu.xmm0 = replaceLowLane(current, r.bits, r.width === 4 ? 4 : 8).buffer as ArrayBuffer;
    return cellOf(r.type, bits);
  }
  const original = bitsOfPointer(retval);
  retval.replace(ptr(hexOf(r.bits)));
  return cellOf(r.type, original);
}

/** Emit the override/1 row of one application (already counted by `admit`). */
function applied(o: ActiveOverride, tid: number, kind: "args" | "ret" | "replace", detail: ValueCell[]): void {
  const reg = o.reg;
  if (reg === null) return;
  reg.emit([tid, reg.id, kind, detail]);
  if (reg.streamId !== null) reg.counters.recorded += 1;
}

/** One call's decision: registered + active, not a bypassing BEA call, matching `when`, under max_hits. */
function admit(o: ActiveOverride, tid: number): boolean {
  const reg = o.reg;
  if (reg === null || !reg.active) return false;
  if (seam.bypass(tid)) {
    reg.counters.agent_calls_suppressed += 1;
    return false;
  }
  const decision = o.gate.decide(tid);
  if (decision !== "apply") {
    if (decision === "skip") reg.counters.filtered += 1;
    return false;
  }
  return reg.hit();
}

/**
 * The replace stub: code page (r-x before the target is patched) + data page whose first qword receives the trampoline
 * to the original. `decide` answers 1 = return the constant, 0 = run the original.
 */
function installReplace(o: ActiveOverride, target: NativePointer | InstrumentationTarget): void {
  const replace = o.plan.replace;
  const decide = new NativeCallback(
    () => {
      const tid = Process.getCurrentThreadId();
      if (!admit(o, tid)) return 0;
      applied(o, tid, "replace", []);
      return 1;
    },
    "int",
    [],
  );
  const stub = Memory.alloc(2 * Process.pageSize);
  const slot = stub.add(Process.pageSize);
  pinned.add(decide);
  pinned.add(stub);
  o.callback = decide;
  o.stub = stub;
  const code = replaceStubBytes({
    decide: BigInt(decide.toString()),
    originalSlot: BigInt(slot.toString()),
    bits: replace?.bits ?? null,
    float: replace?.retType === "f32" || replace?.retType === "f64",
  });
  stub.writeByteArray(code.buffer as ArrayBuffer);
  Memory.protect(stub, Process.pageSize, "r-x");
  // The trampoline exists only once replaceFast has patched the target. No target thread reads the slot before it is
  // written: the stub reads it only after `decide`, which needs the JS lock this synchronous RPC holds.
  slot.writePointer(Interceptor.replaceFast(target, stub));
}

function attachOrReplace(o: ActiveOverride, forced: boolean): void {
  const target: NativePointer | InstrumentationTarget = forced ? { target: o.target, relocation: "forced" } : o.target;
  const plan = o.plan;
  if (plan.mode === "replace") {
    installReplace(o, target);
    return;
  }
  const callbacks: InvocationListenerCallbacks = {
    onEnter(args) {
      if (!admit(o, this.threadId)) return;
      if (plan.args.length === 0) {
        this["beaOverride"] = true;
        return;
      }
      const originals = plan.args.map((a) => applyArg(this, args, a));
      applied(o, this.threadId, "args", originals);
    },
  };
  if (plan.ret !== null) {
    const ret = plan.ret;
    callbacks.onLeave = function (retval) {
      // Admitted (and counted) at onEnter; the max_hits-th call leaves the registry "stopping" but must still be
      // applied. Once disarmed (reverted), late callbacks of in-flight calls change nothing.
      if (this["beaOverride"] !== true || o.listener === null) return;
      applied(o, this.threadId, "ret", [applyRet(this, retval, ret)]);
    };
  }
  o.listener = Interceptor.attach(target, callbacks);
}

/** S4 §10.2: default relocation first, then "forced" (tiny functions, A-40); "already replaced" → HookConflict. */
function installWithRetry(o: ActiveOverride, address: Hex): { readonly forced: boolean } | AgentResult<never> {
  const attempts: ("default" | "forced")[] = [];
  for (const forced of o.plan.relocation === "forced" ? [true] : [false, true]) {
    attempts.push(forced ? "forced" : "default");
    try {
      attachOrReplace(o, forced);
      return { forced };
    } catch (cause) {
      if (o.callback !== null) pinned.delete(o.callback); // the replace never took effect
      if (o.stub !== null) pinned.delete(o.stub);
      o.callback = null;
      o.stub = null;
      const text = cause instanceof Error ? cause.message : String(cause);
      if (/already replaced/iu.test(text))
        return fail({
          _tag: "HookConflict",
          message: "already replaced",
          address,
          existing: "unknown",
          kind: "replace",
        });
      if (forced)
        return fail({
          _tag: "HookInstallFailed",
          message: "install failed",
          address,
          attempts,
          frida_message: text.slice(0, 512),
          alternatives: ALTERNATIVES,
        });
    }
  }
  return fail({ _tag: "Internal", message: "unreachable", where: "override.install" });
}

/** Synchronous part of the revert (dispose-safe): detach / revert, flush, invalidate, release the originals. */
function disarm(o: ActiveOverride): boolean {
  let threw = false;
  try {
    o.listener?.detach();
    if (o.callback !== null) Interceptor.revert(o.target);
  } catch {
    threw = true;
  }
  o.listener = null;
  Interceptor.flush();
  seam.invalidate?.([o.target]);
  seam.originals?.release(o.owner);
  live.delete(o.target.toString());
  const callback = o.callback;
  const stub = o.stub;
  if (callback !== null) setTimeout(() => pinned.delete(callback), SETTLE_MS);
  if (stub !== null) setTimeout(() => pinned.delete(stub), SETTLE_MS);
  return threw;
}

/** Patch-site bytes vs the head saved before patching; `final` = no point in re-checking. */
function checkSite(o: ActiveOverride): { readonly ok: boolean; readonly final: boolean; readonly detail: string } {
  if (seam.originals?.isPatched(o.target, o.head.length) === true)
    return { ok: true, final: true, detail: "patch site still shared with another BEA instrument" };
  try {
    const now = o.target.readByteArray(o.head.length);
    return now !== null && sameBytes(new Uint8Array(now), o.head)
      ? { ok: true, final: true, detail: "patch site restored" }
      : { ok: false, final: false, detail: "patch site bytes differ from the original head" };
  } catch {
    return { ok: false, final: true, detail: "patch site unreadable after revert" };
  }
}

/** The registry's revert step (memoized). */
function revertOverride(o: ActiveOverride): Promise<RevertResult> {
  if (o.reverting !== null) return o.reverting;
  o.gate.stop();
  const threw = disarm(o);
  o.reverting = (async () => {
    let check = checkSite(o);
    for (let i = 0; !check.ok && !check.final && i < VERIFY_TRIES; i++) {
      await new Promise<void>((resolve) => setTimeout(resolve, VERIFY_INTERVAL_MS));
      check = checkSite(o);
    }
    const detail = threw ? "revert threw (code unmapped?)" : check.detail;
    return {
      reverted: check.ok,
      verification: { kind: "bytes", ok: check.ok, detail },
      ...(check.ok ? {} : { detail }),
    };
  })();
  return o.reverting;
}

// ------------------------------------------------------------------------------------------- RPC
function resolveTarget(p: OverrideInstallParams): NativePointer | AgentResult<never> {
  const t = p.target;
  if ("va" in t) return ptr(t.va);
  let module: Module;
  try {
    module = Process.getModuleByName(t.module);
  } catch {
    return fail({ _tag: "ModuleNotFound", message: "module not loaded", module: t.module });
  }
  if ("rva" in t) return module.base.add(ptr(t.rva));
  try {
    return module.getExportByName(t.export);
  } catch {
    return fail({ _tag: "ExportNotFound", message: "export not found", module: t.module, export: t.export });
  }
}

/** Executable, not already overridden by BEA, head readable: the protection and the ≥ 32 original bytes. */
function inspectTarget(
  target: NativePointer,
  address: Hex,
): { readonly protection: string; readonly head: Uint8Array } | AgentResult<never> {
  let protection: string;
  try {
    protection = Memory.queryProtection(target);
  } catch {
    return fail({ _tag: "AccessViolation", message: "target unmapped", address, operation: "execute" });
  }
  if (!protection.includes("x")) return fail({ _tag: "NotExecutable", message: "not executable", address, protection });
  const other = live.get(target.toString());
  if (other !== undefined)
    return fail({
      _tag: "HookConflict",
      message: "an override is already active on this function",
      address,
      existing: other.reg?.id ?? "unknown",
      kind: other.plan.mode === "replace" ? "replace" : "override",
    });
  try {
    const bytes = target.readByteArray(HEAD_BYTES);
    if (bytes === null) throw new Error("unreadable");
    return { protection, head: new Uint8Array(bytes) };
  } catch {
    return fail({ _tag: "AccessViolation", message: "target unreadable", address, operation: "read" });
  }
}

function resolvedTargetOf(
  p: OverrideInstallParams,
  target: NativePointer,
  address: Hex,
  protection: string,
): ResolvedTarget {
  const module = Process.findModuleByAddress(target);
  const range = Process.findFunctionRange(target);
  return {
    va: address,
    module: module?.name ?? null,
    module_base: module === null ? null : hexOf(BigInt(module.base.toString())),
    rva: module === null ? null : hexOf(BigInt(target.sub(module.base).toString())),
    export: "export" in p.target ? p.target.export : null,
    function: range === null ? null : { base: hexOf(BigInt(range.base.toString())), size: range.size, source: "pdata" },
    protection,
  };
}

function overrideInstall(p: OverrideInstallParams): AgentResult<OverrideInstallResult> {
  if (core === null) return fail({ _tag: "NotReady", message: "override is not initialized" });
  const planned = planOverride(p, core.limits);
  if (!planned.ok)
    return fail({ _tag: "BadParams", message: "invalid overrideInstall params", issues: planned.issues });
  const plan = planned.plan;
  const target = resolveTarget(p);
  if (!(target instanceof NativePointer)) return target;
  const address = hexOf(BigInt(target.toString()));
  const inspected = inspectTarget(target, address);
  if ("ok" in inspected) return inspected;
  const o: ActiveOverride = {
    plan,
    target,
    owner: `override@${address}`,
    head: inspected.head,
    // max_hits belongs to the registry: the gate only filters threads / every_n
    gate: new ApplicationGate(plan.threadIds, plan.everyN, Number.MAX_SAFE_INTEGER),
    reg: null,
    listener: null,
    callback: null,
    stub: null,
    reverting: null,
  };
  seam.originals?.save(o.owner, target, HEAD_BYTES);
  live.set(target.toString(), o);
  // Patch first, register second: listeners run on target threads only after this RPC releases the JS lock, and
  // until `o.reg` is set they treat the override as inactive.
  const installed = installWithRetry(o, address);
  if ("ok" in installed) {
    disarm(o);
    return installed;
  }
  Interceptor.flush();
  seam.invalidate?.([target]);
  seam.originals?.markPatched(o.owner);
  const registration: OverrideRegistration<NativePointer> = {
    label: plan.label,
    lifetime: { duration_ms: plan.durationMs, max_hits: plan.maxHits, clock: plan.clock },
    targets: [address],
    sites: [target],
    record: plan.record,
    revert: () => revertOverride(o),
  };
  const reg = seam.instruments === null ? registerLocally(registration) : seam.instruments.register(registration);
  if ("_tag" in reg) {
    disarm(o);
    return fail(reg);
  }
  o.reg = reg;
  return ok({
    instrument_id: reg.id,
    stream_id: reg.streamId,
    resolved: resolvedTargetOf(p, target, address, inspected.protection),
    mode: plan.mode,
    relocation: installed.forced ? "forced" : "default",
    stalker_invalidated: [],
    effect: {
      kind: "override-installed",
      reversible: true,
      targets: [{ address, size: null }],
      thread_ids: plan.threadIds === null ? null : [...plan.threadIds],
      before: [{ address, hex: toHexBytes(inspected.head) }],
    },
  });
}

export const rpc = {
  overrideInstall,
} satisfies Partial<AgentRpcImpl>;
