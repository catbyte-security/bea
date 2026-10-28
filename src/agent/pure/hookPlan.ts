// =================================================================================================
// src/agent/pure/hookPlan.ts — WP7-HOOK pure helpers for the agent hook engine (no GumJS globals or types).
// Structural validation of HookInstallParams (S4 §5.2 "the agent does structural checks only"), the Win64
// slot → source mapping (S4 §10.3), the native-tier field mapping (S4 §10.4, layout hook-native/1) and the
// thunk decoder used by the install algorithm (S4 §10.2 step 2). Imported by src/agent/hooks.ts and by
// tests/unit/instrument/** (vitest), so it stays free of anything the host or the agent lacks.
// =================================================================================================
import type {
  AgentFeature,
  AgentLimits,
  ArgCapture,
  CaptureRegister,
  HookInstallParams,
  ValueType,
} from "../../shared/agentProtocol.js";

export interface PlanIssue {
  readonly path: string;
  readonly problem: string;
}

/** Where a capture's raw value comes from (S4 §10.3; p = slot + hidden_ret_ptr shift). */
export type CaptureSource =
  | { readonly kind: "slot-int"; readonly p: number } // args[p]: rcx, rdx, r8, r9, then [rsp+0x28+8*(p-4)]
  | { readonly kind: "slot-xmm"; readonly p: number } // float class, p < 4: xmm<p> bits
  | { readonly kind: "slot-stack"; readonly p: number; readonly offset: number } // float class, p >= 4: [rsp+offset]
  | { readonly kind: "reg"; readonly reg: CaptureRegister };

export interface CapturePlan {
  /** index in HookInstallParams.capture.args == index of the cell in HookRow.args */
  readonly index: number;
  readonly source: CaptureSource;
  readonly type: ValueType;
  readonly deref: readonly number[];
  /** element count at the final address (1 = scalar) */
  readonly count: number;
  /** strings: max characters; bytes: max bytes; other types: 0 */
  readonly maxLen: number;
  readonly at: "enter" | "leave";
}

export interface RetPlan {
  readonly type: ValueType;
  readonly deref: readonly number[];
  readonly count: number;
  readonly maxLen: number;
  /** f32/f64 without deref: bits from xmm0 at onLeave; else rax (retval) */
  readonly fromXmm0: boolean;
}

/** One hook-native/1 record field per capture (S4 §6.4). */
export type NativeField = "w0" | "w1" | "w2" | "w3" | "x0" | "x1" | "x2" | "x3" | "s4" | "s5" | "s6" | "s7";
export interface NativePlan {
  readonly fields: readonly { readonly index: number; readonly field: NativeField; readonly type: ValueType }[];
  readonly ret: "rax" | "xmm0_ret" | null;
  readonly threads: readonly number[];
}

export interface HookPlan {
  readonly engine: "js" | "native";
  readonly probe: boolean;
  readonly emit: "enter" | "leave";
  readonly captures: readonly CapturePlan[];
  readonly ret: RetPlan | null;
  readonly backtrace: { readonly depth: number; readonly perSec: number } | null;
  readonly threadIds: readonly number[];
  readonly callerModules: readonly string[];
  readonly everyN: number;
  readonly maxPerSec: number;
  readonly maxHits: number;
  readonly durationMs: number;
  readonly observeAgentCalls: boolean;
  readonly native: NativePlan | null;
}

export const VALUE_TYPES: readonly ValueType[] = [
  "i8",
  "u8",
  "i16",
  "u16",
  "i32",
  "u32",
  "i64",
  "u64",
  "ptr",
  "bool8",
  "bool32",
  "f32",
  "f64",
  "utf8",
  "utf16",
  "ansi",
  "bytes",
];
export const CAPTURE_REGISTERS: readonly CaptureRegister[] = [
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
  "xmm0",
  "xmm1",
  "xmm2",
  "xmm3",
  "xmm4",
  "xmm5",
  "xmm6",
  "xmm7",
  "xmm8",
  "xmm9",
  "xmm10",
  "xmm11",
  "xmm12",
  "xmm13",
  "xmm14",
  "xmm15",
];

/** Element sizes of the scalar value types; strings and bytes have none. */
export const TYPE_BYTES: Readonly<Partial<Record<ValueType, number>>> = {
  i8: 1,
  u8: 1,
  bool8: 1,
  i16: 2,
  u16: 2,
  i32: 4,
  u32: 4,
  bool32: 4,
  f32: 4,
  i64: 8,
  u64: 8,
  ptr: 8,
  f64: 8,
};
export const isTextType = (t: ValueType): boolean => t === "utf8" || t === "utf16" || t === "ansi";
export const isFloatType = (t: ValueType): boolean => t === "f32" || t === "f64";

/** Arrays at the final address are bounded by the wire contract (ArgCapture.count ≤ 64). */
export const MAX_CAPTURE_COUNT = 64;
/** S4 §10.3 defaults: strings 256 characters, bytes 64. */
export const DEFAULT_TEXT_CHARS = 256;
export const DEFAULT_BYTES = 64;
/** Native tier thread filter (BeaNativeHook.threads[16]). */
export const NATIVE_MAX_THREADS = 16;
/** Stack offset of positional slot p at function entry: [rsp] = return address, slot 4 = rsp+0x28. */
export const stackSlotOffset = (p: number): number => 8 + 8 * p;

const isInt = (v: unknown, lo: number, hi: number): v is number =>
  typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi;

const NATIVE_REG_FIELDS: Readonly<Partial<Record<CaptureRegister, NativeField>>> = {
  rcx: "w0",
  rdx: "w1",
  r8: "w2",
  r9: "w3",
  xmm0: "x0",
  xmm1: "x1",
  xmm2: "x2",
  xmm3: "x3",
};

const planDeref = (raw: unknown, path: string, limits: AgentLimits, issues: PlanIssue[]): readonly number[] => {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    issues.push({ path, problem: "deref must be an array of byte offsets" });
    return [];
  }
  if (raw.length > limits.max_deref_depth)
    issues.push({ path, problem: `deref has ${raw.length} offsets; at most ${limits.max_deref_depth}` });
  const out: number[] = [];
  raw.forEach((d, i) => {
    if (!isInt(d, -0x8000_0000, 0x7fff_ffff))
      issues.push({ path: `${path}[${i}]`, problem: "offset must be an int32" });
    else out.push(d);
  });
  return out;
};

const planLength = (
  type: ValueType,
  count: unknown,
  maxLen: unknown,
  path: string,
  limits: AgentLimits,
  issues: PlanIssue[],
): { count: number; maxLen: number } => {
  if (count !== undefined && !isInt(count, 1, MAX_CAPTURE_COUNT))
    issues.push({ path: `${path}.count`, problem: `count must be 1..${MAX_CAPTURE_COUNT}` });
  if (maxLen !== undefined && !isInt(maxLen, 1, 1 << 20))
    issues.push({ path: `${path}.max_len`, problem: "max_len must be a positive integer" });
  const n = isInt(count, 1, MAX_CAPTURE_COUNT) ? count : 1;
  if (isTextType(type)) {
    const want = isInt(maxLen, 1, 1 << 20) ? maxLen : DEFAULT_TEXT_CHARS;
    return { count: 1, maxLen: Math.min(want, limits.max_string_chars) };
  }
  if (type === "bytes") {
    const want = isInt(maxLen, 1, 1 << 20) ? maxLen : DEFAULT_BYTES;
    return { count: 1, maxLen: Math.min(want, limits.max_capture_bytes) };
  }
  return { count: n, maxLen: 0 };
};

const planSource = (
  c: ArgCapture,
  shift: number,
  path: string,
  issues: PlanIssue[],
  hasDeref: boolean,
): CaptureSource | null => {
  const hasSlot = c.slot !== undefined;
  const hasReg = c.reg !== undefined;
  if (hasSlot === hasReg) {
    issues.push({ path, problem: "give exactly one of slot (+class) or reg" });
    return null;
  }
  if (hasReg) {
    if (!CAPTURE_REGISTERS.includes(c.reg as CaptureRegister)) {
      issues.push({ path: `${path}.reg`, problem: "unknown register" });
      return null;
    }
    return { kind: "reg", reg: c.reg as CaptureRegister };
  }
  if (!isInt(c.slot, 0, 15)) {
    issues.push({ path: `${path}.slot`, problem: "slot must be 0..15" });
    return null;
  }
  const cls = c.class ?? (isFloatType(c.type) && !hasDeref ? "float" : "int");
  if (cls !== "int" && cls !== "float") {
    issues.push({ path: `${path}.class`, problem: 'class must be "int" or "float"' });
    return null;
  }
  const p = c.slot + shift;
  if (cls === "float") {
    if (hasDeref) {
      issues.push({ path: `${path}.class`, problem: "a deref chain starts from an integer-class slot" });
      return null;
    }
    return p < 4 ? { kind: "slot-xmm", p } : { kind: "slot-stack", p, offset: stackSlotOffset(p) };
  }
  return { kind: "slot-int", p };
};

const nativeFieldOf = (src: CaptureSource): NativeField | null => {
  if (src.kind === "reg") return NATIVE_REG_FIELDS[src.reg] ?? null;
  if (src.p > 7) return null;
  if (src.p >= 4) return `s${src.p}` as NativeField;
  return src.kind === "slot-xmm" ? (`x${src.p}` as NativeField) : (`w${src.p}` as NativeField);
};

/**
 * Validate + plan one hookInstall. The host already validated with zod; this guards against host bugs and applies
 * the agent's own clamps (AGENT_LIMIT_HARD via `limits`). Issues become AgentError BadParams.
 */
export function planHook(
  params: HookInstallParams,
  limits: AgentLimits,
  features: readonly AgentFeature[],
): { readonly ok: true; readonly plan: HookPlan } | { readonly ok: false; readonly issues: readonly PlanIssue[] } {
  const issues: PlanIssue[] = [];
  const p = params as Partial<HookInstallParams>;
  if (p.engine !== "js" && p.engine !== "native") issues.push({ path: "engine", problem: 'must be "js" or "native"' });
  if (p.relocation !== "auto" && p.relocation !== "forced")
    issues.push({ path: "relocation", problem: 'must be "auto" or "forced"' });
  if (p.emit !== "enter" && p.emit !== "leave") issues.push({ path: "emit", problem: 'must be "enter" or "leave"' });
  if (p.target === undefined || typeof p.target !== "object") issues.push({ path: "target", problem: "required" });
  const capture = p.capture;
  const args: readonly ArgCapture[] = Array.isArray(capture?.args) ? capture.args : [];
  if (capture === undefined || !Array.isArray(capture.args))
    issues.push({ path: "capture.args", problem: "must be an array" });
  if (args.length > limits.max_capture_args)
    issues.push({ path: "capture.args", problem: `at most ${limits.max_capture_args} captures` });
  const lifetime = p.lifetime;
  if (lifetime === undefined || !isInt(lifetime.duration_ms, 0, 2 ** 31) || !isInt(lifetime.max_hits, 0, 2 ** 53))
    issues.push({ path: "lifetime", problem: "duration_ms and max_hits must be non-negative integers" });
  const probe = p.probe === true;
  const shift = p.hidden_ret_ptr === true ? 1 : 0;

  const captures: CapturePlan[] = [];
  args.forEach((c, index) => {
    const path = `capture.args[${index}]`;
    if (typeof c !== "object" || c === null) {
      issues.push({ path, problem: "must be an object" });
      return;
    }
    if (!VALUE_TYPES.includes(c.type)) {
      issues.push({ path: `${path}.type`, problem: "unknown value type" });
      return;
    }
    const at = c.at ?? "enter";
    if (at !== "enter" && at !== "leave") issues.push({ path: `${path}.at`, problem: 'must be "enter" or "leave"' });
    const deref = planDeref(c.deref, `${path}.deref`, limits, issues);
    const source = planSource(c, shift, path, issues, deref.length > 0);
    if (source === null) return;
    if (probe && source.kind !== "reg")
      issues.push({ path, problem: "an instruction probe captures registers only (no argument slots)" });
    if (probe && at === "leave") issues.push({ path: `${path}.at`, problem: "an instruction probe has no leave" });
    const len = planLength(c.type, c.count, c.max_len, path, limits, issues);
    captures.push({ index, source, type: c.type, deref, count: len.count, maxLen: len.maxLen, at });
  });

  let ret: RetPlan | null = null;
  const rawRet = capture?.ret ?? null;
  if (rawRet !== null) {
    if (probe) issues.push({ path: "capture.ret", problem: "an instruction probe has no return value" });
    if (!VALUE_TYPES.includes(rawRet.type)) issues.push({ path: "capture.ret.type", problem: "unknown value type" });
    else {
      const deref = planDeref(rawRet.deref, "capture.ret.deref", limits, issues);
      const len = planLength(rawRet.type, rawRet.count, rawRet.max_len, "capture.ret", limits, issues);
      ret = {
        type: rawRet.type,
        deref,
        count: len.count,
        maxLen: len.maxLen,
        fromXmm0: isFloatType(rawRet.type) && deref.length === 0,
      };
    }
  }

  const bt = capture?.backtrace ?? null;
  let backtrace: HookPlan["backtrace"] = null;
  if (bt !== null) {
    if (!isInt(bt.depth, 0, 1024) || !isInt(bt.max_per_sec, 0, 1_000_000))
      issues.push({ path: "capture.backtrace", problem: "depth and max_per_sec must be non-negative integers" });
    else if (bt.depth > 0)
      backtrace = {
        depth: Math.min(bt.depth, limits.max_backtrace_depth),
        perSec: Math.max(
          1,
          Math.min(bt.max_per_sec === 0 ? limits.backtrace_per_sec : bt.max_per_sec, limits.backtrace_per_sec),
        ),
      };
  }
  if (capture !== undefined && capture.registers !== "none" && capture.registers !== "gpr")
    issues.push({ path: "capture.registers", problem: 'must be "none" or "gpr"' });

  const threadIds = p.filter?.thread_ids ?? [];
  if (!Array.isArray(threadIds) || !threadIds.every((t) => isInt(t, 0, 0xffff_ffff)))
    issues.push({ path: "filter.thread_ids", problem: "must be thread ids" });
  const callerModules = p.filter?.caller_modules ?? [];
  if (!Array.isArray(callerModules) || !callerModules.every((m) => typeof m === "string" && m.length <= 260))
    issues.push({ path: "filter.caller_modules", problem: "must be module names" });
  const everyN = p.sample?.every_n ?? 1;
  const maxPerSec = p.sample?.max_per_sec ?? 0;
  if (!isInt(everyN, 1, 1_000_000_000)) issues.push({ path: "sample.every_n", problem: "must be >= 1" });
  if (!isInt(maxPerSec, 0, 1_000_000_000)) issues.push({ path: "sample.max_per_sec", problem: "must be >= 0" });

  const needsLeave = ret !== null || captures.some((c) => c.at === "leave");
  const emit: HookPlan["emit"] = probe ? "enter" : needsLeave ? "leave" : p.emit === "leave" ? "leave" : "enter";

  let native: NativePlan | null = null;
  if (p.engine === "native") {
    if (probe) issues.push({ path: "probe", problem: "the native tier hooks function entries only" });
    if (backtrace !== null) issues.push({ path: "capture.backtrace", problem: "the native tier records no backtrace" });
    if (capture?.registers === "gpr")
      issues.push({ path: "capture.registers", problem: "the native tier records no register dump" });
    if (callerModules.length > 0)
      issues.push({ path: "filter.caller_modules", problem: "the native tier filters threads only" });
    if (threadIds.length > NATIVE_MAX_THREADS)
      issues.push({
        path: "filter.thread_ids",
        problem: `the native tier filters at most ${NATIVE_MAX_THREADS} threads`,
      });
    const fields: { index: number; field: NativeField; type: ValueType }[] = [];
    for (const c of captures) {
      const path = `capture.args[${c.index}]`;
      if (c.deref.length > 0 || c.count !== 1 || isTextType(c.type) || c.type === "bytes" || c.at !== "enter") {
        issues.push({ path, problem: "the native tier captures bare slot or register values at entry only" });
        continue;
      }
      const field = nativeFieldOf(c.source);
      if (field === null) {
        issues.push({ path, problem: "the native tier records slots 0..7, rcx/rdx/r8/r9 and xmm0..xmm3 only" });
        continue;
      }
      if (field.startsWith("x") && !features.includes("hooks.native.xmm"))
        issues.push({ path, problem: "this agent build cannot record xmm registers in the native tier" });
      fields.push({ index: c.index, field, type: c.type });
    }
    let nativeRet: NativePlan["ret"] = null;
    if (ret !== null) {
      if (ret.deref.length > 0 || ret.count !== 1 || isTextType(ret.type) || ret.type === "bytes")
        issues.push({ path: "capture.ret", problem: "the native tier records a scalar return value only" });
      else if (ret.fromXmm0 && !features.includes("hooks.native.xmm"))
        issues.push({ path: "capture.ret", problem: "this agent build cannot record xmm0 in the native tier" });
      nativeRet = ret.fromXmm0 ? "xmm0_ret" : "rax";
    }
    native = { fields, ret: nativeRet, threads: threadIds };
  }

  if (issues.length > 0) return { ok: false, issues };
  return {
    ok: true,
    plan: {
      engine: p.engine as "js" | "native",
      probe,
      emit,
      captures,
      ret,
      backtrace,
      threadIds,
      callerModules: callerModules.map((m) => m.toLowerCase()),
      everyN,
      maxPerSec,
      maxHits: Math.min(lifetime?.max_hits ?? 0, limits.max_hits_cap),
      durationMs: Math.min(lifetime?.duration_ms ?? 0, limits.max_duration_ms),
      observeAgentCalls: p.observe_agent_calls === true,
      native,
    },
  };
}

/** HookInstallResult.arg_map: which source each cell reads (diagnostic, BEA-authored text only). */
export const describeSource = (src: CaptureSource): string => {
  switch (src.kind) {
    case "slot-int":
      return src.p < 4
        ? (["rcx", "rdx", "r8", "r9"][src.p] ?? "?")
        : `[rsp+0x${(0x28 + 8 * (src.p - 4)).toString(16)}]`;
    case "slot-xmm":
      return `xmm${src.p}`;
    case "slot-stack":
      return `[rsp+0x${src.offset.toString(16)}]`;
    case "reg":
      return src.reg;
  }
};

// ------------------------------------------------------------------------------------------------ thunks (§10.2)
/** A thunk at the hook address: Interceptor patches the thunk TARGET (S4 F5), so deny checks look there too. */
export type ThunkInsn =
  | { readonly kind: "jmp-rip"; readonly length: number; readonly disp: number } // jmp qword ptr [rip+disp]
  | { readonly kind: "jmp-rel"; readonly length: number; readonly rel: number }; // jmp rel32

const i32le = (b: Uint8Array, o: number): number =>
  (b[o] ?? 0) | ((b[o + 1] ?? 0) << 8) | ((b[o + 2] ?? 0) << 16) | ((b[o + 3] ?? 0) << 24) | 0;

/** Decode the first instruction when it is an indirect or rel32 jump (FF 25, 48 FF 25, E9). */
export function decodeThunk(bytes: Uint8Array): ThunkInsn | null {
  if (bytes.length >= 6 && bytes[0] === 0xff && bytes[1] === 0x25)
    return { kind: "jmp-rip", length: 6, disp: i32le(bytes, 2) };
  if (bytes.length >= 7 && bytes[0] === 0x48 && bytes[1] === 0xff && bytes[2] === 0x25)
    return { kind: "jmp-rip", length: 7, disp: i32le(bytes, 3) };
  if (bytes.length >= 5 && bytes[0] === 0xe9) return { kind: "jmp-rel", length: 5, rel: i32le(bytes, 1) };
  return null;
}

/** First bytes of an Interceptor patch on x64 (diagnostic "verify each site now begins with a jmp"). */
export const looksPatched = (bytes: Uint8Array): boolean =>
  bytes[0] === 0xe9 ||
  (bytes[0] === 0xff && bytes[1] === 0x25) ||
  (bytes[0] === 0x48 && bytes[1] === 0xff && bytes[2] === 0x25);

// ------------------------------------------------------------------------------------------------ sampling
/** max_per_sec token bucket (S4 §10.3 filter 8; backtrace budget). Time in microseconds, injected. */
export class TokenBucket {
  #tokens: number;
  #last: number;
  constructor(
    readonly perSec: number,
    nowUs: number,
  ) {
    this.#tokens = perSec;
    this.#last = nowUs;
  }
  take(nowUs: number): boolean {
    const elapsed = nowUs - this.#last;
    if (elapsed > 0) {
      this.#tokens = Math.min(this.perSec, this.#tokens + (elapsed * this.perSec) / 1e6);
      this.#last = nowUs;
    }
    if (this.#tokens < 1) return false;
    this.#tokens -= 1;
    return true;
  }
}

// ------------------------------------------------------------------------------------------------ deny list
export interface ResolvedSiteRule {
  readonly api: string;
  readonly va: string; // lowercase "0x…"
  readonly reason: "deadlock-risk" | "agent-critical" | "caution";
}
/** S4 §10.8: deny/caution check on the hook address and every effective site (thunk targets included). */
export function siteRuleHit(sites: readonly string[], rules: readonly ResolvedSiteRule[]): ResolvedSiteRule | null {
  const want = new Set(sites.map((s) => s.toLowerCase()));
  for (const rule of rules) if (rule.reason !== "caution" && want.has(rule.va)) return rule;
  for (const rule of rules) if (rule.reason === "caution" && want.has(rule.va)) return rule;
  return null;
}

/** HookDenied alternatives (S4 §10.8, S6 §4.20); BEA-authored text. */
export const DENY_ALTERNATIVES: readonly string[] = [
  "trace_api {profiles:['memory_protection']} (NtProtectVirtualMemory, VirtualAllocEx/VirtualAlloc2, memmap watcher)",
  "watch_memory {method:'debug_register', access:'execute'} at the entry for occasional observation",
];
export const INSTALL_ALTERNATIVES: readonly string[] = [
  "watch_memory {method:'debug_register', access:'execute'} at the entry",
  "trace_execution {on_call} on the caller",
  "hook the call sites (disassemble the callers)",
];
