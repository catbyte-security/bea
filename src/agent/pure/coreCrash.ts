// =================================================================================================
// src/agent/pure/coreCrash.ts — WP3-AGENT crash policy defaults and clamping (S4 §7; CrashPolicy) and the first-chance
// pass-through rules (BEA-FEEDBACK.md item 4). Pure: no Frida globals (unit-tested in tests/unit/agent/core/).
//  - first_chance_blocking is opt-in. A blocking report runs on the faulting thread, which may hold the target's own
//    locks (ASan's allocator commits its shadow memory from its own exception handler; JITs and drivers probe memory
//    under SEH), and waits for the host's ack. The last-chance (UEF) report stays on.
//  - pass-through: an exception whose pc lies in a module that matches a pass-through pattern returns false at once,
//    with no row and no report. ASan's runtime (clang_rt.asan*.dll) always passes, and so does an access violation in
//    ASan's shadow memory: [__asan_shadow_memory_dynamic_address, +2^44) on Win64, the shadow (addr >> 3) of the
//    47-bit user address space. A static-runtime ASan executable publishes that variable itself.
// =================================================================================================
import type { CrashPolicy, ExceptionType } from "../../shared/agentProtocol.js";

export const EXCEPTION_TYPES: readonly ExceptionType[] = [
  "abort",
  "access-violation",
  "guard-page",
  "illegal-instruction",
  "stack-overflow",
  "arithmetic",
  "breakpoint",
  "single-step",
  "system",
];

/**
 * "system" is not a crash class by default (review fix AGENT-11): Frida reports every code it does not map as
 * "system", which includes C++ throws (0xE06D7363, 0x20474343), OutputDebugString (0x40010006/0x4001000A), thread
 * naming (0x406D1388) and RPC errors, all normally handled. An unhandled one is reported at last chance.
 * first_chance_blocking is false (BEA-FEEDBACK #4): crash-class exceptions are first-chance rows, and the blocking
 * crash report comes from the last-chance (UEF) layer unless the host opts in.
 */
export const DEFAULT_CRASH_POLICY: CrashPolicy = {
  first_chance_rows: true,
  first_chance_blocking: false,
  crash_class: ["access-violation", "illegal-instruction", "stack-overflow", "arithmetic", "abort"],
  ack_timeout_ms: 1000,
  last_chance_ack_timeout_ms: 2000,
  max_blocking_per_10s: 8,
  rows_per_sec: 1000,
  stack_bytes: 256,
  backtrace_depth: 32,
  include_xmm: false,
  passthrough_modules: [],
};

export const MAX_PASSTHROUGH_PATTERNS = 32;
export const MAX_PASSTHROUGH_PATTERN_CHARS = 128;
/** A module file name, or one with `*` wildcards: no path separators, drive colons or control characters. */
const PATTERN = /^[^\\/:\p{Cc}]+$/u;

/** A usable pass-through pattern: 1..128 characters of a file name, not only wildcards and blanks. */
export const isPassthroughPattern = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length <= MAX_PASSTHROUGH_PATTERN_CHARS &&
  PATTERN.test(value) &&
  value.split("*").join("").trim() !== "";

/** The valid patterns of a host list, lower-cased and de-duplicated, at most 32; everything else is dropped. */
export const normalizePassthroughModules = (raw: unknown): string[] => {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const value of raw as unknown[]) {
    if (out.length === MAX_PASSTHROUGH_PATTERNS) break;
    if (!isPassthroughPattern(value)) continue;
    const lower = value.toLowerCase();
    if (!out.includes(lower)) out.push(lower);
  }
  return out;
};

const clampInt = (v: unknown, lo: number, hi: number, fallback: number): number =>
  typeof v === "number" && Number.isFinite(v) ? Math.max(lo, Math.min(Math.floor(v), hi)) : fallback;

/** Host crash policy clamped to the documented maxima (CrashPolicy comments); missing fields take the defaults. */
export const clampCrashPolicy = (p: Partial<CrashPolicy> | undefined): CrashPolicy => {
  const d = DEFAULT_CRASH_POLICY;
  const classes = Array.isArray(p?.crash_class)
    ? p.crash_class.filter((t) => EXCEPTION_TYPES.includes(t))
    : d.crash_class;
  return {
    first_chance_rows: typeof p?.first_chance_rows === "boolean" ? p.first_chance_rows : d.first_chance_rows,
    first_chance_blocking:
      typeof p?.first_chance_blocking === "boolean" ? p.first_chance_blocking : d.first_chance_blocking,
    crash_class: [...classes],
    ack_timeout_ms: clampInt(p?.ack_timeout_ms, 0, 5000, d.ack_timeout_ms),
    last_chance_ack_timeout_ms: clampInt(p?.last_chance_ack_timeout_ms, 0, 5000, d.last_chance_ack_timeout_ms),
    max_blocking_per_10s: clampInt(p?.max_blocking_per_10s, 0, 64, d.max_blocking_per_10s),
    rows_per_sec: clampInt(p?.rows_per_sec, 1, 100_000, d.rows_per_sec),
    stack_bytes: clampInt(p?.stack_bytes, 0, 4096, d.stack_bytes),
    backtrace_depth: clampInt(p?.backtrace_depth, 0, 64, d.backtrace_depth),
    include_xmm: typeof p?.include_xmm === "boolean" ? p.include_xmm : d.include_xmm,
    passthrough_modules: normalizePassthroughModules(p?.passthrough_modules),
  };
};

/** ASan's runtime DLLs (clang and MSVC ship the same names): their exceptions always pass through. */
export const ASAN_RUNTIME_PATTERNS: readonly string[] = ["clang_rt.asan*.dll"];
/** The variable an ASan runtime publishes its shadow offset in (Win64 ASan uses a dynamic shadow offset). */
export const ASAN_SHADOW_EXPORT = "__asan_shadow_memory_dynamic_address";
/** Win64 ASan: shadow = (address >> 3) + offset over the 47-bit user address space, 2^44 bytes. */
export const ASAN_SHADOW_BYTES = 1n << 44n;

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

/** One case-insensitive matcher of module file names for patterns (`*` = any run of characters); null when empty. */
export const modulePatternMatcher = (patterns: readonly string[]): ((name: string) => boolean) | null => {
  if (patterns.length === 0) return null;
  const re = new RegExp(`^(?:${patterns.map((p) => p.split("*").map(escapeRegExp).join(".*")).join("|")})$`, "iu");
  return (name) => re.test(name);
};

/** Length of an `FF /2` (near indirect call) whose opcode is at bytes[i], else 0 (ModRM, SIB and displacement). */
const indirectCallLength = (bytes: Uint8Array, i: number): number => {
  const modrm = bytes[i + 1];
  if (bytes[i] !== 0xff || modrm === undefined || ((modrm >> 3) & 7) !== 2) return 0;
  const mod = modrm >> 6;
  const rm = modrm & 7;
  if (mod === 3) return 2;
  let length = 2;
  if (rm === 4) {
    length += 1;
    const sib = bytes[i + 2];
    if (mod === 0 && sib !== undefined && (sib & 7) === 5) length += 4;
  }
  if (mod === 0 && rm === 5) length += 4;
  else if (mod === 1) length += 1;
  else if (mod === 2) length += 4;
  return length;
};

/**
 * The bytes right before a candidate return address end with a call instruction: `E8 rel32`, or `FF /2` in any
 * addressing form, optionally after one REX prefix. `before` holds the (up to 8) bytes that precede the address. The
 * unwinder applies the leaf rule ([rsp] is the return address) to a faulting pc outside every image (a call through a
 * bad pointer, a jump to data) only when the value at [rsp] passes this check.
 */
export const isCallReturnSite = (before: Uint8Array): boolean => {
  const n = before.length;
  if (n >= 5 && before[n - 5] === 0xe8) return true;
  for (let start = Math.max(0, n - 8); start <= n - 2; start++) {
    if (start + indirectCallLength(before, start) === n) return true;
    const rex = before[start];
    if (rex !== undefined && rex >= 0x40 && rex <= 0x4f && start + 1 + indirectCallLength(before, start + 1) === n)
      return true;
  }
  return false;
};

/** [lo, hi) of ASan's shadow for a published shadow offset; null while it is 0 (runtime not initialized yet). */
export const asanShadowRange = (offset: bigint): { readonly lo: bigint; readonly hi: bigint } | null =>
  offset <= 0n || offset + ASAN_SHADOW_BYTES > 1n << 64n ? null : { lo: offset, hi: offset + ASAN_SHADOW_BYTES };
