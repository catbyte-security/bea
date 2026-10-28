// =================================================================================================
// src/agent/memory.ts — WP3-AGENT guard-aware reads (S4 §8.2, CT-I5): readMemory (binary tuple) and readTyped
// (pointer chains, typed values). Core because address resolution and byte verification need them before any
// feature WP (D-INT-36). Every read walks VirtualQuery first: unmapped / no read right / a TARGET guard page stop the
// read (touching the target's guard would consume it, A-18); BEA's own guard pages are read inside
// withBeaGuardsSuspended. A TOCTOU fault falls back to page-wise reads. `safeReadBytes` is the shared primitive for
// capture derefs, crash stack windows and the disassembler.
// =================================================================================================
import type {
  AgentRpcImpl,
  AgentResult,
  Hex,
  ReadMemoryMeta,
  ReadMemoryParams,
  ReadTypedParams,
  ReadTypedResult,
  TypedOut,
  TypedRead,
  ValueType,
} from "../shared/agentProtocol.js";
import { AGENT_LIMIT_HARD } from "../shared/agentLimits.js";
import { big, hex, toPtr } from "./encode.js";
import { badParam, fail, mapThrown, ok } from "./errors.js";
import { GuardTable } from "./guards.js";
import { bytesHex, hexOfBigint } from "./pure/coreHex.js";
import { planRead, type ReadPlan } from "./pure/coreMem.js";
import { bitsFromBytes, typedOutOfBits, VALUE_TYPE_BYTES } from "./pure/coreScalar.js";
import type { Mbi } from "./pure/coreWin64.js";
import type { AgentCore } from "./state.js";

export interface SafeRead {
  /** the readable prefix (length ≤ requested) */
  readonly bytes: Uint8Array;
  readonly stop: ReadMemoryMeta["stop"];
  /** BEA guard pages suspended for this read */
  readonly beaPages: readonly Hex[];
}

const PAGE_CACHE_TTL_MS = 1000;

/** Per-page VirtualQuery cache (1 s TTL) for hot capture paths (S4 §10.3). */
class ProtCache {
  readonly #entries = new Map<string, { mbi: Mbi | null; at: number }>();

  get(c: AgentCore, address: bigint): Mbi | null {
    const now = Date.now();
    const key = (address - (address % 4096n)).toString(16);
    const hit = this.#entries.get(key);
    if (hit !== undefined && now - hit.at < PAGE_CACHE_TTL_MS) return hit.mbi;
    const mbi = c.guards.query(ptr(`0x${address.toString(16)}`));
    if (this.#entries.size > 4096) this.#entries.clear();
    this.#entries.set(key, { mbi, at: now });
    return mbi;
  }
}

const protCache = new ProtCache();

/** The guard-aware read plan for [p, p+size) (pure planner over live VirtualQuery). */
export const planReadAt = (c: AgentCore, p: NativePointer, size: number, cached = false): ReadPlan =>
  planRead({
    start: big(p),
    size,
    pageSize: Process.pageSize,
    query: (a) => (cached ? protCache.get(c, a) : c.guards.query(ptr(`0x${a.toString(16)}`))),
    isBeaPage: (page) => c.guards.ownsPage(page),
  });

const readRaw = (p: NativePointer, n: number): Uint8Array | null => {
  try {
    const ab = p.readByteArray(n);
    return ab === null ? null : new Uint8Array(ab);
  } catch {
    return null;
  }
};

/** Page-wise fallback after a fault in the middle of a planned prefix (unmapped between VirtualQuery and the read). */
const pageWise = (p: NativePointer, n: number): { bytes: Uint8Array; failedAt: NativePointer | null } => {
  const ps = Process.pageSize;
  const out = new Uint8Array(n);
  let done = 0;
  while (done < n) {
    const at = p.add(done);
    const chunk = Math.min(n - done, ps - Number(big(at) % BigInt(ps)));
    const b = readRaw(at, chunk);
    if (b === null) return { bytes: out.slice(0, done), failedAt: at };
    out.set(b, done);
    done += chunk;
  }
  return { bytes: out, failedAt: null };
};

/**
 * Guard-aware read of up to `n` bytes at `p`: stops at unmapped/protected/target-guard memory; BEA guard pages are
 * suspended for the read. Never throws for memory faults.
 */
export const safeReadBytes = (c: AgentCore, p: NativePointer, n: number, cached = false): SafeRead => {
  const plan = planReadAt(c, p, n, cached);
  let stop: ReadMemoryMeta["stop"] =
    plan.stop === null ? null : { reason: plan.stop.reason, at: hexOfBigint(plan.stop.at) };
  if (plan.readable === 0) return { bytes: new Uint8Array(0), stop, beaPages: [] };
  const ranges = [{ base: p, size: plan.readable }];
  let beaPages: Hex[] = [];
  const result = c.guards.withBeaGuardsSuspended(ranges, (pages) => {
    beaPages = GuardTable.pagesHex(pages);
    const whole = readRaw(p, plan.readable);
    return whole !== null ? { bytes: whole, failedAt: null } : pageWise(p, plan.readable);
  });
  if (result.failedAt !== null) stop = { reason: "access-violation", at: hex(result.failedAt) };
  return { bytes: result.bytes, stop, beaPages };
};

/** Read a pointer guard-aware; null when unreadable. */
export const safeReadPointer = (c: AgentCore, p: NativePointer, cached = false): NativePointer | null => {
  const r = safeReadBytes(c, p, 8, cached);
  return r.bytes.length < 8 ? null : ptr(hexOfBigint(bitsFromBytes(r.bytes, 0, "ptr")));
};

const clampSize = (c: AgentCore, size: unknown): number | null => {
  const max = Math.min(c.limits.read_max_bytes, AGENT_LIMIT_HARD.read_max_bytes);
  return typeof size === "number" && Number.isInteger(size) && size >= 1 && size <= max ? size : null;
};

/** readMemory: [ok(meta), ArrayBuffer] for ≥ 1 readable byte; AccessViolation/GuardPage when nothing was readable. */
export const readMemory = (
  c: AgentCore,
  p: ReadMemoryParams,
): [AgentResult<ReadMemoryMeta>, ArrayBuffer] | AgentResult<never> => {
  const size = clampSize(c, p.size);
  if (size === null) return fail(badParam("size", `1..${c.limits.read_max_bytes} bytes`));
  const at = toPtr(p.address);
  const r = safeReadBytes(c, at, size);
  if (r.bytes.length === 0) {
    if (r.stop?.reason === "guard-page")
      return fail({ _tag: "GuardPage", message: "a target guard page", address: r.stop.at, owner: "target" });
    return fail({
      _tag: "AccessViolation",
      message: "no readable byte at the address",
      address: hex(at),
      operation: "read",
      partial_bytes: 0,
    });
  }
  const meta: ReadMemoryMeta = {
    address: hex(at),
    requested: size,
    returned: r.bytes.length,
    complete: r.bytes.length === size,
    stop: r.bytes.length === size ? null : r.stop,
    bea_guard_suspended: [...r.beaPages],
  };
  return [ok(meta), r.bytes.buffer.slice(r.bytes.byteOffset, r.bytes.byteOffset + r.bytes.length) as ArrayBuffer];
};

const STRING_CHAR_BYTES: Partial<Record<ValueType, number>> = { utf8: 1, ansi: 1, utf16: 2 };

const decodeString = (t: ValueType, bytes: Uint8Array, maxChars: number): { text: string; trunc: boolean } => {
  const unit = STRING_CHAR_BYTES[t] ?? 1;
  let end = -1;
  for (let i = 0; i + unit <= bytes.length; i += unit) {
    if (bytes[i] === 0 && (unit === 1 || bytes[i + 1] === 0)) {
      end = i;
      break;
    }
  }
  const len = end === -1 ? Math.min(bytes.length, maxChars * unit) : end;
  const body = bytes.slice(0, len - (len % unit));
  let text = "";
  if (unit === 2)
    for (let i = 0; i + 1 < body.length; i += 2) text += String.fromCharCode(body[i]! | (body[i + 1]! << 8));
  else if (t === "utf8") text = utf8Decode(body);
  else for (const b of body) text += String.fromCharCode(b);
  return { text, trunc: end === -1 };
};

const utf8Decode = (b: Uint8Array): string => {
  let out = "";
  for (let i = 0; i < b.length;) {
    const x = b[i]!;
    const n = x < 0x80 ? 1 : x >= 0xf0 ? 4 : x >= 0xe0 ? 3 : x >= 0xc0 ? 2 : 1;
    let cp = n === 1 ? x : x & (0xff >> (n + 1));
    for (let k = 1; k < n; k++) cp = (cp << 6) | ((b[i + k] ?? 0) & 0x3f);
    out += String.fromCodePoint(n > 1 && cp > 0x10ffff ? 0xfffd : cp);
    i += n;
  }
  return out;
};

/** One typed value (or array) at a final address, guard-aware. */
const typedAt = (
  c: AgentCore,
  at: NativePointer,
  r: TypedRead,
): TypedOut | TypedOut[] | { error: ReturnType<typeof mapThrown> } => {
  const width = VALUE_TYPE_BYTES[r.type];
  if (width === null) {
    const maxChars = Math.min(r.max_len ?? 256, c.limits.max_string_chars);
    const unit = STRING_CHAR_BYTES[r.type] ?? 1;
    const want =
      r.type === "bytes" ? Math.min(r.count ?? r.max_len ?? 16, c.limits.max_capture_bytes) : (maxChars + 1) * unit;
    const got = safeReadBytes(c, at, want);
    if (got.bytes.length === 0) return { error: unreadable(at, got.stop?.reason) };
    if (r.type === "bytes") return { type: "bytes", value: null, hex: bytesHex(got.bytes) };
    const s = decodeString(r.type, got.bytes, maxChars);
    return {
      type: r.type,
      value: s.text,
      trunc: s.trunc,
      hex: bytesHex(got.bytes, 0, Math.min(got.bytes.length, maxChars * unit)),
    };
  }
  const count = Math.max(1, Math.min(r.count ?? 1, 256));
  const got = safeReadBytes(c, at, width * count);
  if (got.bytes.length < width) return { error: unreadable(at, got.stop?.reason) };
  const values: TypedOut[] = [];
  for (let i = 0; i + width <= got.bytes.length && values.length < count; i += width)
    values.push(typedOutOfBits(r.type, bitsFromBytes(got.bytes, i, r.type)));
  return count === 1 ? values[0]! : values;
};

const unreadable = (at: NativePointer, reason: string | undefined): ReturnType<typeof mapThrown> =>
  reason === "guard-page"
    ? { _tag: "GuardPage", message: "a target guard page", address: hex(at), owner: "target" }
    : { _tag: "AccessViolation", message: "unreadable", address: hex(at), operation: "read", partial_bytes: 0 };

/**
 * readTyped (S4 §8.2): `p = address`, `path = [p]`; for each offset `o` of `chain`: `p = readPointer(p + o)`, push
 * `p` (a null pointer is AccessViolation{0x0}); the final read is at `p`. Note: the S4 chain has no trailing field
 * offset — Cheat-Engine `[[A]+d0]+d1` is chain [0, d0] (the final pointer) plus d1 added by the caller.
 */
export const readTyped = (c: AgentCore, p: ReadTypedParams): AgentResult<ReadTypedResult> => {
  if (!Array.isArray(p.reads)) return fail(badParam("reads", "must be an array"));
  const max = Math.min(c.limits.typed_max_reads, AGENT_LIMIT_HARD.typed_max_reads);
  if (p.reads.length > max) return fail(badParam("reads", `at most ${max} reads`));
  const results: ReadTypedResult["results"] = [];
  for (const r of p.reads) results.push(readOne(c, r));
  return ok({ results });
};

const readOne = (c: AgentCore, r: TypedRead): ReadTypedResult["results"][number] => {
  const path: Hex[] = [];
  try {
    let at = toPtr(r.address);
    path.push(hex(at));
    const chain = r.chain ?? [];
    if (chain.length > c.limits.max_deref_depth)
      return { ok: false, error: badParam("chain", `at most ${c.limits.max_deref_depth} offsets`), path };
    for (const o of chain) {
      const next = safeReadPointer(c, at.add(o));
      if (next === null) return { ok: false, error: unreadable(at.add(o), undefined), path };
      if (next.isNull())
        return {
          ok: false,
          error: { _tag: "AccessViolation", message: "null pointer in chain", address: "0x0", operation: "read" },
          path,
        };
      at = next;
      path.push(hex(at));
    }
    const value = typedAt(c, at, r);
    if ("error" in value) return { ok: false, error: value.error, path };
    return { ok: true, final_address: hex(at), path, value };
  } catch (e) {
    return { ok: false, error: mapThrown(e, "readTyped"), path };
  }
};

let bound: AgentCore | null = null;
const core = (): AgentCore => {
  if (bound === null) throw new Error("memory.init() has not run");
  return bound;
};

/** Feature contract (S4 §3.1): index.ts calls init(core) before spreading `rpc`. */
export function init(c: AgentCore): void {
  bound = c;
}

export const rpc = {
  readMemory: (p) => readMemory(core(), p),
  readTyped: (p) => readTyped(core(), p),
} satisfies Partial<AgentRpcImpl>;
