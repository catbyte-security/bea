// =================================================================================================
// src/agent/pure/scanEngine.ts — WP10-SCAN: Cheat-Engine-style scans as sliced jobs (S4 §9 as amended by
// DESIGN §5.3 / D-INT-44). Pure: every target access goes through ScanPlatform, so vitest drives the same code
// with a fake address space, and src/agent/scan.ts binds GumJS.
//
// - First scan (job "scan-first"): numeric compares run in the C kernel (writes candidates straight into the
//   native arrays; no JS object per hit), byte strings and patterns use Memory.scanSync, pointers-to uses
//   Memory.findPointers, unknown-initial copies the regions into a snapshot.
// - Next scan (job "scan-next"): the kernel re-reads every candidate and compacts in place; a snapshot is narrowed
//   into explicit candidates.
// - Every slice runs inside platform.suspendGuards (CT-I5: a value on a BEA guard-watched page is found and the
//   watch keeps recording). A stolen access violation skips the rest of a region (first scan) or drops the
//   candidates of the faulting 4 KiB page (next scan).
// =================================================================================================
import type {
  AgentError,
  AgentResult,
  JobKind,
  Paged,
  Progress,
  RegionFilter,
  ScalarInput,
  ScanHit,
  ScanNextParams,
  ScanResultsParams,
  ScanStartParams,
  ScanStatus,
  ScanValueType,
  TimeUs,
} from "../../shared/agentProtocol.js";
import { HEX_INPUT_RE, hexToBytes, HEX_BYTES_RE } from "../../shared/hex.js";
import { addrAt, setAddrAt } from "./scanReference.js";
import {
  BYTE_OPS,
  CHUNK_BYTES,
  INITIAL_CAPACITY,
  isFloatType,
  isNumericType,
  MAX_ELEM_BYTES,
  MAX_POINTER_TARGETS,
  naturalAlign,
  NEXT_CHUNK,
  NUMERIC_ELEM,
  PAGE_BYTES,
  PATTERN_CHUNK_BYTES,
  POINTER_CHUNK_BYTES,
  SHORT_PATTERN_CHUNK_BYTES,
  VT_CODE,
  ZERO_BITS,
  type Candidates,
  type KernelOp,
  type KernelSpec,
  type NumericScanType,
  type RawRange,
  type ScanBuf,
  type ScanLimits,
  type ScanPlatform,
} from "./scanTypes.js";
import {
  decodeValue,
  floatOrder,
  hexAddr,
  parseNumericOperand,
  parsePattern,
  patternOf,
  readFloat,
  utf16Encode,
  utf8Encode,
  type NumericOperand,
} from "./scanValue.js";

/** One slice-able unit of work handed to the job runner (S4 §5.8). */
export interface ScanJobWork {
  readonly kind: Extract<JobKind, "scan-first" | "scan-next">;
  readonly scanId: string;
  /** does at most about `budgetMs` of work */
  step(budgetMs: number): "more" | "done";
  progress(): Progress;
  /** checked before the next slice; the scan keeps what it has */
  cancel(): void;
  /** valid after step() returned "done" */
  outcome(): {
    readonly state: "done" | "failed" | "cancelled";
    readonly result: ScanStatus;
    readonly error: AgentError | null;
  };
}

export interface Region {
  readonly base: number;
  readonly size: number;
  readonly module: string | null;
}

/** Candidates beyond this count keep no first values (same_as_first then needs a narrower scan). */
const FIRSTS_MAX = 1_048_576;

const fail = (error: AgentError): AgentResult<never> => ({ ok: false, error });
const badParams = (path: string, problem: string): AgentResult<never> =>
  fail({ _tag: "BadParams", message: "invalid scan parameters", issues: [{ path, problem }] });
const notFound = (id: string): AgentResult<never> =>
  fail({ _tag: "NotFound", message: "no such scan", what: "scan", id });
const PROTECTION_RE = /^[r-][w-][x-]$/u;

const parseVa = (text: string | undefined): number | null =>
  text === undefined || !HEX_INPUT_RE.test(text) ? null : Number(BigInt(text.toLowerCase()));

const moduleMatches = (list: readonly string[], module: string | null): boolean =>
  module !== null && list.some((m) => m === "*" || m.toLowerCase() === module.toLowerCase());

/**
 * Region list (S4 §9.1): the platform's committed ranges filtered by modules ("*" = any module image), excluded
 * modules, private_only (no module), the [min, max) window and max_region_bytes; sorted by base, never coalesced.
 */
export const selectRegions = (raw: readonly RawRange[], f: RegionFilter): Region[] => {
  const min = parseVa(f.min) ?? 0;
  const max = parseVa(f.max) ?? Number.MAX_SAFE_INTEGER;
  const out: Region[] = [];
  for (const r of raw) {
    if (f.modules !== undefined && f.modules.length > 0 && !moduleMatches(f.modules, r.module)) continue;
    if (f.exclude_modules !== undefined && moduleMatches(f.exclude_modules, r.module)) continue;
    if (f.private_only === true && r.module !== null) continue;
    const base = Math.max(r.base, min);
    const end = Math.min(r.base + r.size, max);
    if (end <= base) continue;
    if (f.max_region_bytes !== undefined && end - base > f.max_region_bytes) continue;
    out.push({ base, size: end - base, module: r.module });
  }
  return out.sort((x, y) => x.base - y.base);
};

/** Aligned element starts in `size` bytes. */
const elementsIn = (size: number, elem: number, align: number): number =>
  size >= elem ? Math.floor((size - elem) / align) + 1 : 0;

type FirstPlan =
  | { readonly kind: "kernel"; readonly spec: KernelSpec }
  | { readonly kind: "pattern"; readonly pattern: string; readonly exact: Uint8Array | null }
  | { readonly kind: "pointers"; readonly targets: readonly number[] }
  | { readonly kind: "snapshot" };

interface Snap {
  readonly region: Region;
  buf: ScanBuf | null;
  /** false once a copy failed (the region is left out) */
  readable: boolean;
}

interface ScanState {
  readonly id: string;
  readonly label: string | null;
  readonly vt: ScanValueType;
  readonly elem: number;
  readonly align: number;
  readonly cap: number;
  readonly regions: readonly Region[];
  mode: "explicit" | "snapshot";
  cands: Candidates | null;
  count: number;
  snaps: Snap[] | null;
  history: { op: string; count_after: number; t: TimeUs }[];
  bytesScanned: number;
  unreadable: number;
  faultedDropped: number;
  state: "running" | "ready" | "failed" | "closed";
  job: string | null;
  error: AgentError | null;
  work: ScanJobWork | null;
}

const NUMERIC_FIRST_OPS = new Set(["eq", "approx", "range", "gt", "lt"]);

/** The scan registry of one agent (S4 §9): at most scan_max_concurrent open scans, state in target memory. */
export class ScanEngine {
  readonly #platform: ScanPlatform;
  readonly #limits: () => ScanLimits;
  readonly #scans = new Map<string, ScanState>();
  #seq = 0;

  constructor(platform: ScanPlatform, limits: () => ScanLimits) {
    this.#platform = platform;
    this.#limits = limits;
  }

  // ------------------------------------------------------------------ RPC surface

  start(p: ScanStartParams): AgentResult<ScanJobWork> {
    const limits = this.#limits();
    if (this.#scans.size >= limits.scan_max_concurrent)
      return fail({
        _tag: "ResourceLimit",
        message: "too many open scans",
        resource: "scans",
        limit: limits.scan_max_concurrent,
        observed: this.#scans.size,
      });
    if (!PROTECTION_RE.test(p.regions.protection))
      return badParams("regions.protection", 'protection must look like "rw-", "r--" or "r-x"');
    const planned = this.#plan(p);
    if (!planned.ok) return planned;
    const { vt, elem, plan } = planned.value;
    const align = p.align ?? naturalAlign(vt);
    if (![1, 2, 4, 8].includes(align)) return badParams("align", "align must be 1, 2, 4 or 8");
    if (p.max_candidates !== undefined && (!Number.isSafeInteger(p.max_candidates) || p.max_candidates < 1))
      return badParams("max_candidates", "max_candidates must be a positive integer");
    const regions = selectRegions(this.#platform.ranges(p.regions.protection), p.regions);
    if (plan.kind === "snapshot") {
      const total = regions.reduce((sum, r) => sum + r.size, 0);
      if (total > limits.scan_snapshot_bytes)
        return fail({
          _tag: "ResourceLimit",
          message: "the unknown-value snapshot would exceed scan_snapshot_bytes",
          resource: "scan_snapshot",
          limit: limits.scan_snapshot_bytes,
          observed: total,
        });
    }
    this.#seq += 1;
    const s: ScanState = {
      id: `sc${String(this.#seq)}`,
      label: p.label ?? null,
      vt,
      elem,
      align,
      cap: Math.min(p.max_candidates ?? limits.scan_max_candidates, limits.scan_max_candidates),
      regions,
      mode: plan.kind === "snapshot" ? "snapshot" : "explicit",
      cands: null,
      count: 0,
      snaps: plan.kind === "snapshot" ? regions.map((region) => ({ region, buf: null, readable: true })) : null,
      history: [],
      bytesScanned: 0,
      unreadable: 0,
      faultedDropped: 0,
      state: "running",
      job: null,
      error: null,
      work: null,
    };
    this.#scans.set(s.id, s);
    const opName = p.kind === "value" ? (p.compare?.op ?? "eq") : p.kind === "pattern" ? "pattern" : p.kind;
    const work = new FirstScan(this, s, plan, opName);
    s.work = work;
    return { ok: true, value: work };
  }

  next(p: ScanNextParams): AgentResult<ScanJobWork> {
    const s = this.#scans.get(p.scan_id);
    if (s === undefined) return notFound(p.scan_id);
    if (s.state === "running") return badParams("scan_id", "the scan is still running; wait for its job first");
    if (s.mode === "explicit" && s.cands === null && s.count === 0 && s.state === "failed")
      return badParams("scan_id", "the scan has no candidates to narrow");
    const spec = this.#nextSpec(s, p);
    if (!spec.ok) return spec;
    s.state = "running";
    s.error = null;
    const work = s.mode === "snapshot" ? new SnapshotNext(this, s, spec.value) : new ExplicitNext(this, s, spec.value);
    s.work = work;
    return { ok: true, value: work };
  }

  /** The job runner refused the work: a first scan is closed; a next scan ends cancelled with its candidates intact. */
  abandon(work: ScanJobWork): void {
    const s = this.#scans.get(work.scanId);
    if (s === undefined || s.work !== work) return;
    if (work.kind === "scan-first") {
      this.#release(s);
      return;
    }
    work.cancel();
    work.step(0);
  }

  attachJob(scanId: string, jobId: string): void {
    const s = this.#scans.get(scanId);
    if (s !== undefined) s.job = jobId;
  }

  status(scanId: string): AgentResult<ScanStatus> {
    const s = this.#scans.get(scanId);
    return s === undefined ? notFound(scanId) : { ok: true, value: this.statusOf(s) };
  }

  list(): ScanStatus[] {
    return [...this.#scans.values()].map((s) => this.statusOf(s));
  }

  results(p: ScanResultsParams): AgentResult<Paged<ScanHit>> {
    const s = this.#scans.get(p.scan_id);
    if (s === undefined) return notFound(p.scan_id);
    if (s.state === "running") return badParams("scan_id", "the scan is still running; wait for its job first");
    if (s.mode === "snapshot")
      return badParams("scan_id", "an unknown-value scan holds a snapshot; narrow it with scanNext first");
    if (!Number.isSafeInteger(p.offset) || p.offset < 0) return badParams("offset", "offset must be ≥ 0");
    if (!Number.isSafeInteger(p.limit) || p.limit < 1) return badParams("limit", "limit must be ≥ 1");
    const limit = Math.min(p.limit, this.#limits().scan_page_rows);
    const end = Math.min(s.count, p.offset + limit);
    const items: ScanHit[] = [];
    const cands = s.cands;
    if (cands !== null && p.offset < end) {
      const first = addrAt(cands.addrs, p.offset);
      const last = addrAt(cands.addrs, end - 1);
      const span = { base: first, size: last - first + s.elem };
      this.#platform.suspendGuards(span, () => {
        for (let i = p.offset; i < end; i++) {
          const va = addrAt(cands.addrs, i);
          const stored = decodeValue(s.vt, cands.vals.u8.slice(i * s.elem, (i + 1) * s.elem));
          if (!p.read_current) {
            items.push({ address: hexAddr(va), stored });
            continue;
          }
          const now = this.#platform.read(va, s.elem);
          items.push({
            address: hexAddr(va),
            stored,
            current:
              now === null
                ? {
                    error: {
                      _tag: "AccessViolation",
                      message: "the candidate is no longer readable",
                      address: hexAddr(va),
                      operation: "read",
                    },
                  }
                : decodeValue(s.vt, now),
          });
        }
      });
    }
    return {
      ok: true,
      value: { total: s.count, offset: p.offset, items, next_offset: end < s.count ? end : null },
    };
  }

  close(scanId: string): AgentResult<{ closed: true; freed_bytes: number }> {
    const s = this.#scans.get(scanId);
    if (s === undefined) return notFound(scanId);
    return { ok: true, value: { closed: true, freed_bytes: this.#release(s) } };
  }

  /** Shutdown: frees every scan; returns how many there were (ShutdownResult.scans_freed). */
  closeAll(): number {
    const n = this.#scans.size;
    for (const s of this.#scans.values()) this.#release(s); // deleting the visited entry is safe in Map iteration
    return n;
  }

  /** Bytes the scans hold in target memory (AgentStatus.memory.scan_bytes). */
  memoryBytes(): number {
    let total = 0;
    for (const s of this.#scans.values()) total += memoryOf(s);
    return total;
  }

  // ------------------------------------------------------------------ helpers used by the jobs

  get platform(): ScanPlatform {
    return this.#platform;
  }

  statusOf(s: ScanState): ScanStatus {
    return {
      scan_id: s.id,
      label: s.label,
      state: s.state,
      mode: s.mode,
      value_type: s.vt,
      count: s.count,
      ops: s.history.map((h) => ({ ...h })),
      bytes_scanned: s.bytesScanned,
      regions: s.regions.length,
      unreadable_regions: s.unreadable,
      faulted_candidates_dropped: s.faultedDropped,
      job: s.job,
      memory_bytes: memoryOf(s),
      error: s.error,
    };
  }

  /** Allocates candidate arrays for `cap` entries (null when the allocation fails). */
  allocCandidates(s: ScanState, cap: number, firsts: boolean): Candidates | null {
    const addrs = this.#platform.alloc(cap * 8);
    const vals = addrs === null ? null : this.#platform.alloc(cap * s.elem);
    const fs = vals === null || !firsts ? null : this.#platform.alloc(cap * s.elem);
    if (addrs === null || vals === null || (firsts && fs === null)) {
      for (const b of [addrs, vals, fs]) if (b !== null) this.#platform.free(b);
      return null;
    }
    return { addrs, vals, firsts: fs, cap };
  }

  freeCandidates(c: Candidates | null): void {
    if (c === null) return;
    this.#platform.free(c.addrs);
    this.#platform.free(c.vals);
    if (c.firsts !== null) this.#platform.free(c.firsts);
  }

  /**
   * Grows `s.cands` (×4, at most s.cap) so it holds more than `count` entries. Returns false when the scan's cap
   * is reached or the allocation failed (s.error is set accordingly).
   */
  grow(s: ScanState, count: number): boolean {
    const old = s.cands;
    const current = old?.cap ?? 0;
    if (current >= s.cap) {
      s.error = {
        _tag: "ResourceLimit",
        message: "the scan reached its candidate cap; narrow the type, regions or value",
        resource: "scan_candidates",
        limit: s.cap,
        observed: count,
      };
      return false;
    }
    const cap = Math.min(s.cap, Math.max(INITIAL_CAPACITY, current * 4));
    const next = this.allocCandidates(s, cap, old?.firsts != null);
    if (next === null) {
      s.error = {
        _tag: "ResourceLimit",
        message: "agent memory allocation failed",
        resource: "agent_memory",
        limit: cap * (8 + s.elem),
      };
      return false;
    }
    if (old !== null) {
      next.addrs.u8.set(old.addrs.u8.subarray(0, count * 8));
      next.vals.u8.set(old.vals.u8.subarray(0, count * s.elem));
      if (old.firsts !== null && next.firsts !== null) next.firsts.u8.set(old.firsts.u8.subarray(0, count * s.elem));
      this.freeCandidates(old);
    }
    s.cands = next;
    return true;
  }

  /** After a narrowing: release most of the slack when the arrays are mostly empty. */
  shrink(s: ScanState): void {
    const c = s.cands;
    if (c === null || c.cap <= INITIAL_CAPACITY || s.count * 4 > c.cap) return;
    const cap = Math.max(INITIAL_CAPACITY, s.count);
    const next = this.allocCandidates(s, cap, c.firsts !== null);
    if (next === null) return;
    next.addrs.u8.set(c.addrs.u8.subarray(0, s.count * 8));
    next.vals.u8.set(c.vals.u8.subarray(0, s.count * s.elem));
    if (c.firsts !== null && next.firsts !== null) next.firsts.u8.set(c.firsts.u8.subarray(0, s.count * s.elem));
    this.freeCandidates(c);
    s.cands = next;
  }

  /** First values for same_as_first: a copy of the stored values when the scan is small enough. */
  captureFirsts(s: ScanState): void {
    const c = s.cands;
    if (c === null || c.firsts !== null || s.count > FIRSTS_MAX) return;
    const firsts = this.#platform.alloc(c.cap * s.elem);
    if (firsts === null) return;
    firsts.u8.set(c.vals.u8.subarray(0, s.count * s.elem));
    s.cands = { ...c, firsts };
  }

  finish(s: ScanState, op: string, error: AgentError | null): void {
    if (s.state === "closed") return;
    s.error = error ?? s.error;
    s.state = s.error === null ? "ready" : "failed";
    s.history.push({ op, count_after: s.count, t: this.#platform.nowUs() });
    s.work = null;
  }

  // ------------------------------------------------------------------ planning

  #plan(p: ScanStartParams): AgentResult<{ vt: ScanValueType; elem: number; plan: FirstPlan }> {
    switch (p.kind) {
      case "pattern": {
        if (p.pattern === undefined) return badParams("pattern", "kind pattern needs a pattern");
        const parsed = parsePattern(p.pattern);
        if (!parsed.ok) return badParams("pattern", parsed.problem);
        return ok({ vt: "bytes", elem: parsed.value.elem, plan: { kind: "pattern", ...parsed.value } });
      }
      case "pointers-to": {
        const targets = p.targets ?? [];
        if (targets.length === 0 || targets.length > MAX_POINTER_TARGETS)
          return badParams("targets", `pointers-to needs 1..${String(MAX_POINTER_TARGETS)} targets`);
        const vas = targets.map(parseVa);
        if (vas.some((v) => v === null)) return badParams("targets", "targets must be 0x… hex addresses");
        return ok({ vt: "ptr", elem: 8, plan: { kind: "pointers", targets: vas as number[] } });
      }
      case "unknown": {
        const vt = p.value_type;
        if (vt === undefined || !isNumericType(vt))
          return badParams("value_type", "an unknown-value scan needs a numeric value_type");
        return ok({ vt, elem: NUMERIC_ELEM[vt], plan: { kind: "snapshot" } });
      }
      case "value":
        return this.#planValue(p);
    }
  }

  #planValue(p: ScanStartParams): AgentResult<{ vt: ScanValueType; elem: number; plan: FirstPlan }> {
    const vt = p.value_type;
    const c = p.compare;
    if (vt === undefined) return badParams("value_type", "kind value needs a value_type");
    if (c === undefined || !NUMERIC_FIRST_OPS.has(c.op))
      return badParams("compare.op", "compare.op must be eq, approx, range, gt or lt");
    if (!isNumericType(vt)) {
      if (c.op !== "eq") return badParams("compare.op", `${vt} scans support eq only`);
      const bytes = byteComparand(vt, c.text, c.bytes);
      if (!bytes.ok) return bytes;
      return ok({
        vt,
        elem: bytes.value.length,
        plan: { kind: "pattern", pattern: patternOf(bytes.value), exact: bytes.value },
      });
    }
    const spec = numericSpec(
      vt,
      c.op,
      { value: c.value, min: c.min, max: c.max, eps: c.eps },
      p.align ?? naturalAlign(vt),
      "compare",
    );
    if (!spec.ok) return spec;
    return ok({ vt, elem: NUMERIC_ELEM[vt], plan: { kind: "kernel", spec: spec.value } });
  }

  #nextSpec(s: ScanState, p: ScanNextParams): AgentResult<KernelSpec> {
    const op = p.op as KernelOp;
    if (!isNumericType(s.vt)) {
      if (!BYTE_OPS.has(op))
        return badParams("op", `${s.vt} scans support eq, ne, changed, unchanged and same_as_first`);
      let operand: Uint8Array | null = null;
      if (op === "eq" || op === "ne") {
        if (typeof p.value !== "string") return badParams("value", `${op} on a ${s.vt} scan needs a string value`);
        const bytes = byteComparand(
          s.vt,
          s.vt === "bytes" ? undefined : p.value,
          s.vt === "bytes" ? p.value : undefined,
        );
        if (!bytes.ok) return bytes;
        if (bytes.value.length !== s.elem)
          return badParams("value", `the value must be ${String(s.elem)} bytes long, like the scan's elements`);
        operand = bytes.value;
      }
      if (op === "same_as_first" && s.mode === "explicit" && s.cands?.firsts == null)
        return badParams("op", "same_as_first is unavailable: the first scan kept no first values");
      return ok({ vt: VT_CODE[s.vt], elem: s.elem, align: s.align, op, a: ZERO_BITS, b: ZERO_BITS, eps: 0, operand });
    }
    if (op === "same_as_first" && s.mode === "explicit" && s.cands?.firsts == null)
      return badParams(
        "op",
        `same_as_first is unavailable: the first scan had more than ${String(FIRSTS_MAX)} candidates`,
      );
    return numericSpec(s.vt, op, { value: p.value, min: p.min, max: p.max, eps: p.eps }, s.align, "");
  }

  #release(s: ScanState): number {
    const freed = memoryOf(s);
    s.work?.cancel();
    s.state = "closed";
    this.freeCandidates(s.cands);
    s.cands = null;
    for (const snap of s.snaps ?? []) if (snap.buf !== null) this.#platform.free(snap.buf);
    s.snaps = null;
    this.#scans.delete(s.id);
    return freed;
  }
}

const ok = <T>(value: T): AgentResult<T> => ({ ok: true, value });

const memoryOf = (s: ScanState): number => {
  let total = 0;
  const c = s.cands;
  if (c !== null) total += c.addrs.bytes + c.vals.bytes + (c.firsts?.bytes ?? 0);
  for (const snap of s.snaps ?? []) total += snap.buf?.bytes ?? 0;
  return total;
};

const byteComparand = (
  vt: ScanValueType,
  text: string | undefined,
  hex: string | undefined,
): AgentResult<Uint8Array> => {
  let bytes: Uint8Array;
  if (vt === "bytes") {
    if (hex === undefined || !HEX_BYTES_RE.test(hex.toLowerCase()) || hex.length === 0)
      return badParams("compare.bytes", "a bytes comparand is an even-length hex string");
    bytes = hexToBytes(hex.toLowerCase());
  } else {
    if (text === undefined || text.length === 0) return badParams("compare.text", `a ${vt} scan needs non-empty text`);
    bytes = vt === "utf16" ? utf16Encode(text) : utf8Encode(text);
  }
  if (bytes.length > MAX_ELEM_BYTES)
    return badParams("compare", `the comparand is longer than ${String(MAX_ELEM_BYTES)} bytes`);
  return ok(bytes);
};

interface NumericInputs {
  readonly value: ScalarInput | undefined;
  readonly min: ScalarInput | undefined;
  readonly max: ScalarInput | undefined;
  readonly eps: number | undefined;
}

const operand = (vt: NumericScanType, v: ScalarInput | undefined, path: string): AgentResult<NumericOperand> => {
  if (v === undefined) return badParams(path, `${path || "value"} is required for this comparison`);
  const parsed = parseNumericOperand(vt, v);
  return parsed.ok ? ok(parsed.value) : badParams(path, parsed.problem);
};

const operandOrder = (vt: NumericScanType, lo: NumericOperand, hi: NumericOperand): boolean => {
  if (isFloatType(vt)) {
    // from the bits: QJS has no infinities (scanValue floatClass)
    const order = floatOrder(readFloat(vt === "f64", lo.bytes), readFloat(vt === "f64", hi.bytes));
    return order !== null && order <= 0;
  }
  const read = (x: NumericOperand): bigint => {
    const u = (BigInt(x.bits.hi >>> 0) << 32n) | BigInt(x.bits.lo >>> 0);
    return vt.startsWith("i") ? BigInt.asIntN(64, u) : u;
  };
  return read(lo) <= read(hi);
};

/** KernelSpec of a numeric compare (first scan: eq/approx/range/gt/lt; next: the whole S4 §9.3 op list). */
const numericSpec = (
  vt: NumericScanType,
  op: KernelOp,
  inputs: NumericInputs,
  align: number,
  prefix: string,
): AgentResult<KernelSpec> => {
  const path = (field: string): string => (prefix === "" ? field : `${prefix}.${field}`);
  const base = { vt: VT_CODE[vt], elem: NUMERIC_ELEM[vt], align, operand: null };
  const eps = inputs.eps ?? 0;
  if (!Number.isFinite(eps) || eps < 0) return badParams(path("eps"), "eps must be a finite number ≥ 0");
  switch (op) {
    case "eq":
    case "ne":
    case "gt":
    case "lt":
    case "approx":
    case "increased_by":
    case "decreased_by": {
      const a = operand(vt, inputs.value, path("value"));
      if (!a.ok) return a;
      if (op === "approx" && inputs.eps === undefined) return badParams(path("eps"), "approx needs eps");
      // a float given as raw bits compares bit for bit (S4 §9.2 "Value encoding")
      if (op === "eq" && isFloatType(vt) && a.value.exactBits)
        return ok({ ...base, op: "eq_bits", a: a.value.bits, b: ZERO_BITS, eps, operand: a.value.bytes });
      return ok({ ...base, op, a: a.value.bits, b: ZERO_BITS, eps });
    }
    case "range": {
      const lo = operand(vt, inputs.min, path("min"));
      if (!lo.ok) return lo;
      const hi = operand(vt, inputs.max, path("max"));
      if (!hi.ok) return hi;
      if (!operandOrder(vt, lo.value, hi.value)) return badParams(path("min"), "min must not be greater than max");
      return ok({ ...base, op, a: lo.value.bits, b: hi.value.bits, eps });
    }
    case "changed":
    case "unchanged":
    case "increased":
    case "decreased":
    case "same_as_first":
      return ok({ ...base, op, a: ZERO_BITS, b: ZERO_BITS, eps });
    case "eq_bits":
      return badParams(path("op"), "unknown op");
  }
};

// ---------------------------------------------------------------------------------------------- jobs

abstract class SlicedWork implements ScanJobWork {
  abstract readonly kind: "scan-first" | "scan-next";
  protected readonly engine: ScanEngine;
  protected readonly s: ScanState;
  protected cancelled = false;
  protected finished: "done" | "failed" | "cancelled" | null = null;

  constructor(engine: ScanEngine, s: ScanState) {
    this.engine = engine;
    this.s = s;
  }
  get scanId(): string {
    return this.s.id;
  }
  cancel(): void {
    this.cancelled = true;
  }
  step(budgetMs: number): "more" | "done" {
    if (this.finished !== null) return "done";
    const clock = this.engine.platform;
    const t0 = clock.nowMs();
    do {
      if (this.s.state === "closed") {
        this.finished = "cancelled";
        return "done";
      }
      if (this.cancelled) {
        this.onCancel();
        this.finished = "cancelled";
        return "done";
      }
      if (this.slice()) {
        this.finished = this.s.state === "failed" ? "failed" : "done";
        return "done";
      }
    } while (clock.nowMs() - t0 < budgetMs);
    return "more";
  }
  outcome() {
    const state = this.finished ?? "failed";
    return { state, result: this.engine.statusOf(this.s), error: this.s.error };
  }
  abstract progress(): Progress;
  /** one bounded unit of work; true when the job finished (state set through engine.finish) */
  protected abstract slice(): boolean;
  protected abstract onCancel(): void;
}

class FirstScan extends SlicedWork {
  readonly kind = "scan-first" as const;
  readonly #plan: FirstPlan;
  readonly #op: string;
  readonly #total: number;
  #ri = 0;
  #off = 0;
  #done = 0;

  constructor(engine: ScanEngine, s: ScanState, plan: FirstPlan, op: string) {
    super(engine, s);
    this.#plan = plan;
    this.#op = op;
    this.#total = s.regions.reduce((sum, r) => sum + r.size, 0);
  }

  progress(): Progress {
    return { done: this.#done, total: this.#total, unit: "bytes" };
  }

  protected onCancel(): void {
    if (this.s.mode === "snapshot") this.#dropSnapshot();
    this.engine.finish(this.s, this.#op, {
      _tag: "Cancelled",
      message: "the scan job was cancelled",
      phase: "scan-first",
    });
  }

  protected slice(): boolean {
    const r = this.s.regions[this.#ri];
    if (r === undefined) return this.#complete();
    const outcome =
      this.#plan.kind === "kernel"
        ? this.#kernelChunk(r, this.#plan.spec)
        : this.#plan.kind === "pattern"
          ? this.#patternChunk(r, this.#plan.pattern, this.#plan.exact)
          : this.#plan.kind === "pointers"
            ? this.#pointerChunk(r, this.#plan.targets)
            : this.#snapshotChunk(r);
    if (outcome === "stop") {
      this.engine.finish(this.s, this.#op, this.s.error);
      return true;
    }
    if (outcome === "skip-region") {
      this.s.unreadable += 1;
      this.#done += r.size - this.#off;
      this.#nextRegion();
    } else if (this.#off >= r.size) this.#nextRegion();
    return false;
  }

  #nextRegion(): void {
    this.#ri += 1;
    this.#off = 0;
  }

  #advance(n: number): void {
    this.#off += n;
    this.#done += n;
    this.s.bytesScanned += n;
  }

  #complete(): boolean {
    const s = this.s;
    if (s.mode === "snapshot") {
      s.count = 0;
      for (const snap of s.snaps ?? [])
        if (snap.readable && snap.buf !== null) s.count += elementsIn(snap.region.size, s.elem, s.align);
    } else this.engine.captureFirsts(s);
    this.engine.finish(s, this.#op, null);
    return true;
  }

  /** room for one more candidate; false = the scan stops (cap or memory; s.error set) */
  #room(): boolean {
    const c = this.s.cands;
    return (c !== null && this.s.count < c.cap) || this.engine.grow(this.s, this.s.count);
  }

  #kernelChunk(r: Region, spec: KernelSpec): "ok" | "skip-region" | "stop" {
    const s = this.s;
    const p = this.engine.platform;
    if (!this.#room()) return "stop";
    const cands = s.cands as Candidates;
    const va = r.base + this.#off;
    const remain = r.size - this.#off;
    const len = Math.min(CHUNK_BYTES, remain);
    const res = p.suspendGuards({ base: va, size: Math.min(remain, len + s.elem - 1) }, () =>
      p.kernels.cmp(spec, { va, len, avail: remain, progress: 0, out: cands, at: s.count }),
    );
    s.count = res.at;
    if (res.fault) {
      s.bytesScanned += res.progress;
      return "skip-region";
    }
    const finished = res.progress >= len || res.progress + s.elem > remain;
    this.#advance(finished ? len : res.progress);
    return "ok";
  }

  #patternChunk(r: Region, pattern: string, exact: Uint8Array | null): "ok" | "skip-region" | "stop" {
    const s = this.s;
    const p = this.engine.platform;
    const va = r.base + this.#off;
    const remain = r.size - this.#off;
    const len = Math.min(s.elem <= 4 ? SHORT_PATTERN_CHUNK_BYTES : PATTERN_CHUNK_BYTES, remain);
    const span = Math.min(remain, len + s.elem - 1);
    let stop = false;
    const outcome = p.suspendGuards({ base: va, size: span }, (): "ok" | "skip-region" | "bad-pattern" => {
      let hits: readonly number[];
      try {
        hits = p.scanPattern(va, span, pattern);
      } catch (e) {
        return /invalid match pattern/iu.test(String(e)) ? "bad-pattern" : "skip-region";
      }
      for (const h of hits) {
        if (h >= va + len || h % s.align !== 0) continue;
        const val = exact ?? p.read(h, s.elem);
        if (val === null) continue;
        if (!this.#room()) {
          stop = true;
          break;
        }
        const c = s.cands as Candidates;
        setAddrAt(c.addrs, s.count, h);
        c.vals.u8.set(val.subarray(0, s.elem), s.count * s.elem);
        s.count += 1;
      }
      return "ok";
    });
    if (outcome === "bad-pattern") {
      s.error = {
        _tag: "BadParams",
        message: "invalid match pattern",
        issues: [{ path: "pattern", problem: "invalid match pattern" }],
      };
      return "stop";
    }
    if (outcome === "skip-region") return "skip-region";
    this.#advance(len);
    return stop ? "stop" : "ok";
  }

  #pointerChunk(r: Region, targets: readonly number[]): "ok" | "skip-region" | "stop" {
    const s = this.s;
    const p = this.engine.platform;
    const va = r.base + this.#off;
    const len = Math.min(POINTER_CHUNK_BYTES, r.size - this.#off);
    let stop = false;
    const outcome = p.suspendGuards({ base: va, size: len }, (): "ok" | "skip-region" => {
      let matches: readonly { address: number; value: number }[];
      try {
        matches = p.findPointers(va, len, targets);
      } catch {
        return "skip-region";
      }
      const value = new Uint8Array(8);
      const view = new DataView(value.buffer);
      for (const m of matches) {
        if (m.address % s.align !== 0) continue;
        if (!this.#room()) {
          stop = true;
          break;
        }
        view.setUint32(0, m.value % 4_294_967_296, true);
        view.setUint32(4, Math.floor(m.value / 4_294_967_296), true);
        const c = s.cands as Candidates;
        setAddrAt(c.addrs, s.count, m.address);
        c.vals.u8.set(value, s.count * 8);
        s.count += 1;
      }
      return "ok";
    });
    if (outcome === "skip-region") return "skip-region";
    this.#advance(len);
    return stop ? "stop" : "ok";
  }

  #snapshotChunk(r: Region): "ok" | "skip-region" | "stop" {
    const s = this.s;
    const p = this.engine.platform;
    const snap = (s.snaps ?? [])[this.#ri];
    if (snap === undefined) return "skip-region";
    if (snap.buf === null) {
      snap.buf = p.alloc(r.size);
      if (snap.buf === null) {
        s.error = {
          _tag: "ResourceLimit",
          message: "agent memory allocation failed",
          resource: "agent_memory",
          limit: r.size,
        };
        this.#dropSnapshot();
        return "stop";
      }
    }
    const buf = snap.buf;
    const va = r.base + this.#off;
    const len = Math.min(CHUNK_BYTES, r.size - this.#off);
    const copied = p.suspendGuards({ base: va, size: len }, () => p.copyIn(buf, this.#off, va, len));
    if (!copied) {
      p.free(buf);
      snap.buf = null;
      snap.readable = false;
      return "skip-region";
    }
    this.#advance(len);
    return "ok";
  }

  #dropSnapshot(): void {
    for (const snap of this.s.snaps ?? []) {
      if (snap.buf !== null) this.engine.platform.free(snap.buf);
      snap.buf = null;
      snap.readable = false;
    }
    this.s.count = 0;
  }
}

class ExplicitNext extends SlicedWork {
  readonly kind = "scan-next" as const;
  readonly #spec: KernelSpec;
  readonly #total: number;
  #i = 0;
  #kept = 0;

  constructor(engine: ScanEngine, s: ScanState, spec: KernelSpec) {
    super(engine, s);
    this.#spec = spec;
    this.#total = s.count;
  }

  progress(): Progress {
    return { done: this.#i, total: this.#total, unit: "items" };
  }

  protected onCancel(): void {
    // keep the unexamined candidates behind the kept ones: the result is a superset, never a loss
    const c = this.s.cands;
    if (c !== null && this.#i < this.#total) {
      const elem = this.s.elem;
      c.addrs.u8.copyWithin(this.#kept * 8, this.#i * 8, this.#total * 8);
      c.vals.u8.copyWithin(this.#kept * elem, this.#i * elem, this.#total * elem);
      if (c.firsts !== null) c.firsts.u8.copyWithin(this.#kept * elem, this.#i * elem, this.#total * elem);
    }
    this.s.count = this.#kept + (this.#total - this.#i);
    this.engine.finish(this.s, this.#spec.op, {
      _tag: "Cancelled",
      message: "the scan job was cancelled",
      phase: "scan-next",
    });
  }

  protected slice(): boolean {
    const s = this.s;
    const c = s.cands;
    if (c === null || this.#i >= this.#total) {
      s.count = this.#kept;
      this.engine.shrink(s);
      this.engine.finish(s, this.#spec.op, null);
      return true;
    }
    const p = this.engine.platform;
    const end = Math.min(this.#total, this.#i + NEXT_CHUNK);
    const lo = addrAt(c.addrs, this.#i);
    const hi = addrAt(c.addrs, end - 1) + s.elem;
    const res = p.suspendGuards({ base: lo, size: hi - lo }, () =>
      p.kernels.next(this.#spec, { store: c, progress: this.#i, end, kept: this.#kept }),
    );
    this.#kept = res.at;
    if (!res.fault) {
      this.#i = end;
      return false;
    }
    // a page freed since the last scan: drop every candidate on that 4 KiB page and resume after it (S4 §9.3)
    const page = Math.floor(addrAt(c.addrs, res.progress) / PAGE_BYTES);
    let j = res.progress;
    while (j < this.#total && Math.floor(addrAt(c.addrs, j) / PAGE_BYTES) === page) j += 1;
    s.faultedDropped += j - res.progress;
    this.#i = j;
    return false;
  }
}

class SnapshotNext extends SlicedWork {
  readonly kind = "scan-next" as const;
  readonly #spec: KernelSpec;
  readonly #total: number;
  #ri = 0;
  #off = 0;
  #done = 0;
  #out: Candidates | null = null;
  #at = 0;

  constructor(engine: ScanEngine, s: ScanState, spec: KernelSpec) {
    super(engine, s);
    this.#spec = spec;
    this.#total = (s.snaps ?? []).reduce((sum, x) => sum + (x.readable ? x.region.size : 0), 0);
  }

  progress(): Progress {
    return { done: this.#done, total: this.#total, unit: "bytes" };
  }

  protected onCancel(): void {
    this.engine.freeCandidates(this.#out);
    this.#out = null;
    this.engine.finish(this.s, this.#spec.op, {
      _tag: "Cancelled",
      message: "the scan job was cancelled",
      phase: "scan-next",
    });
  }

  #room(): boolean {
    const s = this.s;
    if (this.#out !== null && this.#at < this.#out.cap) return true;
    // grow the output through the engine's growth rule by borrowing s.cands for the copy
    const saved = s.cands;
    s.cands = this.#out;
    const grown = this.engine.grow(s, this.#at);
    this.#out = s.cands;
    s.cands = saved;
    return grown;
  }

  #convert(): void {
    const s = this.s;
    for (const snap of s.snaps ?? []) if (snap.buf !== null) this.engine.platform.free(snap.buf);
    s.snaps = null;
    s.mode = "explicit";
    s.cands = this.#out;
    s.count = this.#at;
    this.#out = null;
  }

  protected slice(): boolean {
    const s = this.s;
    const p = this.engine.platform;
    if (this.#out === null) {
      this.#out = this.engine.allocCandidates(s, Math.min(s.cap, INITIAL_CAPACITY), true);
      if (this.#out === null) {
        this.engine.finish(s, this.#spec.op, {
          _tag: "ResourceLimit",
          message: "agent memory allocation failed",
          resource: "agent_memory",
          limit: INITIAL_CAPACITY * (8 + 2 * s.elem),
        });
        return true;
      }
    }
    const snaps = s.snaps ?? [];
    let snap = snaps[this.#ri];
    while (snap !== undefined && (!snap.readable || snap.buf === null)) {
      this.#ri += 1;
      snap = snaps[this.#ri];
    }
    if (snap === undefined || snap.buf === null) {
      this.#convert();
      this.engine.shrink(s);
      this.engine.finish(s, this.#spec.op, null);
      return true;
    }
    if (!this.#room()) {
      // over the cap: keep what fits as explicit candidates (state failed + ResourceLimit, like a first scan)
      const error = s.error;
      this.#convert();
      this.engine.finish(s, this.#spec.op, error);
      return true;
    }
    const out = this.#out as Candidates;
    const r = snap.region;
    const buf = snap.buf;
    const va = r.base + this.#off;
    const remain = r.size - this.#off;
    const len = Math.min(CHUNK_BYTES, remain);
    const res = p.suspendGuards({ base: va, size: Math.min(remain, len + s.elem - 1) }, () =>
      p.kernels.snap(this.#spec, {
        va,
        snap: buf,
        snapOff: this.#off,
        len,
        avail: remain,
        progress: 0,
        out,
        at: this.#at,
      }),
    );
    this.#at = res.at;
    if (res.fault) {
      s.unreadable += 1;
      s.faultedDropped += elementsIn(remain, s.elem, s.align);
      this.#done += remain;
      this.#ri += 1;
      this.#off = 0;
      return false;
    }
    const finished = res.progress >= len || res.progress + s.elem > remain;
    const step = finished ? len : res.progress;
    this.#off += step;
    this.#done += step;
    s.bytesScanned += step;
    if (this.#off >= r.size) {
      this.#ri += 1;
      this.#off = 0;
    }
    return false;
  }
}
