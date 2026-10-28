// Agent pure helpers of WP12-MODIFY: override planning (S4 §14) and the per-call application gate.
import type { AgentLimits, OverrideInstallParams, ThreadId } from "../../shared/agentProtocol.js";
import type { ParamProblem } from "./modifyWrites.js";
import { isFloat, isScalarType, scalarBits, SCALAR_WIDTH, type ScalarValueType } from "./modifyValues.js";

/**
 * Where one rewritten argument lives on Win64 at function entry (S4 §14, VERIFIED [ext-frida §3.6]):
 * integer slot → `args[slot]` (Frida maps slot ≥ 4 to the stack); float slot < 4 → `xmm<slot>` low lane, upper lanes
 * kept; float slot ≥ 4 → the stack slot at `rsp + 8 + 8*slot` (return address + shadow space; A-39).
 */
export type ArgLocation = "int" | "xmm" | "stack";
export interface ArgPatch {
  readonly slot: number;
  readonly location: ArgLocation;
  readonly type: ScalarValueType;
  readonly width: 1 | 2 | 4 | 8;
  readonly bits: bigint;
}
export interface RetPatch {
  readonly type: ScalarValueType;
  readonly float: boolean;
  readonly width: 1 | 2 | 4 | 8;
  readonly bits: bigint;
}
export interface ReplacePlan {
  readonly retType: ScalarValueType | "void";
  readonly bits: bigint | null;
}
export interface OverridePlan {
  readonly mode: "rewrite" | "replace";
  readonly args: readonly ArgPatch[];
  readonly ret: RetPatch | null;
  readonly replace: ReplacePlan | null;
  readonly threadIds: ReadonlySet<ThreadId> | null;
  readonly everyN: number;
  readonly durationMs: number;
  readonly maxHits: number;
  readonly clock: "install" | "resume";
  readonly record: boolean;
  readonly relocation: "auto" | "forced";
  readonly label: string | null;
}

/** Agent defaults when a lifetime field is 0 (S4 §5.7): 30 s, 10,000 hits. */
const DEFAULT_DURATION_MS = 30_000;
const DEFAULT_MAX_HITS = 10_000;

export const stackArgOffset = (slot: number): number => 8 + 8 * slot;

type Rewrite = NonNullable<OverrideInstallParams["rewrite"]>;

const planArg = (a: NonNullable<Rewrite["args"]>[number], path: string, issues: ParamProblem[]): ArgPatch | null => {
  if (!Number.isInteger(a.slot) || a.slot < 0 || a.slot > 15) issues.push({ path, problem: "slot must be 0..15" });
  if (!isScalarType(a.type)) {
    issues.push({ path, problem: `type ${a.type} is not a scalar` });
    return null;
  }
  if ((a.class === "float") !== isFloat(a.type)) issues.push({ path, problem: "class must match the type" });
  const bits = scalarBits(a.type, a.value);
  if (!bits.ok) {
    issues.push({ path, problem: bits.problem });
    return null;
  }
  const location: ArgLocation = !isFloat(a.type) ? "int" : a.slot < 4 ? "xmm" : "stack";
  return { slot: a.slot, location, type: a.type, width: SCALAR_WIDTH[a.type], bits: bits.bits };
};

const planRewrite = (
  p: OverrideInstallParams,
  issues: ParamProblem[],
): { readonly args: ArgPatch[]; readonly ret: RetPatch | null } => {
  const rw = p.rewrite;
  const hasArgs = rw?.args !== undefined && rw.args.length > 0;
  if (hasArgs === (rw?.ret !== undefined))
    issues.push({ path: "rewrite", problem: "give exactly one of rewrite.args or rewrite.ret" });
  if (p.replace !== undefined) issues.push({ path: "replace", problem: "replace is only valid with mode replace" });
  const args: ArgPatch[] = [];
  const seen = new Set<number>();
  for (const [i, a] of (rw?.args ?? []).entries()) {
    const path = `rewrite.args[${String(i)}]`;
    if (seen.has(a.slot)) issues.push({ path, problem: "duplicate slot" });
    seen.add(a.slot);
    const patch = planArg(a, path, issues);
    if (patch !== null) args.push(patch);
  }
  const r = rw?.ret;
  if (r === undefined) return { args, ret: null };
  if (!isScalarType(r.type)) {
    issues.push({ path: "rewrite.ret.type", problem: `type ${r.type} is not a scalar` });
    return { args, ret: null };
  }
  const bits = scalarBits(r.type, r.value);
  if (!bits.ok) {
    issues.push({ path: "rewrite.ret.value", problem: bits.problem });
    return { args, ret: null };
  }
  return { args, ret: { type: r.type, float: isFloat(r.type), width: SCALAR_WIDTH[r.type], bits: bits.bits } };
};

const planReplace = (p: OverrideInstallParams, issues: ParamProblem[]): ReplacePlan | null => {
  if (p.rewrite !== undefined) issues.push({ path: "rewrite", problem: "rewrite is only valid with mode rewrite" });
  // `when` filters apply as in rewrite mode: a filtered call runs the original through the replace stub's trampoline.
  const rp = p.replace;
  if (rp === undefined) {
    issues.push({ path: "replace", problem: "mode replace needs replace" });
    return null;
  }
  if (rp.ret_type === "void") {
    if (rp.returns !== null) issues.push({ path: "replace.returns", problem: "a void replacement returns null" });
    return { retType: "void", bits: null };
  }
  if (!isScalarType(rp.ret_type)) {
    issues.push({ path: "replace.ret_type", problem: `type ${rp.ret_type} is not a scalar` });
    return null;
  }
  if (rp.returns === null) {
    issues.push({ path: "replace.returns", problem: "a non-void replacement needs returns" });
    return null;
  }
  const bits = scalarBits(rp.ret_type, rp.returns);
  if (!bits.ok) {
    issues.push({ path: "replace.returns", problem: bits.problem });
    return null;
  }
  return { retType: rp.ret_type, bits: bits.bits };
};

export const planOverride = (
  p: OverrideInstallParams,
  limits: Pick<AgentLimits, "max_duration_ms" | "max_hits_cap">,
): { readonly ok: true; readonly plan: OverridePlan } | { readonly ok: false; readonly issues: ParamProblem[] } => {
  const issues: ParamProblem[] = [];
  let args: ArgPatch[] = [];
  let ret: RetPatch | null = null;
  let replace: ReplacePlan | null = null;
  if (p.mode === "rewrite") ({ args, ret } = planRewrite(p, issues));
  else if (p.mode === "replace") replace = planReplace(p, issues);
  else issues.push({ path: "mode", problem: "must be rewrite or replace" });

  const everyN = p.when?.every_n ?? 1;
  if (!Number.isInteger(everyN) || everyN < 1) issues.push({ path: "when.every_n", problem: "must be an integer ≥ 1" });
  const tids = p.when?.thread_ids;
  if (tids !== undefined && !tids.every((t) => Number.isInteger(t) && t >= 0))
    issues.push({ path: "when.thread_ids", problem: "must be thread ids" });
  const lifetime = p.lifetime;
  if (!Number.isInteger(lifetime.duration_ms) || lifetime.duration_ms < 0)
    issues.push({ path: "lifetime.duration_ms", problem: "must be an integer ≥ 0" });
  if (!Number.isInteger(lifetime.max_hits) || lifetime.max_hits < 0)
    issues.push({ path: "lifetime.max_hits", problem: "must be an integer ≥ 0" });
  if (p.relocation !== "auto" && p.relocation !== "forced")
    issues.push({ path: "relocation", problem: "must be auto or forced" });
  if (issues.length > 0) return { ok: false, issues };
  return {
    ok: true,
    plan: {
      mode: p.mode,
      args,
      ret,
      replace,
      threadIds: tids === undefined ? null : new Set(tids),
      everyN,
      durationMs: Math.min(
        lifetime.duration_ms === 0 ? DEFAULT_DURATION_MS : lifetime.duration_ms,
        limits.max_duration_ms,
      ),
      maxHits: Math.min(lifetime.max_hits === 0 ? DEFAULT_MAX_HITS : lifetime.max_hits, limits.max_hits_cap),
      clock: lifetime.clock ?? "install",
      record: p.record,
      relocation: p.relocation,
      label: p.label ?? null,
    },
  };
};

/**
 * Per-call decision of one override (S4 §14): `when.thread_ids` and `when.every_n` filter matching calls (every_n
 * applies to calls 1, 1+n, 1+2n, … of the matching ones); `max_hits` counts APPLICATIONS. "exhausted" is returned
 * for the call that reaches the cap AFTER it is applied, so the caller schedules stop("max_hits") exactly once.
 */
export class ApplicationGate {
  private matching = 0;
  private applied = 0;
  private stopped = false;
  constructor(
    private readonly threadIds: ReadonlySet<ThreadId> | null,
    private readonly everyN: number,
    private readonly maxHits: number,
  ) {}

  /** call at the decision point; "apply" | "skip" | "inactive" (stopping/stopped/exhausted) */
  decide(tid: ThreadId): "apply" | "skip" | "inactive" {
    if (this.stopped || this.applied >= this.maxHits) return "inactive";
    if (this.threadIds !== null && !this.threadIds.has(tid)) return "skip";
    this.matching += 1;
    return (this.matching - 1) % this.everyN === 0 ? "apply" : "skip";
  }
  /** record one application; true when this one reached max_hits */
  applyOne(): boolean {
    this.applied += 1;
    return this.applied === this.maxHits;
  }
  stop(): void {
    this.stopped = true;
  }
  get active(): boolean {
    return !this.stopped;
  }
  get hits(): number {
    return this.applied;
  }
  get seen(): number {
    return this.matching;
  }
}
