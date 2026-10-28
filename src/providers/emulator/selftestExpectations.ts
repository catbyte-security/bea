/**
 * Expected `--selftest` facts per exact unicorn version (S5 §3.16). The bridge's self-test pins the engine gotchas
 * BEA's design depends on (FP reset, VEX mis-execution, TB-cache hook gotcha, COW snapshot ordering, INT3 RIP …).
 * `true` means "behaves the way the design assumes" (the check's `ok`), `false` is an EXPECTED negative observation
 * (`mxcsr_flags_modeled`: Unicorn does not set MXCSR status flags, S5-D9). A mismatch on a pinned engine is a
 * doctor warning; on an unvalidated (`compatible`) engine every emulation result carries EMU_ENGINE_UNVALIDATED.
 */
export const SELFTEST_EXPECTATIONS: Readonly<Record<string, Readonly<Record<string, boolean>>>> = {
  "2.1.4": {
    fp_reset: true,
    vex128_misexecutes: true,
    vex256_rejected: true,
    bmi_ok: true,
    tb_hook_gotcha: true,
    count_budget_gotcha: true,
    cow_lifo_ok: true,
    context_mode_toggle: true,
    int3_rip: true,
    mxcsr_flags_modeled: false,
    x87_reset: true,
    insn_hooks: true,
    gs_base: true,
    memory_limit: true,
  },
};

/** Items whose expectation is believed rather than verified on 2.1.4 (S5 §17.1 A1, A2): a mismatch only warns. */
const BELIEVED_SELFTEST_ITEMS: ReadonlySet<string> = new Set(["x87_reset", "insn_hooks"]);

export interface SelftestReport {
  readonly selftest?: unknown;
  readonly engines?: unknown;
  readonly results?: unknown;
}

export interface SelftestComparison {
  readonly passed: boolean;
  /** item names whose observation differs from the expectation (or that the bridge did not report) */
  readonly mismatches: readonly string[];
  /** believed items that differ (warnings only) */
  readonly warnings: readonly string[];
  readonly validatedAgainst: string | null;
}

const observedTruth = (entry: unknown): boolean | null => {
  if (typeof entry !== "object" || entry === null) return null;
  const record = entry as Record<string, unknown>;
  if (typeof record["observed"] === "boolean" && typeof record["expected"] === "boolean")
    return record["observed"] === record["expected"] ? true : false;
  return typeof record["ok"] === "boolean" ? record["ok"] : null;
};

/**
 * Compare a `--selftest` line with the expectations of `unicornVersion` (falls back to the newest known table for an
 * unvalidated engine). An item counts as matching when the bridge reports `ok` (its own observed == expected) and, for
 * the expected-negative items, when the boolean observation equals the expectation.
 */
export const compareSelftest = (report: SelftestReport, unicornVersion: string): SelftestComparison => {
  const known = Object.keys(SELFTEST_EXPECTATIONS).sort();
  const version = SELFTEST_EXPECTATIONS[unicornVersion] !== undefined ? unicornVersion : (known.at(-1) ?? null);
  const expectations = version === null ? {} : (SELFTEST_EXPECTATIONS[version] ?? {});
  const results =
    typeof report.results === "object" && report.results !== null ? (report.results as Record<string, unknown>) : {};
  const mismatches: string[] = [];
  const warnings: string[] = [];
  for (const [name, expected] of Object.entries(expectations)) {
    const entry = results[name];
    let matches: boolean;
    if (
      entry !== null &&
      typeof entry === "object" &&
      typeof (entry as Record<string, unknown>)["observed"] === "boolean" &&
      !expected
    )
      matches = (entry as Record<string, unknown>)["observed"] === false;
    else matches = observedTruth(entry) === true;
    if (matches) continue;
    if (BELIEVED_SELFTEST_ITEMS.has(name)) warnings.push(name);
    else mismatches.push(name);
  }
  return { passed: mismatches.length === 0, mismatches, warnings, validatedAgainst: version };
};
