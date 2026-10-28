import type { Loc } from "../../domain/address/addressRef.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { EvId } from "../../domain/ids.js";
import type { ExitInfo } from "../../domain/process/instance.js";
import type { DerivedCrash } from "../../ports/sessions.js";
import type { CrashReport } from "../../shared/agentProtocol.js";

/**
 * Derived crash conclusion (D-INT-27, CI-I9; S6 §5.5). Inputs: the root exit (jobhost or watcher), the agent's crash
 * reports with their arrival times, and the first-chance exception count. Rules:
 *  - an error-severity NTSTATUS exit (kind "ntstatus") is a crash; it joins the LAST last-chance report received at
 *    most `windowMs` before the exit, else the last first-chance report of the type the exit status implies (review
 *    fix AGENT-11: a fast fail never joins a first-chance report, because no handler ran for it, and a code-less
 *    first-chance "system" report, e.g. a handled C++ throw, is never joined); without one, pc is null and
 *    CRASH_PC_UNKNOWN is added (fast fail, stack overflow: no user-mode handler ran — BELIEVED for some stack
 *    overflows);
 *  - any other exit with a last-chance (unhandled-exception filter) report in the window is also a crash;
 *  - a BEA kill, a normal exit without a last-chance report, or no exit yet: no crash;
 *  - a last-chance report whose type does not match the exit status adds CRASH_EXIT_MISMATCH.
 * An exception inside a BEA oracle call is an `in-call` row, never a crash report, so it never appears here.
 */
interface ReceivedReport {
  readonly report: CrashReport;
  readonly receivedAt: number;
}

export interface CrashInputs {
  readonly exit: ExitInfo | null;
  readonly exitAt: number | null;
  readonly reports: readonly ReceivedReport[];
  readonly windowMs: number;
  /** first-chance exception rows recorded on s:exceptions */
  readonly exceptionRows: number;
}

export type CrashVerdict =
  | { readonly kind: "none" }
  | {
      readonly kind: "crash";
      readonly report: CrashReport | null;
      readonly type: string;
      readonly ntstatus: string | null;
      readonly firstChanceCount: number;
      readonly limitations: readonly string[];
    };

const ARITHMETIC_CODES: ReadonlySet<number> = new Set([
  0xc000_0094, 0xc000_0095, 0xc000_008e, 0xc000_008f, 0xc000_0090, 0xc000_0091, 0xc000_0092, 0xc000_0093,
]);

/** The crash type an NTSTATUS exit implies when no report says otherwise. */
export const typeForExitCode = (code: number | null): string => {
  if (code === null) return "system";
  if (code === 0xc000_0005) return "access-violation";
  if (code === 0xc000_001d) return "illegal-instruction";
  if (code === 0xc000_00fd) return "stack-overflow";
  if (code === 0xc000_0409 || code === 0xc000_0602) return "fast-fail";
  if (ARITHMETIC_CODES.has(code)) return "arithmetic";
  return "system";
};

const consistent = (code: number | null, type: string): boolean => {
  const implied = typeForExitCode(code);
  if (implied === "system" || code === null) return true;
  if (implied === "fast-fail") return type === "abort" || type === "system";
  return implied === type;
};

const isFastFail = (code: number | null): boolean => code === 0xc000_0409 || code === 0xc000_0602;

/**
 * The report an error-status exit joins: the last last-chance report, else the last first-chance report whose type
 * the exit status implies. A fast fail ran no handler, so an earlier first-chance report is a different exception;
 * a first-chance "system" report has no code and is normally a handled software exception (AGENT-11).
 */
const reportForErrorExit = (
  code: number | null,
  inWindow: readonly ReceivedReport[],
  lastChance: ReceivedReport | null,
): ReceivedReport | null => {
  if (lastChance !== null) return lastChance;
  const implied = typeForExitCode(code);
  if (isFastFail(code) || implied === "system") return null;
  return [...inWindow].reverse().find((r) => r.report.phase === "first-chance" && r.report.type === implied) ?? null;
};

export const deriveCrashVerdict = (input: CrashInputs): CrashVerdict => {
  const { exit, exitAt } = input;
  if (exit === null || exitAt === null || exit.kind === "bea-kill") return { kind: "none" };
  const inWindow = input.reports.filter((r) => r.receivedAt <= exitAt + 50 && exitAt - r.receivedAt <= input.windowMs);
  const lastChance = [...inWindow].reverse().find((r) => r.report.phase === "last-chance") ?? null;
  const isError = exit.kind === "ntstatus";
  if (!isError && lastChance === null) return { kind: "none" };
  const chosen = isError ? reportForErrorExit(exit.code, inWindow, lastChance) : lastChance;
  const limitations: string[] = [];
  if (chosen === null) limitations.push(LIMITATIONS.CRASH_PC_UNKNOWN);
  else if (isError && !consistent(exit.code, chosen.report.type)) limitations.push(LIMITATIONS.CRASH_EXIT_MISMATCH);
  return {
    kind: "crash",
    report: chosen?.report ?? null,
    type: chosen?.report.type ?? typeForExitCode(exit.code),
    ntstatus: exit.name ?? exit.code_hex ?? chosen?.report.code ?? null,
    firstChanceCount: Math.max(0, input.exceptionRows - (chosen === null ? 0 : 1)),
    limitations,
  };
};

const GPRS = [
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

const SAFE_MODULE = /^[A-Za-z0-9_.-]{1,255}$/u;

/** Loc without the address service: `at` is module+0xrva when the agent attributed the frame to a module. */
export const fallbackLoc = (frame: {
  readonly va: string;
  readonly module: string | null;
  readonly rva: string | null;
}): Loc => ({
  va: frame.va as Loc["va"],
  at:
    frame.module !== null && frame.rva !== null && SAFE_MODULE.test(frame.module)
      ? `${frame.module}+${frame.rva}`
      : null,
  static: null,
  func: null,
  sym: null,
});

/**
 * The tool shape (crashReportSchema). `describe` turns an agent frame into a Loc (AddressService.describeCode when
 * available, else fallbackLoc). xmm registers only with `includeXmm` and only when the report captured them.
 */
export const buildDerivedCrash = async (
  verdict: Extract<CrashVerdict, { kind: "crash" }>,
  describe: (frame: {
    readonly va: string;
    readonly module: string | null;
    readonly rva: string | null;
  }) => Promise<Loc>,
  evidenceId: EvId | null,
  includeXmm: boolean,
): Promise<DerivedCrash> => {
  const report = verdict.report;
  if (report === null)
    return {
      type: verdict.type,
      ntstatus: verdict.ntstatus,
      thread_id: null,
      pc: null,
      insn: null,
      memory: null,
      registers: {},
      backtrace: [],
      first_chance_count: verdict.firstChanceCount,
      evidence_id: evidenceId,
    };
  const registers: Record<string, string> = {};
  for (const name of GPRS) {
    const value = report.registers[name];
    if (value !== undefined) registers[name] = value;
  }
  if (includeXmm && report.xmm !== null)
    report.xmm.slice(0, 16).forEach((bits, i) => (registers[`xmm${String(i)}`] = bits));
  const frames = report.backtrace.slice(0, 64);
  const pcFrame = frames[0] ?? { va: report.address, module: null, rva: null };
  const pc = await describe(pcFrame.va === report.address ? pcFrame : { va: report.address, module: null, rva: null });
  const backtrace = await Promise.all(frames.map((frame) => describe(frame)));
  return {
    type: report.type,
    ntstatus: verdict.ntstatus,
    thread_id: report.tid,
    pc,
    insn: report.instruction?.text.slice(0, 200) ?? null,
    memory: report.memory === null ? null : { op: report.memory.operation, address: report.memory.address },
    registers,
    backtrace,
    first_chance_count: verdict.firstChanceCount,
    evidence_id: evidenceId,
  };
};
