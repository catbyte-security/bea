import { formatHex } from "../hex.js";
import type { ExitInfo, ExitKind } from "./instance.js";

/**
 * NTSTATUS names for process exit codes (S3 §14.3; WP-PROC). A crashed Windows process exits with the NTSTATUS of the
 * fault (e.g. 0xC0000005, VERIFIED); bea-jobhost reports the root's code in `root-exit`. Codes are u32.
 */

/** Exit code bea-jobhost gives every job member when BEA terminates the job (S3 §5.5). */
export const BEA_KILL_EXIT_CODE = 0xbea;
/** Name used for {@link BEA_KILL_EXIT_CODE} when `root-exit.byKill` is true. */
export const BEA_KILL_NAME = "BEA_JOB_TERMINATED";

const NAMES: ReadonlyMap<number, string> = new Map([
  [0xc000_0005, "STATUS_ACCESS_VIOLATION"],
  [0xc000_001d, "STATUS_ILLEGAL_INSTRUCTION"],
  [0xc000_0094, "STATUS_INTEGER_DIVIDE_BY_ZERO"],
  [0xc000_0095, "STATUS_INTEGER_OVERFLOW"],
  [0xc000_008e, "STATUS_FLOAT_DIVIDE_BY_ZERO"],
  [0xc000_008f, "STATUS_FLOAT_INEXACT_RESULT"],
  [0xc000_0090, "STATUS_FLOAT_INVALID_OPERATION"],
  [0xc000_0091, "STATUS_FLOAT_OVERFLOW"],
  [0xc000_0092, "STATUS_FLOAT_STACK_CHECK"],
  [0xc000_0093, "STATUS_FLOAT_UNDERFLOW"],
  [0xc000_00fd, "STATUS_STACK_OVERFLOW"],
  [0xc000_0409, "STATUS_STACK_BUFFER_OVERRUN"],
  [0xc000_0602, "STATUS_FAIL_FAST_EXCEPTION"],
  [0xc000_0374, "STATUS_HEAP_CORRUPTION"],
  [0xc000_0420, "STATUS_ASSERTION_FAILURE"],
  [0xc000_0017, "STATUS_NO_MEMORY"],
  [0xc000_0135, "STATUS_DLL_NOT_FOUND"],
  [0xc000_0142, "STATUS_DLL_INIT_FAILED"],
  [0xc000_013a, "STATUS_CONTROL_C_EXIT"],
  [0xe06d_7363, "MSVC_CPP_EXCEPTION"],
  [0x8000_0003, "STATUS_BREAKPOINT"],
  [0x8000_0004, "STATUS_SINGLE_STEP"],
]);

const isU32 = (code: number): boolean => Number.isInteger(code) && code >= 0 && code <= 0xffff_ffff;

/** The NTSTATUS (or MSVC exception) name of an exit code, or null when the code is not a known status. */
export const ntstatusName = (code: number): string | null => (isU32(code) ? (NAMES.get(code) ?? null) : null);

/** S3 §14.3: `bea-kill` when BEA killed the job; `ntstatus` for error-severity codes (≥ 0xC0000000); else `normal`. */
export const exitKindOf = (code: number | null, byKill: boolean): ExitKind => {
  if (byKill) return "bea-kill";
  if (code === null || !isU32(code)) return "unknown";
  return code >= 0xc000_0000 ? "ntstatus" : "normal";
};

/** The name shown for an exit: the BEA kill marker (only with byKill), else the NTSTATUS name, else null. */
export const exitNameOf = (code: number | null, byKill: boolean): string | null => {
  if (code === null) return null;
  if (byKill && code === BEA_KILL_EXIT_CODE) return BEA_KILL_NAME;
  return ntstatusName(code);
};

/** ExitInfo for a root exit code (null when unknown). `code_hex` is canonical lowercase hex. */
export const exitInfoOf = (code: number | null, byKill = false): ExitInfo => {
  const known = code !== null && isU32(code);
  return {
    code: known ? code : null,
    code_hex: known ? formatHex(code) : null,
    kind: exitKindOf(known ? code : null, byKill),
    name: exitNameOf(known ? code : null, byKill),
  };
};
