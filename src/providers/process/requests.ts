import type { BeaError, InputIssue } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AdoptRequest, SpawnRequest, WatchRequest } from "../../ports/jobhost.js";

/**
 * Request checks and argv construction for the helper modes (S3 §5.1). Ports are internal contracts, but a bad value
 * must fail as `invalid_request` here rather than as a helper `usage` error: bea-jobhost parses decimal u64 only,
 * requires a drive-absolute program and caps the command line at 32,767 UTF-16 units.
 */
const U32_MAX = 0xffff_ffff;
const U64_MAX = (1n << 64n) - 1n;
/** CreateProcessW's command-line limit, in UTF-16 code units including the terminator. */
export const COMMAND_LINE_MAX_CHARS = 32_767;

const DRIVE_ABSOLUTE = /^[A-Za-z]:[\\/]/u;

const isU32 = (n: number): boolean => Number.isInteger(n) && n >= 0 && n <= U32_MAX;
const isU64 = (n: bigint): boolean => n >= 0n && n <= U64_MAX;
const hasNul = (s: string): boolean => s.includes("\u0000");

class Issues {
  readonly list: InputIssue[] = [];
  range(path: string, okValue: boolean, message: string): void {
    if (!okValue) this.list.push({ path, reason: "out_of_range", message });
  }
  value(path: string, okValue: boolean, message: string): void {
    if (!okValue) this.list.push({ path, reason: "invalid_value", message });
  }
  result<T>(operation: string, value: T): Result<T, BeaError> {
    return this.list.length === 0 ? ok(value) : err(inputError(operation, this.list));
  }
}

const memLimitArgs = (issues: Issues, memLimitBytes: number | undefined): string[] => {
  if (memLimitBytes === undefined) return [];
  issues.range(
    "memLimitBytes",
    Number.isSafeInteger(memLimitBytes) && memLimitBytes > 0,
    "memLimitBytes must be a positive safe integer.",
  );
  return ["--mem-limit", String(memLimitBytes)];
};

const identityChecks = (
  issues: Issues,
  req: { readonly pid: number; readonly creationTime100ns: bigint; readonly tolerance100ns: bigint },
): void => {
  issues.range("pid", isU32(req.pid), "pid must be an integer in 0..4294967295.");
  issues.range(
    "creationTime100ns",
    isU64(req.creationTime100ns),
    "creationTime100ns must be an unsigned 64-bit value.",
  );
  issues.range("tolerance100ns", isU64(req.tolerance100ns), "tolerance100ns must be an unsigned 64-bit value.");
};

/** `adopt <pid> <ct> --tolerance-100ns N --expect-image P --expect-parent PID [--mem-limit B]` (no kill-on-root-exit). */
export const validateAdopt = (operation: string, req: AdoptRequest): Result<string[], BeaError> => {
  const issues = new Issues();
  identityChecks(issues, req);
  issues.value(
    "expectImage",
    DRIVE_ABSOLUTE.test(req.expectImage) && !hasNul(req.expectImage),
    "expectImage must be a drive-absolute path.",
  );
  issues.range("expectParentPid", isU32(req.expectParentPid), "expectParentPid must be an integer in 0..4294967295.");
  const mem = memLimitArgs(issues, req.memLimitBytes);
  return issues.result(operation, [
    String(req.pid),
    req.creationTime100ns.toString(),
    "--tolerance-100ns",
    req.tolerance100ns.toString(),
    "--expect-image",
    req.expectImage,
    "--expect-parent",
    String(req.expectParentPid),
    ...mem,
  ]);
};

/** `watch <pid> <ct> --tolerance-100ns N`. */
export const validateWatch = (operation: string, req: WatchRequest): Result<string[], BeaError> => {
  const issues = new Issues();
  identityChecks(issues, req);
  return issues.result(operation, [
    String(req.pid),
    req.creationTime100ns.toString(),
    "--tolerance-100ns",
    req.tolerance100ns.toString(),
  ]);
};

/** MSVCRT quoting as bea-jobhost.c appendArg does it, to bound the command line before the helper refuses it. */
export const quotedLength = (arg: string): number => {
  if (arg.length > 0 && !/[ \t\n\v"]/u.test(arg)) return arg.length;
  let n = 2;
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === "\\") {
      backslashes += 1;
      continue;
    }
    n += ch === '"' ? backslashes * 2 + 2 : backslashes + ch.length;
    backslashes = 0;
  }
  return n + backslashes * 2;
};

/** `spawn [--suspended] [--stdin-fd4] [--mem-limit B] [--kill-on-root-exit] -- exe args…`. */
export const validateSpawn = (operation: string, req: SpawnRequest): Result<string[], BeaError> => {
  const issues = new Issues();
  issues.value("exe", DRIVE_ABSOLUTE.test(req.exe) && !hasNul(req.exe), "exe must be a drive-absolute path.");
  issues.value("cwd", DRIVE_ABSOLUTE.test(req.cwd) && !hasNul(req.cwd), "cwd must be a drive-absolute path.");
  req.args.forEach((arg, i) => issues.value(`args[${String(i)}]`, !hasNul(arg), "Arguments must not contain NUL."));
  for (const [key, value] of Object.entries(req.env))
    issues.value(
      "env",
      key.length > 0 && !key.slice(1).includes("=") && !hasNul(key) && !hasNul(value),
      "Environment names must be non-empty without '=' and no entry may contain NUL.",
    );
  const commandLine = [req.exe, ...req.args].reduce((sum, arg) => sum + quotedLength(arg) + 1, 0);
  issues.range("args", commandLine < COMMAND_LINE_MAX_CHARS, "The command line exceeds 32,767 characters.");
  const mem = memLimitArgs(issues, req.memLimitBytes);
  return issues.result(operation, [
    ...(req.suspended ? ["--suspended"] : []),
    ...(req.stdin === "pipe" ? ["--stdin-fd4"] : []),
    ...mem,
    ...(req.killOnRootExit ? ["--kill-on-root-exit"] : []),
    "--",
    req.exe,
    ...req.args,
  ]);
};
