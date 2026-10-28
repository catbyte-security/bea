import { readdir, readFile, readlink } from "node:fs/promises";

/**
 * Minimal Linux /proc reader (S3 §19; BELIEVED, untested on this Windows host). Injectable so the parsing and the
 * best-effort kill algorithm are unit-tested with an in-memory /proc.
 */
export interface ProcFs {
  readText(path: string): Promise<string>;
  readLink(path: string): Promise<string>;
  list(path: string): Promise<readonly string[]>;
}

export const nodeProcFs: ProcFs = {
  readText: (path) => readFile(path, "utf8"),
  readLink: (path) => readlink(path),
  list: async (path) => readdir(path),
};

/** USER_HZ: the kernel ABI value on every mainstream Linux build (BELIEVED default). */
const CLK_TCK = 100n;
/** 100 ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01. */
const FILETIME_UNIX_EPOCH_100NS = 116_444_736_000_000_000n;

export interface ProcStat {
  readonly pid: number;
  readonly state: string;
  readonly ppid: number;
  readonly pgrp: number;
  readonly session: number;
  /** field 22: clock ticks after boot */
  readonly startTicks: bigint;
}

/** Parse /proc/<pid>/stat. `comm` (field 2) may contain spaces and parentheses, so split after the LAST ')'. */
export const parseProcStat = (text: string): ProcStat | null => {
  const open = text.indexOf("(");
  const close = text.lastIndexOf(")");
  if (open < 1 || close < open) return null;
  const pid = Number.parseInt(text.slice(0, open).trim(), 10);
  const rest = text
    .slice(close + 1)
    .trim()
    .split(/\s+/u);
  // rest[0] is field 3 (state); field N is rest[N - 3].
  const [state, ppid, pgrp, session] = [rest[0], rest[1], rest[2], rest[3]];
  const start = rest[19];
  if (state === undefined || ppid === undefined || pgrp === undefined || session === undefined) return null;
  if (start === undefined || !/^\d+$/u.test(start) || !Number.isSafeInteger(pid)) return null;
  return {
    pid,
    state,
    ppid: Number.parseInt(ppid, 10),
    pgrp: Number.parseInt(pgrp, 10),
    session: Number.parseInt(session, 10),
    startTicks: BigInt(start),
  };
};

/** `btime` (boot time, seconds since the Unix epoch) from /proc/stat. */
export const parseBootTime = (text: string): bigint | null => {
  const match = /^btime\s+(\d+)\s*$/mu.exec(text);
  return match?.[1] === undefined ? null : BigInt(match[1]);
};

/** Real uid from /proc/<pid>/status ("Uid:\treal\teffective\tsaved\tfs"). */
export const parseRealUid = (text: string): number | null => {
  const match = /^Uid:\s+(\d+)/mu.exec(text);
  return match?.[1] === undefined ? null : Number.parseInt(match[1], 10);
};

/** Absolute start time as FILETIME (100 ns since 1601) so Linux identities compare like Windows ones. */
export const startTicksToFiletime = (bootTimeSec: bigint, startTicks: bigint): bigint =>
  FILETIME_UNIX_EPOCH_100NS + bootTimeSec * 10_000_000n + (startTicks * 10_000_000n) / CLK_TCK;

export const readProcStat = async (fs: ProcFs, pid: number): Promise<ProcStat | null> => {
  try {
    return parseProcStat(await fs.readText(`/proc/${String(pid)}/stat`));
  } catch {
    return null;
  }
};
