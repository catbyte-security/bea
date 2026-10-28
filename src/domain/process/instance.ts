import { posix, win32 } from "node:path";

import { z } from "zod";

import type { Hex } from "../../shared/hex.js";
import { idOf, sha256Schema, type MmId, type PiId } from "../ids.js";
import type { AgentIdentity } from "../evidence/record.js";
import { sha256Hex } from "../canonical.js";

// ---------------------------------------------------------------- process identity (S2 §4.1)
export type StartTimeSource = "os-creation-time" | "frida-started" | "first-observed";
export interface ProcessIdentity {
  readonly t: "bea.pi/1";
  readonly device_id: string; // "local" in v0.1
  readonly pid: number;
  /** os-creation-time: FILETIME (100 ns) decimal from jobhost adopt/inspect; frida-started: ISO; first-observed: ISO */
  readonly start_time: { readonly source: StartTimeSource; readonly value: string };
  /** sha256(utf8(pathKey(main module path))): binds identity to the path without storing it (redactable). */
  readonly image_path_sha256: string;
}
export const processIdentitySchema = z.strictObject({
  t: z.literal("bea.pi/1"),
  device_id: z.string().min(1).max(128),
  pid: z
    .number()
    .int()
    .min(0)
    .max(2 ** 32 - 1),
  start_time: z.strictObject({
    source: z.enum(["os-creation-time", "frida-started", "first-observed"]),
    value: z.string().min(1).max(64),
  }),
  image_path_sha256: sha256Schema,
});
export const instanceIdOf = (identity: ProcessIdentity): PiId => idOf("pi", { ...identity });

/** Windows: strip \\?\ (\\?\UNC\ -> \\), / -> \, normalize, lowercase. Linux: posix normalize, case kept. */
export const pathKey = (path: string, platform: "win32" | "linux"): string => {
  if (platform === "linux") return posix.normalize(path);
  let p = path;
  if (p.startsWith("\\\\?\\UNC\\")) p = `\\\\${p.slice(8)}`;
  else if (p.startsWith("\\\\?\\")) p = p.slice(4);
  return win32.normalize(p.replaceAll("/", "\\")).toLowerCase();
};
export const pathDigest = (path: string, platform: "win32" | "linux"): string => sha256Hex(pathKey(path, platform));

// ---------------------------------------------------------------- instance state (S2 §4.2)
/** fs.stat({bigint:true}) facts; the hash-cache and PE-cache key (S2 lab E4). */
export interface FileKey {
  readonly path_key: string;
  readonly size: string;
  readonly mtime_ns: string;
  readonly ctime_ns: string;
  readonly ino: string;
  readonly dev: string;
}

export type ExitKind = "normal" | "ntstatus" | "bea-kill" | "unknown";
export interface ExitInfo {
  readonly code: number | null;
  readonly code_hex: Hex | null;
  readonly kind: ExitKind;
  /** e.g. "STATUS_ACCESS_VIOLATION" */
  readonly name: string | null;
}

export interface ProcessInstance {
  readonly instance_id: PiId;
  readonly identity: ProcessIdentity;
  /** Kill authority: owned only. */
  readonly ownership: "owned" | "attached";
  readonly image: {
    readonly display: { readonly path: string | null; readonly name: string | null };
    readonly sha256: string | null; // lazily filled from FileHashCache
    readonly file: FileKey | null;
    readonly pe: {
      readonly machine: "x64" | "x86" | "arm64" | "unknown";
      readonly image_base: Hex; // preferred, from disk
      readonly size_of_image: number;
      readonly time_date_stamp: number;
      readonly codeview: { readonly guid: string; readonly age: number } | null;
    } | null;
  };
  readonly environment: {
    readonly platform: "win32" | "linux";
    readonly os_version: string;
    readonly arch: "x64";
    readonly pointer_size: 8;
  };
  readonly agent: AgentIdentity;
  /** Owned only; counts and basenames, never verbatim argv/env. */
  readonly launch: {
    readonly via: "frida-spawn+adopt" | "jobhost-spawn";
    readonly argv_count: number;
    readonly program_basename: string | null;
    readonly env_keys_count: number;
    readonly env_keys_sha256: string | null;
  } | null;
  state: "suspended" | "running" | "exited" | "detached";
  exit: ExitInfo | null;
}

// ---------------------------------------------------------------- module maps (S2 §5)
export interface ModuleEntry {
  readonly base: Hex;
  /** == PE SizeOfImage (VERIFIED S2 E2). */
  readonly size: number;
  readonly path_sha256: string;
  readonly display: { readonly name: string | null; readonly path: string | null };
}
export interface ModuleMap {
  readonly module_map_id: MmId;
  readonly instance_id: PiId;
  readonly completeness: "complete" | "partial";
  /** sorted by base, non-overlapping */
  readonly modules: readonly ModuleEntry[];
}
/** Module hashes are deliberately NOT in the map identity (lazy hashing of large game DLLs). */
export const moduleMapIdOf = (m: Omit<ModuleMap, "module_map_id">): MmId =>
  idOf("mm", {
    t: "bea.mm/1",
    instance_id: m.instance_id,
    completeness: m.completeness,
    modules: m.modules.map(({ base, size, path_sha256 }) => ({ base, size, path_sha256 })),
  });

/** Binary search by base; null when the VA is outside every module. */
export const moduleAt = (map: ModuleMap, va: bigint): ModuleEntry | null => {
  let lo = 0;
  let hi = map.modules.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const m = map.modules[mid];
    if (m === undefined) return null;
    const base = BigInt(m.base);
    if (va < base) hi = mid - 1;
    else if (va >= base + BigInt(m.size)) lo = mid + 1;
    else return m;
  }
  return null;
};
