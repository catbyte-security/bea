import type { BeaError } from "../domain/errors/beaError.js";
import type { Hex } from "../domain/hex.js";
import type { FileKey } from "../domain/process/instance.js";
import type { Result } from "../domain/result.js";

/**
 * BEA's own on-disk PE32+ reader (S2 §17; cross-checked against pefile, S2 lab E1). Implemented by
 * src/providers/pe/** (WP-ADDR). Positioned reads on short-lived handles (game files stay unlocked); lazy tables.
 */
export type PeErrorKind = "not_found" | "io" | "not_pe" | "unsupported_format" | "malformed";
export interface PeError {
  readonly kind: PeErrorKind;
  readonly detail: string;
  readonly field?: string;
}
export interface PeSection {
  readonly name: string; // long names resolved via the COFF string table
  readonly short_name: string;
  readonly rva: number;
  readonly virtual_size: number;
  readonly raw_offset: number;
  readonly raw_size: number;
  readonly characteristics: number;
  readonly perms: `${"r" | "-"}${"w" | "-"}${"x" | "-"}`;
}
export interface PeExport {
  readonly ordinal: number;
  readonly name: string | null;
  readonly rva: number | null;
  readonly forwarder: string | null;
}
export interface PeImport {
  readonly dll: string;
  readonly name: string | null;
  readonly ordinal: number | null;
  readonly slot_rva: number;
  readonly delay: boolean;
}
export interface FunctionTable {
  readonly count: number;
  readonly chained: number;
  /** fragment containing rva + its primary entry (unwind chains followed, depth ≤ 32) */
  lookup(rva: number): {
    readonly begin: number;
    readonly end: number;
    readonly primary_begin: number;
    readonly fragment: boolean;
  } | null;
  entries(): Iterable<{ readonly begin: number; readonly end: number; readonly primary_begin: number }>;
}
export interface PeImage {
  readonly path_display: string;
  readonly file: FileKey;
  readonly format: "pe32+"; // PE32 -> unsupported_format (WoW64 unsupported in v0.1)
  readonly machine: "x64" | "arm64" | "unknown";
  readonly time_date_stamp: number;
  readonly characteristics: number;
  readonly dll: boolean;
  /** PREFERRED base from disk (the loader rewrites the in-memory header) */
  readonly image_base: Hex;
  readonly size_of_image: number;
  readonly size_of_headers: number;
  readonly entry_rva: number | null;
  readonly subsystem: number;
  readonly dll_characteristics: {
    readonly dynamic_base: boolean;
    readonly high_entropy_va: boolean;
    readonly nx_compat: boolean;
    readonly guard_cf: boolean;
  };
  readonly sections: readonly PeSection[];
  readonly codeview: { readonly guid: string; readonly age: number; readonly pdb_path: string } | null;
  readonly tls_callbacks: readonly number[];
  readonly signed: boolean;
  readonly clr: boolean;
  /** malformed or capped tables -> coverage partial */
  readonly issues: readonly { readonly table: string; readonly reason: string }[];
  exports(): Promise<readonly PeExport[]>;
  imports(): Promise<readonly PeImport[]>;
  functions(): Promise<FunctionTable>;
  /** DIR64 slot rvas, sorted */
  relocations(): Promise<Uint32Array>;
  loaderWritten(): Promise<
    readonly {
      readonly rva: number;
      readonly size: number;
      readonly class: "iat" | "delay-iat" | "loader-thunk" | "loader-cfg";
    }[]
  >;
  readRva(rva: number, len: number): Promise<{ readonly bytes: Uint8Array; readonly backed: Uint8Array }>;
  /** file bytes + base relocations applied for actualBase */
  imageBytes(rva: number, len: number, actualBase: bigint): Promise<Uint8Array>;
  sectionOf(rva: number): PeSection | null;
}
export interface PeImageCache {
  /** LRU keyed by FileKey (path_key, size, mtime_ns, ctime_ns, ino, dev) */
  open(path: string, signal?: AbortSignal): Promise<Result<PeImage, BeaError>>;
}
export interface FileHashCache {
  /** persistent BEA_HOME/cache/file-sha256.jsonl keyed by FileKey */
  sha256(path: string, signal?: AbortSignal): Promise<Result<string, BeaError>>;
}
