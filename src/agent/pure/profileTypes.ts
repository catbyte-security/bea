// Pure types of the API profile engine (WP-BEHAVIOR). No GumJS globals: the engine is generic over the pointer type
// P (NativePointer in the agent, bigint in unit tests) and reads target memory only through ProfileMem<P>.
import type { ValueCell } from "../../shared/agentProtocol.js";
import type { Hex } from "../../shared/hex.js";

/** Target-memory reader. Every read may throw (unmapped, guard page); decoders catch per argument. */
export interface ProfileMem<P> {
  isNull(p: P): boolean;
  add(p: P, offset: number): P;
  /** canonical lowercase hex ("0x0" for null) */
  hex(p: P): Hex;
  /** the pointer value itself read as an unsigned / signed 32-bit integer (register-sized args) */
  u32(p: P): number;
  i32(p: P): number;
  readPointer(p: P): P;
  readU8(p: P): number;
  readU16(p: P): number;
  readU32(p: P): number;
  /** 64-bit value as canonical hex */
  readU64(p: P): Hex;
  /** exactly `chars` UTF-16 code units / bytes */
  readUtf16(p: P, chars: number): string;
  readAnsi(p: P, chars: number): string;
  /** NUL-terminated, at most `max` characters; `trunc` when no terminator was found within max */
  readUtf16z(p: P, max: number): { readonly s: string; readonly trunc: boolean };
  readAnsiz(p: P, max: number): { readonly s: string; readonly trunc: boolean };
  /** raw bytes as lowercase hex (payload capture, ≤ a few KiB) */
  readHex(p: P, bytes: number): string;
}

export type Cells = Record<string, ValueCell>;

/** One handle-cache entry (S4 §10.6). `proto` is set for sockets ("tcp" | "udp" | "raw"). */
export interface HandleEntry {
  readonly kind: string;
  name: string | null;
  proto?: string;
}

/** Payload capture sizes (all default 0 = never capture; S4 §10.6 "Payloads"). */
export interface PayloadCaps {
  readonly fileBytes: number;
  readonly netBytes: number;
  readonly valueBytes: number;
}
