import type { BeaError } from "../../domain/errors/beaError.js";
import { err, ok, type Result } from "../../domain/result.js";
import { formatHex, MASK64, type Hex } from "../../shared/hex.js";

/**
 * Cheat Engine pointer chains for read_memory (S6 §4.14): with deref = [d0…dn],
 * p = readPointer(A) + d0, then p = readPointer(p) + d for each further d, then the read happens at p.
 * Without deref the read happens at A. Each pointer read is one step `{address read, value found}`.
 * Session-agnostic: the caller supplies an 8-byte reader (agent readMemory or bridge mem.read).
 */
export interface ChainStep {
  readonly address: Hex;
  readonly value: Hex;
}
export interface ChainResult {
  readonly final: bigint;
  readonly steps: readonly ChainStep[];
}

/** Reads one little-endian pointer at `va`; a failure is the reader's own BeaError. */
export type PointerReader = (va: bigint) => Promise<Result<bigint, BeaError>>;

/** The steps done so far ride on the error as diagnostics.chain (DESIGN §6.2 #11 `details.chain`). */
const withChain = (error: BeaError, steps: readonly ChainStep[], failedAt: bigint): BeaError => ({
  ...error,
  diagnostics: {
    ...error.diagnostics,
    chain: steps.map((s) => ({ address: s.address, value: s.value })),
    chain_failed_at: formatHex(failedAt),
  },
});

export const walkChain = async (
  readPointer: PointerReader,
  start: bigint,
  deref: readonly number[] | undefined,
): Promise<Result<ChainResult, BeaError>> => {
  const steps: ChainStep[] = [];
  let p = start & MASK64;
  for (const offset of deref ?? []) {
    const value = await readPointer(p);
    if (!value.ok) return err(withChain(value.error, steps, p));
    steps.push({ address: formatHex(p), value: formatHex(value.value) });
    p = (value.value + BigInt(offset)) & MASK64;
  }
  return ok({ final: p, steps });
};

/** Little-endian u64 from the first 8 bytes (null when fewer were read). */
export const pointerFrom = (bytes: Uint8Array): bigint | null =>
  bytes.length < 8 ? null : new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
