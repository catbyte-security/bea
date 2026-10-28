// =================================================================================================
// src/application/watch/plan.ts — host-side watch planning rules (WP9-WATCH). The agent re-validates everything
// (src/agent/pure/dr7.ts, watchPlan.ts); the host checks first so it can name the nearest valid input (DESIGN §6.2
// #23). The module-boundary table keeps application code from importing src/agent, so the few rules live here too;
// tests/unit/watch/plan.test.ts pins both copies to the same answers.
// =================================================================================================

export type DrSize = 1 | 2 | 4 | 8;
const SIZES: readonly DrSize[] = [1, 2, 4, 8];
const PAGE = 4096;

export const isDrSize = (n: number): n is DrSize => n === 1 || n === 2 || n === 4 || n === 8;

/** Smallest aligned power-of-two watch covering [address, address+size); null when it crosses an 8-byte line. */
export const coveringWatch = (
  address: bigint,
  size: number,
): { readonly address: bigint; readonly size: DrSize } | null => {
  for (const s of SIZES) {
    if (s < size) continue;
    const base = address & ~BigInt(s - 1);
    if (base + BigInt(s) >= address + BigInt(size)) return { address: base, size: s };
  }
  return null;
};

/** 4 KiB pages touched by [address, address+size). */
export const pageCount = (address: bigint, size: number): number => {
  if (size <= 0) return 0;
  const first = address / BigInt(PAGE);
  const last = (address + BigInt(size) - 1n) / BigInt(PAGE);
  return Number(last - first) + 1;
};
