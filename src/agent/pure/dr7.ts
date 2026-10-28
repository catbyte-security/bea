// =================================================================================================
// src/agent/pure/dr7.ts — x64 debug-register arithmetic and validation (S4 §11.2; WP9-WATCH).
// Pure: no GumJS globals or types (lint-checked), so the host's vitest exercises it directly.
// Encodings VERIFIED on this host [ext-frida §3.9 a17]: DR7 0x90101 = L0 + LE + RW0=01 + LEN0=10 (8-byte write).
// =================================================================================================

export type DrSlot = 0 | 1 | 2 | 3;
export const DR_SLOTS: readonly DrSlot[] = [0, 1, 2, 3];
/** RW field: x = instruction execution, w = data write, rw = data read or write ("r" is never sent: it means rw). */
export type DrRw = "x" | "w" | "rw";
export type DrSize = 1 | 2 | 4 | 8;

const RW_BITS: { readonly [K in DrRw]: bigint } = { x: 0b00n, w: 0b01n, rw: 0b11n };
/** LEN field: 1→00, 2→01, 4→11, 8→10. */
const LEN_BITS: { readonly [K in DrSize]: bigint } = { 1: 0b00n, 2: 0b01n, 4: 0b11n, 8: 0b10n };

/** L_s | G_s. */
export const enableMask = (s: DrSlot): bigint => 0b11n << BigInt(2 * s);
/** RW_s | LEN_s. */
const ctrlMask = (s: DrSlot): bigint => 0b1111n << BigInt(16 + 4 * s);
/** Every DR7 bit that belongs to slot s. */
export const slotBits = (s: DrSlot): bigint => enableMask(s) | ctrlMask(s);
/** The control bits a correctly armed slot carries (RW and LEN; execute breakpoints always use LEN 00). */
export const ctrlBitsFor = (s: DrSlot, rw: DrRw, size: DrSize): bigint =>
  ((rw === "x" ? 0n : LEN_BITS[size] << 2n) | RW_BITS[rw]) << BigInt(16 + 4 * s);

/** DR7 with slot s cleared (enable and control bits). */
export const clearSlot = (dr7: bigint, s: DrSlot): bigint => dr7 & ~slotBits(s);
/** OR of the bits of every slot in `mask` (bits 0..3 = slots); what a stray-trap handler clears. */
export const clearMaskFor = (mask: number): bigint => {
  let bits = 0n;
  for (const s of DR_SLOTS) if ((mask & (1 << s)) !== 0) bits |= slotBits(s);
  return bits;
};
/** DR6 B0..B3: the slots whose condition fired. */
export const firedSlots = (dr6: bigint): DrSlot[] => DR_SLOTS.filter((s) => (dr6 & (1n << BigInt(s))) !== 0n);
/** DR6 with B0..B3 cleared (A-27: always clear after handling). */
export const clearDr6Hits = (dr6: bigint): bigint => dr6 & ~0xfn;

/** DR6 bits that name a cause: B0..B3 (a slot fired) and BS (a trap-flag step). */
export const DR6_CAUSE_BITS = 0x400fn;
/**
 * The slots a single step with NO cause in DR6 is attributed to. Windows sometimes delivers a data-breakpoint trap
 * whose context DR6 has neither B0..B3 nor BS (WP9 lab, real agent attached to game_sim: the core's last-chance report
 * showed the step right after the speed writer, the very first hit after a cross-thread arm; neither the dispatcher
 * nor the safety net could name a slot and the target died with 0x80000004). Such a step is taken as a hit of every
 * owned slot that the trapping context's DR7 enables (L or G) at that slot's own address. A step whose DR6 names any
 * cause is never inferred (B0..B3 are read as usual; BS is a trap-flag step).
 */
export const inferStepSlots = (
  dr6: bigint,
  dr7: bigint,
  dr: readonly bigint[],
  owned: readonly { readonly slot: DrSlot; readonly address: bigint }[],
): DrSlot[] => {
  if ((dr6 & DR6_CAUSE_BITS) !== 0n) return [];
  return owned.filter((o) => (dr7 & enableMask(o.slot)) !== 0n && dr[o.slot] === o.address).map((o) => o.slot);
};

export type SlotVerification = "armed" | "cleared" | "mismatch";
/**
 * What GetThreadContext shows for one slot. `armed`: enabled with the expected address and control bits;
 * `cleared`: no enable and no control bits; anything else is `mismatch` (a partially armed or foreign slot).
 */
export const verifySlot = (
  dr7: bigint,
  drAddress: bigint,
  s: DrSlot,
  expected: { readonly address: bigint; readonly rw: DrRw; readonly size: DrSize } | null,
): SlotVerification => {
  const enabled = (dr7 & enableMask(s)) !== 0n;
  const ctrl = dr7 & ctrlMask(s);
  if (expected === null) return !enabled && ctrl === 0n ? "cleared" : "mismatch";
  if (!enabled) return ctrl === 0n ? "cleared" : "mismatch";
  return drAddress === expected.address && ctrl === ctrlBitsFor(s, expected.rw, expected.size) ? "armed" : "mismatch";
};

export type DebugRegisterRefusal =
  | { readonly reason: "size"; readonly nearest: { readonly address: bigint; readonly size: DrSize } | null }
  | { readonly reason: "alignment"; readonly nearest: { readonly address: bigint; readonly size: DrSize } | null };

const SIZES: readonly DrSize[] = [1, 2, 4, 8];
const isDrSize = (n: number): n is DrSize => n === 1 || n === 2 || n === 4 || n === 8;

/**
 * The smallest debug-register watch (power-of-two size, naturally aligned) that covers [address, address+size),
 * or null when the range crosses an 8-byte boundary (then two watches or page_guard are needed).
 */
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

/**
 * Frida validates nothing [ext-frida §3.9]: size 3 or a misaligned address "succeed" and mis-attribute neighbours
 * (Frida aligns down). Execute breakpoints ignore size (forced to 1) and alignment.
 */
export const validateDebugRegister = (
  address: bigint,
  size: number,
  rw: DrRw,
): { readonly ok: true; readonly size: DrSize } | ({ readonly ok: false } & DebugRegisterRefusal) => {
  if (rw === "x") return { ok: true, size: 1 };
  if (!isDrSize(size)) return { ok: false, reason: "size", nearest: coveringWatch(address, size) };
  if ((address & BigInt(size - 1)) !== 0n)
    return { ok: false, reason: "alignment", nearest: coveringWatch(address, size) };
  return { ok: true, size };
};

/** Lowest free slot, or the requested one when it is free; null when none is available. */
export const pickSlot = (busy: readonly boolean[], requested: DrSlot | undefined): DrSlot | null => {
  if (requested !== undefined) return busy[requested] === true ? null : requested;
  for (const s of DR_SLOTS) if (busy[s] !== true) return s;
  return null;
};
