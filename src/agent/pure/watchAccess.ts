// =================================================================================================
// src/agent/pure/watchAccess.ts — access kind of a read/write debug-register hit (S4 §11.2 as amended by the WP9
// acceptance; WP9-WATCH). Pure: no GumJS globals or types (lint-checked), so the host's vitest exercises it directly.
//
// The annex classified an `rw` hit by its values alone (`before != after` → write). That needs the watched bytes
// read inside the trap handler, and a user-mode read there trips the same read/write slot again on the trapping
// thread: every value came back null and every access looked like a read. The accessing instruction decides first;
// the values only when the instruction cannot.
// =================================================================================================

/** Capstone's access of an x86 operand, as Frida's Instruction.parse reports it. */
export type OperandAccess = "" | "r" | "w" | "rw";

/** The access of the instruction's only memory operand; null when it has none, several (movs, cmps) or no access. */
export const memoryOperandAccess = (
  operands: readonly { readonly type: string; readonly access?: OperandAccess | undefined }[],
): "r" | "w" | null => {
  const memory = operands.filter((o) => o.type === "mem");
  if (memory.length !== 1) return null;
  const access = memory[0]?.access ?? "";
  if (access.includes("w")) return "w"; // a read-modify-write (add [m], 1) writes the watched bytes
  return access === "r" ? "r" : null;
};

const sameBytes = (a: Uint8Array | null, b: Uint8Array | null): boolean => {
  if (a === null || b === null) return a === b;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

/**
 * Access kind of one hit of a read/write slot: the memory operand's access when the decoded instruction tells it,
 * else changed bytes are a write and unchanged bytes a read (a write of the same value then reads as "r", the
 * annex's documented limitation, now only for instructions the decoder cannot place).
 */
export const rwAccessOf = (operand: "r" | "w" | null, before: Uint8Array | null, after: Uint8Array | null): "r" | "w" =>
  operand ?? (sameBytes(before, after) ? "r" : "w");
