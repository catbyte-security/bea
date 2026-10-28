// Agent pure helpers of WP12-MODIFY: the gated-write registry and the write-method decision (S4 §8.3).
import type { Hex, WriteId, WriteMemoryParams } from "../../shared/agentProtocol.js";
import { fromHexBytes, typedBytes } from "./modifyValues.js";

export type WriteMethod = "direct" | "protect-and-restore" | "patchCode";

export interface WriteRecord {
  readonly id: WriteId;
  readonly address: bigint;
  readonly size: number;
  /** original bytes (revert writes them back) */
  readonly before: Uint8Array;
  /** the bytes BEA wrote (a revert refuses unless memory still holds them, or force) */
  readonly after: Uint8Array;
  readonly mode: "data" | "code";
}

/** Live writes of one agent; ids "wr<n>" are never reused within the agent's lifetime. */
export class WriteRegistry {
  private next = 1;
  private readonly records = new Map<WriteId, WriteRecord>();

  allocate(): WriteId {
    const id: WriteId = `wr${String(this.next)}`;
    this.next += 1;
    return id;
  }
  add(record: WriteRecord): void {
    this.records.set(record.id, record);
  }
  get(id: WriteId): WriteRecord | undefined {
    return this.records.get(id);
  }
  delete(id: WriteId): void {
    this.records.delete(id);
  }
  /** the live write overlapping [address, address+size), if any */
  overlapping(address: bigint, size: number): WriteRecord | undefined {
    const end = address + BigInt(size);
    for (const r of this.records.values()) if (address < r.address + BigInt(r.size) && r.address < end) return r;
    return undefined;
  }
  /** newest first: reverting in reverse order restores stacked state exactly */
  all(): readonly WriteRecord[] {
    return [...this.records.values()].reverse();
  }
  get size(): number {
    return this.records.size;
  }
}

export interface ParamProblem {
  readonly path: string;
  readonly problem: string;
}

/** Structural checks the agent repeats after the host's zod validation (S4 §5.2): bytes, bounds, address. */
export const writeBytesOf = (
  p: WriteMemoryParams,
  maxBytes: number,
):
  | { readonly ok: true; readonly address: bigint; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly issues: ParamProblem[] } => {
  const issues: ParamProblem[] = [];
  const address = /^0x[0-9a-fA-F]{1,16}$/u.test(p.address) ? BigInt(p.address) : null;
  if (address === null || address === 0n) issues.push({ path: "address", problem: "not a non-zero 0x address" });
  if (p.mode !== "data" && p.mode !== "code") issues.push({ path: "mode", problem: "must be data or code" });
  let bytes: Uint8Array | null = null;
  if ((p.bytes === undefined) === (p.typed === undefined))
    issues.push({ path: "bytes", problem: "give exactly one of bytes or typed" });
  else if (p.bytes !== undefined) {
    bytes = fromHexBytes(p.bytes);
    if (bytes === null) issues.push({ path: "bytes", problem: "not an even-length hex byte string" });
  } else if (p.typed !== undefined) {
    const typed = typedBytes(p.typed.type, p.typed.values);
    if (typed.ok) bytes = typed.bytes;
    else issues.push({ path: "typed", problem: typed.problem });
  }
  if (bytes !== null && (bytes.length === 0 || bytes.length > maxBytes))
    issues.push({ path: "bytes", problem: `size must be 1..${String(maxBytes)}` });
  if (p.expect_before !== undefined) {
    const expected = fromHexBytes(p.expect_before);
    if (expected === null || (bytes !== null && expected.length !== bytes.length))
      issues.push({ path: "expect_before", problem: "must be hex of the same length as the write" });
  }
  if (issues.length > 0 || address === null || bytes === null) return { ok: false, issues };
  return { ok: true, address, bytes };
};

/**
 * How a `data` write reaches the page(s) (S4 §8.3 step 3): every page writable → direct; else protect-and-restore
 * when allowed; else refuse (AccessViolation{write}). `code` writes always use Memory.patchCode.
 */
export const dataWriteMethod = (
  protections: readonly string[],
  allowProtectChange: boolean,
): "direct" | "protect-and-restore" | "refuse" => {
  if (protections.length > 0 && protections.every((p) => p.includes("w"))) return "direct";
  return allowProtectChange ? "protect-and-restore" : "refuse";
};

/** Page-aligned bases covering [address, address+size). */
export const pagesOf = (address: bigint, size: number, pageSize: number): bigint[] => {
  const page = BigInt(pageSize);
  const first = address - (address % page);
  const last = address + BigInt(Math.max(size, 1) - 1);
  const pages: bigint[] = [];
  for (let base = first; base <= last; base += page) pages.push(base);
  return pages;
};

export const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

export const hexAddress = (value: bigint): Hex => `0x${value.toString(16)}`;
