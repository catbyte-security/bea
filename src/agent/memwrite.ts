import type {
  AgentResult,
  AgentRpcImpl,
  RevertWriteParams,
  RevertWriteResult,
  WriteMemoryParams,
  WriteResult,
} from "../shared/agentProtocol.js";
import { fail, ok } from "./errors.js";
import { bindModifySeam, type ModifyCoreSeam } from "./pure/modifySeam.js";
import { toHexBytes } from "./pure/modifyValues.js";
import {
  dataWriteMethod,
  hexAddress,
  pagesOf,
  sameBytes,
  WriteRegistry,
  writeBytesOf,
  type WriteMethod,
  type WriteRecord,
} from "./pure/modifyWrites.js";
import type { AgentCore } from "./state.js";

/**
 * Gated writes (WP12-MODIFY; S4 §8.3, gate `write_memory` enforced by rpc.ts wrapAll). Feature file: imports only
 * core services and its own pure helpers. `writeMemory` refuses ranges under a BEA patch, write or guard page, reads
 * the original bytes, writes (`data`: direct when every page is writable, else protect-and-restore; `code`:
 * Memory.patchCode, protection stays r-x [ext-frida §3.5]), reads back to verify and keeps the record `wr<n>` for
 * `revertWrite`. Every live write is reverted on agent dispose/shutdown when the core offers the hook.
 * Review fix AGENT-4: a revert only ever writes `before` over memory that still holds what BEA wrote. revertWrite's
 * WriteConflict (the host then records "left as found") drops the record, and dispose leaves memory the program changed
 * since the write (or freed and reused) as found, so an unload never stamps stale bytes over live data.
 */
let core: AgentCore | null = null;
let seam: ModifyCoreSeam<NativePointer> = bindModifySeam<NativePointer>({});
const writes = new WriteRegistry();

export function init(c: AgentCore): void {
  core = c;
  seam = bindModifySeam<NativePointer>(c);
  seam.onDispose?.(revertAll);
}

/** EffectHint.before: original bytes in ≤ 64-byte chunks, ≤ 64 chunks (S4 §4.2). */
const beforeChunks = (address: bigint, bytes: Uint8Array): WriteResult["effect"]["before"] => {
  const out: WriteResult["effect"]["before"] = [];
  for (let off = 0; off < bytes.length && out.length < 64; off += 64)
    out.push({ address: hexAddress(address + BigInt(off)), hex: toHexBytes(bytes.subarray(off, off + 64)) });
  return out;
};

const readBytes = (at: NativePointer, size: number): Uint8Array => {
  const buffer = at.readByteArray(size);
  if (buffer === null) throw new Error(`access violation accessing ${at.toString()}`);
  return new Uint8Array(buffer);
};

const accessViolation = (address: bigint, operation: "read" | "write"): AgentResult<never> =>
  fail({
    _tag: "AccessViolation",
    message: `cannot ${operation} target memory`,
    address: hexAddress(address),
    operation,
  });

/** Apply `bytes` at `at` with the record's mode; returns the method used and the protection around it. */
const store = (
  at: NativePointer,
  bytes: Uint8Array,
  mode: "data" | "code",
  allowProtectChange: boolean,
): { method: WriteMethod; before: string | null; after: string | null } | null => {
  if (mode === "code") {
    const protection = Memory.queryProtection(at);
    Memory.patchCode(at, bytes.length, (code) => {
      code.writeByteArray(Array.from(bytes));
    });
    seam.invalidate?.([at]);
    return { method: "patchCode", before: protection, after: Memory.queryProtection(at) };
  }
  const pageSize = Process.pageSize;
  const pages = pagesOf(BigInt(at.toString()), bytes.length, pageSize).map((base) => ptr(hexAddress(base)));
  const protections = pages.map((page) => Memory.queryProtection(page));
  const how = dataWriteMethod(protections, allowProtectChange);
  if (how === "refuse") return null;
  if (how === "direct") {
    at.writeByteArray(Array.from(bytes));
    return { method: "direct", before: protections[0] ?? null, after: protections[0] ?? null };
  }
  for (const page of pages) Memory.protect(page, pageSize, "rw-");
  try {
    at.writeByteArray(Array.from(bytes));
  } finally {
    pages.forEach((page, i) => Memory.protect(page, pageSize, protections[i] ?? "r--"));
  }
  const first = pages[0];
  return {
    method: "protect-and-restore",
    before: protections[0] ?? null,
    after: first === undefined ? null : Memory.queryProtection(first),
  };
};

function writeMemory(p: WriteMemoryParams): AgentResult<WriteResult> {
  const limits = core?.limits;
  if (limits === undefined) return fail({ _tag: "NotReady", message: "memwrite is not initialized" });
  const parsed = writeBytesOf(p, limits.write_max_bytes);
  if (!parsed.ok) return fail({ _tag: "BadParams", message: "invalid writeMemory params", issues: parsed.issues });
  const { address, bytes } = parsed;
  const at = ptr(hexAddress(address));
  if (writes.overlapping(address, bytes.length) !== undefined || seam.originals?.isPatched(at, bytes.length) === true)
    return fail({
      _tag: "BadParams",
      message: "range overlaps a BEA patch",
      issues: [{ path: "address", problem: "overlaps a BEA patch or an earlier write; revert that first" }],
    });
  if (seam.isGuarded?.(at, bytes.length) === true)
    return fail({
      _tag: "BadParams",
      message: "range overlaps a BEA guard page",
      issues: [{ path: "address", problem: "overlaps a page BEA guards for a watch; stop the watch first" }],
    });
  const id = writes.allocate();
  let before: Uint8Array;
  try {
    before = readBytes(at, bytes.length);
  } catch {
    return accessViolation(address, "read");
  }
  if (p.expect_before !== undefined && p.expect_before.toLowerCase() !== toHexBytes(before))
    return fail({
      _tag: "WriteConflict",
      message: "memory differs from expect_before",
      write_id: id,
      address: hexAddress(address),
      expected: p.expect_before.toLowerCase(),
      actual: toHexBytes(before),
    });
  seam.originals?.save(id, at, bytes.length);
  let stored: ReturnType<typeof store>;
  try {
    stored = store(at, bytes, p.mode, p.allow_protect_change);
  } catch {
    seam.originals?.release(id);
    return accessViolation(address, "write");
  }
  if (stored === null) {
    seam.originals?.release(id);
    return accessViolation(address, "write");
  }
  let after: Uint8Array;
  try {
    after = readBytes(at, bytes.length);
  } catch {
    after = new Uint8Array(0);
  }
  writes.add({ id, address, size: bytes.length, before, after, mode: p.mode });
  seam.originals?.markPatched(id);
  return ok({
    write_id: id,
    address: hexAddress(address),
    size: bytes.length,
    before: toHexBytes(before),
    after: toHexBytes(after),
    verified: sameBytes(after, bytes),
    method: stored.method,
    protection_before: stored.before,
    protection_after: stored.after,
    effect: {
      kind: "memory-written",
      reversible: true,
      targets: [{ address: hexAddress(address), size: bytes.length }],
      thread_ids: null,
      before: beforeChunks(address, before),
    },
  });
}

function restore(record: WriteRecord): Uint8Array {
  const at = ptr(hexAddress(record.address));
  store(at, record.before, record.mode, true);
  return readBytes(at, record.size);
}

function revertWrite(p: RevertWriteParams): AgentResult<RevertWriteResult> {
  const record = writes.get(p.write_id);
  if (record === undefined)
    return fail({ _tag: "NotFound", message: "no such write", what: "write", id: String(p.write_id) });
  const at = ptr(hexAddress(record.address));
  let current: Uint8Array;
  try {
    current = readBytes(at, record.size);
  } catch {
    return accessViolation(record.address, "read");
  }
  if (!sameBytes(current, record.after) && !p.force) {
    // left as found: the record goes, so neither a later dispose nor a retry writes `before` over the program's data
    writes.delete(record.id);
    seam.originals?.release(record.id);
    return fail({
      _tag: "WriteConflict",
      message: "memory changed after the write",
      write_id: record.id,
      address: hexAddress(record.address),
      expected: toHexBytes(record.after),
      actual: toHexBytes(current),
    });
  }
  let after: Uint8Array;
  try {
    after = restore(record);
  } catch {
    return accessViolation(record.address, "write");
  }
  const reverted = sameBytes(after, record.before);
  if (reverted) {
    writes.delete(record.id);
    seam.originals?.release(record.id);
  }
  return ok({
    write_id: record.id,
    reverted,
    current_before_revert: toHexBytes(current),
    after: toHexBytes(after),
  });
}

/**
 * Synchronous best-effort revert of every live write, newest first (dispose / shutdown(revert)), under revertWrite's
 * rule: only memory that still holds what BEA wrote is restored; memory the program changed since (or freed and
 * reused for another object) is left as found. Every record is dropped, so nothing is retried at a later unload.
 */
function revertAll(): void {
  for (const record of writes.all()) {
    writes.delete(record.id);
    seam.originals?.release(record.id);
    try {
      if (sameBytes(readBytes(ptr(hexAddress(record.address)), record.size), record.after)) restore(record);
    } catch {
      // unmapped since the write (module unloaded, memory freed): nothing left to restore
    }
  }
}

export const rpc = {
  writeMemory,
  revertWrite,
} satisfies Partial<AgentRpcImpl>;
