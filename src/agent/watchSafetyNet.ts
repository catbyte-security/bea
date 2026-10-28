// =================================================================================================
// src/agent/watchSafetyNet.ts — the attached-session safety net (DESIGN §5.3, CT-I4; WP9-WATCH; BELIEVED, lab check
// in WP9 acceptance). Before the first debug-register or guard-page arm in an ATTACHED session the agent installs a
// leaked native vectored handler on the hand-assembled code of pure/watchSafetyNetCode.ts, in VirtualAlloc'd memory
// (never Memory.alloc/CModule, which are freed on unload), plus a data page {slot_mask, dr7_clear, guard_pages[≤64],
// tf_tids[≤64]} that the agent keeps current. It is registered LAST (AddVectoredExceptionHandler(0, …)): Frida 17's
// exceptor is itself a vectored handler registered when the agent loads, and a handler registered first would run
// before it and swallow every BEA trap while the agent is still loaded (WP9 lab: a hot DR watch stopped after one
// trap, hits_dr = 1). Registered last, it sees only what Frida's exceptor and BEA's dispatcher passed on: a stray BEA
// DR trap, a pending trap-flag step or a guard fault on a BEA page after an abrupt unload then continues instead of
// killing the target (0x80000004 / 0x80000001 [CT-lab E4, E4c]). Tables are cleared only on a clean disarm.
// =================================================================================================
import { bigOf, protect } from "./hwbp.js";
import { clearMaskFor } from "./pure/dr7.js";
import { addBounded, removeSwap, SAFETY_NET_MAX_PAGES, SAFETY_NET_MAX_TIDS } from "./pure/watchPlan.js";
import {
  SAFETY_NET_ALLOC_BYTES,
  SAFETY_NET_CODE,
  SAFETY_NET_DATA_OFFSET,
  SAFETY_NET_LAYOUT as L,
  SAFETY_NET_MAGIC,
  WIN32,
} from "./pure/watchSafetyNetCode.js";

export interface SafetyNetCounters {
  readonly dr: number;
  readonly tf: number;
  readonly guard: number;
}

export class SafetyNet {
  #code: NativePointer | null = null;
  #data: NativePointer | null = null;
  #handle: NativePointer | null = null;
  readonly #tids: number[] = [];
  #failed = false;

  get installed(): boolean {
    return this.#handle !== null;
  }

  /** Idempotent; false (and never retried) when allocation or registration failed. */
  install(): boolean {
    if (this.#handle !== null) return true;
    if (this.#failed) return false;
    try {
      const kb = Process.getModuleByName("kernelbase.dll");
      const virtualAlloc = new NativeFunction(
        kb.getExportByName("VirtualAlloc"),
        "pointer",
        ["pointer", "uint64", "uint32", "uint32"],
        { scheduling: "exclusive" },
      );
      const addVeh = new NativeFunction(
        Process.getModuleByName("ntdll.dll").getExportByName("RtlAddVectoredExceptionHandler"),
        "pointer",
        ["uint32", "pointer"],
        { scheduling: "exclusive" },
      );
      const block = virtualAlloc(
        NULL,
        SAFETY_NET_ALLOC_BYTES,
        WIN32.MEM_COMMIT | WIN32.MEM_RESERVE,
        WIN32.PAGE_READWRITE,
      );
      if (block.isNull()) throw new Error("VirtualAlloc failed");
      block.writeByteArray(Array.from(SAFETY_NET_CODE));
      const data = block.add(SAFETY_NET_DATA_OFFSET);
      data.add(L.magic).writeU32(SAFETY_NET_MAGIC);
      if (!protect(block, SAFETY_NET_DATA_OFFSET, WIN32.PAGE_EXECUTE_READ)) throw new Error("VirtualProtect failed");
      const handle = addVeh(0, block); // last: after Frida's exceptor (see the header)
      if (handle.isNull()) throw new Error("RtlAddVectoredExceptionHandler failed");
      this.#code = block;
      this.#data = data;
      this.#handle = handle;
      return true;
    } catch {
      this.#failed = true;
      return false;
    }
  }

  /** Debug-register slots BEA owns (armed, disarming or quarantined). */
  setSlots(mask: number): void {
    const data = this.#data;
    if (data === null) return;
    data.add(L.dr7Clear).writeU64(uint64(clearMaskFor(mask).toString()));
    data.add(L.slotMask).writeU32(mask & 0xf);
  }

  /** Pages BEA guards (≤ 64 tracked; the count is written last so the handler never sees a torn table). */
  setPages(pages: readonly NativePointer[]): void {
    const data = this.#data;
    if (data === null) return;
    const kept = pages.slice(0, SAFETY_NET_MAX_PAGES);
    data.add(L.nGuard).writeU32(0);
    kept.forEach((p, i) => data.add(L.guardPages + 8 * i).writeU64(uint64(bigOf(p).toString())));
    data.add(L.nGuard).writeU32(kept.length);
  }

  /** A trap-flag step BEA owes on `tid` (set in onGuard, cleared in onStep). */
  setTrapFlag(tid: number, pending: boolean): void {
    const data = this.#data;
    if (data === null) return;
    const changed = pending ? addBounded(this.#tids, tid, SAFETY_NET_MAX_TIDS) : removeSwap(this.#tids, tid);
    if (!changed && !pending) return;
    data.add(L.nTf).writeU32(0);
    this.#tids.forEach((t, i) => data.add(L.tfTids + 4 * i).writeU32(t));
    data.add(L.nTf).writeU32(this.#tids.length);
  }

  counters(): SafetyNetCounters | null {
    const data = this.#data;
    if (data === null) return null;
    return {
      dr: data.add(L.hitsDr).readU64().toNumber(),
      tf: data.add(L.hitsTf).readU64().toNumber(),
      guard: data.add(L.hitsGuard).readU64().toNumber(),
    };
  }

  /** For diagnostics/tests: where the leaked code lives. */
  get codeAddress(): NativePointer | null {
    return this.#code;
  }
}
