// =================================================================================================
// src/agent/pure/traceDeferred.ts — bookkeeping of trace_execution's deferred follows (threads mode; BEA-FEEDBACK
// item 6): the system-call stub a blocked thread waits in, the target table the native listener on that stub filters
// by, and the location of that listener's Interceptor trampoline, whose translations followed threads must drop when
// it is detached. Pure: no GumJS.
//
// Why the trampoline matters (frida-gum 17.23.2, read in gum/backend-x86/guminterceptor-x86.c, gumcodeallocator.c and
// gumstalker-x86.c): a hook's trampoline is a code slice [GumFunctionContext* slot][on_enter: endbr? push [slot];
// jmp enter_thunk][…][on_leave][on_invoke: endbr? relocated prologue; jmp back]. Detaching the last listener frees the
// slice, and the code allocator hands a freed slice to the next near allocation at once (LIFO free list, no
// quarantine). A followed thread keeps its translations keyed by real address, and the shared enter thunk reaches
// on_invoke through `jmp [rsp-8]`, whose inline cache jumps straight to the cached translation. So after a detach while
// a thread is followed, the next hook that reuses the slice would make that thread run the OLD relocated prologue (here
// the stub's own system call) instead of the new function's. Invalidating the old on_enter and on_invoke block starts
// for every followed thread closes that: an inline-cache hit then lands in Stalker's invalidator, which recompiles the
// block from the current bytes.
// =================================================================================================

/** Native table capacity (keep in sync with BeaDeferred.tids in trace.ts); ≥ AGENT_LIMIT_HARD.stalker_max_threads. */
export const DEFERRED_SLOTS = 16;

/** Where an Interceptor redirect at `at` leads: `jmp rel32` (near slice) or `jmp qword ptr [rip+disp]` (16 bytes). */
export type Redirect =
  | { readonly kind: "near"; readonly target: bigint }
  | { readonly kind: "slot"; readonly slot: bigint };

const s32 = (b: Uint8Array, i: number): bigint =>
  BigInt(new DataView(b.buffer, b.byteOffset, b.byteLength).getInt32(i, true));

/** The redirect in the first bytes of a hooked function, or null when they are not one. */
export const redirectOf = (head: Uint8Array, at: bigint): Redirect | null => {
  if (head.length >= 5 && head[0] === 0xe9) return { kind: "near", target: at + 5n + s32(head, 1) };
  if (head.length >= 6 && head[0] === 0xff && head[1] === 0x25) return { kind: "slot", slot: at + 6n + s32(head, 2) };
  return null;
};

/**
 * The canonical Win64 system-call stub (ntdll and win32u): `mov r10, rcx; mov eax, imm32` (4c 8b d1 b8 …),
 * `test byte ptr [0x7ffe0308], 1; jne +3`, `syscall` at +0x12, `ret` at +0x14 (where a blocked thread's pc is),
 * `int 2e; ret`. SYSCALL_STUB_BYTES covers the stub's start through that `ret`.
 */
export const SYSCALL_STUB_BYTES = 0x15;
/** Offset of the `ret` a thread blocked in the stub returns to (its pc while it waits). */
export const SYSCALL_STUB_RETURN = 0x14;
/** `mov r10, rcx; mov eax, imm32`: the prologue Interceptor relocates (position-independent, copied verbatim). */
export const SYSCALL_STUB_PROLOGUE = 8;
const STUB_HEAD = [0x4c, 0x8b, 0xd1, 0xb8] as const;

/**
 * What `bytes` (read at a stub's start, ≥ SYSCALL_STUB_BYTES) are: "plain" (the canonical stub), "hooked" (the same
 * stub with an Interceptor redirect over its prologue: another instrument already hooks it), else null.
 */
export const syscallStubAt = (bytes: Uint8Array): "plain" | "hooked" | null => {
  if (bytes.length < SYSCALL_STUB_BYTES) return null;
  if (bytes[0x12] !== 0x0f || bytes[0x13] !== 0x05 || bytes[SYSCALL_STUB_RETURN] !== 0xc3) return null;
  if (STUB_HEAD.every((byte, i) => bytes[i] === byte)) return "plain";
  return redirectOf(bytes, 0n) === null ? null : "hooked";
};

/**
 * What the stub's relocated prologue looks like in its trampoline: the whole `mov r10, rcx; mov eax, imm32` when the
 * prologue was read before any hook (`prologue` is the plain stub's first bytes), else (the stub was hooked already and
 * shares that hook's trampoline) the `mov r10, rcx; mov eax,` head.
 */
export const relocatedPrologue = (prologue: Uint8Array): Uint8Array =>
  prologue.length >= SYSCALL_STUB_PROLOGUE && STUB_HEAD.every((byte, i) => prologue[i] === byte)
    ? prologue.slice(0, SYSCALL_STUB_PROLOGUE)
    : Uint8Array.from(STUB_HEAD);

const ENDBR64 = [0xf3, 0x0f, 0x1e, 0xfa] as const;

/**
 * Candidate block starts of the trampoline's on_invoke part in `window` (bytes read at `base`, the on_enter entry):
 * every place `prologue` (relocatedPrologue) occurs, and 4 bytes earlier when an IBT landing pad (endbr64) precedes
 * it. Invalidating an address that starts no block is a no-op, so an extra candidate is harmless.
 */
export const onInvokeCandidates = (window: Uint8Array, base: bigint, prologue: Uint8Array): bigint[] => {
  const out: bigint[] = [];
  if (prologue.length === 0) return out;
  for (let i = 0; i + prologue.length <= window.length; i++) {
    let match = true;
    for (let k = 0; k < prologue.length && match; k++) match = window[i + k] === prologue[k];
    if (!match) continue;
    if (i >= 4 && ENDBR64.every((byte, k) => window[i - 4 + k] === byte)) out.push(base + BigInt(i - 4));
    out.push(base + BigInt(i));
  }
  return out;
};

/**
 * The targets of one deferred-follow listener, by slot, as the native filter sees them (0 = free; Windows never uses
 * thread id 0). A slot is freed when its thread is followed or exits; the table only shrinks.
 */
export class DeferredSlots {
  readonly #tids: number[];

  constructor(tids: readonly number[]) {
    if (tids.length > DEFERRED_SLOTS) throw new RangeError(`at most ${String(DEFERRED_SLOTS)} deferred threads`);
    if (tids.some((tid) => !Number.isInteger(tid) || tid <= 0 || tid > 0xffff_ffff))
      throw new RangeError("thread ids are positive 32-bit integers");
    this.#tids = [...tids];
  }

  /** Occupied length of the native table (`n`): slots past it are never compared. */
  get size(): number {
    return this.#tids.length;
  }

  /** The table as written to the native cell (freed slots are 0). */
  table(): readonly number[] {
    return this.#tids;
  }

  has(tid: number): boolean {
    return tid !== 0 && this.#tids.includes(tid);
  }

  /** Free `tid`'s slot; its index, or -1 when it holds no slot. */
  take(tid: number): number {
    const slot = tid === 0 ? -1 : this.#tids.indexOf(tid);
    if (slot >= 0) this.#tids[slot] = 0;
    return slot;
  }

  /** Every target was followed (or exited): the listener has nothing left to do. */
  get empty(): boolean {
    return this.#tids.every((tid) => tid === 0);
  }
}
