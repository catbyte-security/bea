// =================================================================================================
// src/agent/native/core.ts — WP3-AGENT core CModule (S4 §5.4, D-INT-36): one per agent, pinned forever.
//  - bea_next_g: the agent-global event sequence (atomic, shared by JS rows and native producers, A14).
//  - bea_now_us: µs since agent load from g_get_monotonic_time() (QPC-backed on Windows; the same clock the protocol
//    documents for TimeUs). Lab note [impl-WP3 p2/p3]: TinyCC mis-compiles int64 × extern-double arithmetic, so the
//    clock is a plain monotonic difference and the S4 QPC extern-pointer variant is not used.
//  - bea_call_tids + bea_in_agent_call: threads running a BEA oracle call, readable by CModule listeners (CT-M2).
//  - Ring helpers: multi-producer reservation by CAS (TinyCC inline asm), commit word written last, single consumer.
// Mutable state lives in JS-allocated extern cells (CModule globals are not writable [impl-WP3 p1]). Feature CModules
// receive these symbols as externs (`core.native.symbols`) and declare them with CORE_EXTERN_DECLS.
// =================================================================================================
import type { Gseq, ThreadId, TimeUs } from "../../shared/agentProtocol.js";

/** Commit word of a published ring record (last 8 bytes of every record). @public */
export const RING_COMMIT = "0xbea0bea0bea0bea0";
/** BeaRing header layout (bytes). */
export const RING = {
  head: 0,
  tail: 8,
  mask: 16,
  recBytes: 24,
  stall: 28,
  overrun: 32,
  torn: 40,
  data: 48,
  size: 56,
} as const;
export const CALL_TID_SLOTS = 64;

const CORE_C = String.raw`
#include <glib.h>

typedef struct {
  volatile gint64 head;
  volatile gint64 tail;
  guint64 mask;
  guint32 rec_bytes;
  guint32 stall;
  volatile gint64 overrun;
  volatile gint64 torn;
  guint8 * data;
} BeaRing;

extern volatile gint64 bea_gseq;
extern gint64 bea_t0_us;
extern volatile guint32 bea_call_tids[64];

#define BEA_COMMIT 0xbea0bea0bea0bea0ULL
#define BEA_STALL_LIMIT 4

static int bea_cas64 (volatile gint64 * p, gint64 expected, gint64 desired)
{
  gint64 prev;
  __asm__ __volatile__ ("lock; cmpxchgq %2, %1" : "=a" (prev), "+m" (*p) : "r" (desired), "0" (expected) : "memory");
  return prev == expected;
}

double bea_next_g (void) { return (double) (g_atomic_pointer_add (&bea_gseq, 1) + 1); }
double bea_peek_g (void) { return (double) bea_gseq; }
void bea_clock_init (void) { bea_t0_us = g_get_monotonic_time (); }
double bea_now_us (void) { return (double) (g_get_monotonic_time () - bea_t0_us); }

int bea_in_agent_call (guint32 tid)
{
  int i;
  for (i = 0; i != 64; i++)
    if (bea_call_tids[i] == tid)
      return 1;
  return 0;
}

guint8 * bea_ring_reserve (BeaRing * r)
{
  for (;;)
  {
    gint64 h = r->head;
    if (h - r->tail > (gint64) r->mask)
    {
      g_atomic_pointer_add (&r->overrun, 1);
      return NULL;
    }
    if (bea_cas64 (&r->head, h, h + 1))
      return r->data + (guint64) (h & r->mask) * r->rec_bytes;
  }
}

void bea_ring_commit (BeaRing * r, guint8 * rec)
{
  __asm__ __volatile__ ("" : : : "memory");
  *(volatile guint64 *) (rec + r->rec_bytes - 8) = BEA_COMMIT;
}

guint64 bea_ring_collect (BeaRing * r, guint8 * out, guint64 max_records)
{
  guint64 n = 0;
  gint64 t = r->tail;
  gint64 h = r->head;
  guint64 words = r->rec_bytes / 8;
  while (t < h && n < max_records)
  {
    guint64 * rec = (guint64 *) (r->data + (guint64) (t & r->mask) * r->rec_bytes);
    volatile guint64 * commit = rec + words - 1;
    guint64 * dst = (guint64 *) (out + n * r->rec_bytes);
    guint64 i;
    if (*commit != BEA_COMMIT)
    {
      if (++r->stall < BEA_STALL_LIMIT)
        break;
      r->stall = 0;
      g_atomic_pointer_add (&r->torn, 1);
      t++;
      continue;
    }
    r->stall = 0;
    for (i = 0; i != words; i++)
      dst[i] = rec[i];
    *commit = 0;
    t++;
    n++;
  }
  __asm__ __volatile__ ("" : : : "memory");
  r->tail = t;
  return n;
}
`;

/** Declarations a feature CModule prepends to use the core symbols (pass `core.native.symbols` as its externs). @public */
export const CORE_EXTERN_DECLS = String.raw`
typedef struct {
  volatile gint64 head; volatile gint64 tail; guint64 mask; guint32 rec_bytes; guint32 stall;
  volatile gint64 overrun; volatile gint64 torn; guint8 * data;
} BeaRing;
extern double bea_next_g (void);
extern double bea_now_us (void);
extern int bea_in_agent_call (guint32 tid);
extern guint8 * bea_ring_reserve (BeaRing * r);
extern void bea_ring_commit (BeaRing * r, guint8 * rec);
extern volatile guint32 bea_call_tids[64];
`;

/** `mov rax, gs:[0x30]; ret` — the current thread's TEB (S4 §5.4). */
const TEB_STUB = [0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0xc3];

export interface NativeRing {
  readonly header: NativePointer;
  readonly data: NativePointer;
  readonly capacity: number;
  readonly recBytes: number;
}

export class NativeCore {
  #cm: CModule | null = null;
  #nextG: (() => number) | null = null;
  #peekG: (() => number) | null = null;
  #nowUs: (() => number) | null = null;
  #collect: ((ring: NativePointer, out: NativePointer, max: number | UInt64) => UInt64) | null = null;
  #teb: (() => NativePointer) | null = null;
  #fallbackG = 0;
  readonly #fallbackT0 = Date.now();
  /** extern cells and stubs, pinned for the agent's lifetime */
  readonly #pins: unknown[] = [];
  #symbols: Record<string, NativePointer> = {};
  #callTids: NativePointer | null = null;

  get ready(): boolean {
    return this.#cm !== null;
  }

  /** Compile the core CModule (boot step 1; any failure is fatal for the agent). */
  init(): void {
    if (this.#cm !== null) return;
    const gseq = Memory.alloc(8);
    const t0 = Memory.alloc(8);
    const tids = Memory.alloc(4 * CALL_TID_SLOTS);
    const cm = new CModule(CORE_C, { bea_gseq: gseq, bea_t0_us: t0, bea_call_tids: tids });
    const exclusive = { scheduling: "exclusive" } as const;
    new NativeFunction(cm["bea_clock_init"] as NativePointer, "void", [], exclusive)();
    this.#nextG = new NativeFunction(cm["bea_next_g"] as NativePointer, "double", [], exclusive) as () => number;
    this.#peekG = new NativeFunction(cm["bea_peek_g"] as NativePointer, "double", [], exclusive) as () => number;
    this.#nowUs = new NativeFunction(cm["bea_now_us"] as NativePointer, "double", [], exclusive) as () => number;
    this.#collect = new NativeFunction(
      cm["bea_ring_collect"] as NativePointer,
      "uint64",
      ["pointer", "pointer", "uint64"],
      exclusive,
    ) as unknown as (ring: NativePointer, out: NativePointer, max: number | UInt64) => UInt64;
    const stub = Memory.alloc(Process.pageSize, { protection: "rwx" });
    stub.writeByteArray(TEB_STUB);
    this.#teb = new NativeFunction(stub, "pointer", [], exclusive) as () => NativePointer;
    this.#pins.push(gseq, t0, tids, stub);
    this.#callTids = tids;
    this.#symbols = {
      bea_gseq: gseq,
      bea_call_tids: tids,
      bea_next_g: cm["bea_next_g"] as NativePointer,
      bea_now_us: cm["bea_now_us"] as NativePointer,
      bea_in_agent_call: cm["bea_in_agent_call"] as NativePointer,
      bea_ring_reserve: cm["bea_ring_reserve"] as NativePointer,
      bea_ring_commit: cm["bea_ring_commit"] as NativePointer,
    };
    this.#cm = cm;
  }

  /** Next global sequence number (1-based, strictly increasing over every row of every stream). */
  nextG(): Gseq {
    return this.#nextG === null ? ++this.#fallbackG : this.#nextG();
  }

  /** The last allocated sequence number (ping/status; does not allocate). */
  peekG(): Gseq {
    return this.#peekG === null ? this.#fallbackG : this.#peekG();
  }

  /** µs since agent load (monotonic, all threads). */
  nowUs(): TimeUs {
    return this.#nowUs === null ? (Date.now() - this.#fallbackT0) * 1000 : this.#nowUs();
  }

  /** The current thread's TEB (hooks and runOnThread closures). */
  currentTeb(): NativePointer {
    if (this.#teb === null) throw new Error("native core not initialized");
    return this.#teb();
  }

  /** Extern symbols for feature CModules (see CORE_EXTERN_DECLS). */
  get symbols(): Readonly<Record<string, NativePointer>> {
    return this.#symbols;
  }

  /** The u32[64] table of threads inside a BEA call (calls.ts maintains it). */
  get callTids(): NativePointer | null {
    return this.#callTids;
  }

  /** Allocate a ring of `capacity` (power of two) records of `recBytes` (multiple of 8, ≥ 16); pinned by the caller. */
  allocRing(capacity: number, recBytes: number): NativeRing {
    if (capacity < 2 || (capacity & (capacity - 1)) !== 0) throw new RangeError("ring capacity must be a power of two");
    if (recBytes < 16 || recBytes % 8 !== 0) throw new RangeError("ring records must be a multiple of 8 bytes ≥ 16");
    const header = Memory.alloc(RING.size);
    const data = Memory.alloc(capacity * recBytes);
    header.add(RING.mask).writeU64(capacity - 1);
    header.add(RING.recBytes).writeU32(recBytes);
    header.add(RING.data).writePointer(data);
    return { header, data, capacity, recBytes };
  }

  /** Copy up to `max` committed records into `out` (single consumer, JS thread); returns the count. */
  ringCollect(ring: NativeRing, out: NativePointer, max: number): number {
    if (this.#collect === null) return 0;
    return this.#collect(ring.header, out, max).toNumber();
  }

  /** Ring loss counters (overruns at reservation, torn records skipped by the consumer). */
  ringCounters(ring: NativeRing): { overrun: number; torn: number } {
    return {
      overrun: ring.header.add(RING.overrun).readS64().toNumber(),
      torn: ring.header.add(RING.torn).readS64().toNumber(),
    };
  }

  /** Mark / clear a thread in the in-call table (calls.ts). Returns false when the table is full. */
  setCallTid(tid: ThreadId, inCall: boolean): boolean {
    const table = this.#callTids;
    if (table === null) return false;
    for (let i = 0; i < CALL_TID_SLOTS; i++) {
      const slot = table.add(4 * i);
      const v = slot.readU32();
      if (inCall && v === 0) {
        slot.writeU32(tid);
        return true;
      }
      if (!inCall && v === tid) {
        slot.writeU32(0);
        return true;
      }
    }
    return false;
  }
}
