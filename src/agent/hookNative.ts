// =================================================================================================
// src/agent/hookNative.ts — WP7-HOOK native hook tier (S4 §10.4, layout hook-native/1 of S4 §6.4).
// One CModule (compiled once, pinned forever) holds the C listener pair and the ring collector. Every native hook
// owns a BeaNativeHook struct + a power-of-two ring of 160-byte records; target threads write records with an
// atomic head and a per-index commit tag, the agent JS thread copies committed records into a staging buffer
// (bea_hn_collect) and sends them as binary batches. No JS runs per call (≈ 0.2 µs per hit, [ext-frida §1.9]).
//
// Commit protocol (agent-internal): a writer stores commit = 0, then the record, then commit = TAG|index. The
// collector accepts a record only when the commit word equals TAG|index both before AND after copying it, so a
// lapping writer is detected (counted `torn_record`) instead of delivering mixed data. Copied records carry the
// published constant 0xbea0bea0bea0bea0 in `commit`. Field `reserved` (+144) carries the leave timestamp (µs) of
// phase-2 records (dur_us); 0 otherwise.
// =================================================================================================
import type { NativeField, NativePlan } from "./pure/hookPlan.js";

export const NATIVE_REC_BYTES = 160;
const STRUCT_BYTES = 256;

/** BeaNativeHook field offsets (all 8-byte slots; see the C struct below). */
const OFF = {
  ring: 0,
  mask: 8,
  head: 16,
  tail: 24,
  hits: 32,
  maxHits: 40,
  everyN: 48,
  active: 56,
  flags: 64,
  hookIndex: 72,
  nthreads: 80,
  overrun: 88,
  torn: 96,
  suppressed: 104,
  sampledOut: 112,
  recorded: 120,
  leaves: 128,
  threads: 136,
} as const;

export const FLAG_EMIT_ENTER = 1;
const FLAG_THREAD_FILTER = 2;
const FLAG_OBSERVE_AGENT_CALLS = 4;

const nativeSource = (withXmm: boolean): string => `
#include <gum/guminterceptor.h>
#include <glib.h>

#define BEA_HAS_XMM ${withXmm ? 1 : 0}
#define BEA_TAG 0xbea0000000000000ULL
#define BEA_IDX 0x0000ffffffffffffULL
#define BEA_PUBLISHED 0xbea0bea0bea0bea0ULL
#define BEA_BARRIER() __asm__ __volatile__ ("" : : : "memory")
#define BEA_LOAD(p) (*(volatile guint64 *) (p))
#define BEA_STORE(p, v) (*(volatile guint64 *) (p) = (guint64) (v))
/* doubles convert through gint64: TinyCC has no helper for double -> unsigned 64-bit (__fixunsdfdi) */

extern double bea_next_g (void);
extern double bea_now_us (void);
extern int bea_in_agent_call (guint32 tid);

typedef struct {
  guint64 ring; guint64 mask; volatile gint64 head; gint64 tail;
  volatile gint64 hits; gint64 max_hits; guint64 every_n; volatile gint64 active;
  guint64 flags; guint64 hook_index; guint64 nthreads;
  volatile gint64 overrun; volatile gint64 torn; volatile gint64 suppressed; volatile gint64 sampled_out;
  volatile gint64 recorded; volatile gint64 leaves;
  guint32 threads[16];
} BeaNativeHook;

typedef struct { guint64 g, t, ra, w[4], x[4], s[4]; guint64 depth; guint64 record; } BeaInv;

static void bea_put (BeaNativeHook * h, BeaInv * inv, guint64 phase, guint64 tid, guint64 rax, guint64 xr, guint64 tleave)
{
  gint64 idx = (gint64) g_atomic_pointer_add (&h->head, 1);
  guint64 * r = (guint64 *) (h->ring + ((guint64) idx & h->mask) * ${NATIVE_REC_BYTES});
  int k;
  BEA_STORE (&r[19], 0);
  BEA_BARRIER ();
  r[0] = inv->g;
  r[1] = inv->t;
  r[2] = (tid & 0xffffffffULL) | ((h->hook_index & 0xffffULL) << 32) | (phase << 48) | ((inv->depth & 0xffULL) << 56);
  r[3] = inv->ra;
  for (k = 0; k < 4; k++) { r[4 + k] = inv->w[k]; r[8 + k] = inv->x[k]; r[12 + k] = inv->s[k]; }
  r[16] = rax;
  r[17] = xr;
  r[18] = tleave;
  BEA_BARRIER ();
  BEA_STORE (&r[19], BEA_TAG | ((guint64) idx & BEA_IDX));
  g_atomic_pointer_add (&h->recorded, 1);
}

void bea_hn_enter (GumInvocationContext * ic)
{
  BeaNativeHook * h = GUM_IC_GET_FUNC_DATA (ic, BeaNativeHook *);
  BeaInv * inv = GUM_IC_GET_INVOCATION_DATA (ic, BeaInv);
  GumCpuContext * c = ic->cpu_context;
  guint64 tid;
  gint64 hit;
  int k;
  inv->record = 0;
  if (BEA_LOAD (&h->active) == 0) return;
  tid = (guint64) gum_invocation_context_get_thread_id (ic);
  if ((h->flags & ${FLAG_OBSERVE_AGENT_CALLS}) == 0 && bea_in_agent_call ((guint32) tid)) { g_atomic_pointer_add (&h->suppressed, 1); return; }
  if (h->flags & ${FLAG_THREAD_FILTER}) {
    guint64 i; int found = 0;
    for (i = 0; i < h->nthreads && i < 16; i++) if ((guint64) h->threads[i] == tid) { found = 1; break; }
    if (!found) return;
  }
  hit = (gint64) g_atomic_pointer_add (&h->hits, 1) + 1;
  if (h->max_hits > 0 && hit > h->max_hits) { BEA_STORE (&h->active, 0); return; }
  if (h->every_n > 1 && ((guint64) (hit - 1) % h->every_n) != 0) { g_atomic_pointer_add (&h->sampled_out, 1); return; }
  inv->record = 1;
  inv->g = (guint64) (gint64) bea_next_g ();
  inv->t = (guint64) (gint64) bea_now_us ();
  inv->ra = (guint64) gum_invocation_context_get_return_address (ic);
  inv->depth = (guint64) gum_invocation_context_get_depth (ic);
  inv->w[0] = c->rcx; inv->w[1] = c->rdx; inv->w[2] = c->r8; inv->w[3] = c->r9;
  for (k = 0; k < 4; k++) {
#if BEA_HAS_XMM
    inv->x[k] = *(guint64 *) ((guint8 *) &c->xmm[0] + k * sizeof (c->xmm[0])); /* GumX86VectorReg union: low 8 bytes */
#else
    inv->x[k] = 0;
#endif
    inv->s[k] = (guint64) gum_invocation_context_get_nth_argument (ic, 4 + k);
  }
  if (h->flags & ${FLAG_EMIT_ENTER}) bea_put (h, inv, 1, tid, 0, 0, 0);
}

void bea_hn_leave (GumInvocationContext * ic)
{
  BeaNativeHook * h = GUM_IC_GET_FUNC_DATA (ic, BeaNativeHook *);
  BeaInv * inv = GUM_IC_GET_INVOCATION_DATA (ic, BeaInv);
  GumCpuContext * c = ic->cpu_context;
  guint64 xr = 0;
  if (!inv->record || (h->flags & ${FLAG_EMIT_ENTER})) return;
#if BEA_HAS_XMM
  xr = *(guint64 *) &c->xmm[0];
#endif
  bea_put (h, inv, 2, (guint64) gum_invocation_context_get_thread_id (ic), c->rax, xr, (guint64) (gint64) bea_now_us ());
  g_atomic_pointer_add (&h->leaves, 1);
}

guint64 bea_hn_collect (BeaNativeHook * h, guint8 * out, guint64 max)
{
  gint64 head = (gint64) BEA_LOAD (&h->head);
  gint64 tail = h->tail;
  gint64 cap = (gint64) h->mask + 1;
  guint64 n = 0;
  int k;
  if (head - tail > cap) { h->overrun += head - tail - cap; tail = head - cap; }
  while (tail < head && n < max) {
    guint64 * r = (guint64 *) (h->ring + ((guint64) tail & h->mask) * ${NATIVE_REC_BYTES});
    guint64 want = BEA_TAG | ((guint64) tail & BEA_IDX);
    guint64 c1 = BEA_LOAD (&r[19]);
    guint64 * o = (guint64 *) (out + n * ${NATIVE_REC_BYTES});
    if (c1 != want) {
      if (c1 != 0 && (c1 & BEA_IDX) > ((guint64) tail & BEA_IDX)) { h->torn++; tail++; continue; }
      if (head - tail > cap / 2) { h->torn++; tail++; continue; }
      break;
    }
    BEA_BARRIER ();
    for (k = 0; k < 19; k++) o[k] = r[k];
    BEA_BARRIER ();
    if (BEA_LOAD (&r[19]) != want) { h->torn++; tail++; continue; }
    o[19] = BEA_PUBLISHED;
    n++;
    tail++;
  }
  h->tail = tail;
  return n;
}
`;

/** Core CModule symbols a feature CModule links against (WP3 `core.native.symbols`, CORE_EXTERN_DECLS). */
export interface NativeSymbols {
  readonly bea_next_g: NativePointer;
  readonly bea_now_us: NativePointer;
  /** int bea_in_agent_call(guint32 tid): a BEA oracle call runs on tid (agentCallTids for CModule listeners, CT-M2) */
  readonly bea_in_agent_call: NativePointer;
}

export interface NativeStats {
  readonly hits: number;
  readonly recorded: number;
  readonly leaves: number;
  readonly overrun: number;
  readonly torn: number;
  readonly suppressed: number;
  readonly sampledOut: number;
  readonly active: boolean;
}

const FIELD_INDEX: Readonly<Record<NativeField, number>> = {
  w0: 0,
  w1: 1,
  w2: 2,
  w3: 3,
  x0: 0,
  x1: 1,
  x2: 2,
  x3: 3,
  s4: 0,
  s5: 1,
  s6: 2,
  s7: 3,
};
/** For diagnostics (arg_map): which record offset a native field lands in. */
export const nativeFieldOffset = (field: NativeField): number =>
  (field.startsWith("w") ? 32 : field.startsWith("x") ? 64 : 96) + 8 * FIELD_INDEX[field];

/**
 * One native hook: struct + ring + staging. The struct (a few hundred bytes, the listener's function data) stays pinned
 * for the session; the ring (native_ring_records × 160 B, 5 MiB by default, up to 40 MiB) and the staging buffer
 * (batch_max_bin_bytes) are dropped by dispose() once the hook has been detached and has settled (review fix AGENT-5:
 * every install + stop kept about 6 MiB in the target for the rest of the session).
 */
export class NativeHook {
  readonly #collect: NativeFunction<number | UInt64, [NativePointerValue, NativePointerValue, number | UInt64]>;
  #staging: NativePointer | null;
  readonly #stagingRecords: number;
  readonly struct: NativePointer;
  #ring: NativePointer | null;
  /** ring + staging bytes while they are held (status().memory.ring_bytes) */
  readonly bytes: number;
  readonly callbacks: { readonly onEnter: NativePointer; readonly onLeave: NativePointer };

  constructor(
    tier: NativeHookTier,
    init: {
      readonly hookIndex: number;
      readonly ringRecords: number;
      readonly stagingRecords: number;
      readonly maxHits: number;
      readonly everyN: number;
      readonly emitAtEnter: boolean;
      readonly observeAgentCalls: boolean;
      readonly plan: NativePlan;
    },
  ) {
    const records = 1 << Math.max(4, Math.ceil(Math.log2(Math.max(16, init.ringRecords))));
    const ring = Memory.alloc(records * NATIVE_REC_BYTES);
    this.#ring = ring;
    this.struct = Memory.alloc(STRUCT_BYTES);
    this.#stagingRecords = Math.max(1, Math.min(init.stagingRecords, records));
    this.#staging = Memory.alloc(this.#stagingRecords * NATIVE_REC_BYTES);
    this.bytes = (records + this.#stagingRecords) * NATIVE_REC_BYTES;
    const s = this.struct;
    s.add(OFF.ring).writePointer(ring);
    s.add(OFF.mask).writeU64(records - 1);
    s.add(OFF.maxHits).writeS64(init.maxHits);
    s.add(OFF.everyN).writeU64(Math.max(1, init.everyN));
    const flags =
      (init.emitAtEnter ? FLAG_EMIT_ENTER : 0) |
      (init.plan.threads.length > 0 ? FLAG_THREAD_FILTER : 0) |
      (init.observeAgentCalls ? FLAG_OBSERVE_AGENT_CALLS : 0);
    s.add(OFF.flags).writeU64(flags);
    s.add(OFF.hookIndex).writeU64(init.hookIndex & 0xffff);
    s.add(OFF.nthreads).writeU64(Math.min(16, init.plan.threads.length));
    init.plan.threads.slice(0, 16).forEach((tid, i) => s.add(OFF.threads + 4 * i).writeU32(tid));
    s.add(OFF.active).writeS64(1);
    this.callbacks = tier.callbacks;
    this.#collect = tier.collectFn;
  }

  /** Copy committed records (≤ staging size) into a fresh ArrayBuffer; null when nothing is pending (or disposed). */
  collect(): { readonly data: ArrayBuffer; readonly records: number } | null {
    const staging = this.#staging;
    if (staging === null || this.#ring === null) return null;
    const raw = this.#collect(this.struct, staging, this.#stagingRecords);
    const n = typeof raw === "number" ? raw : raw.toNumber();
    if (n === 0) return null;
    const data = staging.readByteArray(n * NATIVE_REC_BYTES);
    return data === null ? null : { data, records: n };
  }

  /**
   * Drop the ring and staging buffers (QJS frees them with their last reference). Only after deactivate + detach +
   * Interceptor.flush + the final collect and a settle delay: a callback that passed the `active` check just before
   * deactivate may still be writing. The struct keeps its (now dangling) ring pointer: callbacks check `active` first,
   * and it stays 0, so nothing reads the pointer again.
   */
  dispose(): void {
    this.#ring = null;
    this.#staging = null;
  }

  stats(): NativeStats {
    const s = this.struct;
    return {
      hits: s.add(OFF.hits).readS64().toNumber(),
      recorded: s.add(OFF.recorded).readS64().toNumber(),
      leaves: s.add(OFF.leaves).readS64().toNumber(),
      overrun: s.add(OFF.overrun).readS64().toNumber(),
      torn: s.add(OFF.torn).readS64().toNumber(),
      suppressed: s.add(OFF.suppressed).readS64().toNumber(),
      sampledOut: s.add(OFF.sampledOut).readS64().toNumber(),
      active: !s.add(OFF.active).readS64().equals(0),
    };
  }

  /** Stops recording (the listener stays until detached; late callbacks return at their first check). */
  deactivate(): void {
    this.struct.add(OFF.active).writeS64(0);
  }
}

/** The compiled tier (one per agent). */
export class NativeHookTier {
  readonly withXmm: boolean;
  readonly callbacks: { readonly onEnter: NativePointer; readonly onLeave: NativePointer };
  readonly collectFn: NativeFunction<number | UInt64, [NativePointerValue, NativePointerValue, number | UInt64]>;
  /** CModule + extern cells: referenced from module scope forever (QJS frees unreferenced code, S4 §5.4). */
  readonly #keep: unknown[] = [];

  private constructor(cm: CModule, withXmm: boolean, keep: unknown[]) {
    this.withXmm = withXmm;
    this.#keep.push(cm, ...keep);
    const enter = cm["bea_hn_enter"];
    const leave = cm["bea_hn_leave"];
    const collect = cm["bea_hn_collect"];
    if (enter === undefined || leave === undefined || collect === undefined)
      throw new Error("native hook tier: CModule symbols missing");
    this.callbacks = { onEnter: enter, onLeave: leave };
    this.collectFn = new NativeFunction(collect, "uint64", ["pointer", "pointer", "uint64"], {
      scheduling: "exclusive",
    });
  }

  /** Compile with xmm access first (feature hooks.native.xmm), else without it. Throws when neither compiles. */
  static compile(symbols: NativeSymbols): NativeHookTier {
    const externs = {
      bea_next_g: symbols.bea_next_g,
      bea_now_us: symbols.bea_now_us,
      bea_in_agent_call: symbols.bea_in_agent_call,
    };
    let lastError: unknown = null;
    for (const withXmm of [true, false]) {
      try {
        return new NativeHookTier(new CModule(nativeSource(withXmm), externs), withXmm, []);
      } catch (e) {
        lastError = e;
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
  }
}

// ------------------------------------------------------------------------------------------------ standalone clock
/**
 * Fallback for agents whose core exports no clock symbols (S4 §5.4): a tiny CModule with the atomic row sequence, a
 * g_get_monotonic_time µs clock (WP3 found TinyCC mis-compiles int64 × double, so no QPC scaling) and an empty
 * in-call table, reachable from JS (exclusive NativeFunctions) and from the native tier (symbols).
 */
export class StandaloneClock {
  readonly symbols: NativeSymbols;
  readonly nextG: () => number;
  readonly nowUs: () => number;
  readonly #keep: unknown[];

  constructor() {
    const cells = Memory.alloc(16 + 4 * 64);
    const cm = new CModule(
      `
#include <glib.h>
extern volatile gint64 bea_cells[2];
extern volatile guint32 bea_tids[64];
double bea_next_g (void) { return (double) ((gint64) g_atomic_pointer_add (&bea_cells[0], 1) + 1); }
void bea_clock_init (void) { bea_cells[1] = g_get_monotonic_time (); }
double bea_now_us (void) { return (double) (g_get_monotonic_time () - bea_cells[1]); }
int bea_in_agent_call (guint32 tid) { int i; for (i = 0; i != 64; i++) if (bea_tids[i] == tid) return 1; return 0; }
`,
      { bea_cells: cells, bea_tids: cells.add(16) },
    );
    const sym = (name: string): NativePointer => {
      const p = cm[name] as NativePointer | undefined;
      if (p === undefined) throw new Error(`standalone clock: ${name} missing`);
      return p;
    };
    new NativeFunction(sym("bea_clock_init"), "void", [], { scheduling: "exclusive" })();
    this.symbols = {
      bea_next_g: sym("bea_next_g"),
      bea_now_us: sym("bea_now_us"),
      bea_in_agent_call: sym("bea_in_agent_call"),
    };
    const nextFn = new NativeFunction(this.symbols.bea_next_g, "double", [], { scheduling: "exclusive" });
    const nowFn = new NativeFunction(this.symbols.bea_now_us, "double", [], { scheduling: "exclusive" });
    this.nextG = () => nextFn();
    this.nowUs = () => nowFn();
    this.#keep = [cm, cells];
  }

  /** keep-alive reference for module scope (QJS frees unreferenced CModules) */
  get pinned(): number {
    return this.#keep.length;
  }
}
