// =================================================================================================
// src/agent/traceKernels.ts — the native Stalker kernels of trace_execution (S4 §12.3; WP9-WATCH): a TinyCC
// CModule with the block-count transform (block_counts mode, and on_call coverage gated per invocation) and the
// call-site transform (calls mode = the agent's call_summary). One CModule per trace instrument, so the gate extern
// is the instrument's own. VERIFIED on this host (WP9 lab, Frida 17.23.2): per-block callout data (S4 A-31),
// insn->id == X86_INS_CALL and insn->bytes (A-43), g_atomic_pointer_add, follow({data}) as transform user_data.
// Lab lesson: every native allocation the compiled code references (CModule, BeaBc, slab, gate) must stay alive
// until the thread has left Stalker's cache: an unfollowed thread blocked in a syscall still runs callouts when it
// returns, and a slab QJS had already freed corrupted the heap (target crash). KernelSet.release() is delayed.
// Review fixes AGENT-6/AGENT-8: the slab is RESERVED for `cap` entries (VirtualAlloc MEM_RESERVE) and committed one
// 16,384-entry chunk (384 KiB) at a time by the transform, so a trace of 20 blocks no longer commits cap × 24 bytes
// (23 MiB at the default max_events). release() closes the gate and zeroes `cap` at once (callouts and the transform
// then never touch the slab), and frees the slab after the settle delay; the CModule, gate and BeaBc (a few KiB) stay
// pinned for the agent's lifetime, because a thread that lingers in the stopped trace's translated code still runs
// its (gated) callouts, for as long as it lingers.
// =================================================================================================

/** Keep in sync with the struct below (1,320 bytes). */
const BC_LAYOUT = {
  slab: 0,
  used: 8,
  cap: 16,
  overflow: 24,
  nmods: 32,
  lo: 40,
  hi: 168,
  committed: 296,
  size: 1320,
  maxModules: 16,
  /** BeaBlock {start, end, count} and BeaSite {site, target, count}: 24 bytes */
  record: 24,
  /** entries per committed chunk (keep in sync with BEA_CHUNK_ENTRIES) and the chunk count (BeaBc.committed) */
  chunkEntries: 16_384,
  maxChunks: 256,
} as const;

const TRACE_KERNELS_C = `
#include <gum/gumstalker.h>

typedef struct { guint64 start; guint64 end; volatile gint64 count; } BeaBlock;
typedef struct { guint64 site; guint64 target; volatile gint64 count; } BeaSite;
typedef struct {
  gpointer slab;
  volatile gint64 used;
  volatile gint64 cap;
  volatile gint64 overflow;
  guint32 nmods;
  guint32 pad;
  guint64 lo[16];
  guint64 hi[16];
  volatile gint32 committed[256];
} BeaBc;

#define BEA_CHUNK_ENTRIES 16384
#define BEA_RECORD 24

/* 0 = closed: on_call between invocations, and for good once the trace stopped; thread-mode traces keep it open */
extern volatile gint32 bea_gate;
/* kernel32!VirtualAlloc: the slab is reserved up front and committed chunk by chunk on first use */
extern gpointer bea_commit (gpointer address, gsize size, guint32 type, guint32 protect);

/* The slab entry of index i (< cap), its chunk committed first; NULL when the commit failed. Two threads may commit
   the same chunk at once: committing committed pages is a no-op, so the race is benign. */
static gpointer
bea_entry (BeaBc * bc, gint64 i)
{
  guint64 k = ((guint64) i) / BEA_CHUNK_ENTRIES;
  guint8 * chunk = ((guint8 *) bc->slab) + k * (BEA_CHUNK_ENTRIES * BEA_RECORD);
  if (bc->committed[k] == 0)
  {
    if (bea_commit (chunk, BEA_CHUNK_ENTRIES * BEA_RECORD, 0x1000, 0x04) == NULL)
      return NULL;
    bc->committed[k] = 1;
  }
  return chunk + (((guint64) i) % BEA_CHUNK_ENTRIES) * BEA_RECORD;
}

static gboolean
bea_in_mods (BeaBc * bc, guint64 a)
{
  guint32 i;
  for (i = 0; i < bc->nmods; i++)
    if (a >= bc->lo[i] && a < bc->hi[i])
      return TRUE;
  return FALSE;
}

static void
bea_bc_hit (GumCpuContext * cpu, gpointer user_data)
{
  if (bea_gate == 0)
    return;
  g_atomic_pointer_add (&((BeaBlock *) user_data)->count, 1);
}

void
bea_bc_transform (GumStalkerIterator * it, GumStalkerOutput * out, gpointer user_data)
{
  BeaBc * bc = (BeaBc *) user_data;
  cs_insn * insn;
  gboolean first = TRUE;
  BeaBlock * cur = NULL;
  guint64 last = 0;
  while (gum_stalker_iterator_next (it, &insn))
  {
    if (first)
    {
      first = FALSE;
      if (bea_in_mods (bc, insn->address))
      {
        gint64 i = g_atomic_pointer_add (&bc->used, 1);
        BeaBlock * b = (i < bc->cap) ? (BeaBlock *) bea_entry (bc, i) : NULL;
        if (b != NULL)
        {
          cur = b;
          cur->start = insn->address;
          cur->end = insn->address;
          cur->count = 0;
          gum_stalker_iterator_put_callout (it, bea_bc_hit, cur, NULL);
        }
        else
          g_atomic_pointer_add (&bc->overflow, 1);
      }
    }
    last = insn->address + insn->size;
    gum_stalker_iterator_keep (it);
  }
  if (cur != NULL)
    cur->end = last;
}

static void
bea_cs_hit (GumCpuContext * cpu, gpointer user_data)
{
  if (bea_gate == 0)
    return;
  g_atomic_pointer_add (&((BeaSite *) user_data)->count, 1);
}

/* the callout goes BEFORE keep(), so calls that never return are counted */
void
bea_cs_transform (GumStalkerIterator * it, GumStalkerOutput * out, gpointer user_data)
{
  BeaBc * bc = (BeaBc *) user_data;
  cs_insn * insn;
  while (gum_stalker_iterator_next (it, &insn))
  {
    if (insn->id == X86_INS_CALL && bea_in_mods (bc, insn->address))
    {
      gint64 i = g_atomic_pointer_add (&bc->used, 1);
      BeaSite * s = (i < bc->cap) ? (BeaSite *) bea_entry (bc, i) : NULL;
      if (s != NULL)
      {
        s->site = insn->address;
        s->target = (insn->size == 5 && insn->bytes[0] == 0xe8)
            ? (guint64) ((gint64) insn->address + 5 + *(const gint32 *) (insn->bytes + 1))
            : 0;
        s->count = 0;
        gum_stalker_iterator_put_callout (it, bea_cs_hit, s, NULL);
      }
      else
        g_atomic_pointer_add (&bc->overflow, 1);
    }
    gum_stalker_iterator_keep (it);
  }
}
`;

export interface KernelSet {
  readonly transform: NativePointer;
  readonly bc: NativePointer;
  readonly gate: NativePointer;
  readonly cap: number;
  /** used entries (bounded by cap) */
  used(): number;
  overflow(): number;
  /** [a, b, count] per used entry (start/end or site/target); [] once released */
  entries(from: number): { index: number; a: bigint; b: bigint; count: bigint }[];
  setGate(open: boolean): void;
  /**
   * The trace stopped: the gate closes and `cap` drops to 0 at once (nothing touches the slab any more), and the slab
   * is freed `max(1000, 4 × settleMs)` ms later. The CModule, gate and BeaBc stay pinned (see the file header).
   */
  release(settleMs: number): void;
}

/** Module-level pin set (QJS frees what nothing references: VERIFIED crash otherwise). */
const pinned = new Set<object>();

const u64 = (v: bigint): UInt64 => uint64(BigInt.asUintN(64, v).toString());

const MEM_RESERVE = 0x2000;
const MEM_RELEASE = 0x8000;
const PAGE_READWRITE = 0x04;
let win: {
  readonly virtualAllocAt: NativePointer;
  readonly virtualAlloc: NativeFunction<NativePointer, [NativePointerValue, number, number, number]>;
  readonly virtualFree: NativeFunction<number, [NativePointerValue, number, number]>;
} | null = null;
const winApi = (): NonNullable<typeof win> => {
  if (win !== null) return win;
  const k32 = Process.getModuleByName("kernel32.dll");
  const virtualAllocAt = k32.getExportByName("VirtualAlloc");
  win = {
    virtualAllocAt,
    virtualAlloc: new NativeFunction(virtualAllocAt, "pointer", ["pointer", "size_t", "uint32", "uint32"], {
      scheduling: "exclusive",
    }),
    virtualFree: new NativeFunction(k32.getExportByName("VirtualFree"), "int", ["pointer", "size_t", "uint32"], {
      scheduling: "exclusive",
    }),
  };
  return win;
};

/** Entries the slab can hold: `cap` rounded up to whole chunks, at most maxChunks chunks. */
const slabEntries = (cap: number): number => {
  const chunks = Math.min(BC_LAYOUT.maxChunks, Math.max(1, Math.ceil(Math.max(1, cap) / BC_LAYOUT.chunkEntries)));
  return chunks * BC_LAYOUT.chunkEntries;
};

export const createKernels = (
  kind: "blocks" | "calls",
  ranges: readonly { readonly base: NativePointer; readonly size: number }[],
  cap: number,
  gateOpen: boolean,
): KernelSet => {
  const api = winApi();
  const capacity = Math.min(Math.max(1, cap), slabEntries(cap));
  // reserved only: the transform commits a chunk when its first entry is taken (bea_entry)
  const slab = api.virtualAlloc(NULL, slabEntries(cap) * BC_LAYOUT.record, MEM_RESERVE, PAGE_READWRITE);
  if (slab.isNull()) throw new Error("trace slab reservation failed");
  let cm: CModule;
  const gate = Memory.alloc(8);
  const bc = Memory.alloc(BC_LAYOUT.size);
  try {
    gate.writeS32(gateOpen ? 1 : 0);
    cm = new CModule(TRACE_KERNELS_C, { bea_gate: gate, bea_commit: api.virtualAllocAt });
  } catch (e) {
    api.virtualFree(slab, 0, MEM_RELEASE);
    throw e;
  }
  bc.writeByteArray(Array.from({ length: BC_LAYOUT.size }, () => 0));
  bc.add(BC_LAYOUT.slab).writePointer(slab);
  bc.add(BC_LAYOUT.cap).writeS64(capacity);
  const mods = ranges.slice(0, BC_LAYOUT.maxModules);
  bc.add(BC_LAYOUT.nmods).writeU32(mods.length);
  mods.forEach((r, i) => {
    const base = BigInt(r.base.toString());
    bc.add(BC_LAYOUT.lo + 8 * i).writeU64(u64(base));
    bc.add(BC_LAYOUT.hi + 8 * i).writeU64(u64(base + BigInt(r.size)));
  });
  for (const p of [cm, gate, bc]) pinned.add(p);
  const transform = kind === "blocks" ? cm["bea_bc_transform"] : cm["bea_cs_transform"];
  if (transform === undefined) throw new Error("trace kernel symbol missing");
  /** null once the slab was freed (release) */
  const held: { slab: NativePointer | null } = { slab };
  const used = (): number => Math.min(capacity, Math.max(0, bc.add(BC_LAYOUT.used).readS64().toNumber()));
  const committed = (chunk: number): boolean => bc.add(BC_LAYOUT.committed + 4 * chunk).readS32() !== 0;
  let released = false;
  return {
    transform,
    bc,
    gate,
    cap: capacity,
    used,
    overflow: () => bc.add(BC_LAYOUT.overflow).readS64().toNumber(),
    entries: (from) => {
      const out: { index: number; a: bigint; b: bigint; count: bigint }[] = [];
      const base = held.slab;
      if (base === null || released) return out;
      const n = used();
      for (let i = Math.max(0, from); i < n; i++) {
        const chunk = Math.floor(i / BC_LAYOUT.chunkEntries);
        if (!committed(chunk)) {
          i = (chunk + 1) * BC_LAYOUT.chunkEntries - 1; // a thread is committing it right now (or its commit failed)
          continue;
        }
        const e = base.add(i * BC_LAYOUT.record);
        out.push({
          index: i,
          a: BigInt(e.readU64().toString()),
          b: BigInt(e.add(8).readU64().toString()),
          count: BigInt(e.add(16).readS64().toString()),
        });
      }
      return out;
    },
    setGate: (open) => {
      if (!released) gate.writeS32(open ? 1 : 0);
    },
    release: (settleMs) => {
      if (released) return;
      released = true;
      gate.writeS32(0);
      bc.add(BC_LAYOUT.cap).writeS64(0);
      setTimeout(
        () => {
          const base = held.slab;
          held.slab = null;
          if (base !== null) winApi().virtualFree(base, 0, MEM_RELEASE);
        },
        Math.max(1000, settleMs * 4),
      );
    },
  };
};
