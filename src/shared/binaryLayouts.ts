// =================================================================================================
// src/shared/binaryLayouts.ts — fixed little-endian record layouts for binary stream batches (S4 §6.4).
// The stream descriptor (src/ports/evidence.ts StreamDescriptor.encoding) copies these field tables.
// =================================================================================================
import type { BinaryLayout, LayoutId } from "./agentProtocol.js";

const u64 = (name: string, offset: number) => ({ name, offset, type: "u64" as const });

export const BINARY_LAYOUTS: { readonly [K in LayoutId]: BinaryLayout & { id: K } } = {
  "hook-native/1": {
    id: "hook-native/1",
    rec_bytes: 160,
    endian: "le",
    fields: [
      u64("g", 0),
      u64("t", 8),
      { name: "tid", offset: 16, type: "u32" },
      { name: "hook_index", offset: 20, type: "u16" },
      { name: "phase", offset: 22, type: "u8" },
      { name: "depth", offset: 23, type: "u8" },
      u64("ret_addr", 24),
      u64("rcx", 32),
      u64("rdx", 40),
      u64("r8", 48),
      u64("r9", 56),
      u64("xmm0", 64),
      u64("xmm1", 72),
      u64("xmm2", 80),
      u64("xmm3", 88),
      u64("s4", 96),
      u64("s5", 104),
      u64("s6", 112),
      u64("s7", 120),
      u64("rax", 128),
      u64("xmm0_ret", 136),
      u64("reserved", 144), // phase-2 records: leave time in µs since agent load (call duration); 0 otherwise
      u64("commit", 152),
    ],
    notes:
      "native hook tier; int slot k<4 -> rcx..r9, float slot k<4 -> xmmK (f32 = low 4 bytes), slot>=4 -> s[k-4]; ret float -> xmm0_ret else rax; t = us since agent load; reserved = leave t (us) on phase-2 records, else 0",
  },
  "block-span/1": {
    id: "block-span/1",
    rec_bytes: 16,
    endian: "le",
    fields: [u64("start", 0), u64("end", 8)],
    notes: "coverage mode: unique compiled blocks, deduped in the agent",
  },
  "block-count/1": {
    id: "block-count/1",
    rec_bytes: 24,
    endian: "le",
    fields: [u64("start", 0), u64("end", 8), u64("count", 16)],
    notes: "block_counts snapshots; recompiled blocks repeat, the host sums counts by start",
  },
  "call-site-count/1": {
    id: "call-site-count/1",
    rec_bytes: 24,
    endian: "le",
    fields: [u64("site", 0), u64("target", 8), u64("count", 16)],
    notes: "call_summary snapshots; target 0 = indirect",
  },
  "gum-event-x64/1": {
    id: "gum-event-x64/1",
    rec_bytes: 32,
    endian: "le",
    fields: [
      { name: "type", offset: 0, type: "u32" },
      u64("a", 8),
      u64("b", 16),
      { name: "depth", offset: 24, type: "i32" },
    ],
    notes:
      "raw GumEvent passthrough (call_events mode); field layout BELIEVED (S4 A-13), self-checked at the first batch",
  },
};
