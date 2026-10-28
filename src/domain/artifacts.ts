// =================================================================================================
// src/domain/artifacts.ts — on-disk artifact formats shared across work packages (types only; WP0).
// bea.dump/1 (S5 §10.1; producer WP-DUMP owns the zod schema + verifyDumpBundle in src/domain/dumpBundle.ts;
// consumer WP-EMU) and bea.coverage/1 (S5 §11.4; producers WP-EMU and WP-WATCH, consumer export_coverage).
// =================================================================================================
import type { Hex } from "../shared/hex.js";

/** bea.dump/1 bundle manifest: <bundle>/manifest.json (JCS) + regions/<sha256>.bin */
export interface DumpManifestV1 {
  schema: "bea.dump/1";
  bundle_id: `dump_${string}`; // "dump_" + sha256(JCS(manifest without bundle_id))
  created_at: string; // ISO-8601 UTC (part of the identity: a capture is a moment)
  producer: {
    tool: "bea";
    version: string;
    operation: "dump_memory";
    evidence_id: `ev_${string}` | null;
    instance_id: `pi_${string}` | null;
  };
  process: {
    pid: number;
    image_path: string;
    image_sha256: string | null;
    arch: "x64";
    os: { platform: "windows"; version: string };
  };
  capture: {
    mode: "running" | "suspended" | "at_hook";
    time_anchor: { seq: number; effect_epoch: number; module_map_epoch: number } | null;
    duration_ms: number;
    trigger?: {
      // mode "at_hook" only
      kind: "hook";
      target: { va: Hex; module: string; rva: Hex };
      thread_id: number;
      call: {
        gpr: { rcx: Hex; rdx: Hex; r8: Hex; r9: Hex };
        xmm: [Hex, Hex, Hex, Hex] /* 128-bit */;
        rsp: Hex;
        stack: Hex[] /* qwords at [rsp+0x28+8k], ≤ 28 */;
      };
      ret?: { rax: Hex; xmm0: Hex }; // filled by onLeave when requested
    };
  };
  modules: Array<{
    name: string;
    path: string;
    base: Hex;
    size: number;
    file_sha256: string | null;
    preferred_base: Hex | null;
    timestamp: number | null;
    captured: "full" | "partial" | "none";
  }>;
  regions: Array<{
    base: Hex;
    size: number;
    protection: string;
    tag: "module" | "heap" | "stack" | "teb" | "peb" | "tls" | "kuser_shared_data" | "range";
    module: string | null;
    sha256: string;
    complete: boolean;
    unreadable_pages: Hex[];
  }>;
  memory_map: Array<{ base: Hex; size: number; protection: string; module: string | null }>; // readable ranges only
  threads: Array<{
    tid: number;
    primary: boolean;
    teb: Hex;
    context: Record<
      | "rip"
      | "rsp"
      | "rbp"
      | "rax"
      | "rbx"
      | "rcx"
      | "rdx"
      | "rsi"
      | "rdi"
      | "r8"
      | "r9"
      | "r10"
      | "r11"
      | "r12"
      | "r13"
      | "r14"
      | "r15",
      Hex
    > & {
      xmm?: Hex[];
      // Integrator (implement stage, WP13 change request): the captured thread's real RFLAGS/MXCSR/FPCW (S4 §15.1),
      // so the emulator does not fall back to the 0x1F80/0x27F defaults. Absent in bundles that predate them.
      rflags?: Hex;
      mxcsr?: Hex;
      fpcw?: Hex;
    };
    stack: { base: Hex; limit: Hex } | null;
    tls: {
      slots_array: Hex | null;
      static_blocks: Array<{ module: string; index: number; address: Hex; size: number }>;
    };
  }>;
  peb: Hex | null;
  imports: Array<{
    importer: string;
    slot: Hex;
    name: string | null;
    ordinal: number | null;
    dll: string;
    target: Hex;
  }>;
  limitations: string[];
}

/** bea.coverage/1 blob (application/json): module-relative block coverage, ASLR-independent. */
export interface CoverageBlobV1 {
  schema: "bea.coverage/1";
  source:
    | {
        kind: "emulation";
        engine: "unicorn";
        granularity: "translation-block";
        session_id: string;
        evidence_id: string | null;
        vectors: number;
      }
    | {
        kind: "stalker";
        granularity: "stalker-block";
        session_id: string;
        evidence_id: string | null;
        thread_ids: number[];
      };
  address_space: "emulation-image" | "emulation-dump" | "live";
  modules: Array<{
    id: number;
    name: string;
    path: string | null;
    base: Hex;
    size: number;
    file_sha256: string | null;
    preferred_base: Hex | null;
    entry_rva: Hex | null;
    timestamp: number | null;
  }>;
  blocks: Array<[moduleId: number, rva: number, size: number, hits: number]>; // sorted by (moduleId, rva); size ≤ 65535
  unattributed: Array<[va: Hex, size: number, hits: number]>; // outside modules (stub and synthetic regions excluded)
  totals: { distinct_blocks: number; executions: number; truncated: boolean };
}
