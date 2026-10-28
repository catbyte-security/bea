// =================================================================================================
// src/shared/callPlan.ts — the raw-bits Win64 call plan executed by BOTH the emulator bridge
// (bea-emu/0.1, S5 §4.4) and the live agent's exact-bits thunk (S5 §9.5). TypeScript on the host
// classifies the ABI once (src/domain/callModel); executors never interpret types.
// Pure TypeScript, staged into the agent build.
// =================================================================================================
import type { Hex, HexBytes } from "./hex.js";

export type GprName = "rcx" | "rdx" | "r8" | "r9";
export type ArgReg = GprName | "xmm0" | "xmm1" | "xmm2" | "xmm3" | "stack";

export interface SlotWire {
  reg: ArgReg;
  /** Stack slot k (position 4+k): 8 bytes at [rsp + 0x28 + 8k] on entry. */
  stackIndex?: number;
  /** Variadic float at position < 4: also load the integer register. */
  dupGpr?: GprName;
  source:
    | { kind: "column"; column: string } // vectors.columns[column][i]: 64-bit extended bits
    | { kind: "const"; bits: Hex }
    | { kind: "buffer"; buffer: string; offset: number } // pointer = address(buffer) + offset
    | { kind: "byval"; buffer: string }; // size 1/2/4/8: the buffer bytes as an integer
}

export interface BufferWire {
  name: string;
  size: number;
  align: number;
  placement: "scratch" | "heap";
  /** `size` bytes: init + field defaults (codecs already applied by the host). */
  template: HexBytes;
  /** count > 1: array cell. Column cells are 64-bit-extended bits written with `width` bytes. */
  columns: Array<{ column: string; offset: number; width: 1 | 2 | 4 | 8; count: number }>;
  ptrFields: Array<{ offset: number; buffer: string; plus: number }>;
  out: boolean;
}

export type ReturnWire =
  | { kind: "void" }
  | { kind: "int"; width: 1 | 2 | 4 | 8 }
  | { kind: "f32" }
  | { kind: "f64" }
  | { kind: "struct"; size: number; via: "rax" | "hidden"; buffer?: string };

export interface PlanWire {
  /** VA in the executor's address space (emulator image or live process). */
  target: Hex;
  /** A hidden-return pointer is already slot 0 when present. */
  slots: SlotWire[];
  returns: ReturnWire;
  buffers: BufferWire[];
}

export interface VectorsWire {
  offset: number;
  count: number;
  columns: Record<string, Hex[] | Hex[][]>;
}

export type CallStatus =
  | "returned"
  | "fault"
  | "cpu_exception"
  | "invalid_instruction"
  | "unsupported_instruction"
  | "unhandled_import"
  | "syscall"
  | "raised"
  | "terminated"
  | "budget_exhausted"
  | "timeout"
  | "cancelled"
  | "engine_error";
export type StatusCode =
  | "ok"
  | "fault"
  | "cpu"
  | "inv"
  | "unsup"
  | "imp"
  | "sys"
  | "raised"
  | "term"
  | "budget"
  | "timeout"
  | "cancel"
  | "eng";
export type Attribution = "target" | "harness";

/** Executor-neutral raw batch columns (live agent and bridge alike); decoded by callModel.decodeOutcome. */
export interface RawBatchColumns {
  completed: number;
  status: StatusCode[];
  rax: Hex[];
  /** Low 64 bits of XMM0 per vector (f32 in the low 32). */
  xmm0lo: Hex[];
  /** Out-buffer bytes after each call, by buffer name. */
  out: Record<string, HexBytes[]>;
  mxcsrOut: Hex[];
  fpcwOut: Hex[];
}
