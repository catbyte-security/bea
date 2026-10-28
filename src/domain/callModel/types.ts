import type { ArgReg, Attribution, CallStatus, GprName } from "../../shared/callPlan.js";
import type { Hex } from "../../shared/hex.js";

/**
 * Leg-independent Win64 call plan (S5 §7.4). Produced once by classifyWin64 (WP-CALL) and lowered per leg by
 * planToWire (emulator) / planToAgent (live thunk). Every value is raw bits (bigint) until lowering.
 */
export type CallScalarType =
  | "i8"
  | "u8"
  | "i16"
  | "u16"
  | "i32"
  | "u32"
  | "i64"
  | "u64"
  | "ptr"
  | "bool"
  | "f32"
  | "f64";

export interface NormalizedBuffer {
  readonly name: string;
  readonly size: number;
  readonly align: number;
  readonly placement: "scratch" | "heap";
  /** template bytes with defaults and codecs applied */
  readonly template: Uint8Array;
  readonly columns: readonly {
    readonly column: string;
    readonly offset: number;
    readonly width: 1 | 2 | 4 | 8;
    readonly count: number;
  }[];
  /** ptr_to fields; `buffer` is resolved per leg to that buffer's address */
  readonly ptrFields: readonly { readonly offset: number; readonly buffer: string; readonly plus: number }[];
  readonly out: boolean;
  readonly codecs: readonly {
    readonly field: string;
    readonly offset: number;
    readonly width: 1 | 2 | 4 | 8;
    readonly kind: "xor" | "add" | "mul";
    readonly key: bigint;
  }[];
}

export interface CallPlan {
  readonly slots: readonly {
    readonly position: number;
    readonly reg: ArgReg;
    readonly stackIndex?: number;
    readonly dupGpr?: GprName;
    readonly source:
      | { readonly kind: "column"; readonly column: string; readonly type: CallScalarType }
      | { readonly kind: "const"; readonly bits: bigint; readonly type: CallScalarType }
      | { readonly kind: "address-const"; readonly expr: string } // ptr given as an AddrExpr: resolved per leg
      | { readonly kind: "buffer"; readonly buffer: string; readonly offset: number }
      | { readonly kind: "byval"; readonly buffer: string };
  }[];
  readonly returns:
    | { readonly kind: "void" }
    | { readonly kind: "int"; readonly type: CallScalarType; readonly width: 1 | 2 | 4 | 8 }
    | { readonly kind: "f32" }
    | { readonly kind: "f64" }
    | { readonly kind: "struct"; readonly size: number; readonly via: "rax" | "hidden"; readonly buffer: string };
  /** includes synthetic "__ret" and "__byval_<i>" buffers */
  readonly buffers: readonly NormalizedBuffer[];
  readonly columns: readonly {
    readonly name: string;
    readonly type: CallScalarType | `${CallScalarType}[]`;
    readonly count: number;
  }[];
}

export interface NormalizedVectors {
  readonly count: number;
  /** only per-vector columns (constants live in the plan); 64-bit-extended bits */
  readonly columns: Readonly<Record<string, readonly Hex[] | readonly (readonly Hex[])[]>>;
  /** sha256(JCS({count, columns})); enters Evidence identity */
  readonly digest: string;
  readonly source:
    | { readonly kind: "inline" }
    | { readonly kind: "generated"; readonly seed: number; readonly spec_digest: string }
    | { readonly kind: "recording"; readonly recording_id: string; readonly head_digest: string };
}

/** value: f32/f64 number or "NaN"/"Infinity"/"-Infinity"/"-0"; i64/u64 decimal string; ptr hex; bool boolean. */
export interface TypedValue {
  readonly type: CallScalarType;
  readonly bits: Hex;
  readonly value: number | string | boolean | null;
}

/** Produced by the emulator leg (BatchResult) and the live leg (CallFunctionResult.raw) alike (S5 §7.5). */
export interface CallOutcomeColumns {
  readonly count: number;
  readonly offset: number;
  readonly status: readonly CallStatus[];
  readonly attribution: readonly (Attribution | null)[];
  readonly ret: readonly Hex[] | null;
  readonly fields: Readonly<Record<string, readonly Hex[] | readonly (readonly Hex[])[]>>;
  readonly faults: readonly {
    readonly index: number;
    readonly status: CallStatus;
    readonly attribution: Attribution;
    readonly cause: string;
    readonly site: { readonly module: string | null; readonly rva: Hex | null };
  }[];
  readonly fp_after?: { readonly mxcsr_control: readonly Hex[]; readonly fpcw: readonly Hex[] };
}
