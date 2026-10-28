// =================================================================================================
// src/agent/pure/coreWin64.ts — WP3-AGENT pure helpers: Windows x64 structure offsets and decoding (S4 §5.6, §7.4,
// §10.3, F13). CONTEXT, EXCEPTION_RECORD, MEMORY_BASIC_INFORMATION, page protections, NTSTATUS → exception type,
// and the Win64 argument-slot mapping. Offsets marked VERIFIED come from the S4 lab / ext-frida; the rest are winnt.h
// (BELIEVED, S4 A-11) and are exercised by the WP3 acceptance tests (registers of a crash report).
// =================================================================================================
import type { ExceptionType } from "../../shared/agentProtocol.js";
import { readLeBigint, readLeU16, readLeU32 } from "./coreHex.js";

/** CONTEXT (AMD64) layout: total 0x4D0 bytes, 16-byte aligned. */
export const CTX = {
  size: 0x4d0,
  ContextFlags: 0x30, // VERIFIED
  MxCsr: 0x34, // VERIFIED
  EFlags: 0x44, // VERIFIED (u32)
  Dr0: 0x48, // VERIFIED (Dr1..3 follow at +8 each)
  Dr6: 0x68, // VERIFIED
  Dr7: 0x70, // VERIFIED
  Rax: 0x78, // VERIFIED
  Rcx: 0x80,
  Rdx: 0x88,
  Rbx: 0x90,
  Rsp: 0x98, // VERIFIED
  Rbp: 0xa0,
  Rsi: 0xa8,
  Rdi: 0xb0,
  R8: 0xb8, // R9..R15 follow at +8 each
  Rip: 0xf8, // VERIFIED
  FltControlWord: 0x100, // VERIFIED (u16, XMM_SAVE_AREA32.ControlWord)
  FltMxCsr: 0x118,
  Xmm0: 0x1a0, // 16 × 16 bytes
} as const;

export const CONTEXT_AMD64 = 0x100000;
export const CONTEXT_FLAGS = {
  control: CONTEXT_AMD64 | 0x1,
  integer: CONTEXT_AMD64 | 0x2,
  segments: CONTEXT_AMD64 | 0x4,
  floatingPoint: CONTEXT_AMD64 | 0x8,
  debugRegisters: CONTEXT_AMD64 | 0x10,
  full: CONTEXT_AMD64 | 0x1 | 0x2 | 0x8,
  all: CONTEXT_AMD64 | 0x1f,
} as const;

/** The CrashReport / FaultInfo register record order. */
export const GPR_NAMES = [
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "rbp",
  "rsp",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "rip",
] as const;
export type GprName = (typeof GPR_NAMES)[number];

const GPR_OFFSETS: Readonly<Record<GprName, number>> = {
  rax: CTX.Rax,
  rcx: CTX.Rcx,
  rdx: CTX.Rdx,
  rbx: CTX.Rbx,
  rsp: CTX.Rsp,
  rbp: CTX.Rbp,
  rsi: CTX.Rsi,
  rdi: CTX.Rdi,
  r8: CTX.R8,
  r9: CTX.R8 + 8,
  r10: CTX.R8 + 16,
  r11: CTX.R8 + 24,
  r12: CTX.R8 + 32,
  r13: CTX.R8 + 40,
  r14: CTX.R8 + 48,
  r15: CTX.R8 + 56,
  rip: CTX.Rip,
};

export interface ParsedContext {
  readonly gpr: Readonly<Record<GprName, bigint>>;
  readonly eflags: number;
  readonly mxcsr: number;
  readonly fpcw: number;
  readonly dr: readonly [bigint, bigint, bigint, bigint];
  readonly dr6: bigint;
  readonly dr7: bigint;
  /** xmm0..15 as 16-byte slices */
  readonly xmm: readonly Uint8Array[];
}

/** Decode a raw CONTEXT copy (≥ 0x4D0 bytes). */
export const parseContext = (bytes: Uint8Array): ParsedContext => {
  const gpr = {} as Record<GprName, bigint>;
  for (const name of GPR_NAMES) gpr[name] = readLeBigint(bytes, GPR_OFFSETS[name], 8);
  const xmm: Uint8Array[] = [];
  for (let i = 0; i < 16; i++) xmm.push(bytes.slice(CTX.Xmm0 + 16 * i, CTX.Xmm0 + 16 * i + 16));
  return {
    gpr,
    eflags: readLeU32(bytes, CTX.EFlags),
    mxcsr: readLeU32(bytes, CTX.MxCsr),
    fpcw: readLeU16(bytes, CTX.FltControlWord),
    dr: [
      readLeBigint(bytes, CTX.Dr0, 8),
      readLeBigint(bytes, CTX.Dr0 + 8, 8),
      readLeBigint(bytes, CTX.Dr0 + 16, 8),
      readLeBigint(bytes, CTX.Dr0 + 24, 8),
    ],
    dr6: readLeBigint(bytes, CTX.Dr6, 8),
    dr7: readLeBigint(bytes, CTX.Dr7, 8),
    xmm,
  };
};

/** Offset of a GPR inside CONTEXT (for single reads through a NativePointer). */
export const contextOffsetOf = (name: GprName): number => GPR_OFFSETS[name];

/** EXCEPTION_RECORD (x64) offsets, VERIFIED (F13). */
export const EXR = { code: 0x0, flags: 0x4, address: 0x10, numberParameters: 0x18, information: 0x20 } as const;
export const EXCEPTION_MAXIMUM_PARAMETERS = 15;

/** NTSTATUS of an exception → the GumJS exception type vocabulary. */
export const exceptionTypeOfStatus = (code: number): ExceptionType => {
  switch (code >>> 0) {
    case 0xc0000005:
    case 0xc0000006: // in-page error
      return "access-violation";
    case 0x80000001:
      return "guard-page";
    case 0xc000001d:
    case 0xc0000096: // privileged instruction
      return "illegal-instruction";
    case 0xc00000fd:
      return "stack-overflow";
    case 0x80000003:
      return "breakpoint";
    case 0x80000004:
      return "single-step";
    case 0xc0000409: // fast fail (never reaches user handlers, listed for completeness)
    case 0x40000015: // STATUS_FATAL_APP_EXIT (abort)
      return "abort";
    default:
      return isArithmeticStatus(code >>> 0) ? "arithmetic" : "system";
  }
};

const isArithmeticStatus = (code: number): boolean =>
  (code >= 0xc000008c && code <= 0xc0000095) || code === 0xc00002b4 || code === 0xc00002b5;

/** ExceptionInformation[0] of an access violation → operation (0 read, 1 write, 8 execute). */
export const memoryOperationOf = (info0: bigint): "read" | "write" | "execute" | null =>
  info0 === 0n ? "read" : info0 === 1n ? "write" : info0 === 8n ? "execute" : null;

/** MEMORY_BASIC_INFORMATION (x64, 48 bytes). */
export const MBI = {
  size: 48,
  BaseAddress: 0x0,
  AllocationBase: 0x8,
  AllocationProtect: 0x10,
  RegionSize: 0x18,
  State: 0x20,
  Protect: 0x24,
  Type: 0x28,
} as const;
export const MEM_COMMIT = 0x1000;
export const MEM_RESERVE = 0x2000;
export const MEM_FREE = 0x10000;

export interface Mbi {
  readonly base: bigint;
  readonly allocationBase: bigint;
  readonly regionSize: bigint;
  readonly state: number;
  readonly protect: number;
  readonly type: number;
}

export const parseMbi = (bytes: Uint8Array): Mbi => ({
  base: readLeBigint(bytes, MBI.BaseAddress, 8),
  allocationBase: readLeBigint(bytes, MBI.AllocationBase, 8),
  regionSize: readLeBigint(bytes, MBI.RegionSize, 8),
  state: readLeU32(bytes, MBI.State),
  protect: readLeU32(bytes, MBI.Protect),
  type: readLeU32(bytes, MBI.Type),
});

export const PAGE = {
  NOACCESS: 0x01,
  READONLY: 0x02,
  READWRITE: 0x04,
  WRITECOPY: 0x08,
  EXECUTE: 0x10,
  EXECUTE_READ: 0x20,
  EXECUTE_READWRITE: 0x40,
  EXECUTE_WRITECOPY: 0x80,
  GUARD: 0x100,
  NOCACHE: 0x200,
  WRITECOMBINE: 0x400,
} as const;

const BASE_PROTECT_MASK = 0xff;

/** Frida-style "rwx" text of a PAGE_* value (modifiers ignored; NOACCESS → "---"). */
export const protectionText = (protect: number): string => {
  switch (protect & BASE_PROTECT_MASK) {
    case PAGE.READONLY:
      return "r--";
    case PAGE.READWRITE:
    case PAGE.WRITECOPY:
      return "rw-";
    case PAGE.EXECUTE:
      return "--x";
    case PAGE.EXECUTE_READ:
      return "r-x";
    case PAGE.EXECUTE_READWRITE:
    case PAGE.EXECUTE_WRITECOPY:
      return "rwx";
    default:
      return "---";
  }
};

export const isReadableProtect = (protect: number): boolean => protectionText(protect).startsWith("r");
export const isGuardProtect = (protect: number): boolean => (protect & PAGE.GUARD) !== 0;
/** The protection with PAGE_GUARD added / removed. */
export const withGuard = (protect: number): number => protect | PAGE.GUARD;
export const withoutGuard = (protect: number): number => protect & ~PAGE.GUARD;

/**
 * What a BEA guard toggle writes, given the page's CURRENT protection `cur` (VirtualQuery right before the write) and
 * the wanted PAGE_GUARD state: "unchanged" when the page already is in that state (nothing is written), else `cur`
 * with the guard added or removed. Review fix AGENT-2: BEA never writes back a protection it remembered. The target
 * may have re-protected the page since (VirtualProtect also drops the guard), and restoring the remembered value undid
 * that (a write to a page the target had made writable then faulted, and a stopped watch left the old protection
 * behind). PAGE_NOACCESS takes no guard (VirtualProtect refuses the combination): "refused".
 */
export const guardToggle = (cur: number, want: boolean): number | "unchanged" | "refused" => {
  if (isGuardProtect(cur) === want) return "unchanged";
  if (want && (cur & BASE_PROTECT_MASK) === PAGE.NOACCESS) return "refused";
  return want ? withGuard(cur) : withoutGuard(cur);
};

/** The target changed the page's protection since BEA recorded `orig` (guard bits ignored on both sides). */
export const reprotectedSince = (orig: number, cur: number): boolean => withoutGuard(cur) !== withoutGuard(orig);

/** Where a Win64 positional argument lives at function entry (S4 §10.3; VERIFIED for slots 0..5 incl. floats). */
export type SlotSource =
  | { readonly kind: "reg"; readonly reg: "rcx" | "rdx" | "r8" | "r9" }
  | { readonly kind: "xmm"; readonly index: number }
  | { readonly kind: "stack"; readonly rspOffset: number };

const INT_REGS = ["rcx", "rdx", "r8", "r9"] as const;

/** Slot → source with the hidden return pointer shift (`p = slot + 1`). Stack slots: [rsp + 8 + 8*p] at entry. */
export const slotSource = (slot: number, cls: "int" | "float", hiddenRetPtr: boolean): SlotSource => {
  const p = slot + (hiddenRetPtr ? 1 : 0);
  if (p < 4) return cls === "float" ? { kind: "xmm", index: p } : { kind: "reg", reg: INT_REGS[p]! };
  return { kind: "stack", rspOffset: 8 + 8 * p };
};

/** THREAD_BASIC_INFORMATION.TebBaseAddress (+0x8) and NT_TIB stack bounds (S4 §5.6, A-10). */
export const TEB = {
  basicInfoSize: 0x30,
  tebBaseInBasicInfo: 0x8,
  stackBase: 0x8,
  stackLimit: 0x10,
  peb: 0x60,
  tlsPointer: 0x58,
  tlsSlots: 0x1480,
} as const;

/** OpenThread access masks (S4 §5.5). */
export const THREAD_ACCESS = {
  getContext: 0x8,
  suspendResume: 0x2,
  queryLimited: 0x800,
} as const;
