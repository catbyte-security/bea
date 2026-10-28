// =================================================================================================
// src/agent/pure/callBlock.ts — the oracle thunk page and CallBlock layout (DESIGN §5.3.1; S5 §9.5).
// Pure: no GumJS globals or types (importable by vitest; staged into the agent build).
// =================================================================================================
import type { ExceptionType } from "../../shared/agentProtocol.js";

/** CallBlock (0x200 bytes, little endian). S5 layout + the rev. 2 exception record in the free tail. */
export const CALL_BLOCK = {
  size: 0x200,
  target: 0x00,
  /** rcx, rdx, r8, r9 */
  gpr: 0x08,
  /** xmm0..xmm3, 16 bytes each */
  xmm: 0x28,
  nstack: 0x68,
  /** status bits cleared (& 0xFFC0) */
  mxcsrIn: 0x70,
  fpcwIn: 0x74,
  raxOut: 0x78,
  xmm0Out: 0x80,
  mxcsrOut: 0x90,
  fpcwOut: 0x94,
  savedMxcsr: 0x98,
  savedFpcw: 0x9c,
  /** stack_args[≤ 28], copied to [rsp+0x20+8k] before the call ([rsp+0x28+8k] on callee entry) */
  stack: 0xa0,
  maxStack: 28,
  /** 0 not run, 1 returned, 2 exception caught by the thunk's SEH frame */
  status: 0x180,
  code: 0x184,
  flags: 0x188,
  nparams: 0x18c,
  exceptionAddress: 0x190,
  /** ExceptionInformation[0..2] */
  info: 0x198,
  faultRip: 0x1b0,
  faultRsp: 0x1b8,
} as const;

/** @public */
export const STATUS_NOT_RUN = 0;
export const STATUS_RETURNED = 1;
export const STATUS_CAUGHT = 2;

/**
 * The SEH-frame thunk page (0x200 bytes; the rest of the 4 KiB page is zero): thunk 0x000–0x0BD, language handler
 * `bea_call_eh` 0x0C0–0x19A (its imm64 at 0x190 is patched with ntdll!RtlUnwindEx at load), FP-env read/restore
 * stubs 0x1A0/0x1B0, UNWIND_INFO 0x1C0/0x1D0, RUNTIME_FUNCTION[2] 0x1E0. Generated and verified instruction by
 * instruction (capstone) by bea-lab/design-revise/seh_page.py; VERIFIED in [REV-lab R1].
 *
 * Review fix EMU-5: the recovery label (0x0BA) runs `fninit` (db e3), not `fnclex` (db e2), before it jumps to the
 * FP-env restore at 0x0A6: a callee that faults with values on the x87 stack (MinGW long double, x87 libm, MMX without
 * EMMS) would otherwise leave them on the calling thread, and a later x87 callee on that thread overflows the stack and
 * returns the indefinite NaN as a normal result. fninit empties the tag word and resets TOP and the status word; the
 * `fldcw [rbx+0x9c]` at 0x0AD then puts the caller's control word back over fninit's default 0x37F. The steal
 * fallback's restore stub (0x1B0) starts with the same `fninit` (it now ends at 0x1BF, before UNWIND_INFO). Same
 * length, so no offset moved; re-verified with capstone.
 */
export const SEH_PAGE_HEX = [
  "53554889e548894d184889cb0fae9b98000000d9bb9c0000000fae9370000000d9ab74000000488b4b684883ec084889",
  "c848c1e0034883c00f4883e0f04829c44883ec2031d24839ca7312488b84d3a0000000488944d42048ffc2ebe9f30f6f",
  "4328f30f6f4b38f30f6f5348f30f6f5b58488b4b08488b53104c8b43184c8b4b20ff1348894378f30f7f83800000000f",
  "ae9b90000000d9bb94000000c78380010000010000000fae9398000000d9ab9c000000488d65005d5bc3dbe3ebe80000",
  "4883ec38f6410466740ab8010000004883c438c3488b4218c7808001000002000000448b1144899084010000448b5104",
  "44899088010000448b51184489908c0100004c8b51104c8990900100004c8b51204c8990980100004c8b51284c8990a0",
  "0100004c8b51304c8990a80100004d8b90f80000004c8990b00100004d8b90980000004c8990b8010000458b50344489",
  "9090000000450fb790000100006644899094000000498b41284889442420498b414048894424284d8b51084981c2ba00",
  "0000448b094989c84889d14c89d248b80000000000000000ffd0cc00000000000fae19d97904c3000000000000000000",
  "dbe30fae9198000000d9a99c000000c3090503050503025001300000c000000001040100046200000000000000000000",
  "00000000be000000c0010000c00000009b010000d00100000000000000000000",
].join("");

/** sha256 of SEH_PAGE_HEX with the imm64 zeroed (DESIGN §5.3.1), pinned by a unit test. */
export const SEH_PAGE_SHA256 = "8a9a4e83a720e84b8b2be255a9ab9577950cfa157dcc1b7f65433334ea55b9e5";

export const SEH_PAGE = {
  thunk: 0x000,
  thunkEnd: 0x0be,
  /** return address of `call [rbx]` inside the thunk (RtlLookupFunctionEntry probe) */
  callReturn: 0x083,
  restore: 0x0a6,
  recovery: 0x0ba,
  handler: 0x0c0,
  handlerEnd: 0x19b,
  rtlUnwindExImm: 0x190,
  readStub: 0x1a0,
  restoreStub: 0x1b0,
  unwindThunk: 0x1c0,
  unwindHandler: 0x1d0,
  table: 0x1e0,
  tableEntries: 2,
} as const;

export const hexToByteArray = (hex: string): number[] =>
  Array.from({ length: hex.length / 2 }, (_, i) => Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16));

/** NTSTATUS -> the ExceptionType vocabulary of exception rows and FaultInfo (Frida's names). */
export const exceptionTypeOf = (code: number): ExceptionType => {
  switch (code >>> 0) {
    case 0xc0000005:
    case 0xc0000006:
      return "access-violation";
    case 0x80000001:
      return "guard-page";
    case 0xc000001d:
    case 0xc0000096:
      return "illegal-instruction";
    case 0xc00000fd:
      return "stack-overflow";
    case 0x80000003:
      return "breakpoint";
    case 0x80000004:
      return "single-step";
    case 0xc0000409:
      return "abort";
    default:
      return code >>> 0 >= 0xc000008d && code >>> 0 <= 0xc0000095 ? "arithmetic" : "system";
  }
};

/** ExceptionInformation[0] of an access violation: 0 read, 1 write, 8 execute (DEP). */
export const memoryOperationOf = (info0: number): "read" | "write" | "execute" =>
  info0 === 1 ? "write" : info0 === 8 ? "execute" : "read";

/** Win64 GPR order of the CallBlock. */
export const GPR_ORDER = ["rcx", "rdx", "r8", "r9"] as const;
export const XMM_ORDER = ["xmm0", "xmm1", "xmm2", "xmm3"] as const;
