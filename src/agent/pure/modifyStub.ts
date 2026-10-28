// Win64 replace stub for override_function mode replace (WP12-MODIFY; S4 §14 + §13.4). Pure: bytes only, no Frida.
//
// Interceptor.replaceFast(target, stub) sends every call of `target` here with the caller's registers and stack
// untouched. The stub asks `decide()` (a NativeCallback: registered, active, not a bypassing BEA call, `when`, max_hits)
// whether this call gets the constant; otherwise it tail-jumps to the original through replaceFast's trampoline with
// the argument registers (rcx, rdx, r8, r9, xmm0–xmm3) and the stack exactly as the caller left them. That is how the
// agent-call bypass (call_function overrides:"bypass"), `when` filters and the end of the lifetime reach the original
// without knowing the function's argument types.
//
//   push rcx / rdx / r8 / r9            ; entry rsp ≡ 8 (mod 16); +32 → ≡ 8
//   sub  rsp, 0x68                      ; → ≡ 0: 0x20 shadow, xmm0–3 at +0x20..+0x5f, 8 bytes padding
//   movdqu [rsp+0x20+16*i], xmm<i>      ; i = 0..3
//   mov  rax, decide ; call rax
//   movdqu xmm<i>, [rsp+0x20+16*i]
//   add  rsp, 0x68 ; pop r9 / r8 / rdx / rcx
//   test eax, eax ; jz original
//   [mov rax, bits] [movq xmm0, rax] ret ; the constant (void: just ret; floats: low lane of xmm0)
// original:
//   mov r11, slot ; jmp qword ptr [r11] ; slot: a data qword holding the trampoline; r11 is volatile, no argument
//
// The code never changes once the target is patched (it is r-x before replaceFast runs); only the data slot is filled
// afterwards with the trampoline replaceFast returned.

const FRAME = 0x68;
const XMM_BASE = 0x20;

const imm64 = (value: bigint): number[] => {
  const out: number[] = [];
  let v = BigInt.asUintN(64, value);
  for (let i = 0; i < 8; i++) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return out;
};

/** movdqu [rsp+disp8], xmm<reg> (store) or movdqu xmm<reg>, [rsp+disp8] (load). */
const movdqu = (store: boolean, reg: number): number[] => [
  0xf3,
  0x0f,
  store ? 0x7f : 0x6f,
  0x44 | (reg << 3), // mod 01, reg, rm 100 (SIB)
  0x24, // SIB: base rsp, no index
  XMM_BASE + 16 * reg,
];

export interface ReplaceStubSpec {
  /** address of the decide() NativeCallback: int (*)(void), nonzero = return the constant */
  readonly decide: bigint;
  /** address of a qword (data page) that holds replaceFast's trampoline to the original function */
  readonly originalSlot: bigint;
  /** the constant's raw bits (null for a void replacement) */
  readonly bits: bigint | null;
  /** f32/f64: the constant goes to the low lane of xmm0 (rax as well, harmlessly) */
  readonly float: boolean;
}

/** Machine code of the replace stub (position independent: every target is an absolute 64-bit immediate). */
export const replaceStubBytes = (spec: ReplaceStubSpec): Uint8Array => {
  const constant: number[] = [];
  if (spec.bits !== null) {
    constant.push(0x48, 0xb8, ...imm64(spec.bits)); // mov rax, imm64
    if (spec.float) constant.push(0x66, 0x48, 0x0f, 0x6e, 0xc0); // movq xmm0, rax
  }
  constant.push(0xc3); // ret
  const code = [
    0x51, // push rcx
    0x52, // push rdx
    0x41,
    0x50, // push r8
    0x41,
    0x51, // push r9
    0x48,
    0x83,
    0xec,
    FRAME, // sub rsp, 0x68
    ...[0, 1, 2, 3].flatMap((reg) => movdqu(true, reg)),
    0x48,
    0xb8,
    ...imm64(spec.decide), // mov rax, decide
    0xff,
    0xd0, // call rax
    ...[0, 1, 2, 3].flatMap((reg) => movdqu(false, reg)),
    0x48,
    0x83,
    0xc4,
    FRAME, // add rsp, 0x68
    0x41,
    0x59, // pop r9
    0x41,
    0x58, // pop r8
    0x5a, // pop rdx
    0x59, // pop rcx
    0x85,
    0xc0, // test eax, eax
    0x74,
    constant.length, // jz original
    ...constant,
    0x49,
    0xbb,
    ...imm64(spec.originalSlot), // mov r11, slot
    0x41,
    0xff,
    0x23, // jmp qword ptr [r11]
  ];
  return Uint8Array.from(code);
};
