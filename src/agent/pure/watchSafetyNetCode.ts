// =================================================================================================
// src/agent/pure/watchSafetyNetCode.ts — the attached-session safety net's machine code and data-page layout
// (DESIGN §5.3, CT-I4; WP9-WATCH). The source is tests/unit/watch/agent/safetyNet.S; the unit test assembles it with
// the host gcc and compares it byte for byte with SAFETY_NET_CODE (named skip without gcc). Pure data: no GumJS.
//
// Listing (objdump -d -M intel; the data page is code + 0x1000):
//   00 mov rax,[rcx] / 03 mov r8,[rcx+8]       EXCEPTION_RECORD*, CONTEXT*
//   07 lea r9,[rip+0xff2]                      data page
//   0e mov edx,[rax]; 10 cmp 0x80000004 → 23   STATUS_SINGLE_STEP
//   18 cmp 0x80000001 → 8a                     STATUS_GUARD_PAGE_VIOLATION
//   20 xor eax,eax; ret                        EXCEPTION_CONTINUE_SEARCH
//   23 Dr6 & slot_mask & 0xf == 0 → 57         else Dr7 &= ~dr7_clear, Dr6 &= ~0xf,
//                                              ContextFlags |= CONTEXT_DEBUG_REGISTERS, hits_dr++, return -1
//   57 tid = gs:[0x48]; scan tf_tids[n_tf]     listed → EFlags &= ~TF, hits_tf++, return -1; else → 20
//   8a page = ExceptionInformation[1] & ~0xfff; scan guard_pages[n_guard]
//                                              listed → hits_guard++, return -1; else → 20
// =================================================================================================

/** 184 bytes; EXCEPTION_CONTINUE_EXECUTION = -1, EXCEPTION_CONTINUE_SEARCH = 0. */
export const SAFETY_NET_CODE_HEX =
  "488b014c8b41084c8d0df20f00008b1081fa04000080740b81fa01000080746a31c0c34d8b5068458b59044d21d34183e30f74234d8b5130" +
  "49f7d24d21507049836068f04181483010001000f049ff4110b8ffffffffc365448b142548000000418b490c4d8d994002000085c974b1ff" +
  "c94539148b75f441816044fffefffff049ff4118b8ffffffffc34c8b50284981e200f0ffff418b49084d8d594085c90f847bffffffffc94d" +
  "3914cb75f0f049ff4120b8ffffffffc3";

export const SAFETY_NET_CODE: Uint8Array = Uint8Array.from(SAFETY_NET_CODE_HEX.match(/../gu) ?? [], (pair) =>
  Number.parseInt(pair, 16),
);

/** The code page; the data page starts exactly one page later (RIP-relative `lea r9`). */
export const SAFETY_NET_DATA_OFFSET = 0x1000;
/** VirtualAlloc size: one code page + one data page. */
export const SAFETY_NET_ALLOC_BYTES = 0x2000;

/** Offsets inside the data page. */
export const SAFETY_NET_LAYOUT = {
  magic: 0x000,
  slotMask: 0x004,
  nGuard: 0x008,
  nTf: 0x00c,
  hitsDr: 0x010,
  hitsTf: 0x018,
  hitsGuard: 0x020,
  dr7Clear: 0x030,
  guardPages: 0x040,
  tfTids: 0x240,
} as const;
/** 'BEAS' little-endian. */
export const SAFETY_NET_MAGIC = 0x53414542;

/** Win32 constants the installer uses. */
export const WIN32 = {
  MEM_COMMIT: 0x1000,
  MEM_RESERVE: 0x2000,
  PAGE_READWRITE: 0x04,
  PAGE_EXECUTE_READ: 0x20,
  PAGE_GUARD: 0x100,
  STATUS_SINGLE_STEP: 0x80000004,
  STATUS_GUARD_PAGE_VIOLATION: 0x80000001,
} as const;
