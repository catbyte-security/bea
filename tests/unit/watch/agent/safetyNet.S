# BEA attached-session safety net (DESIGN §5.3, CT-I4; WP9-WATCH). Assembled by tests/unit/watch/agent/safetyNet.test.ts
# with the host gcc and compared byte for byte with SAFETY_NET_CODE in src/agent/pure/watchSafetyNetCode.ts.
#
# LONG CALLBACK veh(EXCEPTION_POINTERS *ep)  (rcx = ep). Registered LAST with AddVectoredExceptionHandler(0, veh) in
# VirtualAlloc'd memory that is never freed; its data page follows the code page (code + 0x1000):
#   +0x000 u32 magic 'BEAS'   +0x004 u32 slot_mask   +0x008 u32 n_guard   +0x00c u32 n_tf
#   +0x010 u64 hits_dr        +0x018 u64 hits_tf     +0x020 u64 hits_guard +0x030 u64 dr7_clear
#   +0x040 u64 guard_pages[64]                       +0x240 u32 tf_tids[64]
# Frida's exceptor (a vectored handler registered before this one) and BEA's dispatcher consume BEA traps while the
# agent is loaded, so this handler only sees what is left after an abrupt unload: a BEA debug-register slot firing (DR6
# B-bits in slot_mask), a trap-flag
# step owed to BEA (thread listed in tf_tids) or a guard-page fault on a page BEA guarded. Everything else is passed on.
        .intel_syntax noprefix
        .text
        .globl  bea_safety_net
bea_safety_net:
        mov     rax, qword ptr [rcx]            # EXCEPTION_RECORD*
        mov     r8, qword ptr [rcx + 8]         # CONTEXT*
        lea     r9, [rip + bea_safety_net + 0x1000]
        mov     edx, dword ptr [rax]            # ExceptionCode
        cmp     edx, 0x80000004                 # STATUS_SINGLE_STEP
        je      .Lstep
        cmp     edx, 0x80000001                 # STATUS_GUARD_PAGE_VIOLATION
        je      .Lguard
.Lpass:
        xor     eax, eax                        # EXCEPTION_CONTINUE_SEARCH
        ret
.Lstep:
        mov     r10, qword ptr [r8 + 0x68]      # Dr6
        mov     r11d, dword ptr [r9 + 4]        # slot_mask
        and     r11, r10
        and     r11d, 0xf
        jz      .Ltf
        mov     r10, qword ptr [r9 + 0x30]      # dr7_clear
        not     r10
        and     qword ptr [r8 + 0x70], r10      # Dr7 &= ~dr7_clear (every BEA slot of this thread)
        and     qword ptr [r8 + 0x68], -16      # Dr6 &= ~0xf
        or      dword ptr [r8 + 0x30], 0x100010 # ContextFlags |= CONTEXT_DEBUG_REGISTERS
        lock inc qword ptr [r9 + 0x10]          # hits_dr++
        mov     eax, -1                         # EXCEPTION_CONTINUE_EXECUTION
        ret
.Ltf:
        mov     r10d, dword ptr gs:[0x48]       # TEB.ClientId.UniqueThread
        mov     ecx, dword ptr [r9 + 0xc]       # n_tf
        lea     r11, [r9 + 0x240]               # tf_tids
.Ltf_loop:
        test    ecx, ecx
        jz      .Lpass
        dec     ecx
        cmp     dword ptr [r11 + rcx*4], r10d
        jne     .Ltf_loop
        and     dword ptr [r8 + 0x44], -257     # EFlags &= ~TF
        lock inc qword ptr [r9 + 0x18]          # hits_tf++
        mov     eax, -1
        ret
.Lguard:
        mov     r10, qword ptr [rax + 0x28]     # ExceptionInformation[1] = faulting address
        and     r10, -4096
        mov     ecx, dword ptr [r9 + 8]         # n_guard
        lea     r11, [r9 + 0x40]                # guard_pages
.Lg_loop:
        test    ecx, ecx
        jz      .Lpass
        dec     ecx
        cmp     qword ptr [r11 + rcx*8], r10
        jne     .Lg_loop
        lock inc qword ptr [r9 + 0x20]          # hits_guard++
        mov     eax, -1
        ret
