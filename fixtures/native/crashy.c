/* BEA fixture crashy.exe: deterministic crashes and handled exceptions for crash-capture tests.
 * Build (scripts/build-fixtures.mjs): gcc -O2 -fno-optimize-sibling-calls -Wno-infinite-recursion
 *                                     -Wl,--no-insert-timestamp -o crashy.exe crashy.c
 * Every faulting instruction sits in an exported function (crash_write, crash_read, crash_exec, crash_div0,
 * crash_illegal, crash_recurse), so a crash report's pc.sym resolves to an exact export (DESIGN §8.1, CI-M26).
 *
 * Usage: crashy.exe <mode> [--delay-ms D] [--thread]
 *   av-write | av-read | av-exec | div0 | illegal | stack-overflow | fastfail | handled | abort | exit:<code>
 *   --delay-ms D  sleep D ms after printing READY before acting (default 300)
 *   --thread      perform the crash on a second thread (crash tid != main tid)
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))

EXPORT volatile int *volatile g_bad_ptr = NULL;       /* hidden from the optimizer: no isolate-paths trap */
EXPORT volatile int *volatile g_low_ptr = (volatile int *)(uintptr_t)0x10;
EXPORT volatile int g_zero = 0;
EXPORT volatile int g_after = 0;
static const char *g_mode = "";

EXPORT NOINLINE void crash_write(volatile int *p) { *p = 0x2A; }
EXPORT NOINLINE int crash_read(volatile int *p) { return *p; }
EXPORT NOINLINE int crash_div0(int a, int b) { return a / b; }
/* DEP: executes a fresh read-write page; the fault pc is the page, the faulting call is crash_exec */
EXPORT NOINLINE void crash_exec(void)
{
    void *page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ((unsigned char *)page)[0] = 0xC3;
    ((void (*)(void))page)();
    g_after++;
}
EXPORT NOINLINE void crash_illegal(void) { __builtin_trap(); } /* ud2 -> 0xC000001D */
EXPORT NOINLINE void level1(volatile int *p) { crash_write(p); g_after++; }
EXPORT NOINLINE void level2(volatile int *p) { level1(p); g_after++; }
EXPORT NOINLINE int crash_recurse(int n)
{
    volatile char buf[4096];
    buf[0] = (char)n;
    return crash_recurse(n + 1) + buf[0];
}

static int do_crash(void)
{
    if (!strcmp(g_mode, "av-write")) level2(g_bad_ptr);
    else if (!strcmp(g_mode, "av-read")) g_after += crash_read(g_low_ptr);
    else if (!strcmp(g_mode, "av-exec")) crash_exec(); /* DEP: execute access violation */
    else if (!strcmp(g_mode, "div0")) g_after += crash_div0(7, g_zero);
    else if (!strcmp(g_mode, "illegal")) crash_illegal();
    else if (!strcmp(g_mode, "stack-overflow")) g_after += crash_recurse(0);
    else if (!strcmp(g_mode, "fastfail")) __asm__ volatile("int $0x29" ::"c"(7)); /* __fastfail(7): no user handlers */
    else if (!strcmp(g_mode, "handled")) {
        for (int i = 0; i < 10; i++) g_after += IsBadReadPtr((const void *)(ULONG_PTR)0x10, 4); /* first-chance AVs */
        printf("HANDLED count=10\n");
        return 0;
    } else if (!strcmp(g_mode, "abort")) abort();
    else if (!strncmp(g_mode, "exit:", 5)) return atoi(g_mode + 5);
    else { fprintf(stderr, "unknown mode %s\n", g_mode); return 2; }
    return 1;
}
static DWORD WINAPI crash_thread_main(LPVOID p) { (void)p; return (DWORD)do_crash(); }

int main(int argc, char **argv)
{
    DWORD delay = 300;
    int on_thread = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: crashy <mode> [--delay-ms D] [--thread]\n"); return 2; }
    g_mode = argv[1];
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--delay-ms") && i + 1 < argc) delay = (DWORD)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--thread")) on_thread = 1;
    }
    printf("READY pid=%lu mode=%s\n", GetCurrentProcessId(), g_mode);
    Sleep(delay);
    if (on_thread) {
        HANDLE t = CreateThread(NULL, 0, crash_thread_main, NULL, 0, NULL);
        WaitForSingleObject(t, INFINITE);
        DWORD code = 0;
        GetExitCodeThread(t, &code);
        return (int)code;
    }
    return do_crash();
}
