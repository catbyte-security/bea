/* BEA fixture vehcommit.exe: an ASan-like allocator that commits its memory on demand (BEA-FEEDBACK.md item 4).
 *
 * Worker threads allocate from a bump allocator over a reserved, uncommitted arena. The allocator holds its lock (an
 * SRW lock, which is not re-entrant) while it writes each block header, so the first write to every new page faults
 * with the lock held. The program's own vectored exception handler commits that page and resumes the thread, the way
 * the ASan runtime commits its shadow memory on Win64. A tool whose first-chance exception handler runs on the
 * faulting thread therefore runs while the allocator lock is held. The handler is registered LAST (First=0), so an
 * instrumentation handler registered with First=1 (Frida's) sees every fault first, before or after the program
 * started. Main prints a heartbeat; the workers call the exported vc_hot after every allocation (a hook target).
 *
 * Build (scripts/lib/fixtures.mjs): gcc -O2 -Wl,--no-insert-timestamp -o vehcommit.exe vehcommit.c
 *
 * Flags:
 *   --threads N        worker threads (1..16, default 4)
 *   --seconds S        exit 0 after S seconds (0 = run until killed; default 0)
 *   --heartbeat-ms M   heartbeat period (10..10000, default 100)
 *   --intercept-crt    model ASan's interception of the CRT: load dbghelp.dll and route its CRT heap imports (malloc,
 *                      calloc, realloc, free, ... and their _o_ variants) through the allocator lock first. Walking a
 *                      stack with dbghelp on a faulting allocator thread then deadlocks on the lock that thread
 *                      already holds, which is the ASan deadlock BEA-FEEDBACK.md item 4 describes.
 *   --asan-shadow      publish the arena base in the exported __asan_shadow_memory_dynamic_address, like an
 *                      executable linked with the static ASan runtime (the arena then lies in the "shadow" range)
 *   --wait-stdin       start the workers only after a line (or EOF) on stdin. Attach tests use it: injecting Frida
 *                      17.23.2 into a process that already faults ~10^5 times per second crashed it during the
 *                      injection in 4 of 5 attempts, with or without BEA's agent.
 *
 * Output, one WriteFile per line: "READY pid=<pid> arena=<p> threads=<n> crt=<hooked imports>", "GO" once the workers
 * start, then every heartbeat "HEARTBEAT n=<allocations> commits=<pages committed> crt=<CRT heap calls through the
 * hook> ms=<since GO>", and "DONE n=<allocations>" when --seconds runs out.
 * Exports: vc_hot, g_progress, g_commits, g_crt_calls, g_arena, __asan_shadow_memory_dynamic_address.
 */
#include <windows.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))

#define ARENA_BYTES (64u << 20)
#define PAGE_BYTES 0x1000u
#define MAX_HOOKS 24

EXPORT volatile LONG64 g_progress = 0;   /* allocations completed by every worker */
EXPORT volatile LONG64 g_commits = 0;    /* pages the vectored handler committed */
EXPORT volatile LONG64 g_crt_calls = 0;  /* CRT heap calls dbghelp made through the --intercept-crt hook */
EXPORT uint8_t *volatile g_arena = NULL;
/* A static-runtime ASan executable exports this; BEA reads it to find the shadow range (--asan-shadow sets it). */
EXPORT volatile uintptr_t __asan_shadow_memory_dynamic_address = 0;

static SRWLOCK g_lock = SRWLOCK_INIT;
static size_t g_next = 0;
static volatile LONG64 g_cycles = 0;
static volatile uint64_t g_sink = 0; /* keeps the vc_hot calls */

/* The hot function the tests hook: cheap, pure, called outside the allocator lock after every allocation. */
EXPORT NOINLINE uint64_t vc_hot(uint64_t size, uint64_t tag)
{
    uint64_t h = 0x9e3779b97f4a7c15ull ^ size;
    for (int i = 0; i < 8; i++) h = (h ^ (tag + (uint64_t)i)) * 0x100000001b3ull;
    return h;
}

/* Bump allocation under the lock. The header write is the first touch of a new page: it faults with the lock held. */
static NOINLINE uint8_t *vc_alloc(size_t size, uint32_t tag)
{
    AcquireSRWLockExclusive(&g_lock);
    if (g_next + size > ARENA_BYTES) {
        VirtualFree(g_arena, ARENA_BYTES, MEM_DECOMMIT); /* start over: every page faults again */
        g_next = 0;
        g_cycles++;
    }
    uint8_t *p = g_arena + g_next;
    g_next += size;
    *(volatile uint64_t *)p = (uint64_t)size | ((uint64_t)tag << 32);
    ReleaseSRWLockExclusive(&g_lock);
    return p;
}

/* Commit-on-demand for the arena only; everything else continues the search. */
static LONG CALLBACK vc_veh(EXCEPTION_POINTERS *ep)
{
    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || er->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    uintptr_t a = (uintptr_t)er->ExceptionInformation[1];
    uintptr_t base = (uintptr_t)g_arena;
    if (base == 0 || a < base || a >= base + ARENA_BYTES) return EXCEPTION_CONTINUE_SEARCH;
    void *page = (void *)(a & ~(uintptr_t)(PAGE_BYTES - 1));
    if (VirtualAlloc(page, PAGE_BYTES, MEM_COMMIT, PAGE_READWRITE) != page) return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement64(&g_commits);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI worker(LPVOID arg)
{
    uint32_t seed = (uint32_t)(uintptr_t)arg * 2654435761u + 1u;
    for (;;) {
        seed = seed * 1103515245u + 12345u;
        size_t size = 64u + ((seed >> 16) & 0x3c0u); /* 64..1024 bytes: every page gets a header */
        uint8_t *block = vc_alloc(size, seed);
        g_sink += vc_hot((uint64_t)size, (uint64_t)(uintptr_t)block);
        InterlockedIncrement64(&g_progress);
    }
    return 0;
}

/* ---- --intercept-crt: dbghelp's CRT heap imports take the allocator lock first (what ASan's CRT hooks amount to) */

static void *g_orig[MAX_HOOKS];

static void vc_crt_gate(void)
{
    AcquireSRWLockExclusive(&g_lock); /* never returns on a thread that already holds the lock */
    ReleaseSRWLockExclusive(&g_lock);
    InterlockedIncrement64(&g_crt_calls);
}

/* Win64: every hooked function takes at most four integer arguments (rcx, rdx, r8, r9) and returns in rax, so one
 * four-argument forwarder per slot preserves each signature. */
typedef void *(__cdecl *Fwd4)(void *, void *, void *, void *);
#define VC_WRAP(i)                                                                                                     \
    static void *__cdecl vc_wrap_##i(void *a, void *b, void *c, void *d)                                               \
    {                                                                                                                  \
        vc_crt_gate();                                                                                                 \
        return ((Fwd4)g_orig[i])(a, b, c, d);                                                                          \
    }
VC_WRAP(0) VC_WRAP(1) VC_WRAP(2) VC_WRAP(3) VC_WRAP(4) VC_WRAP(5) VC_WRAP(6) VC_WRAP(7)
VC_WRAP(8) VC_WRAP(9) VC_WRAP(10) VC_WRAP(11) VC_WRAP(12) VC_WRAP(13) VC_WRAP(14) VC_WRAP(15)
VC_WRAP(16) VC_WRAP(17) VC_WRAP(18) VC_WRAP(19) VC_WRAP(20) VC_WRAP(21) VC_WRAP(22) VC_WRAP(23)
static void *const g_wraps[MAX_HOOKS] = {
    (void *)vc_wrap_0,  (void *)vc_wrap_1,  (void *)vc_wrap_2,  (void *)vc_wrap_3,  (void *)vc_wrap_4,
    (void *)vc_wrap_5,  (void *)vc_wrap_6,  (void *)vc_wrap_7,  (void *)vc_wrap_8,  (void *)vc_wrap_9,
    (void *)vc_wrap_10, (void *)vc_wrap_11, (void *)vc_wrap_12, (void *)vc_wrap_13, (void *)vc_wrap_14,
    (void *)vc_wrap_15, (void *)vc_wrap_16, (void *)vc_wrap_17, (void *)vc_wrap_18, (void *)vc_wrap_19,
    (void *)vc_wrap_20, (void *)vc_wrap_21, (void *)vc_wrap_22, (void *)vc_wrap_23,
};

static const char *const k_heap_functions[] = {
    "malloc",         "calloc",        "realloc",        "free",           "_msize",
    "_recalloc",      "_expand",       "_malloc_base",   "_calloc_base",   "_realloc_base",
    "_free_base",     "_msize_base",   "_recalloc_base", "_expand_base",   "_aligned_malloc",
    "_aligned_free",  "_aligned_realloc", "_aligned_recalloc", "_aligned_msize", NULL,
};

static int is_heap_function(const char *name)
{
    if (strncmp(name, "_o_", 3) == 0) name += 3; /* the OS CRT exports (api-ms-win-crt-private) */
    for (int i = 0; k_heap_functions[i] != NULL; i++)
        if (strcmp(name, k_heap_functions[i]) == 0) return 1;
    return 0;
}

static int is_crt_module(const char *dll)
{
    return _strnicmp(dll, "api-ms-win-crt-", 15) == 0 || _stricmp(dll, "ucrtbase.dll") == 0 ||
           _stricmp(dll, "msvcrt.dll") == 0;
}

/* Patch dbghelp.dll's import address table; returns the number of hooked imports. */
static int intercept_crt(void)
{
    uint8_t *base = (uint8_t *)LoadLibraryA("dbghelp.dll");
    if (base == NULL) return 0;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0) return 0;
    int hooked = 0;
    for (const IMAGE_IMPORT_DESCRIPTOR *d = (const IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress); d->Name != 0;
         d++) {
        if (!is_crt_module((const char *)(base + d->Name))) continue;
        const IMAGE_THUNK_DATA64 *names =
            (const IMAGE_THUNK_DATA64 *)(base + (d->OriginalFirstThunk != 0 ? d->OriginalFirstThunk : d->FirstThunk));
        IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)(base + d->FirstThunk);
        for (; names->u1.AddressOfData != 0; names++, iat++) {
            if (IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal) || hooked >= MAX_HOOKS) continue;
            const IMAGE_IMPORT_BY_NAME *ibn = (const IMAGE_IMPORT_BY_NAME *)(base + names->u1.AddressOfData);
            if (!is_heap_function((const char *)ibn->Name)) continue;
            DWORD old = 0;
            if (!VirtualProtect(&iat->u1.Function, sizeof iat->u1.Function, PAGE_READWRITE, &old)) continue;
            g_orig[hooked] = (void *)(uintptr_t)iat->u1.Function;
            iat->u1.Function = (ULONGLONG)(uintptr_t)g_wraps[hooked];
            VirtualProtect(&iat->u1.Function, sizeof iat->u1.Function, old, &old);
            hooked++;
        }
    }
    return hooked;
}

static void say(const char *fmt, ...)
{
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof line) n = (int)sizeof line - 1;
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, (DWORD)n, &written, NULL);
}

/* --wait-stdin: block until a newline or EOF (or an error, e.g. no stdin) on standard input. */
static void wait_stdin(void)
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    char c = 0;
    DWORD got = 0;
    while (in != NULL && in != INVALID_HANDLE_VALUE && ReadFile(in, &c, 1, &got, NULL) && got == 1 && c != '\n') {
    }
}

int main(int argc, char **argv)
{
    unsigned threads = 4, seconds = 0, heartbeat_ms = 100;
    int crt = 0, asan_shadow = 0, wait_go = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--heartbeat-ms") && i + 1 < argc) heartbeat_ms = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--intercept-crt")) crt = 1;
        else if (!strcmp(argv[i], "--asan-shadow")) asan_shadow = 1;
        else if (!strcmp(argv[i], "--wait-stdin")) wait_go = 1;
        else {
            fprintf(stderr, "unknown flag %s\n", argv[i]);
            return 2;
        }
    }
    if (threads < 1 || threads > 16 || heartbeat_ms < 10 || heartbeat_ms > 10000) {
        fprintf(stderr, "bad --threads or --heartbeat-ms\n");
        return 2;
    }
    g_arena = (uint8_t *)VirtualAlloc(NULL, ARENA_BYTES, MEM_RESERVE, PAGE_NOACCESS);
    if (g_arena == NULL) {
        fprintf(stderr, "arena: VirtualAlloc(MEM_RESERVE) failed\n");
        return 3;
    }
    if (asan_shadow) __asan_shadow_memory_dynamic_address = (uintptr_t)g_arena;
    if (AddVectoredExceptionHandler(0, vc_veh) == NULL) {
        fprintf(stderr, "AddVectoredExceptionHandler failed\n");
        return 3;
    }
    int hooked = crt ? intercept_crt() : 0;
    if (crt && hooked == 0) {
        fprintf(stderr, "--intercept-crt: no CRT heap import of dbghelp.dll was hooked\n");
        return 3;
    }
    say("READY pid=%lu arena=%p threads=%u crt=%d\n", GetCurrentProcessId(), (void *)g_arena, threads, hooked);
    if (wait_go) wait_stdin();
    for (unsigned t = 0; t < threads; t++) {
        HANDLE h = CreateThread(NULL, 0, worker, (LPVOID)(uintptr_t)(t + 1), 0, NULL);
        if (h == NULL) return 3;
        CloseHandle(h);
    }
    say("GO\n");
    ULONGLONG t0 = GetTickCount64();
    for (;;) {
        Sleep(heartbeat_ms);
        ULONGLONG ms = GetTickCount64() - t0;
        say("HEARTBEAT n=%lld commits=%lld crt=%lld ms=%llu\n", (long long)g_progress, (long long)g_commits,
            (long long)g_crt_calls, (unsigned long long)ms);
        if (seconds != 0 && ms >= (ULONGLONG)seconds * 1000u) break;
    }
    say("DONE n=%lld\n", (long long)g_progress);
    ExitProcess(0);
}
