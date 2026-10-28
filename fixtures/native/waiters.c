/* BEA fixture waiters.exe: many threads that block and wake on ONE system-call stub (BEA-FEEDBACK.md item 6).
 *
 * Every thread here waits with WaitForSingleObject, so every wait enters ntdll!NtWaitForSingleObject. The workers
 * block and wake many times a second and count their wake-ups; one more thread (the "parked" thread, the trace
 * target) sits in a long wait on the same stub and wakes up every --park-ms to run the exported parked_work() once.
 * trace_execution threads mode on the parked thread finds it blocked in that stub and follows it from its next entry
 * into it; a listener on the stub that every worker also enters must not slow the workers down.
 *
 * Build (scripts/lib/fixtures.mjs): gcc -O2 -Wl,--no-insert-timestamp -o waiters.exe waiters.c
 *
 * Flags:
 *   --workers N      worker threads (2..64, default 16; even in pingpong mode)
 *   --mode M         ring (default): the workers form a ring of semaphores and --tokens tokens travel around it, so
 *                    every worker blocks and wakes thousands of times a second while only --tokens workers run at
 *                    once (bounded CPU); pingpong: pairs of workers hand an auto-reset event back and forth (every
 *                    worker busy: about one core per pair); timeout: each worker waits 1 ms on an event that is never
 *                    signaled (the process asks for a 1 ms timer resolution)
 *   --tokens K       ring mode: tokens in the ring (1..workers-1, default 2)
 *   --park-ms M      the parked thread's wait (10..60000, default 1000)
 *   --seconds S      exit 0 after S seconds (1..3600, default 120; a safety net, the tests kill it first)
 *
 * Output, one WriteFile per line: "READY pid=<pid> parked_tid=<tid> workers=<n> mode=<m>" once every thread runs, and
 * every second "TICK wakeups=<total> parked_rounds=<n> ms=<since start>".
 * Exports: g_meter {u64 wakeups; u64 clock_us} (the workers' total wake-ups and the fixture's own clock at the same
 * moment, refreshed every 10 ms by a meter thread, so a reader computes rates without trusting its own latency),
 * g_parked_rounds, g_parked_tid, g_bad_syscalls (parked_work's NtGetCurrentProcessorNumber calls that returned no
 * processor number, i.e. ran another system call), parked_work.
 */
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))
#define MAX_WORKERS 64

typedef struct {
    volatile LONG64 wakeups;
    volatile LONG64 clock_us;
} Meter;

EXPORT volatile Meter g_meter = {0, 0};
EXPORT volatile LONG64 g_parked_rounds = 0;
EXPORT volatile LONG g_parked_tid = 0;
/* parked_work's ntdll!NtGetCurrentProcessorNumber results that cannot be a processor number (a wrong system call ran:
   a stale translation of a freed Interceptor trampoline would run another stub's relocated prologue) */
EXPORT volatile LONG64 g_bad_syscalls = 0;

typedef ULONG(NTAPI *ProcessorNumber)(void);
static ProcessorNumber g_processor_number;

/* one cache line per worker: the counters are not contended */
typedef struct {
    volatile LONG64 n;
    char pad[56];
} Counter;

static Counter g_counts[MAX_WORKERS];
static HANDLE g_events[MAX_WORKERS];
static HANDLE g_never;
static HANDLE g_park;
static int g_workers = 16;
static int g_park_ms = 1000;
static volatile LONG g_started = 0;
static volatile LONG64 g_sink = 0;
static LARGE_INTEGER g_freq;
static LARGE_INTEGER g_t0;

static void say(const char *format, ...)
{
    char line[256];
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(line, sizeof line - 1, format, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof line - 2) n = (int)sizeof line - 2;
    line[n++] = '\n';
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, (DWORD)n, &written, NULL);
}

static LONG64 now_us(void)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (LONG64)((t.QuadPart - g_t0.QuadPart) * 1000000 / g_freq.QuadPart);
}

static LONG64 total_wakeups(void)
{
    LONG64 sum = 0;
    for (int i = 0; i < g_workers; i++) sum += g_counts[i].n;
    return sum;
}

/* What the parked thread does after every wake-up: the block a trace of that thread records, and one more system call
   (through a function pointer, so a followed thread runs the stub under Stalker) whose result is checked. */
EXPORT NOINLINE LONG64 parked_work(LONG64 round)
{
    LONG64 h = round * 0x9e3779b97f4a7c15ll;
    for (int i = 0; i < 64; i++) h = (h ^ i) * 0x100000001b3ll;
    if (g_processor_number != NULL && g_processor_number() >= 4096) InterlockedIncrement64(&g_bad_syscalls);
    InterlockedIncrement64(&g_parked_rounds);
    return h;
}

static DWORD WINAPI parked_main(LPVOID arg)
{
    (void)arg;
    InterlockedExchange(&g_parked_tid, (LONG)GetCurrentThreadId());
    InterlockedIncrement(&g_started);
    for (LONG64 round = 0;; round++) {
        WaitForSingleObject(g_park, (DWORD)g_park_ms); /* never signaled: wakes when the wait times out */
        g_sink += parked_work(round);
    }
    return 0;
}

static DWORD WINAPI pingpong_main(LPVOID arg)
{
    int i = (int)(INT_PTR)arg;
    HANDLE mine = g_events[i];
    HANDLE partner = g_events[i ^ 1];
    InterlockedIncrement(&g_started);
    for (;;) {
        WaitForSingleObject(mine, INFINITE);
        g_counts[i].n++;
        SetEvent(partner);
    }
    return 0;
}

/* ring mode: g_events[] are semaphores (a token is never lost when two arrive at once) */
static DWORD WINAPI ring_main(LPVOID arg)
{
    int i = (int)(INT_PTR)arg;
    HANDLE mine = g_events[i];
    HANDLE next = g_events[(i + 1) % g_workers];
    InterlockedIncrement(&g_started);
    for (;;) {
        WaitForSingleObject(mine, INFINITE);
        g_counts[i].n++;
        ReleaseSemaphore(next, 1, NULL);
    }
    return 0;
}

static DWORD WINAPI timeout_main(LPVOID arg)
{
    int i = (int)(INT_PTR)arg;
    InterlockedIncrement(&g_started);
    for (;;) {
        WaitForSingleObject(g_never, 1);
        g_counts[i].n++;
    }
    return 0;
}

static DWORD WINAPI meter_main(LPVOID arg)
{
    (void)arg;
    for (;;) {
        g_meter.wakeups = total_wakeups();
        g_meter.clock_us = now_us();
        Sleep(10);
    }
    return 0;
}

/* 1 ms timer resolution for the timeout mode (ntdll export; no import library needed) */
static void fine_timer(void)
{
    typedef LONG(NTAPI * SetResolution)(ULONG, BOOLEAN, PULONG);
    SetResolution set = (SetResolution)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimerResolution");
    ULONG actual = 0;
    if (set != NULL) set(10000, TRUE, &actual);
}

static int arg_int(const char *v, int lo, int hi, const char *name)
{
    char *end = NULL;
    long x = strtol(v, &end, 10);
    if (end == v || *end != '\0' || x < lo || x > hi) {
        say("ERROR bad %s %s", name, v);
        ExitProcess(2);
    }
    return (int)x;
}

enum Mode { RING, PINGPONG, TIMEOUT };
static const char *const MODE_NAMES[] = {"ring", "pingpong", "timeout"};

int main(int argc, char **argv)
{
    int seconds = 120;
    int tokens = 2;
    enum Mode mode = RING;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : "";
        if (strcmp(a, "--workers") == 0) g_workers = arg_int(v, 2, MAX_WORKERS, a), i++;
        else if (strcmp(a, "--tokens") == 0) tokens = arg_int(v, 1, MAX_WORKERS - 1, a), i++;
        else if (strcmp(a, "--park-ms") == 0) g_park_ms = arg_int(v, 10, 60000, a), i++;
        else if (strcmp(a, "--seconds") == 0) seconds = arg_int(v, 1, 3600, a), i++;
        else if (strcmp(a, "--mode") == 0 && strcmp(v, "ring") == 0) mode = RING, i++;
        else if (strcmp(a, "--mode") == 0 && strcmp(v, "pingpong") == 0) mode = PINGPONG, i++;
        else if (strcmp(a, "--mode") == 0 && strcmp(v, "timeout") == 0) mode = TIMEOUT, i++;
        else {
            say("ERROR unknown argument %s", a);
            return 2;
        }
    }
    if (mode == PINGPONG && g_workers % 2 != 0) g_workers++;
    if (tokens >= g_workers) tokens = g_workers - 1;
    g_processor_number =
        (ProcessorNumber)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetCurrentProcessorNumber");
    QueryPerformanceFrequency(&g_freq);
    QueryPerformanceCounter(&g_t0);
    g_never = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_park = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (mode == TIMEOUT) fine_timer();
    for (int i = 0; i < g_workers; i++)
        g_events[i] = mode == RING ? CreateSemaphoreA(NULL, 0, MAX_WORKERS, NULL) : CreateEventA(NULL, FALSE, FALSE, NULL);
    LPTHREAD_START_ROUTINE worker = mode == RING ? ring_main : mode == PINGPONG ? pingpong_main : timeout_main;
    for (int i = 0; i < g_workers; i++) {
        HANDLE h = CreateThread(NULL, 0, worker, (LPVOID)(INT_PTR)i, 0, NULL);
        if (h == NULL) return 3;
        CloseHandle(h);
    }
    HANDLE parked = CreateThread(NULL, 0, parked_main, NULL, 0, NULL);
    HANDLE meter = CreateThread(NULL, 0, meter_main, NULL, 0, NULL);
    if (parked == NULL || meter == NULL) return 3;
    CloseHandle(parked);
    CloseHandle(meter);
    while (g_started < g_workers + 1) Sleep(1);
    if (mode == PINGPONG)
        for (int i = 0; i < g_workers; i += 2) SetEvent(g_events[i]); /* one token per pair */
    if (mode == RING)
        for (int k = 0; k < tokens; k++) ReleaseSemaphore(g_events[k * g_workers / tokens], 1, NULL);
    say("READY pid=%lu parked_tid=%ld workers=%d mode=%s", GetCurrentProcessId(), g_parked_tid, g_workers,
        MODE_NAMES[mode]);
    for (int s = 0; s < seconds; s++) {
        Sleep(1000);
        say("TICK wakeups=%lld parked_rounds=%lld ms=%lld", total_wakeups(), g_parked_rounds, now_us() / 1000);
    }
    say("DONE wakeups=%lld", total_wakeups());
    ExitProcess(0);
}
