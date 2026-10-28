/*
 * BEA live fixture live_fixture.exe (DESIGN §8.1, S5 §14.2; owner WP0): the ext-frida lab fixture plus the
 * bea_dispatch and bea_vec_sum exports of bea_emu_fixture.dll, for live-vs-emulator parity (S5 §9.6 vector set) and
 * the oracle-thunk SEH checks (touch_counter(NULL), IsBadReadPtr).
 * Build (scripts/build-fixtures.mjs): gcc -O2 -Wl,--no-insert-timestamp -o live_fixture.exe live_fixture.c
 *
 * Original lab description (BEA Frida lab fixture):
 *
 * A tiny "game loop" that updates a global struct car every ~16 ms by calling a
 * non-inlined exported function physics_step(struct car*, float dt).
 *
 * Flags:
 *   --iters N        stop after N frames (0 = run forever, default 0)
 *   --crash-after N  null-write crash at frame N (0 = never)
 *   --hot N          call hot_fn N times per frame (default 0)
 *   --sleep MS       per-frame sleep (default 16)
 *   --worker         start a second thread that also writes g_car.counter
 *   --stdin          start a thread that echoes stdin lines
 *   --av-handled     raise + handle an access violation via SEH each 100 frames
 *   --alloc MB       VirtualAlloc MB megabytes of pseudo-random data with planted
 *                    pointers to g_car every 1 MB (for scan/findPointers benchmarks)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif

#ifdef _MSC_VER
#define EXPORT __declspec(dllexport)
#define NOINLINE __declspec(noinline)
#else
#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))
#endif

struct car {
    float speed;    /* +0x00 */
    int counter;    /* +0x04 */
    double pos[3];  /* +0x08, +0x10, +0x18 */
};

EXPORT struct car g_car = { 0.0f, 0, { 0.0, 0.0, 0.0 } };
EXPORT volatile long long g_hot_sink = 0;
EXPORT volatile int g_frame = 0;
EXPORT volatile double g_mix_result = 0.0;
EXPORT char g_marker[32] = "BEA_MARKER_v1:speed";
EXPORT void *g_big = NULL;
EXPORT size_t g_big_size = 0;

EXPORT NOINLINE float physics_step(struct car *c, float dt)
{
    float accel = 9.81f;
    if (c->speed > 50.0f)
        accel = -2.0f;
    c->speed += accel * dt;
    c->counter++;
    c->pos[0] += (double)c->speed * dt;
    c->pos[1] = sin((double)c->counter * 0.1);
    c->pos[2] = c->pos[2] * 0.5 + 1.0;
    return c->speed;
}

/* Win64 ABI: a->ecx, b->xmm1, c->xmm2, d->xmm3, e->[rsp+0x28], f->[rsp+0x30] */
EXPORT NOINLINE double mix_args(int a, float b, double c, float d, int e, double f)
{
    return (double)a + b + c + d + (double)e + f;
}

/* all-float: xmm0..xmm3 */
EXPORT NOINLINE float four_floats(float a, float b, float c, float d)
{
    return a * 1000.0f + b * 100.0f + c * 10.0f + d;
}

EXPORT NOINLINE int add_ints(int a, int b)
{
    return a + b;
}

EXPORT NOINLINE int hot_fn(int x)
{
    return (int)(((unsigned)x * 2654435761u) >> 16);
}

EXPORT NOINLINE void touch_counter(struct car *c)
{
    c->counter += 1000;
}

EXPORT NOINLINE double car_energy(const struct car *c, double mass)
{
    return 0.5 * mass * (double)c->speed * (double)c->speed + c->pos[2];
}

/* bea_dispatch / bea_vec_sum: identical to bea_emu_fixture.dll exports 15 and 23 (S5 §14.2). */
static int bea_cpu_has_avx2(void)
{
#ifdef _MSC_VER
    int r[4];
    __cpuid(r, 0);
    if (r[0] < 7) return 0;
    __cpuid(r, 1);
    if (!(r[2] & (1 << 27)) || !(r[2] & (1 << 28))) return 0;
    __cpuidex(r, 7, 0);
    return (r[1] & (1 << 5)) != 0;
#else
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_OSXSAVE) || !(c & bit_AVX)) return 0;
    if (__get_cpuid_max(0, NULL) < 7) return 0;
    __cpuid_count(7, 0, a, b, c, d);
    return (b & bit_AVX2) != 0;
#endif
}

EXPORT NOINLINE float bea_dispatch(float x)
{
    return bea_cpu_has_avx2() ? x * 3.0001f : x * 3.0f;
}

typedef struct Vec { float *begin; float *end; float *capacity; } Vec;

EXPORT NOINLINE float bea_vec_sum(const Vec *v)
{
    float s = 0.0f;
    const float *p;
    for (p = v->begin; p != v->end; p++)
        s += *p;
    return s;
}

static volatile int g_worker_run = 1;

static DWORD WINAPI worker_main(LPVOID arg)
{
    (void)arg;
    while (g_worker_run) {
        touch_counter(&g_car);
        Sleep(50);
    }
    return 0;
}

static DWORD WINAPI stdin_main(LPVOID arg)
{
    char line[256];
    (void)arg;
    while (fgets(line, sizeof line, stdin) != NULL) {
        printf("stdin got: %s", line);
        fflush(stdout);
    }
    printf("stdin EOF\n");
    fflush(stdout);
    return 0;
}

static int av_probe(void)
{
#ifdef _MSC_VER
    __try {
        volatile int *p = (volatile int *)(ULONG_PTR)0x10;
        return *p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
#else
    /* kernel32!IsBadReadPtr probes with its own SEH frame: first-chance AV, handled by the app */
    return IsBadReadPtr((const void *)(ULONG_PTR)0x10, 4) ? -1 : 0;
#endif
}

int main(int argc, char **argv)
{
    int iters = 0, crash_after = 0, hot = 0, sleep_ms = 16, worker = 0, use_stdin = 0, av = 0, alloc_mb = 0;
    char cwd[MAX_PATH];
    const char *env;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--crash-after") && i + 1 < argc) crash_after = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hot") && i + 1 < argc) hot = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sleep") && i + 1 < argc) sleep_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--worker")) worker = 1;
        else if (!strcmp(argv[i], "--stdin")) use_stdin = 1;
        else if (!strcmp(argv[i], "--av-handled")) av = 1;
        else if (!strcmp(argv[i], "--alloc") && i + 1 < argc) alloc_mb = atoi(argv[++i]);
    }

    GetCurrentDirectoryA(sizeof cwd, cwd);
    env = getenv("BEA_TEST");
    printf("fixture pid=%lu tid=%lu argc=%d\n", GetCurrentProcessId(), GetCurrentThreadId(), argc);
    for (i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);
    printf("env BEA_TEST=%s\n", env ? env : "(null)");
    printf("env PATH set=%s\n", getenv("PATH") ? "yes" : "no");
    printf("cwd=%s\n", cwd);
    printf("&g_car=%p physics_step=%p\n", (void *)&g_car, (void *)physics_step);
    fflush(stdout);
    fprintf(stderr, "stderr hello from fixture\n");
    fflush(stderr);

    if (alloc_mb > 0) {
        size_t n = (size_t)alloc_mb << 20, k;
        unsigned long long x = 88172645463325252ull;
        unsigned long long *q;
        g_big = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_big_size = n;
        q = (unsigned long long *)g_big;
        for (k = 0; k < n / 8; k++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            q[k] = x;
        }
        for (k = 0; k < n; k += (1u << 20))
            *(void **)((char *)g_big + k + 64) = (void *)&g_car;
        printf("big=%p size=%zu\n", g_big, n);
        fflush(stdout);
    }
    if (worker)
        CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
    if (use_stdin)
        CreateThread(NULL, 0, stdin_main, NULL, 0, NULL);

    for (g_frame = 1; iters == 0 || g_frame <= iters; g_frame++) {
        float s = physics_step(&g_car, 0.016f);
        int k;
        for (k = 0; k < hot; k++)
            g_hot_sink += hot_fn(k);
        g_mix_result = mix_args(g_frame, 1.5f, 2.25, 3.125f, 7, 0.5);
        g_mix_result += four_floats(1.0f, 2.0f, 3.0f, 4.0f);
        g_mix_result += car_energy(&g_car, 1200.0);
        if (av && (g_frame % 100) == 0)
            g_mix_result += av_probe();
        if ((g_frame % 30) == 0) {
            printf("frame=%d speed=%.3f counter=%d pos0=%.3f add=%d\n", g_frame, s, g_car.counter,
                   g_car.pos[0], add_ints(g_frame, 1));
            fflush(stdout);
        }
        if (crash_after && g_frame == crash_after) {
            volatile int *p = NULL;
            printf("about to crash at frame %d\n", g_frame);
            fflush(stdout);
            *p = 42;
        }
        if (sleep_ms > 0)
            Sleep(sleep_ms);
    }
    g_worker_run = 0;
    printf("fixture done frames=%d\n", g_frame - 1);
    fflush(stdout);
    return 0;
}
