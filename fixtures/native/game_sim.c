/* BEA fixture game_sim.exe: a deterministic ~60 Hz "racing game" loop.
 *
 * Exercises: scans (speed/marker/pointers), watchpoints (single writer of speed, two writers of rpm on two threads,
 * a late-created writer thread, a reader thread), hooks with float args/returns (physics_step, mix_args),
 * tiny-function hooks (tiny_add), oracle calls + emulation diff (physics_step is a pure function of *car and dt),
 * Stalker coverage (branches in physics_step), module-load (mathlib.dll), first-chance exceptions, dumps.
 *
 * Build (scripts/build-fixtures.mjs): gcc -O2 -fno-math-errno -Wall -Wl,--no-insert-timestamp -o game_sim.exe game_sim.c
 *
 * Flags:
 *   --frames N            stop after N frames (0 = run until killed; default 0)
 *   --hz H                target frame rate (default 60; 0 = no sleep)
 *   --hot N               call hot_hash N times per frame (default 0)
 *   --no-threads          do not start input/engine/telemetry threads (single-writer world)
 *   --engine-start-ms MS  delay before the engine writer thread is created (default 1000)
 *   --load-mathlib-at F   LoadLibraryW(L"mathlib.dll") at frame F and call mf_lerp (default 0 = never)
 *   --av-handled          every 100 frames raise a first-chance access violation that the program handles
 *   --throttle T          hold throttle at T (0..1) instead of the 4 s ramp cycle (also seeds car->throttle)
 *   --speed V             initial speed (m/s); --speed 20 --throttle 0.125 is an exact f32 equilibrium (speed stays 20.0)
 *   --ramp-at-ms MS       after MS ms of frames: hold throttle at 1.0, print "RAMP", so speed starts increasing
 *   --ballast-mb N        before READY, VirtualAlloc N MiB of pseudo-random, pointer-free data (exported g_ballast /
 *                         g_ballast_size) and print "BALLAST mb=N"; for scan-latency tests (DESIGN §8.1, CI-M14)
 */
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))

typedef struct Vec3 { float x, y, z; } Vec3;
typedef struct Tyre { float grip, temp, wear, load; } Tyre;
typedef struct Car {
    uint32_t magic;          /* +0x00 0x31524143 'CAR1' */
    int32_t id;              /* +0x04 */
    float speed;             /* +0x08 m/s: the ONLY writer is physics_step */
    float throttle;          /* +0x0C written by input_update (input thread) */
    float steer;             /* +0x10 written by input_update */
    float rpm;               /* +0x14 written by physics_step (main) AND engine_update (engine thread) */
    Vec3 pos;                /* +0x18 */
    Vec3 vel;                /* +0x24 */
    double odometer;         /* +0x30 */
    uint32_t frame;          /* +0x38 */
    uint32_t flags;          /* +0x3C */
    Tyre *tyres;             /* +0x40 heap array of 4 */
    float mass;              /* +0x48 tunable, never written after init */
    float drag;              /* +0x4C tunable */
    uint8_t reserved[0x30];  /* pad to 0x80 */
} Car;
typedef struct World { uint32_t magic; uint32_t ncars; Car *cars[4]; double time; } World;

_Static_assert(offsetof(Car, speed) == 0x08, "speed");
_Static_assert(offsetof(Car, rpm) == 0x14, "rpm");
_Static_assert(offsetof(Car, odometer) == 0x30, "odometer");
_Static_assert(offsetof(Car, tyres) == 0x40, "tyres");
_Static_assert(sizeof(Car) == 0x80, "Car size");
_Static_assert(offsetof(World, cars) == 0x08, "cars");

EXPORT World *g_world;                       /* static root: [[g_world]+0x08]+0x08 == &car->speed */
EXPORT volatile float g_telemetry_kmh;       /* written by the telemetry thread from car->speed */
EXPORT volatile uint64_t g_hot_sink;
EXPORT volatile double g_mix_result;
EXPORT volatile LONG g_running = 1;
EXPORT const char g_marker[] = "BEA_GAME_SIM_MARKER_v1";
EXPORT const wchar_t g_wmarker[] = L"BEA_GAME_SIM_WIDE_v1";
EXPORT void *g_ballast;                      /* --ballast-mb region (NULL without the flag) */
EXPORT size_t g_ballast_size;
static float g_hold_throttle = -1.0f;
static float g_initial_speed = 0.0f;

/* Pure function of (*c, dt): the oracle/emulation/diff target. Branches: limiter and clamp (coverage). */
EXPORT NOINLINE float physics_step(Car *c, float dt)
{
    float accel = c->throttle * 8.0f - c->drag * c->speed;
    if (c->speed > 80.0f)
        accel = -2.0f;
    float v = c->speed + accel * dt;
    if (v < 0.0f)
        v = 0.0f;
    c->speed = v;
    c->rpm = v * 60.0f + 800.0f;
    c->vel.x = v * c->steer;
    c->vel.z = v;
    c->pos.x += c->vel.x * dt;
    c->pos.z += c->vel.z * dt;
    c->odometer += (double)(v * dt);
    c->frame++;
    for (int i = 0; i < 4; i++)
        c->tyres[i].temp += v * 0.001f * dt;
    return v;
}

EXPORT NOINLINE void input_update(Car *c, uint32_t tick)
{
    uint32_t phase = tick % 400u; /* 4 s cycle at 10 ms */
    float t = phase < 200u ? (float)phase / 200.0f : (float)(400u - phase) / 200.0f;
    c->throttle = g_hold_throttle >= 0.0f ? g_hold_throttle : t;
    c->steer = (float)((int)(tick % 100u) - 50) / 100.0f;
}

EXPORT NOINLINE void engine_update(Car *c) { c->rpm = c->rpm * 0.5f + 400.0f; }
EXPORT NOINLINE float telemetry_sample(const Car *c) { return c->speed * 3.6f; }
EXPORT NOINLINE int tiny_add(int a, int b) { return a + b; }
EXPORT NOINLINE uint32_t hot_hash(uint32_t x) { return (x * 2654435761u) >> 16; }
EXPORT NOINLINE float car_energy(const Car *c) { return 0.5f * c->mass * c->speed * c->speed; }
/* Win64: a=ecx b=xmm1 c=xmm2 d=xmm3 e=[rsp+0x28] f=[rsp+0x30] */
EXPORT NOINLINE double mix_args(int a, float b, double c, float d, int e, double f)
{
    return (double)a + b + c + d + (double)e + f;
}

static DWORD WINAPI input_main(LPVOID p)
{
    Car *c = (Car *)p;
    uint32_t tick = 0;
    while (g_running) { input_update(c, tick++); Sleep(10); }
    return 0;
}
static DWORD WINAPI engine_main(LPVOID p)
{
    Car *c = (Car *)p;
    while (g_running) { engine_update(c); Sleep(20); }
    return 0;
}
static DWORD WINAPI telemetry_main(LPVOID p)
{
    Car *c = (Car *)p;
    while (g_running) { g_telemetry_kmh = telemetry_sample(c); Sleep(50); }
    return 0;
}
static DWORD WINAPI engine_starter(LPVOID p)
{
    Sleep((DWORD)(uintptr_t)((void **)p)[1]);
    CreateThread(NULL, 0, engine_main, ((void **)p)[0], 0, NULL); /* created late: new-thread arming test */
    return 0;
}

/* Ballast for scan-latency tests. Every dword is 0x7F800000 | (random & 0x007FFFFF): a float NaN/+Inf pattern, an int32
 * above 2^31-2^23, and the high dword of every qword is >= 0x7F800000, so no aligned 8-byte value is a canonical
 * user-mode pointer and no aligned (or unaligned) 4-byte read equals a finite float or a small integer. */
static int make_ballast(unsigned mb)
{
    size_t n = (size_t)mb << 20;
    uint32_t *q = (uint32_t *)VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!q)
        return 0;
    uint64_t x = 0x9E3779B97F4A7C15ull;
    for (size_t k = 0; k < n / 4; k++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        q[k] = ((uint32_t)x & 0x007FFFFFu) | 0x7F800000u;
    }
    g_ballast = q;
    g_ballast_size = n;
    return 1;
}

int main(int argc, char **argv)
{
    unsigned frames = 0, hz = 60, hot = 0, load_at = 0, engine_ms = 1000, ramp_ms = 0, ballast_mb = 0;
    int threads = 1, av = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--frames") && i + 1 < argc) frames = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hz") && i + 1 < argc) hz = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hot") && i + 1 < argc) hot = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-threads")) threads = 0;
        else if (!strcmp(argv[i], "--engine-start-ms") && i + 1 < argc) engine_ms = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--load-mathlib-at") && i + 1 < argc) load_at = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--av-handled")) av = 1;
        else if (!strcmp(argv[i], "--throttle") && i + 1 < argc) g_hold_throttle = (float)atof(argv[++i]);
        else if (!strcmp(argv[i], "--speed") && i + 1 < argc) g_initial_speed = (float)atof(argv[++i]);
        else if (!strcmp(argv[i], "--ramp-at-ms") && i + 1 < argc) ramp_ms = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ballast-mb") && i + 1 < argc) ballast_mb = (unsigned)atoi(argv[++i]);
        else { fprintf(stderr, "unknown flag %s\n", argv[i]); return 2; }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    if (ballast_mb) {
        if (!make_ballast(ballast_mb)) { fprintf(stderr, "ballast: VirtualAlloc(%u MiB) failed\n", ballast_mb); return 3; }
        printf("BALLAST mb=%u\n", ballast_mb);
    }
    World *w = (World *)calloc(1, sizeof(World));
    Car *car = (Car *)calloc(1, sizeof(Car));
    car->magic = 0x31524143u; car->id = 7; car->mass = 1200.0f; car->drag = 0.05f;
    car->throttle = g_hold_throttle >= 0.0f ? g_hold_throttle : 0.0f;
    car->speed = g_initial_speed;
    car->tyres = (Tyre *)calloc(4, sizeof(Tyre));
    for (int i = 0; i < 4; i++) { car->tyres[i].grip = 1.0f; car->tyres[i].temp = 20.0f; }
    w->magic = 0x444C5257u; w->ncars = 1; w->cars[0] = car;
    g_world = w;
    static void *starter_args[2];
    starter_args[0] = car; starter_args[1] = (void *)(uintptr_t)engine_ms;
    if (threads) {
        CreateThread(NULL, 0, input_main, car, 0, NULL);
        CreateThread(NULL, 0, telemetry_main, car, 0, NULL);
        CreateThread(NULL, 0, engine_starter, starter_args, 0, NULL);
    }
    printf("READY pid=%lu world=%p car=%p\n", GetCurrentProcessId(), (void *)w, (void *)car);
    const float dt = 1.0f / 60.0f;
    const ULONGLONG t0 = GetTickCount64();
    int ramped = 0;
    for (unsigned frame = 1; frames == 0 || frame <= frames; frame++) {
        float s = physics_step(car, dt);
        g_mix_result = mix_args((int)frame, 1.5f, 2.25, 3.125f, 7, 0.5) + tiny_add((int)frame, 1) + car_energy(car);
        for (unsigned k = 0; k < hot; k++) g_hot_sink += hot_hash(k ^ frame);
        if (av && frame % 100u == 0u) g_mix_result += IsBadReadPtr((const void *)(ULONG_PTR)0x10, 4);
        if (load_at && frame == load_at) {
            HMODULE h = LoadLibraryW(L"mathlib.dll");
            FARPROC f = h ? GetProcAddress(h, "mf_lerp") : NULL;
            float r = f ? ((float (*)(float, float, float))(void *)f)(0.0f, 10.0f, 0.25f) : -1.0f;
            printf("MATHLIB loaded=%d lerp=%.3f\n", h != NULL, r);
        }
        if (ramp_ms && !ramped && GetTickCount64() - t0 >= ramp_ms) {
            ramped = 1; g_hold_throttle = 1.0f; car->throttle = 1.0f;
            printf("RAMP frame=%u\n", frame);
        }
        w->time += dt;
        if (frame % 60u == 0u) printf("FRAME %u speed=%.3f\n", frame, s);
        if (hz) Sleep(1000u / hz);
    }
    InterlockedExchange(&g_running, 0);
    printf("DONE frames=%u\n", frames);
    return 0;
}
