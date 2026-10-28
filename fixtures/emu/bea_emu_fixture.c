/* BEA emulator fixture bea_emu_fixture.dll (DESIGN §8.1, S5 §14.2; owner WP0, extended by EMU/CALL change request).
 * Exports 1-14 are the ext-backends lab fixture (generic functions for emulator evaluation); 15-23 are the S5 §14.2
 * additions (CPUID dispatch, hidden struct return, by-value struct, variadic, MXCSR/TSC sites, an inline syscall,
 * an obfuscated field codec and a begin/end/capacity container).
 * Build (scripts/build-fixtures.mjs, from the staging directory so the DLL is byte-reproducible):
 *   gcc -O2 -shared -static -fno-builtin-sqrtf -fno-builtin-memcpy -Wl,--no-insert-timestamp -o bea_emu_fixture.dll
 *   bea_emu_fixture.c
 * -static links libgcc (TLS emulation for bea_tls_counter) into the DLL, as in the verified ext-backends build, so
 * the image imports only KERNEL32 and msvcrt.
 */
#include <cpuid.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#define EXPORT __declspec(dllexport)

/* 1. Pure scalar SSE float math (4 float register args). */
EXPORT float bea_spring_damper(float x, float v, float k, float c) {
    float f = -k * x - c * v;
    if (f > 1000.0f) f = 1000.0f;
    if (f < -1000.0f) f = -1000.0f;
    return f;
}

/* 2. Pure scalar SSE double math (Horner polynomial + clamp). */
EXPORT double bea_poly_d(double x, double a, double b, double c) {
    double y = ((a * x + b) * x + c) * x;
    return y < 0.0 ? 0.0 : y;
}

/* 3. Mixed float/double/int args incl. stack args (args 5..7). */
EXPORT double bea_stack_args(float a, float b, float c, float d, float e, double f, int g) {
    return (double)(a + b * c - d * e) * f + (double)g;
}

/* 4. Calls imports: malloc, memcpy, sqrtf, free (msvcrt.dll with this toolchain). */
EXPORT float bea_norm_copy(const float *src, int n, float *out) {
    float *tmp = (float *)malloc((size_t)n * sizeof(float));
    if (!tmp) return -1.0f;
    memcpy(tmp, src, (size_t)n * sizeof(float));
    float s = 0.0f;
    for (int i = 0; i < n; i++) s += tmp[i] * tmp[i];
    float len = sqrtf(s);
    for (int i = 0; i < n; i++) out[i] = len > 0.0f ? tmp[i] / len : 0.0f;
    free(tmp);
    return len;
}

/* 5. Struct in/out through a pointer (integrator step). */
typedef struct Body {
    float pos[3];
    float vel[3];
    float mass;
    uint32_t steps;
} Body;

EXPORT void bea_body_step(Body *b, const float *force, float dt) {
    float inv_m = b->mass > 0.0f ? 1.0f / b->mass : 0.0f;
    for (int i = 0; i < 3; i++) {
        b->vel[i] += force[i] * inv_m * dt;
        b->pos[i] += b->vel[i] * dt;
    }
    b->steps++;
}

/* 6. Globals: a tunable read from .data and a call counter written to .data/.bss. */
EXPORT float g_gain = 1.5f;
EXPORT uint32_t g_calls;
EXPORT float bea_global_gain(float x) {
    g_calls++;
    return x * g_gain;
}

/* 7. Large stack frame: forces a stack probe helper (___chkstk_ms on MinGW, __chkstk on MSVC). */
EXPORT int bea_big_frame(int n) {
    volatile unsigned char buf[16384];
    for (int i = 0; i < (int)sizeof(buf); i++) buf[i] = (unsigned char)(i * 7 + n);
    int s = 0;
    for (int i = 0; i < (int)sizeof(buf); i += 97) s += buf[i];
    return s;
}

/* 8. Thread-local state (TLS model depends on toolchain). */
static __thread int t_counter;
EXPORT int bea_tls_counter(int add) {
    t_counter += add;
    return t_counter;
}

/* 9. AVX2/FMA code path (VEX encoded) -- unsupported by Unicorn 2.x expected. */
__attribute__((target("avx2,fma"))) EXPORT float bea_avx_dot(const float *a, const float *b, int n) {
    float s = 0.0f;
    for (int i = 0; i < n; i++) s = fmaf(a[i], b[i], s);
    return s;
}

/* 10. Integer division (fault when b == 0 -> #DE). */
EXPORT int bea_div(int a, int b) { return a / b; }

/* 11. Indirect call through a caller-supplied function pointer. */
typedef float (*unary_fn)(float);
EXPORT float bea_apply(unary_fn fn, float x) { return fn(x) * 2.0f; }

/* 12. Transcendental imports (sinf/atan2f/powf go to msvcrt.dll here). */
EXPORT float bea_trig(float x, float y) { return sinf(x) + atan2f(y, x) + powf(fabsf(x), 0.5f); }

/* 13. Infinite loop (instruction budget / timeout test). */
EXPORT int bea_spin(int n) {
    volatile int i = 0;
    while (n) { i++; }
    return i;
}

/* 14. Reads the TEB via gs: (NtCurrentTeb()->ThreadLocalStoragePointer style access). */
EXPORT uint64_t bea_read_teb_self(void) {
    uint64_t self;
    __asm__ volatile("movq %%gs:0x30, %0" : "=r"(self));
    return self;
}

/* ---------------------------------------------------------------- S5 §14.2 additions */

/* 15. CPUID-dispatched math: x*3.0001f when CPUID leaf 1/7 report AVX2 with OS-enabled AVX state, else x*3.0f.
 *     A real CPU and the emulator take different paths (diff_function verdict "differ", hint cpuid_dispatch). */
static int bea_cpu_has_avx2(void) {
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_OSXSAVE) || !(c & bit_AVX)) return 0;
    if (__get_cpuid_max(0, NULL) < 7) return 0;
    __cpuid_count(7, 0, a, b, c, d);
    return (b & bit_AVX2) != 0;
}
EXPORT float bea_dispatch(float x) { return bea_cpu_has_avx2() ? x * 3.0001f : x * 3.0f; }

/* 16. A 24-byte struct return: the caller passes a hidden result pointer in rcx and x moves to xmm1. */
typedef struct BeaRet24 { float a, b, c, d, e, f; } BeaRet24;
EXPORT BeaRet24 bea_struct_ret(float x) {
    BeaRet24 r = { x, x * 2.0f, x * 3.0f, x * 4.0f, x * 5.0f, x * 6.0f };
    return r;
}

/* 17. A 12-byte struct by value: Win64 passes a pointer to a caller-made copy. */
typedef struct S12 { float x; float y; int32_t n; } S12;
EXPORT float bea_byval12(S12 s) { return (s.x + s.y) * (float)s.n; }

/* 18. Variadic doubles (Win64: variadic floating-point args are also copied to the integer registers). */
EXPORT double bea_variadic_sum(int n, ...) {
    va_list ap;
    double s = 0.0;
    va_start(ap, n);
    for (int i = 0; i < n; i++) s += va_arg(ap, double);
    va_end(ap);
    return s;
}

/* 19. stmxcsr: an fp_status site. */
EXPORT uint32_t bea_mxcsr_read(void) { return _mm_getcsr(); }

/* 20. rdtsc: a tsc site. */
EXPORT uint64_t bea_rdtsc(void) { return __rdtsc(); }

/* 21. An inline system call (NtQueryInformationFile-style number); never run natively, the emulator stops on it. */
EXPORT __attribute__((naked)) void bea_syscall_stub(void) {
    __asm__ volatile("movl $0x50, %eax\n\tsyscall\n\tret");
}

/* 22. A multiplicatively obfuscated field: stored = logical * KEY (mod 2^32); the getter decodes with KEY^-1. */
#define BEA_CODEC_KEY 0x9e3779b1u
#define BEA_CODEC_KEY_INV 0x0e8b2f51u
_Static_assert((uint32_t)(BEA_CODEC_KEY * BEA_CODEC_KEY_INV) == 1u, "codec key inverse");
typedef struct Obj { uint32_t id; uint32_t gear_enc; float speed; } Obj;
EXPORT uint32_t bea_codec_get(const Obj *o) { return o->gear_enc * BEA_CODEC_KEY_INV; }

/* 23. A begin/end/capacity container (the std::vector<float> layout). */
typedef struct Vec { float *begin; float *end; float *capacity; } Vec;
EXPORT float bea_vec_sum(const Vec *v) {
    float s = 0.0f;
    for (const float *p = v->begin; p != v->end; p++) s += *p;
    return s;
}
