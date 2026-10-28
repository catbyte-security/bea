/* BEA fixture mathlib.dll: pure functions for oracle / emulation / differential tests, plus deliberate edge cases.
 * Build (reference): gcc -O2 -fno-math-errno -shared -Wl,--no-insert-timestamp -o mathlib.dll mathlib.c
 */
#include <math.h>
#include <stdint.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))

typedef struct Body { float pos[3]; float vel[3]; float mass; uint32_t steps; } Body; /* 0x20 */

EXPORT float g_gain = 1.5f;     /* .data tunable: file value 1.5; game_sim never changes it */
EXPORT uint32_t g_calls;        /* .bss counter: state persistence across calls */

EXPORT NOINLINE float mf_spring(float x, float v, float k, float c)
{
    float f = -k * x - c * v;
    if (f > 1000.0f) f = 1000.0f;
    if (f < -1000.0f) f = -1000.0f;
    return f;
}
EXPORT NOINLINE double mf_poly(double x, double a, double b, double c)
{
    double y = ((a * x + b) * x + c) * x;
    return y < 0.0 ? 0.0 : y;
}
/* args 5..7 on the stack, mixed float/double/int */
EXPORT NOINLINE double mf_stack(float a, float b, float c, float d, float e, double f, int g)
{
    return (double)(a + b * c - d * e) * f + (double)g;
}
EXPORT NOINLINE float mf_lerp(float a, float b, float t) { return a + (b - a) * t; }
EXPORT NOINLINE float mf_vec3_len(const float *v) { return sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]); }
EXPORT NOINLINE void mf_body_step(Body *b, const float *force, float dt)
{
    float inv_m = b->mass > 0.0f ? 1.0f / b->mass : 0.0f;
    for (int i = 0; i < 3; i++) {
        b->vel[i] += force[i] * inv_m * dt;
        b->pos[i] += b->vel[i] * dt;
    }
    b->steps++;
}
EXPORT NOINLINE float mf_gain(float x) { g_calls++; return x * g_gain; }
EXPORT NOINLINE int mf_div(int a, int b) { return a / b; }                      /* #DE when b == 0 */
__attribute__((target("avx2,fma"))) EXPORT NOINLINE float mf_avx_dot(const float *a, const float *b, int n)
{
    float s = 0.0f;
    for (int i = 0; i < n; i++) s = fmaf(a[i], b[i], s);
    return s;                                                                 /* VEX: ISA guard stops it */
}
EXPORT NOINLINE double mf_x87_sin(double x) { return sin(x); }                  /* libmingwex: x87 fsin path */
EXPORT NOINLINE int mf_spin(int n) { volatile int i = 0; while (n) { i++; } return i; } /* budget/timeout */
