// =================================================================================================
// src/agent/pure/scanKernelSource.ts — WP10-SCAN: the compare kernels (S4 §9.4) as C source.
// Compiled in the target by CModule/TinyCC (src/agent/scanKernels.ts) and on the host by gcc in
// tests/unit/scan/scanKernels.gcc.test.ts, which checks them against the JS reference (scanReference.ts).
// No #include: TinyCC's CModule libc is minimal, so the source defines its own types and byte loops.
//
// Calling convention: one BeaScanArgs block (every field 8 bytes; ARG offsets below). Kernels are called through
// NativeFunction {exceptions:"steal", scheduling:"exclusive"}; before each target read a kernel publishes its
// position in `progress` and its output count in `at`, so after a stolen access violation JS knows exactly where
// to resume (S4 §9.4 "Reads").
// =================================================================================================

/** Byte offsets of the BeaScanArgs fields. */
export const ARG = {
  /** cmp/snap: target VA of the slice */
  p: 0,
  len: 8,
  avail: 16,
  vt: 24,
  elem: 32,
  align: 40,
  op: 48,
  /** operand bits (sign-extended for signed types; float bits in the low bits) */
  a: 56,
  b: 64,
  /** double */
  eps: 72,
  addrs: 80,
  vals: 88,
  /** 0 = no firsts array */
  firsts: 96,
  /** cmp/snap: next output index; next: candidates kept */
  at: 104,
  cap: 112,
  progress: 120,
  /** snap: snapshot bytes of the slice (offset 0 = p) */
  snap: 128,
  /** byte-string comparand (vt 11 / eq_bits) */
  operand: 136,
  /** next: end index (exclusive) */
  end: 144,
  /** floor(eps) as u64 (saturated), for integer approx: TinyCC has no double→u64 conversion (__fixunsdfdi) */
  epsi: 152,
} as const;
export const ARGS_BYTES = 160;

export const SCAN_KERNEL_SYMBOLS = ["bea_scan_cmp", "bea_scan_next", "bea_scan_snap"] as const;

export const SCAN_KERNEL_SOURCE = String.raw`
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;

typedef struct {
  u64 p, len, avail, vt, elem, align, op, a, b;
  double eps;
  u64 addrs, vals, firsts, at, cap, progress, snap, operand, end, epsi;
} BeaScanArgs;

#define BEA_S64_MAX 0x7fffffffffffffffLL
#define BEA_S64_MIN (-BEA_S64_MAX - 1LL)
#define BEA_U64_MAX 0xffffffffffffffffULL

/* value classes: 0 signed, 1 unsigned, 2 float, 3 bytes */
static int bea_class (u64 vt)
{
  if (vt == 0 || vt == 2 || vt == 4 || vt == 6) return 0;
  if (vt == 8 || vt == 9) return 2;
  if (vt == 11) return 3;
  return 1;
}

static s64 bea_ld_s (const u8 * q, u64 vt)
{
  if (vt == 0) return *(const s8 *) q;
  if (vt == 2) return *(const s16 *) q;
  if (vt == 4) return *(const s32 *) q;
  return *(const s64 *) q;
}

static u64 bea_ld_u (const u8 * q, u64 vt)
{
  if (vt == 1) return *q;
  if (vt == 3) return *(const u16 *) q;
  if (vt == 5) return *(const u32 *) q;
  return *(const u64 *) q;
}

static double bea_ld_f (const u8 * q, u64 vt)
{
  if (vt == 8) return *(const float *) q;
  return *(const double *) q;
}

static double bea_bits_f (u64 bits, u64 vt)
{
  union { u32 u; float f; } h;
  union { u64 u; double d; } w;
  if (vt == 8) { h.u = (u32) bits; return h.f; }
  w.u = bits;
  return w.d;
}

static int bea_memeq (const u8 * x, const u8 * y, u64 n)
{
  u64 i;
  for (i = 0; i != n; i++)
    if (x[i] != y[i]) return 0;
  return 1;
}

static int bea_fnear (double x, double y, double eps)
{
  return x - y <= eps && y - x <= eps;
}

/* one element against the operands, the previous value and the first value (S4 §9.3 op list) */
static int bea_match (const BeaScanArgs * a, const u8 * cur, const u8 * prev, const u8 * first)
{
  u64 op = a->op, elem = a->elem;
  int cls = bea_class (a->vt);
  if (op == 12) return first != 0 && bea_memeq (cur, first, elem);
  if (cls == 3 || op == 13) {
    if (op == 0 || op == 13) return bea_memeq (cur, (const u8 *) a->operand, elem);
    if (op == 1) return !bea_memeq (cur, (const u8 *) a->operand, elem);
    if (op == 6) return !bea_memeq (cur, prev, elem);
    if (op == 7) return bea_memeq (cur, prev, elem);
    return 0;
  }
  if (cls == 2) {
    double x = bea_ld_f (cur, a->vt), fa = bea_bits_f (a->a, a->vt), fb = bea_bits_f (a->b, a->vt);
    double pv = (op >= 6 && op <= 11) ? bea_ld_f (prev, a->vt) : 0.0;
    switch (op) {
      case 0: return x == fa;
      case 1: return !(x == fa);
      case 2: return bea_fnear (x, fa, a->eps);
      case 3: return x > fa;
      case 4: return x < fa;
      case 5: return x >= fa && x <= fb;
      case 6: return a->eps > 0.0 ? !bea_fnear (x, pv, a->eps) : !bea_memeq (cur, prev, elem);
      case 7: return a->eps > 0.0 ? bea_fnear (x, pv, a->eps) : bea_memeq (cur, prev, elem);
      case 8: return x > pv;
      case 9: return x < pv;
      case 10: return bea_fnear (x - pv, fa, a->eps);
      case 11: return bea_fnear (pv - x, fa, a->eps);
    }
    return 0;
  }
  if (op == 6) return !bea_memeq (cur, prev, elem);
  if (op == 7) return bea_memeq (cur, prev, elem);
  {
    u64 e = a->epsi;
    if (cls == 0) {
      s64 x = bea_ld_s (cur, a->vt), as = (s64) a->a, bs = (s64) a->b;
      s64 pv = (op >= 8 && op <= 11) ? bea_ld_s (prev, a->vt) : 0;
      switch (op) {
        case 0: return x == as;
        case 1: return x != as;
        case 2: return x >= as ? (u64) x - (u64) as <= e : (u64) as - (u64) x <= e;
        case 3: return x > as;
        case 4: return x < as;
        case 5: return x >= as && x <= bs;
        case 8: return x > pv;
        case 9: return x < pv;
        case 10: return (u64) x - (u64) pv == (u64) as;
        case 11: return (u64) pv - (u64) x == (u64) as;
      }
      return 0;
    } else {
      u64 x = bea_ld_u (cur, a->vt), au = a->a, bu = a->b;
      u64 pv = (op >= 8 && op <= 11) ? bea_ld_u (prev, a->vt) : 0;
      switch (op) {
        case 0: return x == au;
        case 1: return x != au;
        case 2: return x >= au ? x - au <= e : au - x <= e;
        case 3: return x > au;
        case 4: return x < au;
        case 5: return x >= au && x <= bu;
        case 8: return x > pv;
        case 9: return x < pv;
        case 10: return x - pv == au;
        case 11: return pv - x == au;
      }
      return 0;
    }
  }
}

static void bea_emit (BeaScanArgs * a, u64 at, const u8 * q)
{
  u64 k, elem = a->elem;
  u8 * v = (u8 *) a->vals + at * elem;
  ((u64 *) a->addrs)[at] = (u64) q;
  for (k = 0; k != elem; k++) v[k] = q[k];
}

/* first-scan interval tests, computed once per call so the hot loops stay branch-light */
typedef struct { int empty, neg; s64 slo, shi; u64 ulo, uhi; double fa, fb, eps; } BeaTest;

static void bea_prepare (const BeaScanArgs * a, BeaTest * t)
{
  u64 op = a->op;
  u64 e = a->epsi;
  int cls = bea_class (a->vt);
  t->empty = 0; t->neg = op == 1;
  t->slo = 0; t->shi = 0; t->ulo = 0; t->uhi = 0;
  t->fa = bea_bits_f (a->a, a->vt); t->fb = bea_bits_f (a->b, a->vt); t->eps = a->eps;
  if (cls == 0) {
    s64 as = (s64) a->a, bs = (s64) a->b;
    t->slo = as; t->shi = as;
    if (op == 5) t->shi = bs;
    if (op == 3) { if (as == BEA_S64_MAX) t->empty = 1; else { t->slo = as + 1; t->shi = BEA_S64_MAX; } }
    if (op == 4) { if (as == BEA_S64_MIN) t->empty = 1; else { t->slo = BEA_S64_MIN; t->shi = as - 1; } }
    if (op == 2) {
      t->slo = (e >= (u64) as - (u64) BEA_S64_MIN) ? BEA_S64_MIN : (s64) ((u64) as - e);
      t->shi = (e >= (u64) BEA_S64_MAX - (u64) as) ? BEA_S64_MAX : (s64) ((u64) as + e);
    }
  } else if (cls == 1) {
    u64 au = a->a, bu = a->b;
    t->ulo = au; t->uhi = au;
    if (op == 5) t->uhi = bu;
    if (op == 3) { if (au == BEA_U64_MAX) t->empty = 1; else { t->ulo = au + 1; t->uhi = BEA_U64_MAX; } }
    if (op == 4) { if (au == 0) t->empty = 1; else { t->ulo = 0; t->uhi = au - 1; } }
    if (op == 2) { t->ulo = au >= e ? au - e : 0; t->uhi = au <= BEA_U64_MAX - e ? au + e : BEA_U64_MAX; }
  }
}

#define BEA_LOOP(XT, LOAD, TEST)                                    \
  do {                                                              \
    for (o = a->progress; o < len && o + elem <= avail; o += align) { \
      XT x;                                                         \
      if (at >= cap) break;                                         \
      a->progress = o;                                              \
      x = (XT) (LOAD);                                              \
      if (TEST) { bea_emit (a, at, p + o); at++; a->at = at; }      \
    }                                                               \
  } while (0)

#define BEA_SLOOP(T) BEA_LOOP (s64, *(const T *) (p + o), ((x >= t.slo && x <= t.shi) != t.neg))
#define BEA_ULOOP(T) BEA_LOOP (u64, *(const T *) (p + o), ((x >= t.ulo && x <= t.uhi) != t.neg))
#define BEA_FLOOPS(T)                                                                     \
  do {                                                                                    \
    if (op == 0) BEA_LOOP (double, *(const T *) (p + o), (x == t.fa));                    \
    else if (op == 1) BEA_LOOP (double, *(const T *) (p + o), !(x == t.fa));              \
    else if (op == 2) BEA_LOOP (double, *(const T *) (p + o), (x - t.fa <= t.eps && t.fa - x <= t.eps)); \
    else if (op == 3) BEA_LOOP (double, *(const T *) (p + o), (x > t.fa));                \
    else if (op == 4) BEA_LOOP (double, *(const T *) (p + o), (x < t.fa));                \
    else BEA_LOOP (double, *(const T *) (p + o), (x >= t.fa && x <= t.fb));               \
  } while (0)

/* first scan: elements at offsets [progress, len) step align with offset + elem <= avail */
void bea_scan_cmp (BeaScanArgs * a)
{
  const u8 * p = (const u8 *) a->p;
  u64 len = a->len, avail = a->avail, elem = a->elem, align = a->align, cap = a->cap, at = a->at, op = a->op, o;
  u64 vt = a->vt;
  BeaTest t;
  bea_prepare (a, &t);
  o = a->progress;
  if (t.empty) {
    /* nothing can match: skip to where the loop would have stopped, without reading */
    u64 lim = avail >= elem ? avail - elem + 1 : 0;
    if (lim > len) lim = len;
    if (o < lim) o += ((lim - o + align - 1) / align) * align;
    a->progress = o;
    return;
  }
  if (vt == 11 || op == 13) {
    const u8 * w = (const u8 *) a->operand;
    BEA_LOOP (u64, 0, (bea_memeq (p + o, w, elem) != (op == 1)));
  } else if (vt == 0) BEA_SLOOP (s8);
  else if (vt == 2) BEA_SLOOP (s16);
  else if (vt == 4) BEA_SLOOP (s32);
  else if (vt == 6) BEA_SLOOP (s64);
  else if (vt == 1) BEA_ULOOP (u8);
  else if (vt == 3) BEA_ULOOP (u16);
  else if (vt == 5) BEA_ULOOP (u32);
  else if (vt == 8) BEA_FLOOPS (float);
  else if (vt == 9) BEA_FLOOPS (double);
  else BEA_ULOOP (u64);
  a->progress = o;
  a->at = at;
}

/* next scan: candidates [progress, end) compacted in place into [at, ...) */
void bea_scan_next (BeaScanArgs * a)
{
  u64 * addrs = (u64 *) a->addrs;
  u8 * vals = (u8 *) a->vals;
  u8 * firsts = (u8 *) a->firsts;
  u64 elem = a->elem, end = a->end, kept = a->at, i, k;
  u8 tmp[256];
  for (i = a->progress; i < end; i++) {
    const u8 * cur = (const u8 *) addrs[i];
    a->progress = i;
    for (k = 0; k != elem; k++) tmp[k] = cur[k];
    if (bea_match (a, tmp, vals + i * elem, firsts != 0 ? firsts + i * elem : 0)) {
      addrs[kept] = addrs[i];
      for (k = 0; k != elem; k++) vals[kept * elem + k] = tmp[k];
      if (firsts != 0)
        for (k = 0; k != elem; k++) firsts[kept * elem + k] = firsts[i * elem + k];
      kept++;
      a->at = kept;
    }
  }
  a->progress = end;
  a->at = kept;
}

/* snapshot next scan: compares the region slice at p with its snapshot; emits explicit candidates */
void bea_scan_snap (BeaScanArgs * a)
{
  const u8 * p = (const u8 *) a->p;
  const u8 * s = (const u8 *) a->snap;
  u64 * addrs = (u64 *) a->addrs;
  u8 * vals = (u8 *) a->vals;
  u8 * firsts = (u8 *) a->firsts;
  u64 len = a->len, avail = a->avail, elem = a->elem, align = a->align, cap = a->cap, at = a->at, o, k;
  u8 tmp[256];
  for (o = a->progress; o < len && o + elem <= avail; o += align) {
    if (at >= cap) break;
    a->progress = o;
    for (k = 0; k != elem; k++) tmp[k] = p[o + k];
    if (bea_match (a, tmp, s + o, s + o)) {
      addrs[at] = (u64) (p + o);
      for (k = 0; k != elem; k++) vals[at * elem + k] = tmp[k];
      if (firsts != 0)
        for (k = 0; k != elem; k++) firsts[at * elem + k] = s[o + k];
      at++;
      a->at = at;
    }
  }
  a->progress = o;
  a->at = at;
}
`;
