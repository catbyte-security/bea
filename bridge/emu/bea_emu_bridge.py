#!/usr/bin/env python3
# =================================================================================================
# bridge/emu/bea_emu_bridge.py: the BEA emulator bridge, protocol "bea-emu/0.1" (WP14-EMU; DESIGN §5.6, annex S5
# §3-§6 and §10-§13 as amended by DESIGN Appendix A.4). One self-contained file (S5-D1): stdlib + unicorn + capstone
# + pefile, Python >= 3.10. The canonical wire types are src/domain/emuProtocol.ts; this file mirrors them exactly.
#
#   "<python>" -I -X utf8 bea_emu_bridge.py --mem-limit <bytes> [--cache-dir <dir>] [--probe | --selftest]
#
# Frames are NDJSON on stdin (host -> bridge) and stdout (bridge -> host), <= 64 MiB each; stderr is free-form logs.
# The first stdout line is a `ready` (or `fatal`) event. Requests run one at a time in arrival order; `bridge.cancel`
# and `bridge.ping` are answered out of band by the reader thread. Every emulation outcome is a RESULT with a status
# (faults, exceptions, unhandled imports, budgets); an `error` frame means the request could not be attempted.
# The process exits 0 on `bridge.shutdown` or stdin EOF, 2 on a usage error, 3 when the engines are missing and 70
# when an exception escapes the dispatch loop (a bug). It never relies on signals: the host's kill is the hard stop.
#
# Sections (S5 §3.2): A constants and tables · B value helpers · C frame I/O · D process hygiene (memory limit) ·
# E MappedImage · F engines · G layout and regions · H HLE import models · I ISA guard v2 · J snapshots v2 ·
# K call engine · L tracing · M diagnostics · N batch engine · O sweep and known functions · P probe and selftest ·
# Q server.
# =================================================================================================
from __future__ import annotations

import base64
import bisect
import ctypes
import hashlib
import importlib
import json
import math
import os
import platform
import queue
import struct
import sys
import threading
import time
import traceback

# ------------------------------------------------------------------------------------------------- A. constants
PROTOCOL = "bea-emu/0.1"
BRIDGE_VERSION = "0.1.0"  # build-stamped: scripts/build-bridge.mjs keeps it equal to package.json "version"
CLIENT_NAME = "bea"

MAX_FRAME_BYTES = 64 * 1024 * 1024
MAX_MEM_READ = 16 * 1024 * 1024
MAX_VECTORS_PER_BATCH = 1_000_000
MAX_SWEEP_TARGETS = 20_000
MAX_SWEEP_VECTORS = 16
MAX_NAMED_SNAPSHOTS = 16
MAX_TRACE_EVENTS = 100_000
MAX_PATCHES = 256
MAX_PATCH_BYTES = 1 << 20
MAX_OVERRIDES = 256
MAX_STATE_WRITES = 256
MAX_DISASM = 512
MAX_FUNCTION_DISASM_BYTES = 1 << 16
MAX_COVERAGE_BLOCKS = 1_000_000
MAX_BATCH_FAULTS = 1000
BATCH_FAULT_DETAILS = 8
# Out buffers come back WHOLE: the host decodes every declared field from these bytes, so a cut buffer would read as
# zeros (review fix EMU-2; the old 1 MiB single / 4 KiB batch caps did exactly that). The hex of all out buffers of
# one result is budgeted up front, before anything runs: a request over the budget is refused (invalid_params,
# path params.vectors), never truncated. Per cell: 2 hex digits per byte plus 3 bytes of JSON quoting.
MAX_OUT_HEX = 56 << 20
MAX_CALL_EVENTS = 256
MAX_AUTOMAP_PAGES = 256
SNAPSHOT_BYTES_LIMIT = 512 << 20
COW_LEVELS_BEFORE_COMPACTION = 8
PROGRESS_PERIOD_S = 0.25
DEADLINE_GRACE_S = 0.25
ISA_CACHE_BYTES = 512 << 20
ISA_CACHE_SCHEMA = "bea.isa-scan/1"
LARGE_IMAGE_BYTES = 32 << 20

PAGE = 0x1000
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1
USER_VA_LIMIT = 1 << 47

EXACT_PINS = {"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"}

# Synthetic window (S5 §3.3): every BEA-made region lives in one 1 GiB window at base S.
WINDOW_SIZE = 0x4000_0000
WINDOW_TOP = 0x7E00_0000_0000
WINDOW_FLOOR = 0x0200_0000_0000
WINDOW_STEP = 0x100_0000_0000
OFF_TEB = 0x0
OFF_PEB = 0x1000
OFF_MISC = 0x2000
OFF_ERRNO = 0x2800
OFF_TLS = 0x4000
TLS_MAX = 0xFC000
OFF_STUBS = 0x10_0000
STUB_AREA = 0x10_0000
STUB_SIZE = 16
DYN_STUBS = 256
OFF_SENTINEL = 0x20_0000
OFF_FAKE_HMODULE = 0x0F00_0000
OFF_HEAP = 0x1000_0000
OFF_SCRATCH = 0x2000_0000
OFF_STACK = 0x3000_0000
KUSD_VA = 0x7FFE_0000
MAX_HEAP = 256 << 20
MAX_SCRATCH = 256 << 20
MAX_STACK = 16 << 20
DEFAULT_HEAP = 64 << 20
DEFAULT_SCRATCH = 16 << 20
DEFAULT_STACK = 1 << 20
FAKE_TID = 0x1004
FAKE_PID = 0x1000
FILETIME_EPOCH = 134_000_000_000_000_000  # a fixed 2025 FILETIME; +10,000 (1 ms) per GetSystemTimeAsFileTime
VIRTUAL_TSC_START = 1 << 32

DEFAULT_MXCSR = 0x1F80
DEFAULT_FPCW = 0x027F
MXCSR_CONTROL = 0xFFC0
RFLAGS_ENTRY = 0x202

STATUS_CODE = {
    "returned": "ok", "fault": "fault", "cpu_exception": "cpu", "invalid_instruction": "inv",
    "unsupported_instruction": "unsup", "unhandled_import": "imp", "syscall": "sys", "raised": "raised",
    "terminated": "term", "budget_exhausted": "budget", "timeout": "timeout", "cancelled": "cancel",
    "engine_error": "eng",
}
# int n -> (cause, name) for cpu_exception stops (S5 §3.13). 0x29/0x2c/0x2e are handled as terminate/syscall.
CPU_EXCEPTIONS = {
    0: ("div_error", "#DE divide error"), 1: ("interrupt_1", "#DB debug"), 3: ("breakpoint", "#BP breakpoint"),
    4: ("interrupt_4", "#OF overflow"), 5: ("interrupt_5", "#BR bound range exceeded"),
    6: ("ud", "#UD invalid opcode"), 7: ("interrupt_7", "#NM device not available"),
    13: ("gp", "#GP general protection"), 14: ("interrupt_14", "#PF page fault"),
    16: ("x87_fp", "#MF x87 floating-point error"), 17: ("alignment", "#AC alignment check"),
    19: ("simd_fp", "#XM SIMD floating-point exception"), 0x2D: ("debug_service", "int 0x2d (debug service)"),
}
UD_MNEMONICS = {"ud0", "ud1", "ud2"}
VEX_REASON = ("VEX/EVEX: Unicorn 2.1.x rejects 256-bit/FMA forms and silently mis-executes VEX.128 "
              "[ext-backends §2.4 #2]")
ENGINE_REJECT_REASON = "the engine rejected an instruction that capstone decodes (unsupported by Unicorn 2.1.x)"

# ISA guard site classes (S5 §3.7).
SEG_PREFIXES = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x67))
BMI_ALLOW = frozenset(("andn", "bextr", "blsi", "blsmsk", "blsr", "bzhi", "mulx", "pdep", "pext", "rorx", "sarx",
                       "shlx", "shrx"))
X87_INEXACT = frozenset(("fsin", "fcos", "fsincos", "fptan", "fpatan", "f2xm1", "fyl2x", "fyl2xp1"))
# Legacy-SSE instructions Unicorn 2.1.x (QEMU 5) computes differently from hardware (review fix EMU-1; lab: the same
# bytes run natively and in Unicorn 2.1.4 on random and special inputs): rcp*/rsqrt* are computed exactly instead of
# with the CPU's ~12-bit approximation table (which differs between vendors, so no emulator can be bit-exact); dpps
# adds the products one after another instead of (p0+p1)+(p2+p3) and both dpps and dppd lose the sign of a zero sum.
# Their VEX forms already stop at the ISA guard. NaN-payload-only differences of other SSE arithmetic are documented
# (docs/limitations.md), not tagged.
SSE_INEXACT = frozenset(("rcpss", "rcpps", "rsqrtss", "rsqrtps", "dpps", "dppd"))
FP_STATUS = frozenset(("stmxcsr", "fnstsw", "fstsw", "fnstenv", "fstenv", "fnsave", "fsave", "fxsave", "fxsave64",
                       "fnclex"))
TSC_MNEMONICS = frozenset(("rdtsc", "rdtscp"))
RNG_MNEMONICS = frozenset(("rdrand", "rdseed"))
SYSCALL_MNEMONICS = frozenset(("syscall", "sysenter"))
SITE_KINDS = ("vex", "evex", "x87_inexact", "fp_status", "cpuid", "syscall", "tsc", "rng", "sse_inexact")
TAG_KINDS = ("x87_inexact", "fp_status", "tsc", "rng", "sse_inexact")
# site kind -> the call-level deviation a tagged hit produces
TAG_DEVIATIONS = (("x87_inexact", "x87_transcendental_inexact"), ("sse_inexact", "sse_approx_inexact"),
                  ("fp_status", "fp_status_flags_unmodeled"), ("tsc", "nondeterministic_tsc"),
                  ("rng", "nondeterministic_rng"))
TAG_DEVIATION_OF = dict(TAG_DEVIATIONS)
ISA_CACHE_KEY = "bea-isa/2"  # /2: sse_inexact sites (a /1 scan never classified them, so it must not be reused)
MAX_GAP_VEX_HOOKS = 256
MAX_TAG_HOOKS = 512

# Deviation notes (BEA-authored sentences; S5 §4.4 DeviationKind).
DEVIATION_NOTES = {
    "tls_callbacks_not_run": "TLS callbacks of the image were not executed.",
    "entry_point_not_run": "The entry point (DllMain or the CRT start-up) was not executed; globals keep their "
                           "file-initialized values.",
    "imports_hle_bound": "Imports are bound to BEA's high-level models, not to real system DLLs.",
    "no_seh_dispatch": "There is no SEH or C++ exception dispatch: CPU exceptions stop emulation and are reported.",
    "delay_imports_present": "The image has delay-load imports; they resolve through the dynamic import models.",
    "managed_image": "The image is a .NET (IL-only) image; the CLR is not emulated.",
    "isa_guard_off": "The ISA guard is off: VEX.128 instructions may silently mis-execute.",
    "isa_guard_incomplete": "Some VEX/EVEX sites outside .pdata could not be guarded (hook budget exceeded).",
    "x87_tagging_incomplete": "Some x87 transcendental sites are not tagged (hook budget exceeded).",
    "fp_status_tagging_incomplete": "Some FP-status reader sites are not tagged (hook budget exceeded).",
    "sse_tagging_incomplete": "Some RCPSS/RCPPS/RSQRTSS/RSQRTPS/DPPS/DPPD sites are not tagged (hook budget "
                              "exceeded).",
    "iat_rebound": "Import address table slots were rebound in emulator memory per the dump import policy.",
    "teb_stack_bounds_rewritten": "The emulator copy of the TEB stack bounds points at the synthetic stack.",
    "memory_patched": "Memory was patched before the baseline was taken.",
    "synthetic_teb": "The TEB, PEB and TLS slot array are synthetic.",
    "synthetic_kuser_shared_data": "KUSER_SHARED_DATA is a synthetic page.",
    "malformed_directory": "A PE directory is malformed and was ignored.",
    "engine_unvalidated": "The emulation engines are not the validated set (unicorn 2.1.4, capstone 5.0.9, "
                          "pefile 2024.8.26).",
    "x87_transcendental_inexact": "Unicorn approximates x87 transcendental instructions; results are not "
                                  "bit-exact with hardware.",
    "sse_approx_inexact": "The code executed RCPSS/RCPPS/RSQRTSS/RSQRTPS or DPPS/DPPD, which Unicorn computes "
                          "differently from hardware (exact reciprocals instead of the CPU's approximation table, "
                          "sequential dot-product sums); results are not bit-exact.",
    "hle_heap_exhausted": "A guest allocation failed because the emulated heap (memory.heap_mb) was full; the "
                          "allocator returned NULL where the real process may have succeeded.",
    "inexact_import_model": "Math imports were modeled with host double precision; not bit-exact with the real CRT.",
    "unhandled_import_returned_zero": "Unhandled imports returned zero (imports.unhandled = return_zero).",
    "auto_mapped_zero_pages": "Unmapped accesses were satisfied with zero pages; results are synthetic.",
    "fp_status_flags_unmodeled": "The code read FP status flags, which Unicorn does not model.",
    "cpuid_executed": "The code executed CPUID; the emulated CPU reports no AVX, so dispatch may differ from hardware.",
    "virtualized_tsc": "RDTSC returned a virtual time stamp counter.",
    "nondeterministic_tsc": "The code read the time stamp counter; the value is not deterministic.",
    "nondeterministic_rng": "The code executed RDRAND/RDSEED; the value is not deterministic.",
    "dynamic_import_resolved": "Imports were resolved dynamically (GetProcAddress or delay load).",
    "self_modifying_code": "The code wrote to executable memory.",
    "isa_overlay_overwritten": "A host write replaced an ISA-guard patch site; that site is no longer guarded.",
}
LOADER_ONLY = {"tls_callbacks_not_run", "entry_point_not_run", "imports_hle_bound", "no_seh_dispatch",
               "delay_imports_present", "managed_image", "isa_guard_off", "isa_guard_incomplete",
               "x87_tagging_incomplete", "fp_status_tagging_incomplete", "sse_tagging_incomplete", "iat_rebound",
               "teb_stack_bounds_rewritten",
               "memory_patched", "synthetic_teb", "synthetic_kuser_shared_data", "malformed_directory",
               "engine_unvalidated"}


def out_hex_bytes(buffers, vectors):
    """The out-buffer hex one result carries for `vectors` vectors (MAX_OUT_HEX budget)."""
    return vectors * sum(2 * b.size + 3 for b in buffers if b.out)


def deviation(kind, count=None, detail=None):
    d = {"kind": kind, "note": DEVIATION_NOTES[kind]}
    if count is not None:
        d["count"] = count
    if detail:
        d["detail"] = detail
    return d


# ------------------------------------------------------------------------------------------------- B. value helpers
class BridgeError(Exception):
    """A request-level failure: the request could not be attempted (S5 §3.17). Outcomes are results."""

    def __init__(self, code, message, data=None):
        super().__init__(message)
        self.code = code
        self.data = data


class VectorSetupError(BridgeError):
    """A vector's buffers could not be placed (HLE heap or scratch exhausted). Nothing of the vector ran and its
    allocations were rolled back, so the session is in the state the previous vector left: a batch returns the
    completed prefix with `summary.stopped` instead of discarding it (review fix EMU-6)."""


def hx(v):
    """Canonical lowercase hex ("0x0" for zero)."""
    return hex(v)


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


def parse_hex(v, path, bits=64):
    """Hex inputs: "0x" + 1..bits/4 hex digits, any case."""
    if isinstance(v, str) and len(v) > 2 and v[0] == "0" and v[1] in "xX" and len(v) - 2 <= bits // 4:
        try:
            return int(v[2:], 16)
        except ValueError:
            pass
    raise BridgeError("invalid_params", f"{path}: expected a 0x-prefixed hex value of at most {bits // 4} digits",
                      {"path": path})


def parse_hexbytes(v, path, limit=None):
    if not isinstance(v, str) or len(v) % 2:
        raise BridgeError("invalid_params", f"{path}: expected an even-length hex byte string", {"path": path})
    if limit is not None and len(v) // 2 > limit:
        raise BridgeError("invalid_params", f"{path}: more than {limit} bytes", {"path": path})
    try:
        return bytes.fromhex(v)
    except ValueError:
        raise BridgeError("invalid_params", f"{path}: not a hex byte string", {"path": path}) from None


def p_obj(d, key, path, required=True):
    v = d.get(key)
    if v is None:
        if required:
            raise BridgeError("invalid_params", f"{path}.{key} is required", {"path": f"{path}.{key}"})
        return {}
    if not isinstance(v, dict):
        raise BridgeError("invalid_params", f"{path}.{key} must be an object", {"path": f"{path}.{key}"})
    return v


def p_list(d, key, path, maximum, required=False):
    v = d.get(key)
    if v is None:
        if required:
            raise BridgeError("invalid_params", f"{path}.{key} is required", {"path": f"{path}.{key}"})
        return []
    if not isinstance(v, list):
        raise BridgeError("invalid_params", f"{path}.{key} must be an array", {"path": f"{path}.{key}"})
    if len(v) > maximum:
        raise BridgeError("invalid_params", f"{path}.{key} has more than {maximum} entries", {"path": f"{path}.{key}"})
    return v


def p_int(d, key, path, lo, hi, default=None):
    v = d.get(key, default)
    if v is None or isinstance(v, bool) or not isinstance(v, int) or v < lo or v > hi:
        if v is None and default is None:
            raise BridgeError("invalid_params", f"{path}.{key} is required", {"path": f"{path}.{key}"})
        raise BridgeError("invalid_params", f"{path}.{key} must be an integer in [{lo}, {hi}]",
                          {"path": f"{path}.{key}"})
    return v


def p_enum(d, key, path, choices, default=None):
    v = d.get(key, default)
    if v not in choices:
        raise BridgeError("invalid_params", f"{path}.{key} must be one of {', '.join(map(str, choices))}",
                          {"path": f"{path}.{key}"})
    return v


def p_bool(d, key, path, default):
    v = d.get(key, default)
    if not isinstance(v, bool):
        raise BridgeError("invalid_params", f"{path}.{key} must be a boolean", {"path": f"{path}.{key}"})
    return v


def p_str(d, key, path, maximum=4096, required=True):
    v = d.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v or len(v) > maximum:
        raise BridgeError("invalid_params", f"{path}.{key} must be a non-empty string of at most {maximum} chars",
                          {"path": f"{path}.{key}"})
    return v


# IEEE helpers for the HLE math models and the sweep matcher (bits in, bits out).
F32_SIGN = 0x8000_0000
F64_SIGN = 0x8000_0000_0000_0000
F32_DEFAULT_NAN = 0xFFC0_0000
F64_DEFAULT_NAN = 0xFFF8_0000_0000_0000
F32_QUIET = 0x0040_0000
F64_QUIET = 0x0008_0000_0000_0000


def f32_isnan(b):
    return (b & 0x7F80_0000) == 0x7F80_0000 and (b & 0x007F_FFFF) != 0


def f64_isnan(b):
    return (b & 0x7FF0_0000_0000_0000) == 0x7FF0_0000_0000_0000 and (b & 0x000F_FFFF_FFFF_FFFF) != 0


def bits_to_f32(b):
    return struct.unpack("<f", struct.pack("<I", b & MASK32))[0]


def bits_to_f64(b):
    return struct.unpack("<d", struct.pack("<Q", b & MASK64))[0]


def f64_to_bits(x):
    if math.isnan(x):
        return F64_DEFAULT_NAN
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def f32_to_bits(x):
    """Round a host double to f32 once (IEEE overflow to +-inf); a computed NaN is the x86 default NaN."""
    if math.isnan(x):
        return F32_DEFAULT_NAN
    try:
        return struct.unpack("<I", struct.pack("<f", x))[0]
    except OverflowError:
        return 0xFF80_0000 if x < 0 else 0x7F80_0000


class FloatFmt:
    __slots__ = ("width", "isnan", "quiet", "sign", "default_nan", "to_float", "from_float", "mask")

    def __init__(self, width):
        self.width = width
        if width == 4:
            self.isnan, self.quiet, self.sign, self.default_nan = f32_isnan, F32_QUIET, F32_SIGN, F32_DEFAULT_NAN
            self.to_float, self.from_float, self.mask = bits_to_f32, f32_to_bits, MASK32
        else:
            self.isnan, self.quiet, self.sign, self.default_nan = f64_isnan, F64_QUIET, F64_SIGN, F64_DEFAULT_NAN
            self.to_float, self.from_float, self.mask = bits_to_f64, f64_to_bits, MASK64


FMT32 = FloatFmt(4)
FMT64 = FloatFmt(8)


def ordered_int(bits, fmt):
    """Monotonic integer image of a non-NaN float's bits (for ulp distances; -0 and +0 both map to 0)."""
    return -(bits & (fmt.sign - 1)) if bits & fmt.sign else bits


def ulp_distance(a, b, fmt):
    return abs(ordered_int(a, fmt) - ordered_int(b, fmt))


def _c_floor(x):
    if not math.isfinite(x):
        return x
    r = float(math.floor(x))
    return math.copysign(0.0, x) if r == 0.0 else r


def _c_ceil(x):
    if not math.isfinite(x):
        return x
    r = float(math.ceil(x))
    return math.copysign(0.0, x) if r == 0.0 else r


def _c_trunc(x):
    if not math.isfinite(x):
        return x
    r = float(math.trunc(x))
    return math.copysign(0.0, x) if r == 0.0 else r


def _c_round(x):
    """C round(): half away from zero."""
    if not math.isfinite(x) or abs(x) >= 2.0 ** 52:
        return x
    a = abs(x)
    r = math.floor(a)
    if a - r >= 0.5:  # exact below 2^52
        r += 1
    return math.copysign(float(r), x)


def _c_log(fn):
    def f(x):
        if x == 0.0:
            return -math.inf
        if x < 0.0:
            return math.nan
        if math.isinf(x):
            return x
        return fn(x)
    return f


def _c_pow(x, y):
    try:
        return math.pow(x, y)
    except ZeroDivisionError:
        return math.inf
    except ValueError:
        if x == 0.0 and y < 0.0:
            odd = float(y).is_integer() and int(y) % 2 == 1
            return math.copysign(math.inf, x) if odd else math.inf
        return math.nan
    except OverflowError:
        neg = x < 0.0 and float(y).is_integer() and int(y) % 2 == 1
        return -math.inf if neg else math.inf


def _overflow_to(sign_fn):
    def wrap(fn):
        def f(*xs):
            try:
                return fn(*xs)
            except OverflowError:
                return math.copysign(math.inf, sign_fn(*xs))
            except ValueError:
                return math.nan
        return f
    return wrap


def _plain(fn):
    def f(*xs):
        try:
            return fn(*xs)
        except (ValueError, ZeroDivisionError):
            return math.nan
        except OverflowError:
            return math.inf
    return f


# name -> (arity, host function, exact?)  The exact ones are IEEE-exact when computed in double and rounded once.
MATH_FUNCS = {
    "sqrt": (1, _plain(math.sqrt), True), "floor": (1, _c_floor, True), "ceil": (1, _c_ceil, True),
    "fabs": (1, None, True), "trunc": (1, _c_trunc, True), "fmod": (2, None, True), "copysign": (2, None, True),
    "sin": (1, _plain(math.sin), False), "cos": (1, _plain(math.cos), False), "tan": (1, _plain(math.tan), False),
    "asin": (1, _plain(math.asin), False), "acos": (1, _plain(math.acos), False),
    "atan": (1, _plain(math.atan), False), "atan2": (2, _plain(math.atan2), False),
    "exp": (1, _overflow_to(lambda x: 1.0)(math.exp), False), "log": (1, _c_log(math.log), False),
    "log10": (1, _c_log(math.log10), False), "pow": (2, _c_pow, False),
    "sinh": (1, _overflow_to(lambda x: x)(math.sinh), False),
    "cosh": (1, _overflow_to(lambda x: 1.0)(math.cosh), False), "tanh": (1, _plain(math.tanh), False),
}


def eval_math(name, fmt, args):
    """Evaluate a C math function on raw bits with x86 NaN rules (propagate the first NaN operand, quieted)."""
    arity, fn, _exact = MATH_FUNCS[name]
    sign = fmt.sign
    if name == "fabs":
        return args[0] & ~sign & fmt.mask
    if name == "copysign":
        return (args[0] & ~sign) | (args[1] & sign)
    for b in args:
        if fmt.isnan(b):
            if name == "pow" and arity == 2:
                x, y = (fmt.to_float(a) for a in args)
                if x == 1.0 or (not fmt.isnan(args[1]) and y == 0.0):
                    return fmt.from_float(1.0)
            return b | fmt.quiet
    xs = [fmt.to_float(b) for b in args]
    if name == "fmod":
        x, y = xs
        if math.isinf(x) or y == 0.0:
            return fmt.default_nan
        if math.isinf(y):
            return args[0]
        return fmt.from_float(math.fmod(x, y))
    return fmt.from_float(fn(*xs))


# ------------------------------------------------------------------------------------------------- C. frame I/O
_OUT_LOCK = threading.Lock()
_OUT_BROKEN = threading.Event()


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def write_frame(obj):
    """Compact JSON, allow_nan=False, one line, serialized by _OUT_LOCK (the reader thread writes too)."""
    data = json.dumps(obj, separators=(",", ":"), allow_nan=False, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(data) > MAX_FRAME_BYTES and "id" in obj:
        data = json.dumps({"id": obj["id"], "error": {
            "code": "frame_too_large",
            "message": f"the result frame would be {len(data)} bytes; the limit is {MAX_FRAME_BYTES}"}},
            separators=(",", ":")).encode("utf-8") + b"\n"
    with _OUT_LOCK:
        if _OUT_BROKEN.is_set():
            return
        try:
            _write_all(1, data)
        except OSError:
            _OUT_BROKEN.set()


class FrameReader:
    """os.read(0) framing (never sys.stdin: a daemon thread blocked in BufferedReader.readline() aborts interpreter
    shutdown, ext-backends §2.4 #8). Yields bytes lines; None marks an oversize frame that was discarded."""

    def __init__(self, fd=0, limit=MAX_FRAME_BYTES):
        self.fd = fd
        self.limit = limit

    def lines(self):
        buf = bytearray()
        scan = 0
        discarding = False
        while True:
            try:
                chunk = os.read(self.fd, 1 << 16)
            except OSError:
                chunk = b""
            if not chunk:
                if buf.strip() and not discarding:
                    yield bytes(buf)
                return
            buf += chunk
            while True:
                nl = buf.find(b"\n", scan)
                if nl < 0:
                    scan = len(buf)
                    if len(buf) > self.limit:
                        if not discarding:
                            yield None
                        discarding = True
                        buf.clear()
                        scan = 0
                    break
                line = bytes(buf[:nl])
                del buf[:nl + 1]
                scan = 0
                if discarding:
                    discarding = False
                    continue
                if len(line) > self.limit:
                    yield None
                    continue
                yield line


# ------------------------------------------------------------------------------------------------- D. process hygiene
def apply_memory_limit(limit_bytes):
    """Self-applied memory cap BEFORE unicorn is imported (S5 §3.1.1; VERIFIED lab S5-E5). Never raises."""
    if not limit_bytes:
        return {"applied": False, "bytes": None, "mechanism": "none"}
    if sys.platform == "win32":
        try:
            import ctypes.wintypes as w

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class IoCounters(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount",
                    "WriteTransferCount", "OtherTransferCount")]

            class Basic(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                            ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

            class Extended(ctypes.Structure):
                _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", IoCounters),
                            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

            k32.CreateJobObjectW.restype = w.HANDLE
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
            k32.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
            k32.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
            k32.GetCurrentProcess.restype = w.HANDLE
            job = k32.CreateJobObjectW(None, None)
            if not job:
                return {"applied": False, "bytes": None, "mechanism": "none",
                        "error": f"CreateJobObjectW failed ({ctypes.get_last_error()})"}
            info = Extended()
            # JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION (no WER dialog on a
            # native engine crash). The job handle is deliberately never closed.
            info.BasicLimitInformation.LimitFlags = 0x100 | 0x400
            info.ProcessMemoryLimit = limit_bytes
            if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                return {"applied": False, "bytes": None, "mechanism": "none",
                        "error": f"SetInformationJobObject failed ({ctypes.get_last_error()})"}
            if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
                return {"applied": False, "bytes": None, "mechanism": "none",
                        "error": f"AssignProcessToJobObject failed ({ctypes.get_last_error()})"}
            globals()["_JOB_HANDLE"] = job
            return {"applied": True, "bytes": limit_bytes, "mechanism": "win32-job"}
        except Exception as e:  # noqa: BLE001 - reported, never fatal
            return {"applied": False, "bytes": None, "mechanism": "none", "error": f"{type(e).__name__}: {e}"}
    if sys.platform.startswith("linux"):
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_DATA, (limit_bytes, limit_bytes))
            try:
                ctypes.CDLL(None).prctl(1, 9)  # PR_SET_PDEATHSIG = 1, SIGKILL = 9 (best effort)
            except Exception:  # noqa: BLE001
                pass
            return {"applied": True, "bytes": limit_bytes, "mechanism": "linux-rlimit-data"}
        except Exception as e:  # noqa: BLE001
            return {"applied": False, "bytes": None, "mechanism": "none", "error": f"{type(e).__name__}: {e}"}
    return {"applied": False, "bytes": None, "mechanism": "none", "error": f"unsupported platform {sys.platform}"}


# ------------------------------------------------------------------------------------------------- E. MappedImage
class _Malformed(Exception):
    pass


class MappedImage:
    """A PE64 parser over MAPPED-layout bytes (RVA = offset from `base`), used for dump modules and, after mapping,
    for on-disk images too (S5 §3.5). Every read is bounds-checked; a malformed directory yields an entry in
    `malformed` and empty data, never an exception."""

    def __init__(self, read, base, size, name):
        self._read = read
        self.base = base
        self.size = size
        self.name = name
        self.malformed = []
        self.headers_ok = False
        self.machine = None
        self.size_of_image = size
        self.sections = []      # dicts: name, rva, vsize, chars
        self.dirs = []
        self.pdata = []         # sorted (begin, end) RVAs
        self.exports = {}       # name -> rva
        self.export_dir = (0, 0)
        self.imports = []       # dicts: dll, name, ordinal, slot_rva
        self.tls = None         # dict: start, end, index, callbacks (rvas), zero_fill
        self.delay_imports = 0
        self.managed = False
        self._parse()

    def rd(self, rva, n):
        if rva < 0 or n < 0 or rva + n > self.size:
            raise _Malformed(f"read {rva:#x}+{n:#x} outside the image")
        try:
            return bytes(self._read(self.base + rva, n))
        except Exception as e:  # noqa: BLE001 - unmapped/uncaptured bytes
            raise _Malformed(f"read {rva:#x}+{n:#x} failed: {e}") from None

    def u16(self, rva):
        return struct.unpack("<H", self.rd(rva, 2))[0]

    def u32(self, rva):
        return struct.unpack("<I", self.rd(rva, 4))[0]

    def u64(self, rva):
        return struct.unpack("<Q", self.rd(rva, 8))[0]

    def cstr(self, rva, limit=512):
        out = bytearray()
        while len(out) < limit:
            n = min(64, self.size - (rva + len(out)))
            if n <= 0:
                raise _Malformed("string runs past the image")
            chunk = self.rd(rva + len(out), n)
            z = chunk.find(b"\0")
            if z >= 0:
                out += chunk[:z]
                return out.decode("ascii", "replace")
            out += chunk
        return out.decode("ascii", "replace")

    def directory(self, index):
        return self.dirs[index] if index < len(self.dirs) else (0, 0)

    def _parse(self):
        try:
            if self.rd(0, 2) != b"MZ":
                raise _Malformed("no MZ header")
            e = self.u32(0x3C)
            if self.rd(e, 4) != b"PE\0\0":
                raise _Malformed("no PE signature")
            self.machine = self.u16(e + 4)
            nsec = self.u16(e + 6)
            opt_size = self.u16(e + 20)
            opt = e + 24
            if self.u16(opt) != 0x20B:
                raise _Malformed("not a PE32+ optional header")
            self.size_of_image = self.u32(opt + 56)
            nrva = min(self.u32(opt + 108), 16)
            self.dirs = [(self.u32(opt + 112 + 8 * i), self.u32(opt + 116 + 8 * i)) for i in range(nrva)]
            sh = opt + opt_size
            for i in range(min(nsec, 96)):
                o = sh + 40 * i
                name = self.rd(o, 8).rstrip(b"\0").decode("ascii", "replace")
                vsize, va, raw = self.u32(o + 8), self.u32(o + 12), self.u32(o + 16)
                self.sections.append({"name": name, "rva": va, "vsize": vsize or raw, "chars": self.u32(o + 36)})
            self.headers_ok = True
        except _Malformed:
            self.malformed.append("headers")
            return
        for label, fn in (("pdata", self._pdata), ("exports", self._exports), ("imports", self._imports),
                          ("tls", self._tls), ("delay_imports", self._delay), ("clr", self._clr)):
            try:
                fn()
            except _Malformed:
                self.malformed.append(label)

    def _pdata(self):
        rva, size = self.directory(3)
        if not rva or size < 12:
            return
        raw = self.rd(rva, size // 12 * 12)
        self.pdata = sorted({(b, e) for b, e, _u in struct.iter_unpack("<III", raw) if b and e > b})

    def _exports(self):
        rva, size = self.directory(0)
        if not rva:
            return
        self.export_dir = (rva, size)
        nfun, nnames = self.u32(rva + 20), min(self.u32(rva + 24), 1 << 20)
        aof, aon, aoo = self.u32(rva + 28), self.u32(rva + 32), self.u32(rva + 36)
        names = self.rd(aon, 4 * nnames) if nnames else b""
        ords = self.rd(aoo, 2 * nnames) if nnames else b""
        for i in range(nnames):
            idx = struct.unpack_from("<H", ords, 2 * i)[0]
            if idx >= nfun:
                continue
            frva = self.u32(aof + 4 * idx)
            if rva <= frva < rva + size:  # forwarder
                continue
            self.exports[self.cstr(struct.unpack_from("<I", names, 4 * i)[0])] = frva

    def _imports(self):
        rva, _size = self.directory(1)
        if not rva:
            return
        for d in range(4096):
            oft, _ts, _fc, name_rva, ft = struct.unpack("<IIIII", self.rd(rva + 20 * d, 20))
            if not (oft or name_rva or ft):
                break
            dll = self.cstr(name_rva)
            table = oft or ft
            for k in range(65536):
                entry = self.u64(table + 8 * k)
                if not entry:
                    break
                if entry >> 63:
                    name, ordinal = None, entry & 0xFFFF
                elif oft:
                    name, ordinal = self.cstr((entry & 0x7FFF_FFFF) + 2), None
                else:  # a loaded image without an INT: the IAT holds resolved pointers, the name is unknown
                    name, ordinal = None, None
                self.imports.append({"dll": dll, "name": name, "ordinal": ordinal, "slot_rva": ft + 8 * k})

    def _tls(self):
        rva, _size = self.directory(9)
        if not rva:
            return
        start, end, index, cbs = (self.u64(rva + o) for o in (0, 8, 16, 24))
        zero = self.u32(rva + 32)
        rel = (lambda va: va - self.base if va else 0)
        callbacks = []
        if cbs:
            for k in range(64):
                cb = self.u64(rel(cbs) + 8 * k)
                if not cb:
                    break
                callbacks.append(rel(cb))
        self.tls = {"start": rel(start), "end": rel(end), "index": rel(index), "callbacks": callbacks,
                    "zero_fill": zero}

    def _delay(self):
        rva, _size = self.directory(13)
        if not rva:
            return
        for d in range(1024):
            attrs, name_rva, _h, _iat, int_rva, _b, _u, _t = struct.unpack("<IIIIIIII", self.rd(rva + 32 * d, 32))
            if not (name_rva or int_rva):
                break
            if not attrs & 1:  # old VA-based descriptor
                int_rva = (int_rva - self.base) & MASK32
            for k in range(65536):
                if not self.u64(int_rva + 8 * k):
                    break
                self.delay_imports += 1

    def _clr(self):
        rva, _size = self.directory(14)
        if rva:
            self.managed = bool(self.u32(rva + 16) & 1)  # COMIMAGE_FLAGS_ILONLY

    def exec_ranges(self):
        return sorted((s["rva"], s["rva"] + s["vsize"]) for s in self.sections
                      if s["chars"] & 0x2000_0000 and s["vsize"])

    def function_at(self, rva):
        i = bisect.bisect_right(self.pdata, (rva, MASK64)) - 1
        while i >= 0:
            b, e = self.pdata[i]
            if b <= rva < e:
                return b, e
            if e <= rva and i < len(self.pdata) - 1:
                break
            i -= 1
        return None


def section_perms(chars):
    return (("r" if chars & 0x4000_0000 else "-") + ("w" if chars & 0x8000_0000 else "-")
            + ("x" if chars & 0x2000_0000 else "-"))


# ------------------------------------------------------------------------------------------------- F. engines
# Imported only after the memory limit is applied (S5 §3.1 step 3-4). Module-level names are filled by load_engines().
unicorn = capstone = pefile = None
Uc = UcError = U = X = None
_ENGINE_VERSIONS = None


def _dist_version(name, fallback):
    # Distribution metadata, not __version__: the capstone 5.0.9 wheel reports "5.0.7" (ext-backends §2.4 #8).
    try:
        from importlib import metadata

        return metadata.version(name)
    except Exception:  # noqa: BLE001
        return fallback


def load_engines():
    """Import unicorn, capstone and pefile. Returns (missing, errors); empty lists on success."""
    global unicorn, capstone, pefile, Uc, UcError, U, X
    mods, missing, errors = {}, [], {}
    for name in ("unicorn", "capstone", "pefile"):
        try:
            mods[name] = importlib.import_module(name)
        except Exception as e:  # noqa: BLE001 - reported in the fatal event / probe line
            missing.append(name)
            errors[name] = f"{type(e).__name__}: {e}"
    if missing:
        return missing, errors
    unicorn, capstone, pefile = mods["unicorn"], mods["capstone"], mods["pefile"]
    Uc, UcError = unicorn.Uc, unicorn.UcError
    U = importlib.import_module("unicorn.unicorn_const")
    X = importlib.import_module("unicorn.x86_const")
    _init_tables()
    return [], {}


def engine_versions():
    global _ENGINE_VERSIONS
    if _ENGINE_VERSIONS is None:
        _ENGINE_VERSIONS = {
            "python": platform.python_version(),
            "unicorn": _dist_version("unicorn", getattr(unicorn, "__version__", "unknown")),
            "unicornCore": ".".join(str(x) for x in unicorn.uc_version()[:2]),
            "capstone": _dist_version("capstone", getattr(capstone, "__version__", "unknown")),
            "pefile": _dist_version("pefile", getattr(pefile, "__version__", "unknown")),
        }
    return _ENGINE_VERSIONS


def pin_class(ev):
    """S5 §6.1: exact | compatible | mismatch (the host rejects mismatch candidates)."""
    if sys.version_info < (3, 10):
        return "mismatch"
    if all(ev.get(k) == v for k, v in EXACT_PINS.items()):
        return "exact"
    if ev.get("unicorn", "").startswith("2.1.") and ev.get("capstone", "").startswith("5.") and ev.get("pefile"):
        return "compatible"
    return "mismatch"


def _init_tables():
    g = globals()
    g["REG"] = {n: getattr(X, f"UC_X86_REG_{n.upper()}") for n in (
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "mxcsr", "fpcw", "fpsw", "fptag", "gs_base")}
    g["REG"]["rflags"] = X.UC_X86_REG_EFLAGS
    g["XMM"] = [getattr(X, f"UC_X86_REG_XMM{i}") for i in range(16)]
    g["ARG_REG"] = {"rcx": X.UC_X86_REG_RCX, "rdx": X.UC_X86_REG_RDX, "r8": X.UC_X86_REG_R8, "r9": X.UC_X86_REG_R9,
                    "xmm0": g["XMM"][0], "xmm1": g["XMM"][1], "xmm2": g["XMM"][2], "xmm3": g["XMM"][3]}
    g["GPR_ARGS"] = [X.UC_X86_REG_RCX, X.UC_X86_REG_RDX, X.UC_X86_REG_R8, X.UC_X86_REG_R9]
    g["ZERO_GPRS"] = [g["REG"][n] for n in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10",
                                             "r11", "r12", "r13", "r14", "r15")]
    g["DUMP_REGS"] = [(n, g["REG"][n]) for n in (
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "rflags", "mxcsr", "fpcw", "fpsw")]
    g["ACCESS"] = {
        U.UC_MEM_READ_UNMAPPED: ("read", "unmapped"), U.UC_MEM_WRITE_UNMAPPED: ("write", "unmapped"),
        U.UC_MEM_FETCH_UNMAPPED: ("fetch", "unmapped"), U.UC_MEM_READ_PROT: ("read", "protected"),
        U.UC_MEM_WRITE_PROT: ("write", "protected"), U.UC_MEM_FETCH_PROT: ("fetch", "protected"),
    }
    g["CTX_CPU"] = ctypes.c_int(U.UC_CTL_CONTEXT_CPU)
    g["CTX_CPU_MEM"] = ctypes.c_int(U.UC_CTL_CONTEXT_CPU | U.UC_CTL_CONTEXT_MEMORY)


def perms_to_uc(p):
    v = 0
    if "r" in p:
        v |= U.UC_PROT_READ
    if "w" in p:
        v |= U.UC_PROT_WRITE
    if "x" in p:
        v |= U.UC_PROT_EXEC
    return v


_INSN_HOOK_SUPPORT = None


def insn_hook_support():
    """Which UC_HOOK_INSN instructions this engine accepts (rdtsc is rejected by unicorn 2.1.4: UC_ERR_ARG)."""
    global _INSN_HOOK_SUPPORT
    if _INSN_HOOK_SUPPORT is None:
        out = {}
        uc = Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        for name, ins in (("cpuid", X.UC_X86_INS_CPUID), ("syscall", X.UC_X86_INS_SYSCALL),
                          ("rdtsc", X.UC_X86_INS_RDTSC), ("rdtscp", X.UC_X86_INS_RDTSCP)):
            try:
                uc.hook_add(U.UC_HOOK_INSN, lambda *_a: 0, None, 1, 0, ins)
                out[name] = True
            except Exception:  # noqa: BLE001
                out[name] = False
        _INSN_HOOK_SUPPORT = out
    return _INSN_HOOK_SUPPORT


# ------------------------------------------------------------------------------------------------- G. layout
class Region:
    """One mapped (or deliberately unmapped-but-known) range, for describe() and extents (S5 §3.3)."""

    __slots__ = ("start", "end", "name", "kind", "module", "capture", "perms", "tag")

    def __init__(self, start, end, name, kind, perms, module=None, capture=None, tag=None):
        self.start, self.end, self.name, self.kind, self.perms = start, end, name, kind, perms
        self.module, self.capture, self.tag = module, capture, tag


def choose_window(occupied, size=WINDOW_SIZE):
    """The first free 1 GiB window from 0x7E00_0000_0000 downward in 1 TiB steps (S5 §3.3)."""
    cand = WINDOW_TOP
    while cand >= WINDOW_FLOOR:
        if all(e <= cand or b >= cand + size for b, e in occupied):
            return cand
        cand -= WINDOW_STEP
    raise BridgeError("layout_conflict", "no free 1 GiB window for the synthetic regions")


class RegBatch:
    """A prepared uc_reg_write_batch: register ids, value cells and pointers are built once; a vector only updates
    the cells. The binding's public reg_write_batch re-selects a ctypes class per register on every call (~40 us
    for 26 registers), which dominated the fast batch path. Falls back to the public API when the binding's
    internals differ (compatible engine versions)."""

    __slots__ = ("uc", "ids", "objs", "wide", "c_ids", "c_ptrs", "c_count", "fast", "values")

    def __init__(self, uc, reg_ids):
        self.uc = uc
        self.ids = list(reg_ids)
        self.values = [0] * len(self.ids)
        self.fast = False
        try:
            objs, wide = [], []
            for rid in self.ids:
                cls = uc._select_reg_class(rid)
                objs.append(cls())
                wide.append(hasattr(cls, "qwords"))
            self.objs, self.wide = objs, wide
            self.c_ids = (ctypes.c_int * len(objs))(*self.ids)
            self.c_ptrs = (ctypes.c_void_p * len(objs))(*(ctypes.addressof(o) for o in objs))
            self.c_count = ctypes.c_int(len(objs))
            self.fast = callable(getattr(uc, "_do_reg_write_batch", None))
        except Exception:  # noqa: BLE001 - the public API still works
            self.fast = False

    def set(self, i, v):
        if self.fast:
            if self.wide[i]:
                q = self.objs[i].qwords
                q[0] = v & MASK64
                q[1] = (v >> 64) & MASK64
            else:
                self.objs[i].value = v & MASK64
        else:
            self.values[i] = v

    def write(self):
        if self.fast:
            status = self.uc._do_reg_write_batch(self.c_ids, self.c_ptrs, self.c_count)
            if status != 0:
                raise UcError(status)
        else:
            self.uc.reg_write_batch(list(zip(self.ids, self.values)))


class Module:
    """A module of the emulated address space (the image, or a dump module at its runtime base)."""

    def __init__(self, name, path, base, size, image, sha256, preferred_base, relocated, captured):
        self.name, self.path, self.base, self.size = name, path, base, size
        self.image = image              # MappedImage (may have malformed headers)
        self.sha256, self.preferred_base, self.relocated, self.captured = sha256, preferred_base, relocated, captured
        self.lname = name.lower()

    def contains(self, va):
        return self.base <= va < self.base + self.size

    def info(self):
        img = self.image
        return {
            "name": self.name, "path": self.path, "sha256": self.sha256,
            "preferredBase": hx(self.preferred_base) if self.preferred_base is not None else None,
            "mappedBase": hx(self.base), "size": self.size, "relocated": self.relocated, "captured": self.captured,
            "sections": [{"name": s["name"], "rva": hx(s["rva"]), "size": s["vsize"], "perms": section_perms(s["chars"])}
                         for s in img.sections],
            "exports": len(img.exports), "pdataFunctions": len(img.pdata),
            "tlsCallbacks": [{"rva": hx(r)} for r in (img.tls["callbacks"] if img.tls else [])],
            "tlsCallbacksExecuted": False, "delayImports": img.delay_imports,
        }


# ------------------------------------------------------------------------------------------------- H. HLE models
class GuestFault(Exception):
    """An HLE model was handed guest memory it cannot use: a target fault with cause import_arg."""

    def __init__(self, access, address, size):
        super().__init__(f"{access} {address:#x}+{size:#x}")
        self.access, self.address, self.size = access, address, size


class HleStop(Exception):
    """An HLE model ends the run (terminate / raise / unhandled)."""

    def __init__(self, status, cause, **detail):
        super().__init__(cause)
        self.status, self.cause, self.detail = status, cause, detail


class Args:
    """Win64 argument view at an import stub ([rsp] = return address)."""

    __slots__ = ("uc",)

    def __init__(self, uc):
        self.uc = uc

    def i(self, n):
        if n < 4:
            return self.uc.reg_read(GPR_ARGS[n])
        rsp = self.uc.reg_read(REG["rsp"])
        return struct.unpack("<Q", self.uc.mem_read(rsp + 0x28 + 8 * (n - 4), 8))[0]

    def fbits(self, n, width):
        mask = MASK32 if width == 4 else MASK64
        return (self.uc.reg_read(XMM[n]) if n < 4 else self.i(n)) & mask


MAX_GUEST_COPY = 256 << 20
IPF_PRESENT = frozenset((3, 6, 8, 10, 11, 12, 13, 14, 23, 36, 37, 38))  # winnt.h PF_* the emulated CPU has


def _h_malloc(s, a):
    return "int", s.heap_alloc(a.i(0), 16)


def _h_calloc(s, a):
    total = a.i(0) * a.i(1)
    if total > MAX_GUEST_COPY:
        s.heap_exhausted(min(total, MASK64))
        return "int", 0
    p = s.heap_alloc(total, 16)
    if p and total:
        s.gwrite(p, bytes(total))
    return "int", p


def _h_realloc(s, a):
    old, n = a.i(0), a.i(1)
    if not old:
        return "int", s.heap_alloc(n, 16)
    if n == 0:
        s.heap_free(old)
        return "int", 0
    blk = s.hle["heap_live"].get(old)
    if blk is not None and s.heap_resize(old, n):
        return "int", old
    p = s.heap_alloc(n, 16)
    if p:
        if blk is None:
            s.event("realloc_unknown_pointer", ptr=old)
        else:
            s.gwrite(p, s.gread(old, min(blk[0], n)))
            s.heap_free(old)
    return "int", p


def _h_free(s, a):
    s.heap_free(a.i(0))
    return "none", None


def _h_aligned_malloc(s, a):
    size, align = a.i(0), a.i(1)
    if align == 0 or align & (align - 1):
        return "int", 0
    return "int", s.heap_alloc(size, max(16, align))


def _h_memcpy(s, a):
    d, src, n = a.i(0), a.i(1), a.i(2)
    s.gwrite(d, s.gread(src, n))
    return "int", d


def _h_memset(s, a):
    d, c, n = a.i(0), a.i(1) & 0xFF, a.i(2)
    if n > MAX_GUEST_COPY:
        raise GuestFault("write", d, n)
    s.gwrite(d, bytes([c]) * n)
    return "int", d


def _h_memcmp(s, a):
    x, y = s.gread(a.i(0), a.i(2)), s.gread(a.i(1), a.i(2))
    return "int", (0 if x == y else (-1 if x < y else 1)) & MASK64


def _h_strlen(s, a):
    return "int", len(s.cstr(a.i(0)))


def _h_wcslen(s, a):
    return "int", len(s.wstr_raw(a.i(0))) // 2


def _h_strcmp(s, a):
    x, y = s.cstr(a.i(0)), s.cstr(a.i(1))
    return "int", (0 if x == y else (-1 if x < y else 1)) & MASK64


def _h_errno(s, a):
    return "int", s.errno_cell


def _h_get_last_error(s, a):
    return "int", struct.unpack("<I", s.gread(s.teb_va + 0x68, 4))[0]


def _h_set_last_error(s, a):
    s.gwrite(s.teb_va + 0x68, struct.pack("<I", a.i(0) & MASK32))
    return "none", None


def _h_tid(s, a):
    return "int", s.tid


def _h_pid(s, a):
    return "int", s.pid


def _h_ret(value):
    return lambda s, a: ("int", value)


def _h_noop(s, a):
    return "none", None


def _h_tls_alloc(s, a):
    h = s.hle
    if h["tls_next"] >= 1088:
        return "int", 0xFFFF_FFFF  # TLS_OUT_OF_INDEXES
    idx = h["tls_next"]
    h["tls_next"] += 1
    h["tls_slots"][idx] = 0
    return "int", idx


def _h_tls_get(s, a):
    return "int", s.hle["tls_slots"].get(a.i(0) & MASK32, 0)


def _h_tls_set(s, a):
    idx = a.i(0) & MASK32
    if idx not in s.hle["tls_slots"]:
        return "int", 0
    s.hle["tls_slots"][idx] = a.i(1)
    return "int", 1


def _h_tls_free(s, a):
    return "int", 1 if s.hle["tls_slots"].pop(a.i(0) & MASK32, None) is not None else 0


def _h_qpc(s, a):
    s.hle["qpc"] += 1000
    s.gwrite(a.i(0), struct.pack("<q", s.hle["qpc"]))
    return "int", 1


def _h_qpf(s, a):
    s.gwrite(a.i(0), struct.pack("<q", 10_000_000))
    return "int", 1


def _h_tick(s, a):
    s.hle["tick"] += 1
    return "int", s.hle["tick"] & MASK32


def _h_tick64(s, a):
    s.hle["tick"] += 1
    return "int", s.hle["tick"]


def _h_filetime(s, a):
    s.hle["filetime"] += 10_000
    s.gwrite(a.i(0), struct.pack("<Q", s.hle["filetime"]))
    return "none", None


def _h_ipf(s, a):
    return "int", 1 if (a.i(0) & MASK32) in IPF_PRESENT else 0


def _h_terminate(cause, code_arg=None):
    def h(s, a):
        code = hx(a.i(code_arg) & MASK32) if code_arg is not None else None
        raise HleStop("terminated", cause, terminate={"via": s.current_import, "code": code})
    return h


def _h_terminate_process(s, a):
    if a.i(0) != MASK64:  # only the current-process pseudo-handle ends the run
        return "int", 0
    raise HleStop("terminated", "terminate_process", terminate={"via": s.current_import, "code": hx(a.i(1) & MASK32)})


def _h_raise(cause):
    def h(s, a):
        raise HleStop("raised", cause, importCall=s.import_call_detail())
    return h


def _h_load_library(wide):
    def h(s, a):
        name = s.wstr(a.i(0)) if wide else s.cstr(a.i(0)).decode("latin-1")
        return "int", s.fake_hmodule(name)
    return h


def _h_get_module_handle(wide):
    def h(s, a):
        p = a.i(0)
        if not p:
            return "int", s.primary.base
        name = s.wstr(p) if wide else s.cstr(p).decode("latin-1")
        return "int", s.fake_hmodule(name)
    return h


def _h_get_proc_address(s, a):
    h, p = a.i(0), a.i(1)
    name = f"#{p}" if p < 0x10000 else s.cstr(p).decode("latin-1")
    return "int", s.dynamic_import(h, name)


def _math_model(name, width):
    fmt = FMT32 if width == 4 else FMT64
    arity = MATH_FUNCS[name][0]
    kind = "f32" if width == 4 else "f64"

    def h(s, a):
        return kind, eval_math(name, fmt, [a.fbits(k, width) for k in range(arity)])
    return h


# lower-case import name -> (handler, model, is_math)
BUILTIN = {}


def _reg(names, handler, model="builtin", is_math=False):
    for n in names:
        BUILTIN[n.lower()] = (handler, model, is_math)


_reg(["malloc"], _h_malloc)
_reg(["calloc"], _h_calloc)
_reg(["realloc"], _h_realloc)
_reg(["free", "_aligned_free"], _h_free)
_reg(["_aligned_malloc"], _h_aligned_malloc)
_reg(["memcpy", "memmove"], _h_memcpy)
_reg(["memset"], _h_memset)
_reg(["memcmp"], _h_memcmp)
_reg(["strlen"], _h_strlen)
_reg(["strcmp"], _h_strcmp)
_reg(["wcslen"], _h_wcslen)
_reg(["_errno"], _h_errno)
_reg(["GetLastError"], _h_get_last_error)
_reg(["SetLastError"], _h_set_last_error)
_reg(["GetCurrentThreadId"], _h_tid)
_reg(["GetCurrentProcessId"], _h_pid)
_reg(["GetCurrentProcess"], _h_ret(MASK64))
_reg(["GetCurrentThread"], _h_ret(MASK64 - 1))
_reg(["TlsAlloc"], _h_tls_alloc)
_reg(["TlsGetValue"], _h_tls_get)
_reg(["TlsSetValue"], _h_tls_set)
_reg(["TlsFree"], _h_tls_free)
_reg(["InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
      "InitializeSRWLock", "AcquireSRWLockExclusive", "AcquireSRWLockShared", "ReleaseSRWLockExclusive",
      "ReleaseSRWLockShared", "Sleep", "OutputDebugStringA", "OutputDebugStringW"], _h_noop)
_reg(["InitializeCriticalSectionAndSpinCount", "TryEnterCriticalSection", "TryAcquireSRWLockExclusive",
      "TryAcquireSRWLockShared", "FreeLibrary"], _h_ret(1))
_reg(["QueryPerformanceCounter"], _h_qpc)
_reg(["QueryPerformanceFrequency"], _h_qpf)
_reg(["GetTickCount"], _h_tick)
_reg(["GetTickCount64"], _h_tick64)
_reg(["GetSystemTimeAsFileTime"], _h_filetime)
_reg(["IsProcessorFeaturePresent"], _h_ipf)
_reg(["abort"], _h_terminate("abort"))
_reg(["_assert"], _h_terminate("assertion"))
_reg(["_amsg_exit"], _h_terminate("abort", 0))
_reg(["exit", "_exit"], _h_terminate("exit", 0))
_reg(["ExitProcess"], _h_terminate("exit_process", 0))
_reg(["TerminateProcess"], _h_terminate_process)
_reg(["RaiseException"], _h_raise("raise_exception"))
_reg(["_CxxThrowException"], _h_raise("cxx_throw"))
_reg(["LoadLibraryA", "LoadLibraryExA"], _h_load_library(False))
_reg(["LoadLibraryW", "LoadLibraryExW"], _h_load_library(True))
_reg(["GetModuleHandleA"], _h_get_module_handle(False))
_reg(["GetModuleHandleW"], _h_get_module_handle(True))
_reg(["GetProcAddress"], _h_get_proc_address)
for _name, (_arity, _fn, _exact) in MATH_FUNCS.items():
    _reg([_name], _math_model(_name, 8), "builtin" if _exact else "builtin-inexact", True)
    _reg([_name + "f"], _math_model(_name, 4), "builtin" if _exact else "builtin-inexact", True)


def builtin_model(name):
    """(handler, model, is_math) for an import name (case-insensitive), or None."""
    return BUILTIN.get(name.lower()) if name else None


# ------------------------------------------------------------------------------------------------- I. ISA guard v2
class ScanUnit:
    """Code to scan: `ranges` are (begin_rva, end_rva, kind) relative to `base`; kind "p" = a .pdata function,
    "g" = a gap (or code without .pdata)."""

    def __init__(self, label, base, ranges, module, primary):
        self.label, self.base, self.ranges, self.module, self.primary = label, base, ranges, module, primary


def _vex_lead(code, off, size):
    """The VEX/EVEX lead byte of an instruction after its segment/address-size prefixes, else None."""
    i, end = off, off + size
    while i < end and code[i] in SEG_PREFIXES:
        i += 1
    if i < end and code[i] in (0xC4, 0xC5, 0x62):
        return code[i]
    return None


def classify_site(mnemonic, ops, lead):
    if lead is not None and mnemonic not in BMI_ALLOW:
        return "evex" if lead == 0x62 else "vex"
    if mnemonic in X87_INEXACT:
        return "x87_inexact"
    if mnemonic in SSE_INEXACT:
        return "sse_inexact"
    if mnemonic in FP_STATUS:
        return "fp_status"
    if mnemonic == "cpuid":
        return "cpuid"
    if mnemonic in SYSCALL_MNEMONICS or (mnemonic == "int" and ops.strip() == "0x2e"):
        return "syscall"
    if mnemonic in TSC_MNEMONICS:
        return "tsc"
    if mnemonic in RNG_MNEMONICS:
        return "rng"
    return None


class IsaGuard:
    """Scan executable code once per bytes digest (cached), then guard it (S5 §3.7 as amended by CT-M3):
    VEX/EVEX sites reached by a skipdata-free decode from a .pdata function start get their first byte patched to
    INT3 in emulator memory (originals kept in `overlay`); other VEX/EVEX sites get non-destructive per-address hooks
    (<= 256); x87 transcendental, FP-status, TSC and RNG sites get per-address tag hooks (<= 512)."""

    def __init__(self, sess, mode, cache_dir):
        self.s = sess
        self.mode = mode
        self.cache_dir = cache_dir
        self.overlay = {}          # va -> (original byte, mnemonic, encoding)
        self.overlay_version = 0
        self.seq = 0  # versions are never reused, so equal versions mean equal overlays
        self._keys = None
        self.hook_sites = {}       # va -> (mnemonic, encoding)
        self.tags = {}             # va -> (kind, mnemonic)
        self.initial_sites = frozenset()
        self.report = None
        self.deviations = []

    # ---- overlay transparency
    def keys(self):
        if self._keys is None:
            self._keys = sorted(self.overlay)
        return self._keys

    def set_overlay(self, overlay, version):
        self.overlay, self.overlay_version, self._keys = overlay, version, None

    def restore_into(self, addr, data):
        """Put the original bytes of patched sites back into `data` (read at `addr`); returns how many."""
        if not self.overlay:
            return 0
        keys = self.keys()
        i = bisect.bisect_left(keys, addr)
        n = 0
        end = addr + len(data)
        while i < len(keys) and keys[i] < end:
            data[keys[i] - addr] = self.overlay[keys[i]][0]
            n += 1
            i += 1
        return n

    def drop_range(self, addr, size):
        """A host write covered patched sites: they leave the overlay (not re-applied)."""
        if not self.overlay:
            return []
        keys = self.keys()
        i = bisect.bisect_left(keys, addr)
        dropped = []
        while i < len(keys) and keys[i] < addr + size:
            dropped.append(keys[i])
            i += 1
        if dropped:
            gone = set(dropped)
            self.overlay = {k: v for k, v in self.overlay.items() if k not in gone}
            self.seq += 1
            self.overlay_version = self.seq
            self._keys = None
        return dropped

    # ---- scanning
    def _cache_key(self, unit, read):
        h = hashlib.sha256()
        h.update(f"{ISA_CACHE_KEY}|{engine_versions()['capstone']}|".encode())
        chunks = []
        for b, e, kind in unit.ranges:
            data = read(unit.base + b, e - b)
            chunks.append(data)
            h.update(kind.encode() + struct.pack("<QQ", b, e - b))
            h.update(data)
        return h.hexdigest(), chunks

    def _cache_path(self, key):
        return os.path.join(self.cache_dir, "isa", f"{key}.json") if self.cache_dir else None

    def _cache_load(self, key):
        path = self._cache_path(key)
        if path is None:
            return None
        try:
            with open(path, "rb") as fh:
                doc = json.loads(fh.read().decode("utf-8"))
            if doc.get("schema") != ISA_CACHE_SCHEMA or doc.get("key") != key or not isinstance(doc.get("sites"), dict):
                return None
            try:
                os.utime(path)  # LRU by mtime
            except OSError:
                pass
            return doc
        except (OSError, ValueError, UnicodeDecodeError):
            return None

    def _cache_store(self, key, doc):
        path = self._cache_path(key)
        if path is None:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "wb") as fh:
                fh.write(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
            os.replace(tmp, path)
        except OSError:
            pass

    def scan_unit(self, unit, read, ctx):
        key, chunks = self._cache_key(unit, read)
        cached = self._cache_load(key)
        if cached is not None:
            return cached, True
        t0 = time.perf_counter()
        sync = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        loose = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        loose.skipdata = True
        found = {}   # rva -> [kind, mnemonic, in_pdata]
        count = 0

        def visit(cs, code, start_rva, base_rva, in_pdata):
            nonlocal count
            end = start_rva
            for addr, size, mn, ops in cs.disasm_lite(code[start_rva - base_rva:], start_rva):
                end = addr + size
                if mn == ".byte":
                    continue
                count += 1
                kind = classify_site(mn, ops, _vex_lead(code, addr - base_rva, size))
                if kind is not None:
                    prev = found.get(addr)
                    if prev is None:
                        found[addr] = [kind, mn, in_pdata]
                    elif in_pdata:
                        prev[2] = True
            return end

        for idx, ((b, e, kind), code) in enumerate(zip(unit.ranges, chunks)):
            if kind == "p":
                end = visit(sync, code, b, b, True)
                if end < e:  # undecodable bytes: the rest is not a synchronized decode (CT-M3)
                    visit(loose, code, end, b, False)
            else:
                visit(loose, code, b, b, False)
            if idx % 64 == 0:
                ctx.check()
                ctx.progress("isa-scan", idx, len(unit.ranges))
        sites = {k: [] for k in SITE_KINDS}
        for rva in sorted(found):
            kind, mn, in_pdata = found[rva]
            sites[kind].append([rva, mn, in_pdata])
        doc = {"schema": ISA_CACHE_SCHEMA, "key": key, "ranges": len(unit.ranges), "sites": sites,
               "instructions": count, "scanMs": round((time.perf_counter() - t0) * 1000, 1)}
        self._cache_store(key, doc)
        return doc, False

    def scan_and_install(self, units, read, ctx):
        s, uc = self.s, self.s.uc
        t0 = time.perf_counter()
        totals = {k: 0 for k in SITE_KINDS}
        instructions = 0
        hits = []
        funcs_with_vex = set()
        vex_sites, tag_sites = [], []
        primary_has_pdata = False
        for unit in units:
            doc, hit = self.scan_unit(unit, read, ctx)
            hits.append(hit)
            instructions += int(doc.get("instructions", 0))
            if unit.primary and any(k == "p" for _b, _e, k in unit.ranges):
                primary_has_pdata = True
            for kind in SITE_KINDS:
                for rva, mn, in_pdata in doc["sites"].get(kind, []):
                    totals[kind] += 1
                    va = unit.base + rva
                    if kind in ("vex", "evex"):
                        vex_sites.append((va, mn, kind, bool(in_pdata)))
                        if unit.primary and unit.module is not None:
                            f = unit.module.image.function_at(rva)
                            if f is not None:
                                funcs_with_vex.add(f[0])
                    elif kind in TAG_KINDS:
                        tag_sites.append((va, mn, kind))
        int3 = hooks = unguarded = 0
        if self.mode == "stop":
            for va, mn, enc, in_pdata in vex_sites:
                if in_pdata:
                    orig = bytes(uc.mem_read(va, 1))[0]
                    uc.mem_write(va, b"\xCC")
                    self.overlay[va] = (orig, mn, enc)
                    int3 += 1
                elif hooks < MAX_GAP_VEX_HOOKS:
                    uc.hook_add(U.UC_HOOK_CODE, s._on_vex_hook, None, va, va)
                    self.hook_sites[va] = (mn, enc)
                    hooks += 1
                else:
                    unguarded += 1
            self._keys = None
            self.initial_sites = frozenset(self.overlay)
            if unguarded:
                self.deviations.append(deviation("isa_guard_incomplete", unguarded, {"unguarded": unguarded}))
        else:
            unguarded = len(vex_sites)
            self.deviations.append(deviation("isa_guard_off", unguarded or None))
        virt_tsc = insn_hook_support().get("rdtsc", False)
        budget = MAX_TAG_HOOKS
        dropped = {k: 0 for k in TAG_KINDS}
        for prio in ("tsc", "rng", "fp_status", "x87_inexact", "sse_inexact"):
            for va, mn, kind in tag_sites:
                if kind != prio or (kind == "tsc" and virt_tsc):
                    continue
                if budget <= 0:
                    dropped[kind] += 1
                    continue
                uc.hook_add(U.UC_HOOK_CODE, s._on_tag, None, va, va)
                self.tags[va] = (kind, mn)
                budget -= 1
        if dropped["x87_inexact"]:
            self.deviations.append(deviation("x87_tagging_incomplete", dropped["x87_inexact"]))
        if dropped["sse_inexact"]:
            self.deviations.append(deviation("sse_tagging_incomplete", dropped["sse_inexact"]))
        if dropped["fp_status"] or dropped["tsc"] or dropped["rng"]:
            self.deviations.append(deviation("fp_status_tagging_incomplete",
                                             dropped["fp_status"] + dropped["tsc"] + dropped["rng"],
                                             {"untagged": {k: dropped[k] for k in ("fp_status", "tsc", "rng")
                                                           if dropped[k]}}))
        if virt_tsc and totals["tsc"]:
            s.install_virtual_tsc()
        self.report = {
            "scanSource": "pdata+gaps" if primary_has_pdata else "sections",
            "cache": "off" if not self.cache_dir else ("hit" if hits and all(hits) else "miss"),
            "scanMs": round((time.perf_counter() - t0) * 1000, 1),
            "instructionsScanned": instructions,
            "sites": totals,
            "guarded": {"int3": int3, "hooks": hooks, "unguarded": unguarded},
            "functionsWithVex": [hx(f) for f in sorted(funcs_with_vex)[:100]],
            "guard": self.mode,
        }
        return self.report


def prune_isa_cache(cache_dir, limit=ISA_CACHE_BYTES):
    """Bound <cacheDir>/isa/*.json at `limit` bytes, oldest mtime first (S5 §13). Best effort."""
    d = os.path.join(cache_dir, "isa")
    try:
        entries = []
        for name in os.listdir(d):
            if name.endswith(".json"):
                p = os.path.join(d, name)
                st = os.stat(p)
                entries.append((st.st_mtime, st.st_size, p))
    except OSError:
        return
    total = sum(e[1] for e in entries)
    for _mt, size, p in sorted(entries):
        if total <= limit:
            break
        try:
            os.remove(p)
            total -= size
        except OSError:
            pass


# ------------------------------------------------------------------------------------------------- J. snapshots v2
class Meta:
    """Host-side state that travels with every snapshot: HLE state, scratch high-water mark, the ISA overlay,
    host-written ranges, the code-dirty flag and the auto-mapped page count."""

    __slots__ = ("hle", "scratch_high", "overlay", "overlay_version", "host_dirty", "code_dirty", "automapped")


def hle_copy(h):
    return {"heap_top": h["heap_top"], "heap_live": dict(h["heap_live"]), "heap_free": list(h["heap_free"]),
            "heap_sizes": list(h["heap_sizes"]), "tls_next": h["tls_next"], "tls_slots": dict(h["tls_slots"]),
            "qpc": h["qpc"], "tick": h["tick"], "filetime": h["filetime"], "tsc": h["tsc"], "dyn": dict(h["dyn"]),
            "dyn_keys": dict(h["dyn_keys"]), "hmods": dict(h["hmods"])}


class Snapshots:
    """Snapshots v2 (S5-D5; VERIFIED lab S5-E8/E8b). COW contexts (CPU+memory) only for the baseline B and one
    temporary T per batch; only B or the current T is ever restored, and restoring B forgets T (restoring a COW
    context newer than the last restored one crashes unicorn.dll). Named snapshots are host copies of the writable
    extents plus a CPU-only context. `manual` sessions (required by map_zero) make B and T host copies too."""

    def __init__(self, sess, mode):
        self.s = sess
        self.mode = mode
        self.B = None
        self.T = None
        self.levels = 0
        self.named = {}
        self.total = 0
        self.limit = SNAPSHOT_BYTES_LIMIT
        if mode == "cow":
            sess.uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU_MEM)

    def _cpu_save(self):
        uc = self.s.uc
        if self.mode != "cow":
            return uc.context_save()
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU)
        try:
            return uc.context_save()
        finally:
            uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU_MEM)

    def _cpu_restore(self, ctx):
        uc = self.s.uc
        if self.mode != "cow":
            uc.context_restore(ctx)
            return
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU)
        try:
            uc.context_restore(ctx)
        finally:
            uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU_MEM)

    def _host_copy(self):
        s, uc = self.s, self.s.uc
        mem, total = [], 0
        for a, n in s.extents():
            mem.append((a, bytes(uc.mem_read(a, n))))
            total += n
        return {"mem": mem, "cpu": self._cpu_save(), "meta": s.meta_save(), "bytes": total}

    def _host_restore(self, snap):
        s, uc = self.s, self.s.uc
        flush = s.code_dirty
        if self.mode == "manual":
            s.manual_trim(snap["meta"])  # layout first: the snapshot's auto-mapped pages must exist again
            for page in s.host_dirty - snap["meta"].host_dirty:  # host writes newer than the snapshot
                if page in s.pristine:
                    uc.mem_write(page, s.pristine[page])
                    flush = flush or s.is_exec(page, PAGE)
        for a, b in snap["mem"]:
            uc.mem_write(a, b)
            if not flush and s.is_exec(a, len(b)):
                flush = True
        if flush:
            s.flush_tb()
        self._cpu_restore(snap["cpu"])
        s.meta_restore(snap["meta"])
        s.just_restored = True
        s.frame_clean = False

    def take_baseline(self):
        s = self.s
        if self.mode == "cow":
            self.B = {"ctx": s.uc.context_save(), "meta": s.meta_save()}
        else:
            self.B = self._host_copy()
        self.T = None
        self.levels = 0
        s.frame_clean = True

    def restore_baseline(self):
        s = self.s
        if self.mode == "cow":
            if s.code_dirty:
                s.flush_tb()
            s.uc.context_restore(self.B["ctx"])
            s.meta_restore(self.B["meta"])
            self.T = None
            self.levels = 0
            s.just_restored = True
        else:
            self._host_restore(self.B)
        s.frame_clean = True

    def take_temp(self):
        s = self.s
        if self.mode == "cow":
            if self.levels > COW_LEVELS_BEFORE_COMPACTION:
                self._compact()
            self.T = {"ctx": s.uc.context_save(), "meta": s.meta_save()}
            self.levels += 1
        else:
            self.T = self._host_copy()
        self.T["frame_clean"] = s.frame_clean

    def restore_temp(self):
        s = self.s
        if self.mode == "cow":
            if s.code_dirty:
                s.flush_tb()
            s.uc.context_restore(self.T["ctx"])
            s.meta_restore(self.T["meta"])
            s.just_restored = True
        else:
            self._host_restore(self.T)
        s.frame_clean = self.T["frame_clean"]

    def end_batch(self):
        self.T = None  # abandoned; never restored again (it is newer than B)

    def _compact(self):
        """Free abandoned COW levels: host-copy the current state, restore B, write the copy back (same state)."""
        n = self._host_copy()
        self.restore_baseline()
        self._host_restore(n)

    def save_named(self, name):
        if name not in self.named and len(self.named) >= MAX_NAMED_SNAPSHOTS:
            raise BridgeError("resource_exhausted", f"at most {MAX_NAMED_SNAPSHOTS} named snapshots per session. "
                              "This release has no runtime override.", {"resource": "memory"})
        snap = self._host_copy()
        old = self.named.get(name)
        total = self.total - (old["bytes"] if old else 0) + snap["bytes"]
        if total > self.limit:
            raise BridgeError("resource_exhausted", f"named snapshots would hold {total} bytes; the limit is "
                              f"{self.limit}", {"resource": "memory"})
        self.named[name] = snap
        self.total = total
        return snap["bytes"]

    def restore_named(self, name):
        snap = self.named.get(name)
        if snap is None:
            raise BridgeError("unknown_snapshot", f"no snapshot named {name!r}", {"name": name})
        if self.mode == "cow":
            self.restore_baseline()  # discards every COW level above B (verified order: B, host copy, then T)
        self._host_restore(snap)

    def drop(self, name):
        snap = self.named.pop(name, None)
        if snap is None:
            return False
        self.total -= snap["bytes"]
        return True

    def listing(self):
        return [{"name": n, "bytes": v["bytes"]} for n, v in self.named.items()]


# ------------------------------------------------------------------------------------------------- watchdog
class Watchdog:
    """One 5 ms polling thread (never emu_start(timeout=): ~15 ms per call, ext-backends §2.4 #6). Arming is a
    lock-protected tuple swap; `probe` returns a Uc to stop while the active request is cancelled (an emu_stop()
    issued before emu_start begins is lost, so it is re-issued every period)."""

    def __init__(self, period=0.005):
        self.lock = threading.Lock()
        self.armed = None   # (seq, deadline, uc, cause)
        self.fired = None   # (seq, cause)
        self.seq = 0
        self.period = period
        self.probe = None
        threading.Thread(target=self._loop, name="bea-emu-watchdog", daemon=True).start()

    def arm(self, uc, seconds, cause):
        with self.lock:
            self.seq += 1
            self.armed = (self.seq, time.monotonic() + seconds, uc, cause)
            return self.seq

    def disarm(self, seq):
        with self.lock:
            self.armed = None
            if self.fired is not None and self.fired[0] == seq:
                return self.fired[1]
            return None

    def _loop(self):
        while True:
            time.sleep(self.period)
            probe = self.probe
            if probe is not None:
                target = probe()
                if target is not None:
                    try:
                        target.emu_stop()
                    except Exception:  # noqa: BLE001
                        pass
            a = self.armed
            if a is not None and time.monotonic() > a[1]:
                with self.lock:
                    if self.armed is a:
                        self.fired = (a[0], a[3])
                        self.armed = None
                        try:
                            a[2].emu_stop()
                        except Exception:  # noqa: BLE001
                            pass


WATCHDOG = None


# ------------------------------------------------------------------------------------------------- request context
class RequestCtx:
    """Per-request cancellation, deadline and throttled progress (S5 §3.10, §4.1)."""

    def __init__(self, rid, cancel, deadline_at=None, emit=None):
        self.rid = rid
        self.cancel = cancel
        self.deadline_at = deadline_at
        self.emit = emit
        self._last = 0.0

    def cancelled(self):
        return self.cancel is not None and self.cancel.is_set()

    def deadline_reached(self):
        return self.deadline_at is not None and time.monotonic() >= self.deadline_at

    def check(self):
        if self.cancelled():
            raise BridgeError("cancelled", "the request was cancelled", {"reason": "cancelled"})
        if self.deadline_reached():
            raise BridgeError("cancelled", "the request deadline passed", {"reason": "deadline"})

    def progress(self, phase, completed, total, force=False):
        if self.emit is None:
            return
        now = time.monotonic()
        if force or now - self._last >= PROGRESS_PERIOD_S:
            self._last = now
            self.emit({"type": "progress", "phase": phase, "completed": completed, "total": total})


NO_CTX = RequestCtx(None, None)


# ------------------------------------------------------------------------------------------------- dump manifest
def jcs(v):
    """RFC 8785 canonical JSON for the bea.dump/1 manifest (integers and strings only; keys by UTF-16 units)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 1e21:
            return str(int(v))
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(f"not JSON: {type(v).__name__}")


def _dump_field(obj, key, typ, path):
    v = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(v, typ) or isinstance(v, bool) and typ is not bool:
        raise BridgeError("dump_invalid", f"manifest {path}.{key} is missing or has the wrong type",
                          {"path": f"{path}.{key}"})
    return v


def _dump_hex(obj, key, path):
    v = _dump_field(obj, key, str, path)
    try:
        return parse_hex(v, f"{path}.{key}", 64)
    except BridgeError:
        raise BridgeError("dump_invalid", f"manifest {path}.{key} is not a hex value", {"path": f"{path}.{key}"}) \
            from None


# ------------------------------------------------------------------------------------------------- session
CPU_MODEL = "qemu64 (Unicorn 2.1 default: SSE4.2, BMI1/2; no AVX/FMA)"


class StubRec:
    __slots__ = ("key", "name", "model", "handler", "stop_cause")

    def __init__(self, key, name, model, handler, stop_cause=None):
        self.key, self.name, self.model, self.handler, self.stop_cause = key, name, model, handler, stop_cause


class RunCtx:
    """Per-run (single call or batch) accumulators; `begin_vector` resets the per-vector part."""

    def __init__(self, fault_policy="stop", imports_mode="off", max_events=10_000, blocks=False, coverage=False,
                 count=False, memory="off", instructions=False, disassemble=False):
        self.fault_policy = fault_policy
        self.imports_mode = imports_mode
        self.max_events = max_events
        self.want_blocks, self.want_coverage, self.want_count = blocks, coverage, count
        self.memory, self.want_insns, self.disassemble = memory, instructions, disassemble
        self.import_events = []
        self.import_counts = {}
        self.coverage = {}
        self.events = []
        self.trunc = {}
        self.begin_vector()

    def begin_vector(self):
        self.stop = None
        self.stop_pc = None
        self.tags = None
        self.cpuid = None
        self.inexact = None
        self.returned_zero = None
        self.dyn = None
        self.automapped = None
        self.code_written = False
        self.vtsc = False
        self.heap_oom = 0  # guest allocations the HLE heap could not satisfy (S5 §3.6 models; review fix EMU-6)
        self.icount = 0
        self.nblocks = 0
        self.last_blocks = None
        self.blocks = [] if self.want_blocks else None
        self.mem_events = [] if self.memory != "off" else None
        self.insns = [] if self.want_insns else None

    def vector_kinds(self):
        """The call-level deviation kinds this vector produced."""
        kinds = set()
        if self.tags:
            for kind in {k for k, _a, _m in self.tags}:
                kinds.add(TAG_DEVIATION_OF[kind])
        if self.heap_oom:
            kinds.add("hle_heap_exhausted")
        if self.cpuid:
            kinds.add("cpuid_executed")
        if self.inexact:
            kinds.add("inexact_import_model")
        if self.returned_zero:
            kinds.add("unhandled_import_returned_zero")
        if self.dyn:
            kinds.add("dynamic_import_resolved")
        if self.automapped:
            kinds.add("auto_mapped_zero_pages")
        if self.code_written:
            kinds.add("self_modifying_code")
        if self.vtsc:
            kinds.add("virtualized_tsc")
        return kinds


class Session:
    """One emulation session: an image or a bea.dump/1 bundle in one Unicorn instance (S5 §3)."""

    def __init__(self, sid, params, ctx, defaults):
        t_total = time.perf_counter()
        self.sid = sid
        self.poisoned = False
        self.calls = 0
        self.vectors = 0
        src = p_obj(params, "source", "params")
        self.source = p_enum(src, "kind", "params.source", ("image", "dump"))
        mem = p_obj(params, "memory", "params", required=False)
        self.heap_size = align_up(p_int(mem, "heapBytes", "params.memory", PAGE, MAX_HEAP, DEFAULT_HEAP))
        self.scratch_size = align_up(p_int(mem, "scratchBytes", "params.memory", PAGE, MAX_SCRATCH, DEFAULT_SCRATCH))
        self.stack_size = align_up(p_int(mem, "stackBytes", "params.memory", 64 << 10, MAX_STACK, DEFAULT_STACK))
        self.protections = p_enum(params, "protections", "params", ("sections", "rwx"), "sections")
        imp = p_obj(params, "imports", "params", required=False)
        self.builtin_enabled = p_bool(imp, "builtin", "params.imports", True)
        self.unhandled_policy = p_enum(imp, "unhandled", "params.imports", ("stop", "return_zero"), "stop")
        self.dump_policy = p_enum(imp, "dumpPolicy", "params.imports", ("auto", "hle_known", "lle", "stop_all"), "auto")
        self.overrides = self._parse_overrides(p_list(imp, "overrides", "params.imports", MAX_OVERRIDES))
        patches = p_list(params, "patches", "params", MAX_PATCHES)
        cpu = p_obj(params, "cpu", "params", required=False)
        self.default_mxcsr = p_int(cpu, "mxcsr", "params.cpu", 0, 0xFFFF, DEFAULT_MXCSR) if cpu else DEFAULT_MXCSR
        self.default_fpcw = p_int(cpu, "fpcw", "params.cpu", 0, 0xFFFF, DEFAULT_FPCW) if cpu else DEFAULT_FPCW
        self.isa_mode = p_enum(params, "isaGuard", "params", ("stop", "off"), "stop")
        self.snap_mode = p_enum(params, "snapshots", "params", ("cow", "manual"), "cow")
        self.fault_policy = p_enum(params, "faultPolicy", "params", ("stop", "map_zero"), "stop")
        if self.fault_policy == "map_zero" and self.snap_mode != "manual":
            raise BridgeError("unsupported_combination", 'faultPolicy "map_zero" requires snapshots "manual" '
                              "(Unicorn memory snapshots need a frozen memory layout)")
        cache_dir = params["cacheDir"] if "cacheDir" in params else defaults.get("cache_dir")
        if cache_dir is not None and not isinstance(cache_dir, str):
            raise BridgeError("invalid_params", "params.cacheDir must be a string or null", {"path": "params.cacheDir"})
        self.memory_limit = defaults.get("memory_limit") or {}

        self.uc = Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.regions = []
        self._starts = []
        self.modules = []
        self.primary = None
        self.memory_map = []
        self.unreadable = set()
        self.exec_ranges = []
        self.loader_devs = []
        self.sticky_devs = {}
        self.stubs = []
        self.stub_index = {}
        self.n_static = 0
        self.dyn_cache = {}
        self.import_models = {k: 0 for k in ("builtin", "builtin-inexact", "override", "unhandled", "lle", "stop")}
        self.import_total = 0
        self.unhandled_keys = []
        self.bundle_id = None
        self.thread = None
        self.tid, self.pid = FAKE_TID, FAKE_PID
        self.host_dirty = set()     # pages written by the host after the baseline (snapshot extents)
        self.pristine = {}          # manual snapshots: page -> its bytes before the first host write
        self.code_dirty = False
        self.automapped_pages = []
        self.scratch_high = 0
        self.just_restored = False
        self.frame_clean = False    # the stack holds the baseline's pre-written return frame (no stack args)
        self.hle_touched = False
        self._hle_src = None
        self.tb_flushes = 0
        self.rc = RunCtx()
        self.current_import = None
        self._stub_ret = 0
        self._hook_sig = None
        self._dyn_hooks = []
        self._budget_mode = None
        self._needs_flush = True
        self.isa = IsaGuard(self, self.isa_mode, cache_dir)
        self._block_icount = {}

        t = time.perf_counter()
        if self.source == "image":
            self._load_image(src, ctx)
        else:
            self._load_dump(src, ctx)
        self._map_synthetic()
        load_ms = (time.perf_counter() - t) * 1000
        ctx.check()
        t = time.perf_counter()
        if self.source == "image":
            self._bind_image_imports()
        else:
            self._bind_dump_imports()
        bind_ms = (time.perf_counter() - t) * 1000
        self._apply_patches(patches)
        t = time.perf_counter()
        self.isa.scan_and_install(self._scan_units(), lambda a, n: bytes(self.uc.mem_read(a, n)), ctx)
        isa_ms = (time.perf_counter() - t) * 1000
        self.loader_devs.extend(self.isa.deviations)
        self._install_static_hooks()
        self._apply_protections()
        uc = self.uc
        uc.reg_write(REG["mxcsr"], self.default_mxcsr & MXCSR_CONTROL)
        uc.reg_write(REG["fpcw"], self.default_fpcw)
        uc.reg_write(REG["gs_base"], self.teb_va)
        if pin_class(engine_versions()) != "exact":
            self.loader_devs.append(deviation("engine_unvalidated", detail={"engines": engine_versions()}))
        ctx.check()
        # the return frame of a call without stack arguments, written into the baseline once: a vector restored
        # from the baseline then needs no stack write (and no copy-on-write page copy)
        entry0 = ((self.stack_top - 0x1000 - 0x20) & ~0xF) - 8
        uc.mem_write(entry0, struct.pack("<Q", self.sentinel) + bytes(0x20))
        t = time.perf_counter()
        self.flush_tb()
        self.snaps = Snapshots(self, self.snap_mode)
        self.snaps.take_baseline()
        snap_ms = (time.perf_counter() - t) * 1000
        self.timings = {"loadMs": round(load_ms, 1), "isaMs": round(isa_ms, 1), "bindMs": round(bind_ms, 1),
                        "snapshotMs": round(snap_ms, 1), "totalMs": round((time.perf_counter() - t_total) * 1000, 1)}
        self.open_result = self._open_result()

    # ---------------------------------------------------------------- regions
    def add_region(self, start, end, name, kind, perms, module=None, capture=None, tag=None):
        r = Region(start, end, name, kind, perms, module, capture, tag)
        i = bisect.bisect_left(self._starts, start)
        self._starts.insert(i, start)
        self.regions.insert(i, r)
        return r

    def region_at(self, addr):
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0 and addr < self.regions[i].end:
            return self.regions[i]
        return None

    def module_at(self, va):
        for m in self.modules:
            if m.contains(va):
                return m
        return None

    def rva_of(self, va):
        m = self.module_at(va)
        return (m, va - m.base) if m else (None, None)

    def is_exec(self, a, n):
        for s, e in self.exec_ranges:
            if s < a + n and a < e:
                return True
        return False

    def _parse_overrides(self, items):
        out = {}
        for i, o in enumerate(items):
            path = f"params.imports.overrides[{i}]"
            if not isinstance(o, dict):
                raise BridgeError("invalid_params", f"{path} must be an object", {"path": path})
            key = p_str(o, "key", path, 600)
            action = p_enum(o, "action", path, ("return", "stop", "model"))
            if "!" in key:
                dll, name = key.split("!", 1)
                key = f"{dll.lower()}!{name}"
            if action == "return":
                r = p_obj(o, "returns", path)
                kind = p_enum(r, "kind", f"{path}.returns", ("int", "f32", "f64", "void"))
                bits = parse_hex(r.get("bits", "0x0"), f"{path}.returns.bits", 64)
                out[key] = ("return", kind, bits)
            elif action == "model":
                model = p_str(o, "model", path, 64)
                if builtin_model(model) is None:
                    raise BridgeError("invalid_params", f"{path}.model: no builtin model named {model!r}",
                                      {"path": f"{path}.model", "models": sorted(BUILTIN)[:200]})
                out[key] = ("model", model)
            else:
                out[key] = ("stop",)
        return out

    # ---------------------------------------------------------------- image source (S5 §3.4)
    def _load_image(self, src, ctx):
        path = p_str(src, "path", "params.source")
        want = src.get("base")
        want_base = parse_hex(want, "params.source.base") if want is not None else None
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            raise BridgeError("image_unreadable", f"cannot read the image: {e.strerror or e}",
                              {"path": path}) from None
        if len(data) > LARGE_IMAGE_BYTES:
            ctx.progress("load", 0, 3, force=True)
        sha = hashlib.sha256(data).hexdigest()
        try:
            pe = pefile.PE(data=data, fast_load=True)
        except pefile.PEFormatError as e:
            raise BridgeError("unsupported_image", f"not a PE image: {e}", {"reason": "not_pe"}) from None
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14C:
            raise BridgeError("unsupported_image", "32-bit (WoW64) images are unsupported in v0.1",
                              {"machine": "x86", "reason": "wow64_unsupported_v0.1"})
        if machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise BridgeError("unsupported_image", f"machine {machine:#x} is not x86-64",
                              {"machine": hx(machine), "reason": "unsupported_machine"})
        preferred = pe.OPTIONAL_HEADER.ImageBase
        size = align_up(pe.OPTIONAL_HEADER.SizeOfImage)
        base = preferred if want_base is None else want_base
        relocated = False
        if base != preferred:
            if base & 0xFFFF:
                raise BridgeError("relocation_unavailable", "image base must be 64 KiB aligned", {"base": hx(base)})
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size == 0:
                raise BridgeError("relocation_unavailable", "the image has no .reloc; it maps only at its preferred "
                                  "base", {"preferredBase": hx(preferred)})
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
            pe.relocate_image(base)
            relocated = True
        if base < 0x10000 or base + size > USER_VA_LIMIT or (base < KUSD_VA + PAGE and KUSD_VA < base + size):
            raise BridgeError("layout_conflict", f"image range [{base:#x}, {base + size:#x}) is not usable",
                              {"base": hx(base), "size": size})
        self.S = choose_window([(base, base + size), (KUSD_VA, KUSD_VA + PAGE)])
        uc = self.uc
        uc.mem_map(base, size, U.UC_PROT_ALL)
        hdr = min(align_up(pe.OPTIONAL_HEADER.SizeOfHeaders), size)
        uc.mem_write(base, bytes(pe.__data__[:hdr]))
        name = os.path.basename(path)
        spans = [(base, base + hdr, f"{name}:headers", "r--")]
        for sec in pe.sections:
            sname = sec.Name.rstrip(b"\0").decode("ascii", "replace")
            vsize = sec.Misc_VirtualSize or sec.SizeOfRawData
            if not vsize or sec.VirtualAddress >= size:
                continue
            raw = sec.get_data()
            uc.mem_write(base + sec.VirtualAddress, bytes(raw[:min(len(raw), vsize)]))
            start = base + sec.VirtualAddress
            spans.append((start, min(start + align_up(vsize), base + size), f"{name}:{sname}",
                          section_perms(sec.Characteristics)))
        spans.sort()
        cur = base
        image = MappedImage(lambda a, n: uc.mem_read(a, n), base, size, name)
        mod = Module(name, os.path.abspath(path), base, size, image, sha, preferred, relocated, "image")
        self.prot_plan = []
        for s, e, rname, perms in spans:
            s = max(s, cur)
            if s >= e:
                continue
            if s > cur:
                self.add_region(cur, s, f"{name}:padding", "image", "r--", mod)
                self.prot_plan.append((cur, s - cur, "r--"))
            self.add_region(s, e, rname, "image", perms, mod)
            self.prot_plan.append((s, e - s, perms))
            cur = e
        if cur < base + size:
            self.add_region(cur, base + size, f"{name}:padding", "image", "r--", mod)
            self.prot_plan.append((cur, base + size - cur, "r--"))
        self.modules = [mod]
        self.primary = mod
        self.exec_ranges = ([(base, base + size)] if self.protections == "rwx"
                            else [(s, s + n) for s, n, p in self.prot_plan if "x" in p])
        if image.malformed:
            self.loader_devs.append(deviation("malformed_directory", len(image.malformed),
                                              {"module": name, "directories": image.malformed}))
        if image.managed:
            self.loader_devs.append(deviation("managed_image"))
        self.loader_devs.append(deviation("entry_point_not_run"))
        if image.tls and image.tls["callbacks"]:
            self.loader_devs.append(deviation("tls_callbacks_not_run", len(image.tls["callbacks"])))
        if image.delay_imports:
            self.loader_devs.append(deviation("delay_imports_present", image.delay_imports))
        self.loader_devs.append(deviation("no_seh_dispatch"))
        self.loader_devs.append(deviation("synthetic_teb"))
        self.loader_devs.append(deviation("synthetic_kuser_shared_data"))

    # ---------------------------------------------------------------- dump source (S5 §10.3)
    def _load_dump(self, src, ctx):
        bundle = p_str(src, "bundlePath", "params.source")
        want_tid = src.get("thread")
        if want_tid is not None and (isinstance(want_tid, bool) or not isinstance(want_tid, int)):
            raise BridgeError("invalid_params", "params.source.thread must be an integer", {"path": "params.source"})
        want_primary = src.get("primaryModule")
        try:
            with open(os.path.join(bundle, "manifest.json"), "rb") as fh:
                text = fh.read().decode("utf-8")
            man = json.loads(text)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            raise BridgeError("dump_invalid", f"cannot read the bundle manifest: {e}", {"path": bundle}) from None
        if not isinstance(man, dict) or man.get("schema") != "bea.dump/1":
            raise BridgeError("dump_invalid", "the manifest is not a bea.dump/1 manifest", {"path": bundle})
        bid = _dump_field(man, "bundle_id", str, "manifest")
        expect = "dump_" + hashlib.sha256(jcs({k: v for k, v in man.items() if k != "bundle_id"}).encode()).hexdigest()
        if bid != expect:
            raise BridgeError("dump_invalid", "bundle_id does not match the manifest digest",
                              {"bundle_id": bid, "computed": expect})
        self.bundle_id = bid
        process = _dump_field(man, "process", dict, "manifest")
        self.pid = _dump_field(process, "pid", int, "manifest.process") or FAKE_PID
        image_path = _dump_field(process, "image_path", str, "manifest.process")
        regions = _dump_field(man, "regions", list, "manifest")
        modules = _dump_field(man, "modules", list, "manifest")
        mmap = _dump_field(man, "memory_map", list, "manifest")
        threads = _dump_field(man, "threads", list, "manifest")
        self.dump_imports = _dump_field(man, "imports", list, "manifest")
        parsed = []
        total = 0
        for i, r in enumerate(regions):
            path = f"manifest.regions[{i}]"
            base, size = _dump_hex(r, "base", path), _dump_field(r, "size", int, path)
            prot, tag = _dump_field(r, "protection", str, path), _dump_field(r, "tag", str, path)
            sha = _dump_field(r, "sha256", str, path)
            unread = [_dump_hex({"p": p}, "p", f"{path}.unreadable_pages") for p in
                      _dump_field(r, "unreadable_pages", list, path)]
            if base % PAGE or size % PAGE or size <= 0 or base + size > USER_VA_LIMIT:
                raise BridgeError("dump_invalid", f"{path} is not a run of 4 KiB pages", {"path": path})
            parsed.append((base, size, prot, tag, r.get("module"), sha.lower(), set(unread)))
            total += size
        parsed.sort()
        for a, b in zip(parsed, parsed[1:]):
            if b[0] < a[0] + a[1]:
                raise BridgeError("dump_invalid", "manifest regions overlap", {"base": hx(b[0])})
        for i, m in enumerate(mmap):
            if not str(m.get("protection", "")).startswith("r"):
                raise BridgeError("dump_invalid", "memory_map lists only readable ranges",
                                  {"path": f"manifest.memory_map[{i}]"})
        synthetic = self.heap_size + self.scratch_size + self.stack_size + STUB_AREA + 0x10000
        lim = self.memory_limit
        if lim.get("applied") and lim.get("bytes") and total + synthetic + (256 << 20) > lim["bytes"]:
            raise BridgeError("resource_exhausted", f"the bundle needs {total + synthetic} bytes of emulator memory; "
                              f"the bridge limit is {lim['bytes']}", {"resource": "memory"})
        # threads and the primary module are validated before anything is mapped
        primaries = [t for t in threads if isinstance(t, dict) and t.get("primary") is True]
        if len(primaries) != 1:
            raise BridgeError("dump_invalid", "exactly one primary thread is required", {"path": "manifest.threads"})
        chosen = primaries[0] if want_tid is None else next(
            (t for t in threads if isinstance(t, dict) and t.get("tid") == want_tid), None)
        if chosen is None:
            raise BridgeError("dump_incomplete", f"thread {want_tid} is not in the bundle", {"thread": want_tid})
        teb = _dump_hex(chosen, "teb", "manifest.threads[]")
        if not any(b <= teb < b + n for b, n, *_r in parsed):
            raise BridgeError("dump_incomplete", "the chosen thread's TEB was not captured; re-capture including it",
                              {"teb": hx(teb)})
        if not modules:
            raise BridgeError("dump_incomplete", "the bundle has no modules", {})
        uc = self.uc
        mod_bytes = {}
        loaded = 0
        for idx, (base, size, prot, tag, modname, sha, unread) in enumerate(parsed):
            fpath = os.path.join(bundle, "regions", f"{sha}.bin")
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
            except OSError as e:
                raise BridgeError("dump_invalid", f"region file {sha}.bin is unreadable: {e.strerror or e}",
                                  {"sha256": sha}) from None
            if len(data) != size or hashlib.sha256(data).hexdigest() != sha:
                raise BridgeError("dump_invalid", f"region file {sha}.bin does not match its manifest entry",
                                  {"sha256": sha, "base": hx(base)})
            if modname:
                mod_bytes.setdefault(modname.lower(), []).append((base, data))
            run_start = None
            for off in range(0, size + PAGE, PAGE):
                page = base + off
                readable = off < size and page not in unread
                if readable and run_start is None:
                    run_start = page
                elif not readable and run_start is not None:
                    uc.mem_map(run_start, page - run_start, U.UC_PROT_ALL)
                    uc.mem_write(run_start, data[run_start - base:page - base])
                    kind = {"module": "module", "teb": "teb"}.get(tag, "captured")
                    self.add_region(run_start, page, f"{modname or 'captured'}:{tag}", kind, prot, None, "captured", tag)
                    run_start = None
            self.unreadable.update(unread)
            loaded += size
            ctx.progress("load", loaded, total)
            if idx % 16 == 0:
                ctx.check()
        self.memory_map = sorted((_dump_hex(m, "base", "manifest.memory_map[]"),
                                  _dump_hex(m, "base", "manifest.memory_map[]") + int(m.get("size", 0)),
                                  str(m.get("protection")), m.get("module")) for m in mmap)
        for i, m in enumerate(modules):
            path = f"manifest.modules[{i}]"
            name = _dump_field(m, "name", str, path)
            base, size = _dump_hex(m, "base", path), _dump_field(m, "size", int, path)
            pref = m.get("preferred_base")
            pref = parse_hex(pref, f"{path}.preferred_base") if isinstance(pref, str) else None
            image = MappedImage(lambda a, n: uc.mem_read(a, n), base, size, name)
            sha = m.get("file_sha256")
            if not isinstance(sha, str):
                h = hashlib.sha256()
                for _b, d in sorted(mod_bytes.get(name.lower(), []), key=lambda x: x[0]):
                    h.update(d)
                sha = h.hexdigest() if mod_bytes.get(name.lower()) else None
            captured = m.get("captured") if m.get("captured") in ("full", "partial", "none") else "none"
            mod = Module(name, m.get("path") if isinstance(m.get("path"), str) else None, base, size, image, sha,
                         pref, pref is not None and pref != base, captured)
            self.modules.append(mod)
            if captured != "none" and image.malformed:
                self.loader_devs.append(deviation("malformed_directory", len(image.malformed),
                                                  {"module": name, "directories": image.malformed}))
        for r in self.regions:
            if r.tag == "module":
                r.module = self.module_at(r.start)
                if r.module is not None:
                    r.name = f"{r.module.name}:captured"
        if want_primary:
            self.primary = next((m for m in self.modules if m.lname == str(want_primary).lower()), None)
            if self.primary is None:
                raise BridgeError("dump_incomplete", f"primary module {want_primary!r} is not in the bundle",
                                  {"modules": [m.name for m in self.modules][:50]})
        else:
            self.primary = next((m for m in self.modules if m.path and m.path.lower() == image_path.lower()),
                                next((m for m in self.modules if m.image.headers_ok), self.modules[0]))
        rwx = self.protections == "rwx"
        self.exec_ranges = sorted((r.start, r.end) for r in self.regions if rwx or "x" in r.perms)
        occupied = [(b, b + n) for b, n, *_r in parsed] + [(b, e) for b, e, p, _m in self.memory_map if p != "---"]
        occupied.append((KUSD_VA, KUSD_VA + PAGE))
        self.S = choose_window(occupied)
        self.thread = {"tid": int(chosen.get("tid", 0)), "teb": hx(teb)}
        self.tid = int(chosen.get("tid", 0)) or FAKE_TID
        self.teb_va = teb
        self.loader_devs.append(deviation("no_seh_dispatch"))

    # ---------------------------------------------------------------- synthetic regions (S5 §3.3)
    def _map_synthetic(self):
        uc, S = self.uc, self.S
        rw, rx = U.UC_PROT_READ | U.UC_PROT_WRITE, U.UC_PROT_READ | U.UC_PROT_EXEC
        self.stubs_va = S + OFF_STUBS
        self.sentinel = S + OFF_SENTINEL
        self.heap = S + OFF_HEAP
        self.scratch = S + OFF_SCRATCH
        self.stack = S + OFF_STACK
        self.stack_top = self.stack + self.stack_size
        self.errno_cell = S + OFF_ERRNO
        self.scratch_high = self.scratch
        self.scratch_top = self.scratch
        if self.source == "image":
            self.teb_va = S + OFF_TEB
            uc.mem_map(S, 0x4000, rw)
            self.add_region(S, S + PAGE, "TEB (synthetic)", "teb", "rw-")
            self.add_region(S + OFF_PEB, S + OFF_PEB + PAGE, "PEB (synthetic)", "runtime", "rw-")
            self.add_region(S + OFF_MISC, S + 0x4000, "misc (TLS slot array, errno)", "runtime", "rw-")
            teb = bytearray(PAGE)
            struct.pack_into("<Q", teb, 0x00, MASK64)             # NtTib.ExceptionList (unused on x64)
            struct.pack_into("<Q", teb, 0x08, self.stack_top)     # NtTib.StackBase
            struct.pack_into("<Q", teb, 0x10, self.stack)         # NtTib.StackLimit (read by __chkstk)
            struct.pack_into("<Q", teb, 0x30, S)                  # NtTib.Self
            struct.pack_into("<Q", teb, 0x40, FAKE_PID)           # ClientId.UniqueProcess
            struct.pack_into("<Q", teb, 0x48, FAKE_TID)           # ClientId.UniqueThread
            struct.pack_into("<Q", teb, 0x58, S + OFF_MISC)       # ThreadLocalStoragePointer
            struct.pack_into("<Q", teb, 0x60, S + OFF_PEB)        # ProcessEnvironmentBlock
            uc.mem_write(S, bytes(teb))
            peb = bytearray(PAGE)
            struct.pack_into("<Q", peb, 0x10, self.primary.base)  # ImageBaseAddress
            struct.pack_into("<Q", peb, 0x30, self.heap)          # ProcessHeap (an opaque handle)
            uc.mem_write(S + OFF_PEB, bytes(peb))
            tls = self.primary.image.tls
            if tls and tls["start"] and tls["end"] >= tls["start"]:
                base = self.primary.base
                tmpl = bytes(uc.mem_read(base + tls["start"], tls["end"] - tls["start"]))
                size = align_up(len(tmpl) + tls["zero_fill"] + 1)
                if size <= TLS_MAX:
                    uc.mem_map(S + OFF_TLS, size, rw)
                    uc.mem_write(S + OFF_TLS, tmpl)
                    self.add_region(S + OFF_TLS, S + OFF_TLS + size, "static TLS block (index 0)", "runtime", "rw-")
                    uc.mem_write(S + OFF_MISC, struct.pack("<Q", S + OFF_TLS))
                    if tls["index"]:
                        uc.mem_write(base + tls["index"], struct.pack("<I", 0))
                else:
                    self.loader_devs.append(deviation("malformed_directory", 1, {"directory": "tls",
                                                                                 "reason": "TLS block too large"}))
            kusd = bytearray(PAGE)
            struct.pack_into("<I", kusd, 0x26C, 10)     # NtMajorVersion
            struct.pack_into("<I", kusd, 0x260, 26100)  # NtBuildNumber
            uc.mem_map(KUSD_VA, PAGE, U.UC_PROT_READ)
            uc.mem_write(KUSD_VA, bytes(kusd))
            self.add_region(KUSD_VA, KUSD_VA + PAGE, "KUSER_SHARED_DATA (synthetic)", "runtime", "r--")
        else:
            uc.mem_map(S + OFF_MISC, 0x2000, rw)
            self.add_region(S + OFF_MISC, S + 0x4000, "misc (errno)", "runtime", "rw-")
            if self.region_at(KUSD_VA) is None:
                kusd = bytearray(PAGE)
                struct.pack_into("<I", kusd, 0x26C, 10)
                struct.pack_into("<I", kusd, 0x260, 26100)
                uc.mem_map(KUSD_VA, PAGE, U.UC_PROT_READ)
                uc.mem_write(KUSD_VA, bytes(kusd))
                self.add_region(KUSD_VA, KUSD_VA + PAGE, "KUSER_SHARED_DATA (synthetic)", "runtime", "r--")
                self.loader_devs.append(deviation("synthetic_kuser_shared_data"))
        uc.mem_map(self.stubs_va, STUB_AREA, rx)
        uc.mem_write(self.stubs_va, (b"\xC3" + b"\xCC" * (STUB_SIZE - 1)) * (STUB_AREA // STUB_SIZE))
        self.add_region(self.stubs_va, self.stubs_va + STUB_AREA, "import stubs", "stub", "r-x")
        uc.mem_map(self.sentinel, PAGE, rx)
        uc.mem_write(self.sentinel, b"\xF4" * 16)
        self.add_region(self.sentinel, self.sentinel + PAGE, "return sentinel", "runtime", "r-x")
        uc.mem_map(self.heap, self.heap_size, rw)
        self.add_region(self.heap, self.heap + self.heap_size, "guest heap (HLE malloc)", "heap", "rw-")
        uc.mem_map(self.scratch, self.scratch_size, rw)
        self.add_region(self.scratch, self.scratch + self.scratch_size, "argument scratch", "scratch", "rw-")
        uc.mem_map(self.stack, self.stack_size, rw)
        self.add_region(self.stack, self.stack_top, "stack", "stack", "rw-")
        if self.source == "dump":
            uc.mem_write(self.teb_va + 0x08, struct.pack("<QQ", self.stack_top, self.stack))
            self.loader_devs.append(deviation("teb_stack_bounds_rewritten"))
        self.hle = {"heap_top": self.heap, "heap_live": {}, "heap_free": [], "heap_sizes": [], "tls_next": 1,
                    "tls_slots": {}, "qpc": 1_000_000, "tick": 1_000_000, "filetime": FILETIME_EPOCH,
                    "tsc": VIRTUAL_TSC_START, "dyn": {}, "dyn_keys": {}, "hmods": {}}

    # ---------------------------------------------------------------- import binding (S5 §3.6)
    def _model_for(self, dll, name, key):
        """§3.6.2 precedence: overrides["dll!name"], overrides["name"], builtin (case-insensitive), unhandled."""
        ov = self.overrides.get(key) or (self.overrides.get(name) if name else None)
        if ov is not None:
            if ov[0] == "return":
                return StubRec(key, name, "override", self._return_handler(ov[1], ov[2]))
            if ov[0] == "model":
                return StubRec(key, name, "override", builtin_model(ov[1])[0])
            return StubRec(key, name, "override", None, "override_stop")
        b = builtin_model(name) if self.builtin_enabled else None
        if b is not None:
            return StubRec(key, name, b[1], b[0])
        return StubRec(key, name, "unhandled", None, "no_model")

    @staticmethod
    def _return_handler(kind, bits):
        if kind == "void":
            return _h_noop
        if kind in ("f32", "f64"):
            return lambda s, a: (kind, bits)
        return lambda s, a: ("int", bits)

    def _stub_for(self, rec):
        idx = self.stub_index.get(rec.key)
        if idx is None:
            if len(self.stubs) >= STUB_AREA // STUB_SIZE - DYN_STUBS:
                raise BridgeError("layout_conflict", "too many distinct imports for the stub area")
            idx = len(self.stubs)
            self.stubs.append(rec)
            self.stub_index[rec.key] = idx
        return self.stubs_va + idx * STUB_SIZE

    @staticmethod
    def import_key(dll, name, ordinal):
        if name:
            return f"{dll.lower()}!{name}"
        return f"{dll.lower()}!#{ordinal if ordinal is not None else '?'}"

    def _count_model(self, rec_model, key):
        self.import_total += 1
        self.import_models[rec_model] += 1
        if rec_model in ("unhandled", "stop") and len(self.unhandled_keys) < 200 and key not in self.unhandled_keys:
            self.unhandled_keys.append(key)

    def _bind_image_imports(self):
        mod, uc = self.primary, self.uc
        for imp in mod.image.imports:
            key = self.import_key(imp["dll"], imp["name"], imp["ordinal"])
            rec = self._model_for(imp["dll"], imp["name"], key)
            uc.mem_write(mod.base + imp["slot_rva"], struct.pack("<Q", self._stub_for(rec)))
            self._count_model(rec.model, key)
        self.n_static = len(self.stubs)
        if self.import_total:
            self.loader_devs.append(deviation("imports_hle_bound", self.import_total))

    def _captured_at(self, va):
        r = self.region_at(va)
        return r is not None and r.capture == "captured"

    def _bind_dump_imports(self):
        """S5 §3.6.4: rebind IAT slots of captured modules in emulator memory per imports.dumpPolicy."""
        uc = self.uc
        entries, seen = [], set()
        for i, e in enumerate(self.dump_imports):
            if not isinstance(e, dict):
                continue
            try:
                slot = parse_hex(e.get("slot"), f"manifest.imports[{i}].slot")
            except BridgeError:
                continue
            if slot in seen:
                continue
            seen.add(slot)
            name = e.get("name") if isinstance(e.get("name"), str) else None
            ordinal = e.get("ordinal") if isinstance(e.get("ordinal"), int) else None
            entries.append((str(e.get("dll", "?")), name, ordinal, slot))
        for m in self.modules:
            for imp in m.image.imports:
                slot = m.base + imp["slot_rva"]
                if slot not in seen:
                    seen.add(slot)
                    entries.append((imp["dll"], imp["name"], imp["ordinal"], slot))
        counts = {"hle": 0, "lle": 0, "stop": 0}
        policy = self.dump_policy
        for dll, name, ordinal, slot in entries:
            if not self._captured_at(slot):
                continue
            key = self.import_key(dll, name, ordinal)
            target = struct.unpack("<Q", uc.mem_read(slot, 8))[0]
            captured = self._captured_at(target)
            rec = self._model_for(dll, name, key)
            b = builtin_model(name) if self.builtin_enabled else None
            if rec.model == "override":
                action = "hle"
            elif policy == "stop_all":
                rec, action = StubRec(key, name, "stop", None, "no_model"), "stop"
            elif policy == "lle":
                action = "lle"
            elif policy == "auto":
                if b is not None and not b[2]:
                    action = "hle"
                elif captured:
                    action = "lle"
                elif b is not None:
                    action = "hle"
                else:
                    action = "stop"
            else:  # hle_known
                action = "hle" if b is not None else ("lle" if captured else "stop")
            if action == "lle":
                self._count_model("lle", key)
                counts["lle"] += 1
                continue
            if action == "stop" and rec.model != "stop":
                rec = StubRec(key, name, "unhandled", None, "no_model")
            uc.mem_write(slot, struct.pack("<Q", self._stub_for(rec)))
            self._count_model(rec.model, key)
            counts["hle" if action == "hle" else "stop"] += 1
        self.n_static = len(self.stubs)
        self.loader_devs.append(deviation("iat_rebound", counts["hle"] + counts["stop"], dict(counts)))

    # ---------------------------------------------------------------- patches and symbolic addresses
    def resolve_symbolic(self, text, path):
        """"0x..." | "module+0xRVA" | "module!export" (the bridge knows a dump's modules; S5 §8.1 step 6)."""
        if not isinstance(text, str) or not text or len(text) > 600:
            raise BridgeError("invalid_params", f"{path} must be an address string", {"path": path})
        if text[:2].lower() == "0x":
            return parse_hex(text, path)
        for sep in ("+", "!"):
            if sep in text:
                modname, rest = text.rsplit(sep, 1)
                mod = next((m for m in self.modules if m.lname == modname.lower()), None)
                if mod is None:
                    raise BridgeError("unknown_symbol", f"{path}: no module named {modname!r}",
                                      {"path": path, "modules": [m.name for m in self.modules][:50]})
                if sep == "+":
                    return mod.base + parse_hex(rest, path)
                rva = mod.image.exports.get(rest)
                if rva is None:
                    raise BridgeError("unknown_symbol", f"{path}: {mod.name} has no export {rest!r}",
                                      {"path": path, "exports_sample": sorted(mod.image.exports)[:50]})
                return mod.base + rva
        raise BridgeError("invalid_params", f"{path}: expected 0x..., module+0xRVA or module!export", {"path": path})

    def _apply_patches(self, patches):
        total = 0
        for i, p in enumerate(patches):
            path = f"params.patches[{i}]"
            if not isinstance(p, dict):
                raise BridgeError("invalid_params", f"{path} must be an object", {"path": path})
            addr = self.resolve_symbolic(p.get("address"), f"{path}.address")
            data = parse_hexbytes(p.get("hex"), f"{path}.hex", MAX_PATCH_BYTES)
            total += len(data)
            if total > MAX_PATCH_BYTES:
                raise BridgeError("invalid_params", "patches exceed 1 MiB in total. This release has no runtime "
                                  "override.", {"path": "params.patches"})
            try:
                self.uc.mem_write(addr, data)
            except UcError:
                raise BridgeError("unmapped", f"{path}: {addr:#x}+{len(data):#x} is not mapped",
                                  {"path": path, "region": self.describe(addr)}) from None
        if patches:
            self.loader_devs.append(deviation("memory_patched", len(patches), {"bytes": total}))

    # ---------------------------------------------------------------- ISA units
    def _mapped_pieces(self, start, end):
        out = []
        i = max(bisect.bisect_right(self._starts, start) - 1, 0)
        while i < len(self.regions) and self.regions[i].start < end:
            r = self.regions[i]
            s, e = max(r.start, start), min(r.end, end)
            if s < e and (self.source == "image" or r.capture == "captured"):
                out.append((s, e))
            i += 1
        return out

    def _scan_units(self):
        units = []
        covered = []
        for m in self.modules:
            img = m.image
            if not img.headers_ok:
                continue
            pieces = []
            for b, e in img.exec_ranges():
                pieces.extend(self._mapped_pieces(m.base + b, m.base + min(e, m.size)))
            if not pieces:
                continue
            covered.extend(pieces)
            ranges = []
            for ps, pe_ in pieces:
                pb, pe_r = ps - m.base, pe_ - m.base
                funcs = []
                for fb, fe in img.pdata:
                    if pb <= fb < pe_r:
                        funcs.append((fb, min(fe, pe_r)))
                cur = pb
                for fb, fe in funcs:
                    if fb > cur:
                        ranges.append((cur, fb, "g"))
                    if fe > max(fb, cur):
                        ranges.append((max(fb, cur), fe, "p" if fb >= cur else "g"))
                    cur = max(cur, fe)
                if cur < pe_r:
                    ranges.append((cur, pe_r, "g"))
            units.append(ScanUnit(m.name, m.base, ranges, m, m is self.primary))
        if self.source == "dump":
            for r in self.regions:
                if r.capture == "captured" and "x" in r.perms and not any(s <= r.start < e for s, e in covered):
                    units.append(ScanUnit(r.name, r.start, [(0, r.end - r.start, "g")], None, False))
        return units

    def _install_static_hooks(self):
        uc = self.uc
        uc.hook_add(U.UC_HOOK_MEM_READ_UNMAPPED | U.UC_HOOK_MEM_WRITE_UNMAPPED | U.UC_HOOK_MEM_FETCH_UNMAPPED,
                    self._on_bad_mem)
        uc.hook_add(U.UC_HOOK_MEM_READ_PROT | U.UC_HOOK_MEM_WRITE_PROT | U.UC_HOOK_MEM_FETCH_PROT, self._on_bad_mem)
        uc.hook_add(U.UC_HOOK_INTR, self._on_intr)
        uc.hook_add(U.UC_HOOK_CODE, self._on_stub, None, self.stubs_va,
                    self.stubs_va + (self.n_static + DYN_STUBS) * STUB_SIZE - 1)
        uc.hook_add(U.UC_HOOK_INSN, self._on_cpuid, None, 1, 0, X.UC_X86_INS_CPUID)
        uc.hook_add(U.UC_HOOK_INSN, self._on_syscall, None, 1, 0, X.UC_X86_INS_SYSCALL)
        try:
            uc.hook_add(U.UC_HOOK_INSN, self._on_syscall, None, 1, 0, X.UC_X86_INS_SYSENTER)
        except UcError:
            pass
        if self.protections == "rwx":
            for s, e in self.exec_ranges:
                uc.hook_add(U.UC_HOOK_MEM_WRITE, self._on_code_write, None, s, e - 1)

    def install_virtual_tsc(self):
        for ins in (X.UC_X86_INS_RDTSC, X.UC_X86_INS_RDTSCP):
            try:
                self.uc.hook_add(U.UC_HOOK_INSN, self._on_rdtsc, None, 1, 0, ins)
            except UcError:
                pass

    def _apply_protections(self):
        if self.protections == "rwx":
            return
        uc = self.uc
        if self.source == "image":
            for s, n, p in self.prot_plan:
                uc.mem_protect(s, n, perms_to_uc(p) or U.UC_PROT_READ)
        else:
            for r in self.regions:
                if r.capture == "captured":
                    uc.mem_protect(r.start, r.end - r.start, perms_to_uc(r.perms) or U.UC_PROT_READ)

    def _open_result(self):
        mapped = sum(r.end - r.start for r in self.regions)
        return {
            "session": self.sid,
            "primary": self.primary.info(),
            "modules": [m.info() for m in self.modules],
            "imports": {"total": self.import_total, "models": dict(self.import_models),
                        "unhandled": list(self.unhandled_keys)},
            "isa": self.isa.report,
            "layout": {"syntheticBase": hx(self.S), "regions": len(self.regions), "mappedBytes": mapped},
            "cpu": {"mxcsr": hx(self.default_mxcsr), "fpcw": hx(self.default_fpcw), "model": CPU_MODEL},
            "snapshots": self.snap_mode,
            "thread": self.thread,
            "loaderDeviations": self.loader_devs,
            "timings": self.timings,
        }

    # ---------------------------------------------------------------- host-side state (snapshot meta)
    def meta_save(self):
        m = Meta()
        m.hle = hle_copy(self.hle)
        m.scratch_high = self.scratch_high
        m.overlay = dict(self.isa.overlay)
        m.overlay_version = self.isa.overlay_version
        m.host_dirty = frozenset(self.host_dirty)
        m.code_dirty = self.code_dirty
        m.automapped = tuple(self.automapped_pages)
        return m

    def meta_restore(self, m):
        if self.hle_touched or self._hle_src is not m:
            self.hle = hle_copy(m.hle)
            self.hle_touched = False
            self._hle_src = m
        self.scratch_high = m.scratch_high
        if self.isa.overlay_version != m.overlay_version:
            self.isa.set_overlay(dict(m.overlay), m.overlay_version)
        if self.host_dirty != m.host_dirty:
            self.host_dirty = set(m.host_dirty)
        self.code_dirty = m.code_dirty

    def manual_trim(self, m):
        """Manual snapshots: zero heap/scratch growth beyond the snapshot and unmap pages auto-mapped after it."""
        uc = self.uc
        for base, now, then in ((self.heap, self.hle["heap_top"], m.hle["heap_top"]),
                                (self.scratch, self.scratch_high, m.scratch_high)):
            lo, hi = align_up(then + 16 - base) + base, align_up(now + 16 - base) + base
            limit = base + (self.heap_size if base == self.heap else self.scratch_size)
            hi = min(hi, limit)
            if hi > lo:
                uc.mem_write(lo, bytes(hi - lo))
        keep = set(m.automapped)
        for page in [p for p in self.automapped_pages if p not in keep]:
            uc.mem_unmap(page, PAGE)
            self._remove_region(page)
        for page in m.automapped:
            if page not in self.automapped_pages:
                uc.mem_map(page, PAGE, U.UC_PROT_READ | U.UC_PROT_WRITE)
                self.add_region(page, page + PAGE, "auto-mapped zero page", "auto", "rw-")
        self.automapped_pages = list(m.automapped)

    def _remove_region(self, start):
        i = bisect.bisect_left(self._starts, start)
        if i < len(self._starts) and self._starts[i] == start:
            del self._starts[i]
            del self.regions[i]

    def extents(self):
        """The writable state a host-copy snapshot must carry (S5 §3.11)."""
        rwx = self.protections == "rwx"
        out = []
        for r in self.regions:
            if r.kind in ("image", "module", "captured", "teb") and (rwx or "w" in r.perms):
                out.append((r.start, r.end - r.start))
            elif r.kind == "runtime" and "w" in r.perms:
                out.append((r.start, r.end - r.start))
            elif r.kind == "auto":
                out.append((r.start, r.end - r.start))
        heap_used = min(align_up(self.hle["heap_top"] - self.heap + 16), self.heap_size)
        scratch_used = min(align_up(self.scratch_high - self.scratch + 16), self.scratch_size)
        out.append((self.heap, heap_used))
        out.append((self.scratch, scratch_used))
        out.append((self.stack, self.stack_size))
        out.extend((page, PAGE) for page in sorted(self.host_dirty))
        return out

    def flush_tb(self):
        self.uc.ctl_flush_tb()
        self.tb_flushes += 1

    def _host_wrote(self, addr, n):
        """Bookkeeping after a host write: TB invalidation on code, overlay sites, host-dirty extents."""
        flushed = False
        if self.is_exec(addr, n):
            try:
                self.uc.ctl_remove_cache(addr, addr + n)
            except Exception:  # noqa: BLE001 - the binding may lack it on other versions [B A3]
                self.flush_tb()
            self.code_dirty = True
            flushed = True
        self.isa.drop_range(addr, n)
        self.host_dirty.update(range(addr & ~(PAGE - 1), align_up(addr + n), PAGE))
        return flushed

    # ---------------------------------------------------------------- guest memory (HLE models)
    def _writable(self, addr, n):
        if self.protections == "rwx":
            return True
        cur, end = addr, addr + n
        while cur < end:
            r = self.region_at(cur)
            if r is None or "w" not in r.perms:
                return False
            cur = r.end
        return True

    def gread(self, addr, n):
        if n == 0:
            return b""
        if n > MAX_GUEST_COPY:
            raise GuestFault("read", addr, n)
        try:
            return bytes(self.uc.mem_read(addr, n))
        except UcError:
            raise GuestFault("read", addr, n) from None

    def gwrite(self, addr, data):
        if not data:
            return
        if len(data) > MAX_GUEST_COPY or not self._writable(addr, len(data)):
            raise GuestFault("write", addr, len(data))
        try:
            self.uc.mem_write(addr, data)
        except UcError:
            raise GuestFault("write", addr, len(data)) from None

    def cstr(self, addr, limit=1 << 20):
        out = bytearray()
        while len(out) < limit:
            chunk = self.gread(addr + len(out), 64 - ((addr + len(out)) & 63))
            z = chunk.find(b"\0")
            if z >= 0:
                return bytes(out + chunk[:z])
            out += chunk
        return bytes(out)

    def wstr_raw(self, addr, limit=1 << 20):
        out = bytearray()
        while len(out) < limit:
            chunk = self.gread(addr + len(out), 2)
            if chunk == b"\0\0":
                return bytes(out)
            out += chunk
        return bytes(out)

    def wstr(self, addr):
        return self.wstr_raw(addr).decode("utf-16-le", "replace")

    # The HLE heap (review fix EMU-6; it was a bump allocator that never reused freed memory). Blocks tile
    # [heap, heap_top) as chunks [cs, p + n): the 16-byte gap before each block belongs to its chunk. Freed chunks are
    # coalesced into free ranges indexed twice, both snapshotted with the rest of the HLE state: by address
    # (hle["heap_free"], for coalescing) and by size (hle["heap_sizes"], for a best fit in O(log n)). So a malloc/free
    # loop never exhausts the heap, and fragmentation does not make malloc slow. heap_top stays a high-water mark
    # (snapshot extents and manual-mode trims rely on it); the free range that ends at heap_top (the tail) extends to
    # the end of the heap.
    def heap_alloc(self, n, align=16, harness=False):
        """A block of n bytes, or 0 when the heap cannot hold it (a guest allocation then counts as
        hle_heap_exhausted; `harness` allocations are the caller's error to report)."""
        n = max(int(n), 1)
        h = self.hle
        end = self.heap + self.heap_size
        if n <= self.heap_size:
            top, free, sizes = h["heap_top"], h["heap_free"], h["heap_sizes"]
            k = bisect.bisect_left(sizes, (n + 16,))
            while k < len(sizes):  # best fit: the smallest range that holds the gap, the alignment and the block
                size, fs = sizes[k]
                p = align_up(fs + 16, align)
                if p + n <= fs + size:
                    return self._heap_carve(fs, fs + size, p, n)
                k += 1
            if free and free[-1][1] == top:  # the tail grows into the never-used space above heap_top
                fs = free[-1][0]
                p = align_up(fs + 16, align)
                if p + n <= end:
                    return self._heap_carve(fs, top, p, n)
            p = align_up(top + 16, align)
            if p + n <= end:
                return self._heap_take(p, n, top)
        if not harness:
            self.heap_exhausted(n)
        return 0

    def _heap_carve(self, fs, fe, p, n):
        """Allocate [p, p + n) out of the free range [fs, fe); only the tail range may be outgrown."""
        self._heap_unlist(fs, fe)
        if p + n < fe:
            self._heap_list(p + n, fe)
        return self._heap_take(p, n, fs)

    def _heap_take(self, p, n, cs):
        h = self.hle
        if p + n > h["heap_top"]:
            h["heap_top"] = p + n
        h["heap_live"][p] = (n, cs)
        self.hle_touched = True
        return p

    def _heap_list(self, fs, fe):
        bisect.insort(self.hle["heap_free"], (fs, fe))
        bisect.insort(self.hle["heap_sizes"], (fe - fs, fs))

    def _heap_unlist(self, fs, fe):
        free, sizes = self.hle["heap_free"], self.hle["heap_sizes"]
        del free[bisect.bisect_left(free, (fs, fe))]
        del sizes[bisect.bisect_left(sizes, (fe - fs, fs))]

    def heap_exhausted(self, size):
        """A guest allocation the HLE heap cannot satisfy: an out_of_memory event and the hle_heap_exhausted
        deviation (the real process may well have succeeded)."""
        self.rc.heap_oom += 1
        self.event("out_of_memory", size=size)

    def heap_free(self, p):
        if not p:
            return
        self.hle_touched = True
        blk = self.hle["heap_live"].pop(p, None)
        if blk is None:
            self.event("invalid_or_double_free", ptr=p)
            return
        self._heap_release(blk[1], p + blk[0])

    def _heap_release(self, cs, ce):
        """Return the chunk [cs, ce) to the free ranges, coalescing it with its free neighbours."""
        free = self.hle["heap_free"]
        k = bisect.bisect_left(free, (cs,))
        nxt = free[k] if k < len(free) and free[k][0] == ce else None
        prv = free[k - 1] if k > 0 and free[k - 1][1] == cs else None
        if nxt is not None:
            self._heap_unlist(*nxt)
            ce = nxt[1]
        if prv is not None:
            self._heap_unlist(*prv)
            cs = prv[0]
        self._heap_list(cs, ce)
        self.hle_touched = True

    def heap_resize(self, p, n):
        """realloc in place: a shrink always fits; a growth fits when the block ends at the high-water mark or a free
        range starts where the block ends. False: the block has to move."""
        h = self.hle
        oldn, cs = h["heap_live"][p]
        n = max(int(n), 1)
        ce, new_end = p + oldn, p + n
        if new_end <= ce:
            h["heap_live"][p] = (n, cs)
            self.hle_touched = True
            if new_end < ce:
                self._heap_release(new_end, ce)
            return True
        end, top, free = self.heap + self.heap_size, h["heap_top"], h["heap_free"]
        if new_end > end:
            return False
        if ce != top:
            k = bisect.bisect_left(free, (ce,))
            if k == len(free) or free[k][0] != ce:
                return False
            fe = free[k][1]
            if new_end > (end if fe == top else fe):
                return False
            self._heap_unlist(ce, fe)
            if new_end < fe:
                self._heap_list(new_end, fe)
        h["heap_live"][p] = (n, cs)
        if new_end > top:
            h["heap_top"] = new_end
        self.hle_touched = True
        return True

    def scratch_alloc(self, n, align):
        p = align_up(self.scratch_top, align)
        if p + n > self.scratch + self.scratch_size:
            raise BridgeError("resource_exhausted", "the argument scratch region is exhausted; raise memory.scratch_mb",
                              {"resource": "scratch", "scratchBytes": self.scratch_size})
        self.scratch_top = p + max(n, 1)
        if self.scratch_top > self.scratch_high:
            self.scratch_high = self.scratch_top
        return p

    def event(self, kind, ptr=None, size=None):
        ev = self.rc.events
        if len(ev) < MAX_CALL_EVENTS:
            e = {"type": "heap", "kind": kind}
            if ptr is not None:
                e["ptr"] = hx(ptr)
            if size is not None:
                e["size"] = size
            ev.append(e)

    def fake_hmodule(self, name):
        key = name.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        hm = self.hle["hmods"]
        if key not in hm:
            hm[key] = self.S + OFF_FAKE_HMODULE + 0x10000 * len(hm)
            self.hle_touched = True
        return hm[key]

    def dynamic_import(self, handle, name):
        """GetProcAddress: bind the next free dynamic stub slot to the model the name resolves to (S5 §3.6.3)."""
        dll = next((k for k, v in self.hle["hmods"].items() if v == handle), None)
        if dll is None:
            m = self.module_at(handle) if handle else None
            dll = m.lname if m is not None else "unknown"
        key = f"{dll}!{name}"
        rc = self.rc
        if rc.dyn is None:
            rc.dyn = set()
        idx = self.hle["dyn_keys"].get(key)
        if idx is None:
            if len(self.hle["dyn"]) >= DYN_STUBS:
                rc.dyn.add(f"{key} (dynamic_stub_exhausted)")
                return 0
            idx = self.n_static + len(self.hle["dyn"])
            self.hle["dyn"][idx] = key
            self.hle["dyn_keys"][key] = idx
            self.hle_touched = True
        rc.dyn.add(key)
        return self.stubs_va + idx * STUB_SIZE

    def _dyn_rec(self, key):
        rec = self.dyn_cache.get(key)
        if rec is None:
            dll, name = key.split("!", 1)
            rec = self._model_for(dll, None if name.startswith("#") else name, key)
            self.dyn_cache[key] = rec
        return rec

    def import_call_detail(self):
        uc = self.uc
        m, rva = self.rva_of(self._stub_ret)
        return {"import": self.current_import, "caller": hx(self._stub_ret),
                "callerRva": hx(rva) if m else None,
                "args": [hx(uc.reg_read(r)) for r in GPR_ARGS],
                "xmm": [hx(uc.reg_read(XMM[k]) & MASK64) for k in range(4)]}

    # ---------------------------------------------------------------- diagnostics (S5 §3.13)
    def describe(self, addr):
        r = self.region_at(addr)
        if r is not None:
            d = {"region": r.name, "kind": r.kind if r.kind != "auto" else "runtime", "offset": hx(addr - r.start)}
            m = r.module or (self.module_at(addr) if r.kind in ("image", "module") else None)
            if m is not None:
                d["module"] = m.name
                d["rva"] = hx(addr - m.base)
            if r.kind == "stub":
                idx = (addr - self.stubs_va) // STUB_SIZE
                key = self.stubs[idx].key if idx < self.n_static else self.hle["dyn"].get(idx)
                if key:
                    d["import"] = key
            if r.capture:
                d["capture"] = r.capture
            return d
        page = addr & ~(PAGE - 1)
        if self.source == "dump":
            live = self._live_range(addr)
            if page in self.unreadable or live is not None:
                m = self.module_at(addr)
                what = m.name if m is not None else (f"{live[0]:#x}-{live[1]:#x}" if live else f"{page:#x}")
                d = {"region": "not captured", "kind": "unmapped", "capture": "not-captured-mapped-live",
                     "remediation": f"re-run dump_memory including {what}"}
                if m is not None:
                    d["module"] = m.name
                    d["rva"] = hx(addr - m.base)
                if live is not None:
                    d["liveProtection"] = live[2]
                if page in self.unreadable:
                    d["hint"] = "unreadable at capture"
                return d
        if self.S <= addr < self.S + WINDOW_SIZE:
            return {"region": "synthetic (unmapped)", "kind": "unmapped", "capture": "synthetic"}
        if addr < 0x10000:
            return {"region": "null page", "kind": "unmapped", "capture": "unmapped-live",
                    "hint": f"likely NULL pointer dereference (+{addr:#x})"}
        d = {"region": "unmapped", "kind": "unmapped", "capture": "unmapped-live"}
        i = bisect.bisect_right(self._starts, addr)
        best = None
        for j in (i - 1, i):
            if 0 <= j < len(self.regions):
                r = self.regions[j]
                dist = addr - r.end + 1 if addr >= r.end else r.start - addr
                if best is None or dist < best[0]:
                    best = (dist, r.name)
        if best is not None:
            d["nearest"] = best[1]
            d["distance"] = hx(best[0])
        return d

    def _live_range(self, addr):
        mm = self.memory_map
        i = bisect.bisect_right(mm, (addr, MASK64)) - 1
        while i >= 0:
            b, e, prot, mod = mm[i]
            if b <= addr < e:
                return (b, e, prot, mod)
            if e <= addr:
                return None
            i -= 1
        return None

    def pc_function(self, pc):
        m = self.module_at(pc)
        if m is None:
            return None
        f = m.image.function_at(pc - m.base)
        if f is None:
            return None
        return {"module": m.name, "beginRva": hx(f[0]), "endRva": hx(f[1]), "source": "pdata",
                "offset": hx(pc - m.base - f[0])}

    def read_orig(self, addr, n):
        data = bytearray(self.uc.mem_read(addr, n))
        restored = self.isa.restore_into(addr, data)
        return data, restored

    def _readable_prefix(self, addr, n):
        try:
            return self.read_orig(addr, n)[0]
        except UcError:
            out = bytearray()
            cur = addr
            while len(out) < n:
                take = min(PAGE - (cur & (PAGE - 1)), n - len(out))
                try:
                    out += self.read_orig(cur, take)[0]
                except UcError:
                    break
                cur += take
            return out

    def insn_dict(self, addr, size, mnemonic, op_str, raw):
        m, rva = self.rva_of(addr)
        return {"va": hx(addr), "rva": hx(rva) if m else None, "module": m.name if m else None,
                "bytes": bytes(raw).hex(), "text": f"{mnemonic} {op_str}".strip()}

    def disasm(self, va, count=1, max_bytes=None):
        code = self._readable_prefix(va, max_bytes or 16 * count)
        out = []
        for ins in self.cs.disasm(bytes(code), va):
            out.append(self.insn_dict(ins.address, ins.size, ins.mnemonic, ins.op_str, ins.bytes))
            if len(out) >= count:
                break
        if not out and code:
            out.append(self.insn_dict(va, len(code[:16]), "(undecodable)", "", code[:16]))
        return out

    def insn_at(self, va):
        code = self._readable_prefix(va, 16)
        for ins in self.cs.disasm(bytes(code), va):
            return ins.mnemonic, ins.op_str, ins.size
        return None

    def registers(self):
        uc = self.uc
        regs = {n: hx(uc.reg_read(r)) for n, r in DUMP_REGS}
        for i, r in enumerate(XMM):
            regs[f"xmm{i}"] = hx(uc.reg_read(r))
        return regs

    def stack_scan(self, limit=0x400, max_frames=16):
        """Heuristic return-address scan: stack qwords that point just after a call inside a module."""
        uc = self.uc
        rsp = uc.reg_read(REG["rsp"])
        if not (self.stack <= rsp < self.stack_top):
            return []
        blob = bytes(uc.mem_read(rsp, min(limit, self.stack_top - rsp)))
        frames = []
        for off in range(0, len(blob) - 7, 8):
            q = struct.unpack_from("<Q", blob, off)[0]
            if q == self.sentinel:
                frames.append({"stackOffset": hx(off), "va": hx(q), "module": None, "rva": None,
                               "note": "harness return sentinel"})
                break
            m = self.module_at(q)
            if m is None or q < 6:
                continue
            try:
                pre = bytes(self.read_orig(q - 6, 6)[0])
            except UcError:
                continue
            if pre[1] == 0xE8 or pre[0:2] == b"\xFF\x15" or (pre[4] == 0xFF and pre[5] & 0x38 == 0x10):
                frames.append({"stackOffset": hx(off), "va": hx(q), "module": m.name, "rva": hx(q - m.base)})
                if len(frames) >= max_frames:
                    break
        return frames

    # ---------------------------------------------------------------- hooks
    def _set_stop(self, status, attribution, cause, pc, **sub):
        rc = self.rc
        if rc.stop is None:
            rc.stop = {"status": status, "attribution": attribution, "cause": cause, **sub}
            rc.stop_pc = pc

    def _on_bad_mem(self, uc, access, address, size, value, _ud):
        rc = self.rc
        acc, kind = ACCESS.get(access, ("read", "unmapped"))
        if (kind == "unmapped" and acc != "fetch" and rc.fault_policy == "map_zero"
                and not (self.S <= address < self.S + WINDOW_SIZE)):
            if rc.automapped is None:
                rc.automapped = []
            if len(rc.automapped) < MAX_AUTOMAP_PAGES:
                page = address & ~(PAGE - 1)
                uc.mem_map(page, PAGE, U.UC_PROT_READ | U.UC_PROT_WRITE)
                rc.automapped.append(page)
                self.automapped_pages.append(page)
                self.add_region(page, page + PAGE, "auto-mapped zero page", "auto", "rw-")
                return True
        desc = self.describe(address)
        cap = desc.get("capture")
        harness = cap in ("not-captured-mapped-live", "synthetic")
        cause = "synthetic_unmapped" if cap == "synthetic" else f"{acc}_{kind}"
        pc = address if acc == "fetch" else uc.reg_read(REG["rip"])
        self._set_stop("fault", "harness" if harness else "target", cause, pc,
                       fault={"access": acc, "kind": kind, "address": hx(address), "size": size,
                              "value": hx(value & MASK64) if acc == "write" else None, "addressRegion": desc})
        return False

    def _on_intr(self, uc, intno, _ud):
        rip = uc.reg_read(REG["rip"])
        site = rip - 1
        if intno == 3 and site in self.isa.overlay:
            _orig, mn, enc = self.isa.overlay[site]
            m, rva = self.rva_of(site)
            self._set_stop("unsupported_instruction", "harness", enc, site,
                           isa={"mnemonic": mn, "encoding": enc, "rva": hx(rva) if m else None, "reason": VEX_REASON})
        else:
            try:
                pre = bytes(uc.mem_read(rip - 2, 2))
            except UcError:
                pre = b""
            pc = rip - 2 if pre == bytes((0xCD, intno & 0xFF)) else (rip - 1 if intno == 3 else rip)
            if intno == 0x29:
                self._set_stop("terminated", "target", "fastfail", pc,
                               terminate={"via": "int 0x29", "code": hx(uc.reg_read(REG["rcx"]) & MASK32)})
            elif intno == 0x2C:
                self._set_stop("terminated", "target", "assertion", pc, terminate={"via": "int 0x2c", "code": None})
            elif intno == 0x2E:
                self._set_stop("syscall", "harness", "int2e", pc, syscall=self._syscall_detail())
            else:
                cause, name = CPU_EXCEPTIONS.get(intno, (f"interrupt_{intno}", f"interrupt {intno}"))
                self._set_stop("cpu_exception", "target", cause, pc, exception={"vector": intno, "name": name})
        uc.emu_stop()

    def _syscall_detail(self):
        uc = self.uc
        return {"number": hx(uc.reg_read(REG["rax"]) & MASK32),
                "args": [hx(uc.reg_read(REG[r])) for r in ("r10", "rdx", "r8", "r9")]}

    def _on_syscall(self, uc, _ud):
        rip = uc.reg_read(REG["rip"])
        try:
            pre = bytes(uc.mem_read(rip - 2, 2))
        except UcError:
            pre = b""
        pc = rip - 2 if pre in (b"\x0f\x05", b"\x0f\x34") else rip
        self._set_stop("syscall", "harness", "syscall", pc, syscall=self._syscall_detail())
        uc.emu_stop()

    def _on_cpuid(self, uc, _ud):
        rc = self.rc
        if rc.cpuid is None:
            rc.cpuid = set()
        rc.cpuid.add((uc.reg_read(REG["rax"]) & MASK32, uc.reg_read(REG["rcx"]) & MASK32))
        return 0  # execute the real (emulated) CPUID

    def _on_rdtsc(self, uc, _ud):
        self.hle["tsc"] += 1000
        self.hle_touched = True
        uc.reg_write(REG["rax"], self.hle["tsc"] & MASK32)
        uc.reg_write(REG["rdx"], self.hle["tsc"] >> 32)
        self.rc.vtsc = True
        return 1

    def _on_tag(self, uc, address, _size, _ud):
        t = self.isa.tags.get(address)
        if t is not None:
            rc = self.rc
            if rc.tags is None:
                rc.tags = set()
            rc.tags.add((t[0], address, t[1]))

    def _on_vex_hook(self, uc, address, _size, _ud):
        site = self.isa.hook_sites.get(address)
        if site is None:
            return
        m, rva = self.rva_of(address)
        self._set_stop("unsupported_instruction", "harness", site[1], address,
                       isa={"mnemonic": site[0], "encoding": site[1], "rva": hx(rva) if m else None,
                            "reason": VEX_REASON})
        uc.emu_stop()

    def _on_code_write(self, uc, _access, _address, _size, _value, _ud):
        self.rc.code_written = True
        self.code_dirty = True

    def _on_stub(self, uc, address, _size, _ud):
        idx = (address - self.stubs_va) // STUB_SIZE
        if idx < self.n_static:
            rec = self.stubs[idx]
        else:
            key = self.hle["dyn"].get(idx)
            rec = self._dyn_rec(key) if key else StubRec(f"dynamic#{idx}", None, "unhandled", None, "no_model")
        rc = self.rc
        self.hle_touched = True
        self._stub_ret = struct.unpack("<Q", uc.mem_read(uc.reg_read(REG["rsp"]), 8))[0]
        self.current_import = rec.key
        mode = rc.imports_mode
        if mode != "off":
            c = rc.import_counts.get(rec.key)
            if c is None:
                rc.import_counts[rec.key] = {"calls": 1, "model": rec.model}
            else:
                c["calls"] += 1
        if rec.handler is None:
            if rec.model != "stop" and rec.stop_cause == "no_model" and self.unhandled_policy == "return_zero":
                uc.reg_write(REG["rax"], 0)
                uc.reg_write(XMM[0], 0)
                if rc.returned_zero is None:
                    rc.returned_zero = set()
                rc.returned_zero.add(rec.key)
                self._log_import(rec, "int", 0)
                return
            self._set_stop("unhandled_import", "harness", rec.stop_cause or "no_model", address,
                           importCall=self.import_call_detail())
            uc.emu_stop()
            return
        try:
            kind, val = rec.handler(self, Args(uc))
        except GuestFault as gf:
            desc = self.describe(gf.address)
            mapped = desc.get("kind") != "unmapped"
            self._set_stop("fault", "target", "import_arg", address,
                           fault={"access": gf.access, "kind": "protected" if mapped else "unmapped",
                                  "address": hx(gf.address), "size": min(gf.size, MASK32), "value": None,
                                  "addressRegion": desc})
            uc.emu_stop()
            return
        except HleStop as hs:
            self._set_stop(hs.status, "target" if hs.status == "terminated" else "harness", hs.cause, address,
                           **hs.detail)
            uc.emu_stop()
            return
        if kind == "int":
            uc.reg_write(REG["rax"], val & MASK64)
        elif kind in ("f32", "f64"):
            uc.reg_write(XMM[0], val)
        if rec.model == "builtin-inexact":
            if rc.inexact is None:
                rc.inexact = set()
            rc.inexact.add(rec.key)
        self._log_import(rec, kind, val)

    def _log_import(self, rec, kind, val):
        rc = self.rc
        if rc.imports_mode != "full":
            return
        if len(rc.import_events) >= rc.max_events:
            rc.trunc["imports"] = True
            return
        uc = self.uc
        m, rva = self.rva_of(self._stub_ret)
        rc.import_events.append({"import": rec.key, "model": rec.model, "callerRva": hx(rva) if m else None,
                                 "args": [hx(uc.reg_read(r)) for r in GPR_ARGS],
                                 "ret": hx(val & MASK64) if kind != "none" and val is not None else None})

    def _on_block(self, uc, address, size, _ud):
        rc = self.rc
        key = (address, size)
        n = self._block_icount.get(key)
        if n is None:
            try:
                n = sum(1 for _ in self.cs.disasm_lite(bytes(self.read_orig(address, size)[0]), address))
            except UcError:
                n = 0
            self._block_icount[key] = n
        rc.icount += n
        rc.nblocks += 1
        lb = rc.last_blocks
        if lb is None:
            lb = rc.last_blocks = []
        lb.append(address)
        if len(lb) > 32:
            del lb[:16]
        if rc.want_coverage:
            cov = rc.coverage
            c = cov.get(key)
            if c is not None:
                cov[key] = c + 1
            elif len(cov) < MAX_COVERAGE_BLOCKS:
                cov[key] = 1
            else:
                rc.trunc["coverage"] = True
        if rc.blocks is not None:
            if len(rc.blocks) < rc.max_events:
                rc.blocks.append(address)
            else:
                rc.trunc["blocks"] = True

    def _on_insn_trace(self, uc, address, _size, _ud):
        rc = self.rc
        if len(rc.insns) < rc.max_events:
            rc.insns.append(address)
        else:
            rc.trunc["instructions"] = True

    def _on_mem_trace(self, uc, access, address, size, value, _ud):
        rc = self.rc
        if len(rc.mem_events) >= rc.max_events:
            rc.trunc["memory"] = True
            return
        if access == U.UC_MEM_READ:
            try:
                value = int.from_bytes(uc.mem_read(address, size), "little")
            except UcError:
                value = 0
            acc = "r"
        else:
            acc = "w"
        rc.mem_events.append((uc.reg_read(REG["rip"]), acc, address, size, value & MASK64))

    # ---------------------------------------------------------------- call engine (S5 §3.8-§3.10)
    def _ensure_dynamic_hooks(self, sig):
        """Code/block hooks are baked into translated blocks: keep them per signature and flush on change."""
        if sig == self._hook_sig:
            return
        uc = self.uc
        for h in self._dyn_hooks:
            uc.hook_del(h)
        self._dyn_hooks = []
        block, insns, mem = sig
        if block:
            self._dyn_hooks.append(uc.hook_add(U.UC_HOOK_BLOCK, self._on_block))
        if insns:
            self._dyn_hooks.append(uc.hook_add(U.UC_HOOK_CODE, self._on_insn_trace))
        if mem != "off":
            mask = {"reads": U.UC_HOOK_MEM_READ, "writes": U.UC_HOOK_MEM_WRITE,
                    "all": U.UC_HOOK_MEM_READ | U.UC_HOOK_MEM_WRITE}[mem]
            self._dyn_hooks.append(uc.hook_add(mask, self._on_mem_trace))
        self._hook_sig = sig
        self._needs_flush = True

    def _prepare(self, rc, max_ins):
        self.rc = rc
        self._ensure_dynamic_hooks((rc.want_blocks or rc.want_coverage or rc.want_count, rc.want_insns, rc.memory))
        budget = max_ins > 0
        if budget != self._budget_mode:  # count= is honoured only by blocks translated in budget mode
            self._budget_mode = budget
            self._needs_flush = True
        if self._needs_flush:
            self.flush_tb()
            self._needs_flush = False

    def parse_run_options(self, o, path, batch):
        opts = {
            "maxInstructions": p_int(o, "maxInstructions", path, 0, 10 ** 10, 1_000_000),
            "timeoutMs": p_int(o, "timeoutMs", path, 0, 110_000, 0),
            "mxcsr": p_int(o, "mxcsr", path, 0, 0xFFFF, self.default_mxcsr),
            "fpcw": p_int(o, "fpcw", path, 0, 0xFFFF, self.default_fpcw),
            "faultPolicy": p_enum(o, "faultPolicy", path, ("stop", "map_zero"), self.fault_policy),
        }
        if opts["faultPolicy"] == "map_zero" and self.snap_mode != "manual":
            raise BridgeError("unsupported_combination", 'faultPolicy "map_zero" requires a session opened with '
                              'snapshots "manual"')
        tr = p_obj(o, "trace", path, required=False)
        tp = f"{path}.trace"
        trace = {
            "imports": p_enum(tr, "imports", tp, ("off", "counts", "full"), "counts" if batch else "full"),
            "blocks": p_bool(tr, "blocks", tp, False), "coverage": p_bool(tr, "coverage", tp, False),
            "countInstructions": p_bool(tr, "countInstructions", tp, False),
            "memory": p_enum(tr, "memory", tp, ("off", "reads", "writes", "all"), "off"),
            "instructions": p_bool(tr, "instructions", tp, False), "disassemble": p_bool(tr, "disassemble", tp, False),
            "maxEvents": p_int(tr, "maxEvents", tp, 1, MAX_TRACE_EVENTS, 10_000),
        }
        if batch and (trace["blocks"] or trace["memory"] != "off" or trace["instructions"]):
            raise BridgeError("unsupported_combination", "block, memory and instruction traces are single-call only; "
                              "batches aggregate coverage instead", {"path": tp})
        opts["trace"] = trace
        return opts

    @staticmethod
    def new_rc(opts, batch):
        t = opts["trace"]
        imports = t["imports"]
        if batch and imports == "full":
            imports = "counts"
        return RunCtx(opts["faultPolicy"], imports, t["maxEvents"], t["blocks"], t["coverage"],
                      t["countInstructions"], t["memory"], t["instructions"], t["disassemble"])

    def parse_state(self, st, path):
        frm = st.get("from", "baseline")
        if not isinstance(frm, str) or not frm:
            raise BridgeError("invalid_params", f"{path}.from must be a string", {"path": f"{path}.from"})
        writes = []
        for i, w in enumerate(p_list(st, "writes", path, MAX_STATE_WRITES)):
            wp = f"{path}.writes[{i}]"
            if not isinstance(w, dict):
                raise BridgeError("invalid_params", f"{wp} must be an object", {"path": wp})
            writes.append((parse_hex(w.get("address"), f"{wp}.address"), parse_hexbytes(w.get("hex"), f"{wp}.hex",
                                                                                         MAX_MEM_READ)))
        save_as = st.get("saveAs")
        if save_as is not None:
            check_snapshot_name(save_as, f"{path}.saveAs")
        return frm, writes, save_as

    def _position(self, frm):
        if frm == "baseline":
            self.snaps.restore_baseline()
        elif frm == "current":
            self.just_restored = False
        else:
            self.snaps.restore_named(frm)

    def _mapped(self, addr, n):
        cur, end = addr, addr + max(n, 1)
        while cur < end:
            r = self.region_at(cur)
            if r is None:
                return False
            cur = r.end
        return True

    def host_write(self, addr, data, what):
        """A host write after the baseline. VERIFIED (WP14 lab): once a CPU+memory context exists, unicorn 2.1.4
        fails host writes to non-writable pages with UC_ERR_WRITE_UNMAPPED and refuses mem_protect (UC_ERR_ARG),
        so a COW session with section protections can only write writable memory here."""
        if not self._mapped(addr, len(data)):
            raise BridgeError("unmapped", f"{what} {addr:#x}+{len(data):#x} is not (entirely) mapped",
                              {"region": self.describe(addr)})
        if self.snap_mode == "cow" and not self._writable(addr, len(data)):
            raise BridgeError("unsupported_combination", f"{what} {addr:#x}+{len(data):#x} targets read-only memory; "
                              "a session with copy-on-write snapshots and section protections can write only "
                              'writable memory after its baseline. Use emu_open patches, protections "rwx", or '
                              'snapshots "manual".', {"region": self.describe(addr)})
        if self.snap_mode == "manual":
            for page in range(addr & ~(PAGE - 1), align_up(addr + len(data)), PAGE):
                if page not in self.pristine:
                    self.pristine[page] = bytes(self.uc.mem_read(page, PAGE))
        try:
            self.uc.mem_write(addr, data)
        except UcError:
            raise BridgeError("unmapped", f"{what} {addr:#x}+{len(data):#x} is not writable by the host",
                              {"region": self.describe(addr)}) from None
        return self._host_wrote(addr, len(data)) if data else False

    def apply_writes(self, writes):
        for addr, data in writes:
            self.host_write(addr, data, "state write")

    def compile_plan(self, plan, vectors, path, single):
        """Validate a PlanWire + VectorsWire once (TypeScript classified the ABI; no ABI reasoning here)."""
        if not isinstance(plan, dict):
            raise BridgeError("invalid_params", f"{path}.plan must be an object", {"path": f"{path}.plan"})
        if not isinstance(vectors, dict):
            raise BridgeError("invalid_params", f"{path}.vectors must be an object", {"path": f"{path}.vectors"})
        pp, vp = f"{path}.plan", f"{path}.vectors"
        cp = CompiledPlan()
        cp.target = parse_hex(plan.get("target"), f"{pp}.target")
        cp.offset = p_int(vectors, "offset", vp, 0, MAX_VECTORS_PER_BATCH, 0)
        cp.count = p_int(vectors, "count", vp, 0, MAX_VECTORS_PER_BATCH)
        if single and cp.count != 1:
            raise BridgeError("invalid_params", f"{vp}.count must be 1 for emu.call", {"path": f"{vp}.count"})
        raw_cols = vectors.get("columns", {})
        if not isinstance(raw_cols, dict):
            raise BridgeError("invalid_params", f"{vp}.columns must be an object", {"path": f"{vp}.columns"})
        cols = {}

        def column(name, where, array):
            if name in cols:
                vals = cols[name]
            else:
                vals = raw_cols.get(name)
                cpath = f"{vp}.columns.{name}"
                if not isinstance(vals, list) or len(vals) < cp.count:
                    raise BridgeError("invalid_params", f"{where}: column {name!r} needs {cp.count} cells",
                                      {"path": cpath, "column": name})
                try:
                    vals = [([int(x[2:], 16) for x in v] if isinstance(v, list) else int(v[2:], 16))
                            for v in vals[:cp.count]]
                except (TypeError, ValueError, IndexError):
                    raise BridgeError("invalid_params", f"{cpath}: cells must be 0x-prefixed hex bits",
                                      {"path": cpath, "column": name}) from None
                cols[name] = vals
            if cp.count and (isinstance(vals[0], list) != array):
                raise BridgeError("invalid_params", f"{where}: column {name!r} must hold "
                                  f"{'arrays' if array else 'scalars'}", {"path": f"{vp}.columns.{name}"})
            return vals

        bufs = p_list(plan, "buffers", pp, 64)
        names = set()
        for i, b in enumerate(bufs):
            bp = f"{pp}.buffers[{i}]"
            if not isinstance(b, dict):
                raise BridgeError("invalid_params", f"{bp} must be an object", {"path": bp})
            bw = BufferPlan()
            bw.name = p_str(b, "name", bp, 64)
            if bw.name in names:
                raise BridgeError("invalid_params", f"{bp}.name {bw.name!r} is duplicated", {"path": f"{bp}.name"})
            names.add(bw.name)
            bw.size = p_int(b, "size", bp, 0, MAX_SCRATCH)
            bw.align = p_int(b, "align", bp, 1, 4096, 16)
            if bw.align & (bw.align - 1):
                raise BridgeError("invalid_params", f"{bp}.align must be a power of two", {"path": f"{bp}.align"})
            bw.placement = p_enum(b, "placement", bp, ("scratch", "heap"), "scratch")
            bw.template = parse_hexbytes(b.get("template", ""), f"{bp}.template", MAX_SCRATCH)
            if len(bw.template) != bw.size:
                raise BridgeError("invalid_params", f"{bp}.template must be exactly size bytes", {"path": bp})
            bw.out = p_bool(b, "out", bp, False)
            bw.columns = []
            for j, c in enumerate(p_list(b, "columns", bp, 4096)):
                cpath = f"{bp}.columns[{j}]"
                cname = p_str(c, "column", cpath, 256)
                off = p_int(c, "offset", cpath, 0, max(bw.size - 1, 0))
                width = p_enum(c, "width", cpath, (1, 2, 4, 8))
                count = p_int(c, "count", cpath, 1, 1 << 20, 1)
                if off + width * count > bw.size:
                    raise BridgeError("invalid_params", f"{cpath} runs past the buffer", {"path": cpath})
                bw.columns.append((off, width, count, column(cname, cpath, count > 1)))
            bw.ptr_fields = []
            for j, f in enumerate(p_list(b, "ptrFields", bp, 4096)):
                fpath = f"{bp}.ptrFields[{j}]"
                off = p_int(f, "offset", fpath, 0, max(bw.size - 8, 0))
                if off + 8 > bw.size:
                    raise BridgeError("invalid_params", f"{fpath} runs past the buffer", {"path": fpath})
                bw.ptr_fields.append((off, p_str(f, "buffer", fpath, 64),
                                      p_int(f, "plus", fpath, -(1 << 40), 1 << 40, 0)))
            cp.buffers.append(bw)
        sizes = {b.name: b.size for b in cp.buffers}
        for b in cp.buffers:
            for _off, target, _plus in b.ptr_fields:
                if target not in sizes:
                    raise BridgeError("invalid_params", f"{pp}: buffer {b.name!r} points at unknown buffer {target!r}",
                                      {"path": f"{pp}.buffers", "buffer": target})
        nstack = 0
        for i, s in enumerate(p_list(plan, "slots", pp, 64)):
            sp = f"{pp}.slots[{i}]"
            if not isinstance(s, dict):
                raise BridgeError("invalid_params", f"{sp} must be an object", {"path": sp})
            reg = p_enum(s, "reg", sp, ("rcx", "rdx", "r8", "r9", "xmm0", "xmm1", "xmm2", "xmm3", "stack"))
            sidx = None
            if reg == "stack":
                sidx = p_int(s, "stackIndex", sp, 0, 63)
                nstack = max(nstack, sidx + 1)
            dup = s.get("dupGpr")
            if dup is not None:
                dup = ARG_REG[p_enum(s, "dupGpr", sp, ("rcx", "rdx", "r8", "r9"))]
            src = p_obj(s, "source", sp)
            kind = p_enum(src, "kind", f"{sp}.source", ("column", "const", "buffer", "byval"))
            if kind == "column":
                compiled = ("col", column(p_str(src, "column", f"{sp}.source", 256), f"{sp}.source", False))
            elif kind == "const":
                compiled = ("const", parse_hex(src.get("bits"), f"{sp}.source.bits", 128))
            else:
                bname = p_str(src, "buffer", f"{sp}.source", 64)
                if bname not in sizes:
                    raise BridgeError("invalid_params", f"{sp}.source: unknown buffer {bname!r}",
                                      {"path": f"{sp}.source.buffer", "buffer": bname})
                if kind == "buffer":
                    compiled = ("buf", bname, p_int(src, "offset", f"{sp}.source", 0, max(sizes[bname], 0), 0))
                else:
                    if sizes[bname] not in (1, 2, 4, 8):
                        raise BridgeError("invalid_params", f"{sp}.source: a by-value buffer must be 1, 2, 4 or 8 "
                                          "bytes", {"path": f"{sp}.source.buffer"})
                    compiled = ("byval", bname)
            xmm = reg.startswith("xmm")
            cp.slots.append((None if reg == "stack" else ARG_REG[reg], sidx, compiled, dup, MASK128 if xmm else MASK64))
        ret = p_obj(plan, "returns", pp)
        p_enum(ret, "kind", f"{pp}.returns", ("void", "int", "f32", "f64", "struct"))
        cp.nstack = nstack
        cp.entry_rsp = ((self.stack_top - 0x1000 - 0x20 - 8 * nstack) & ~0xF) - 8
        cp.head = struct.pack("<Q", self.sentinel) + bytes(0x20)
        cp.scalar_only = not cp.buffers and all(s[2][0] in ("col", "const") for s in cp.slots)
        return cp

    def _materialize(self, cp, i):
        """Place vector i's buffers. Heap-placement buffers persist in the session state like any guest allocation
        (S5 §7.4: "heap" exists to persist, e.g. with save_as), so a chain batch holds one per vector. When a buffer
        does not fit, this vector's heap blocks are released again and VectorSetupError is raised before anything
        ran."""
        uc = self.uc
        self.scratch_top = self.scratch
        addrs, datas = {}, {}
        placed = []
        try:
            for b in cp.buffers:
                data = bytearray(b.template)
                for off, width, count, vals in b.columns:
                    cell = vals[i]
                    mask = (1 << (8 * width)) - 1
                    if count == 1:
                        data[off:off + width] = (cell & mask).to_bytes(width, "little")
                    else:
                        for k in range(min(count, len(cell))):
                            o = off + k * width
                            data[o:o + width] = (cell[k] & mask).to_bytes(width, "little")
                if b.placement == "heap":
                    a = self.heap_alloc(b.size, b.align, harness=True)
                    if not a:
                        raise VectorSetupError(
                            "resource_exhausted", f"the HLE heap cannot hold buffer {b.name!r} ({b.size} bytes; the "
                            f"heap is {self.heap_size} bytes and keeps earlier heap-placement buffers); raise "
                            "memory.heap_mb or use placement scratch", {"resource": "heap", "buffer": b.name,
                                                                        "bytes": b.size, "heapBytes": self.heap_size})
                    placed.append(a)
                else:
                    a = self.scratch_alloc(b.size, b.align)
                addrs[b.name] = a
                datas[b.name] = data
        except BridgeError as e:
            for a in placed:
                self.heap_free(a)
            if isinstance(e, VectorSetupError):
                raise
            raise VectorSetupError(e.code, str(e), e.data) from None
        for b in cp.buffers:
            for off, target, plus in b.ptr_fields:
                struct.pack_into("<Q", datas[b.name], off, (addrs[target] + plus) & MASK64)
        for b in cp.buffers:
            if b.size:
                uc.mem_write(addrs[b.name], bytes(datas[b.name]))
        return addrs, datas

    def _arm(self, opts, ctx):
        best = None
        if opts["timeoutMs"] > 0:
            best = (opts["timeoutMs"] / 1000.0, "watchdog")
        if ctx.deadline_at is not None:
            rem = max(ctx.deadline_at - time.monotonic() + DEADLINE_GRACE_S, 0.0)
            if best is None or rem < best[0]:
                best = (rem, "deadline")
        return WATCHDOG.arm(self.uc, best[0], best[1]) if best else None

    def _writer(self, cp, opts, zero):
        """The prepared register batch for this plan: CPU environment, zeroed registers, argument slots, RSP."""
        key = (zero, opts["mxcsr"], opts["fpcw"])
        w = cp.writers.get(key)
        if w is None:
            env = [(REG["mxcsr"], opts["mxcsr"] & MXCSR_CONTROL), (REG["fpcw"], opts["fpcw"]), (REG["fpsw"], 0),
                   (REG["fptag"], 0xFFFF), (REG["rflags"], RFLAGS_ENTRY)]
            if zero:
                env += [(r, 0) for r in ZERO_GPRS] + [(x, 0) for x in XMM]
            ids = [r for r, _v in env]
            slot_pos = []
            for reg, _sidx, _src, dup, _mask in cp.slots:
                pos = []
                if reg is not None:
                    pos.append(len(ids))
                    ids.append(reg)
                if dup is not None:
                    pos.append(len(ids))
                    ids.append(dup)
                slot_pos.append(pos)
            ids.append(REG["rsp"])
            batch = RegBatch(self.uc, ids)
            for i, (_r, v) in enumerate(env):
                batch.set(i, v)
            batch.set(len(ids) - 1, cp.entry_rsp)
            w = cp.writers[key] = (batch, slot_pos)
        return w

    def run_vector(self, cp, i, opts, ctx):
        """One vector (S5 §3.8): buffers, pointer fields, register/stack plan, CPU environment, run, classify."""
        uc = self.uc
        self.rc.begin_vector()
        writer, slot_pos = self._writer(cp, opts, not self.just_restored)
        addrs, datas = self._materialize(cp, i) if cp.buffers else ({}, {})
        stack = [0] * cp.nstack if cp.nstack else None
        for (reg, sidx, src, dup, mask), pos in zip(cp.slots, slot_pos):
            k = src[0]
            if k == "col":
                v = src[1][i]
            elif k == "const":
                v = src[1]
            elif k == "buf":
                v = addrs[src[1]] + src[2]
            else:
                v = int.from_bytes(datas[src[1]], "little")
            if reg is None:
                stack[sidx] = v & MASK64
                if dup is not None:
                    writer.set(pos[0], v & MASK64)
            else:
                writer.set(pos[0], v & mask)
                if dup is not None:
                    writer.set(pos[1], v & MASK64)
        if stack is not None or not self.frame_clean:
            uc.mem_write(cp.entry_rsp, cp.head + (b"".join(struct.pack("<Q", v) for v in stack) if stack else b""))
        writer.write()
        self.just_restored = False
        self.frame_clean = False
        seq = self._arm(opts, ctx)
        err = None
        t0 = time.perf_counter()
        try:
            uc.emu_start(cp.target, self.sentinel, count=opts["maxInstructions"])
        except UcError as e:
            err = e
        wall = (time.perf_counter() - t0) * 1e6
        fired = WATCHDOG.disarm(seq) if seq is not None else None
        return self._classify(err, fired, opts["maxInstructions"], ctx), addrs, wall

    def _classify(self, err, fired, max_ins, ctx):
        rc, uc = self.rc, self.uc
        if rc.stop is not None:
            return rc.stop["status"]
        if err is not None and err.errno == U.UC_ERR_NOMEM:
            raise MemoryError("unicorn: UC_ERR_NOMEM")
        rip = uc.reg_read(REG["rip"])
        if err is None and rip == self.sentinel:
            return "returned"
        if ctx.cancelled():
            self._set_stop("cancelled", "harness", "host_cancel", rip)
        elif err is not None:
            e = err.errno
            if e == U.UC_ERR_INSN_INVALID:
                ins = self.insn_at(rip)
                if ins is None:
                    self._set_stop("invalid_instruction", "target", "undecodable", rip)
                elif ins[0] in UD_MNEMONICS:
                    self._set_stop("cpu_exception", "target", "ud", rip, exception={"vector": 6,
                                                                                    "name": CPU_EXCEPTIONS[6][1]})
                else:
                    m, rva = self.rva_of(rip)
                    self._set_stop("unsupported_instruction", "harness", "engine_rejected", rip,
                                   isa={"mnemonic": ins[0], "encoding": "engine", "rva": hx(rva) if m else None,
                                        "reason": ENGINE_REJECT_REASON})
            else:
                self._set_stop("engine_error", "harness", f"uc_err_{e}", rip,
                               engineError={"errno": e, "message": str(err)})
        elif fired is not None:
            self._set_stop("timeout", "harness", fired, rip)
        elif self._hlt_before(rip):
            self._set_stop("cpu_exception", "target", "gp", rip - 1,
                           exception={"vector": 13, "name": "#GP general protection (hlt is privileged)"})
        elif max_ins:
            self._set_stop("budget_exhausted", "harness", "max_instructions", rip)
        else:
            self._set_stop("engine_error", "harness", "uc_err_0", rip,
                           engineError={"errno": 0, "message": "emulation stopped before the return sentinel"})
        return rc.stop["status"]

    def _hlt_before(self, rip):
        try:
            if bytes(self.uc.mem_read(rip - 1, 1)) != b"\xF4":
                return False
        except UcError:
            return False
        ins = self.insn_at(rip - 1)
        return ins is not None and ins[0] == "hlt"

    def stop_record(self):
        rc = self.rc
        st = dict(rc.stop)
        pc = rc.stop_pc if rc.stop_pc is not None else self.uc.reg_read(REG["rip"])
        rec = {"status": st.pop("status"), "attribution": st.pop("attribution"), "cause": st.pop("cause"),
               "pc": hx(pc), "pcRegion": self.describe(pc), "pcFunction": self.pc_function(pc),
               "instruction": self.disasm(pc, 1)}
        rec.update(st)
        if rec["status"] in ("cpu_exception", "invalid_instruction", "unsupported_instruction", "engine_error") or (
                rec["status"] == "fault" and rec["attribution"] == "target"):
            rec["registers"] = self.registers()
        rec["stackScan"] = self.stack_scan()
        if rc.last_blocks is not None:
            rec["lastBlocks"] = [hx(a) for a in rc.last_blocks[-16:]]
        return rec

    def stop_pc_rva(self):
        """The current stop's pc as an image rva (hex), None outside an image (batch `pcRva` column, EMU-9)."""
        rc = self.rc
        m, rva = self.rva_of(rc.stop_pc if rc.stop_pc is not None else self.uc.reg_read(REG["rip"]))
        return hx(rva) if m else None

    def compact_fault(self, index):
        rc = self.rc
        st = rc.stop
        pc = rc.stop_pc if rc.stop_pc is not None else self.uc.reg_read(REG["rip"])
        m, rva = self.rva_of(pc)
        f = {"index": index, "status": st["status"], "attribution": st["attribution"], "cause": st["cause"],
             "pc": hx(pc), "pcRva": hx(rva) if m else None}
        if "fault" in st:
            f["faultAddress"] = st["fault"]["address"]
        if "importCall" in st:
            f["import"] = st["importCall"]["import"]
        if "isa" in st:
            f["mnemonic"] = st["isa"]["mnemonic"]
        return f

    def call_deviations(self, rc):
        devs = []
        if rc.tags:
            by = {}
            for kind, addr, mn in rc.tags:
                by.setdefault(kind, []).append((addr, mn))
            for kind, dkind in TAG_DEVIATIONS:
                sites = sorted(by.get(kind, []))
                if sites:
                    devs.append(deviation(dkind, len(sites), {"sites": [
                        {"rva": hx(self.rva_of(a)[1]) if self.rva_of(a)[0] else hx(a), "mnemonic": mn}
                        for a, mn in sites[:32]]}))
        if rc.vtsc:
            devs.append(deviation("virtualized_tsc"))
        if rc.cpuid:
            devs.append(deviation("cpuid_executed", len(rc.cpuid), {"leaves": [
                {"leaf": hx(lf), "subleaf": hx(sl)} for lf, sl in sorted(rc.cpuid)[:32]]}))
        if rc.inexact:
            devs.append(deviation("inexact_import_model", len(rc.inexact), {"imports": sorted(rc.inexact)}))
        if rc.returned_zero:
            devs.append(deviation("unhandled_import_returned_zero", len(rc.returned_zero),
                                  {"imports": sorted(rc.returned_zero)}))
        if rc.dyn:
            devs.append(deviation("dynamic_import_resolved", len(rc.dyn), {"names": sorted(rc.dyn)[:64]}))
        if rc.automapped:
            devs.append(deviation("auto_mapped_zero_pages", len(rc.automapped),
                                  {"pages": [hx(p) for p in rc.automapped[:64]]}))
        if rc.heap_oom:
            devs.append(deviation("hle_heap_exhausted", rc.heap_oom, {"heapBytes": self.heap_size}))
        if rc.code_written:
            devs.append(deviation("self_modifying_code"))
        devs.extend(self.overlay_deviation())
        return devs

    def overlay_deviation(self):
        lost = len(self.isa.initial_sites) - len(self.isa.overlay)
        if lost > 0:
            gone = sorted(self.isa.initial_sites - set(self.isa.overlay))[:32]
            return [deviation("isa_overlay_overwritten", lost, {"sites": [hx(a) for a in gone]})]
        return []

    def nondeterministic(self, rc, status):
        if status in ("timeout", "cancelled"):
            return True
        return bool(rc.tags) and any(k in ("tsc", "rng") for k, _a, _m in rc.tags)

    def provenance(self, target, opts):
        p = self.primary
        m, rva = self.rva_of(target)
        export = None
        if m is not None:
            export = next((n for n, r in m.image.exports.items() if r == rva), None)
        return {"evidence": "emulation", "engine": "unicorn", "engines": engine_versions(),
                "bridge": {"version": BRIDGE_VERSION, "sha256": BRIDGE_SHA256}, "protocol": PROTOCOL,
                "source": self.source, "bundleId": self.bundle_id,
                "primary": {"name": p.name, "sha256": p.sha256, "mappedBase": hx(p.base),
                            "preferredBase": hx(p.preferred_base) if p.preferred_base is not None else None},
                "target": {"va": hx(target), "module": m.name if m else None, "rva": hx(rva) if m else None,
                           "export": export},
                "abi": "win64", "mxcsr": hx(opts["mxcsr"]), "fpcw": hx(opts["fpcw"]), "isaGuard": self.isa_mode}

    @staticmethod
    def coverage_wire(rc):
        blocks = sorted(rc.coverage.items())
        return {"granularity": "tb", "blocks": [[hx(a), size, hits] for (a, size), hits in blocks],
                "distinct": len(blocks), "truncated": bool(rc.trunc.get("coverage"))}

    def _cancelled_call(self, params):
        """A queued emu.call cancelled before it started: a full CallResult with status cancelled."""
        plan = params.get("plan") if isinstance(params.get("plan"), dict) else {}
        try:
            target = parse_hex(plan.get("target"), "params.plan.target")
        except BridgeError:
            target = 0
        opts = {"mxcsr": self.default_mxcsr, "fpcw": self.default_fpcw}
        return {"status": "cancelled", "attribution": "harness",
                "raw": {"rax": "0x0", "xmm0": "0x0", "mxcsr": hx(self.default_mxcsr & MXCSR_CONTROL),
                        "fpcw": hx(self.default_fpcw), "fpsw": "0x0"},
                "buffers": {}, "out": {}, "stop": None, "metrics": {"wallUs": 0.0, "tbFlushes": 0}, "events": [],
                "deviations": [], "deterministic": False, "provenance": self.provenance(target, opts)}

    @staticmethod
    def check_out_budget(cp, vectors):
        """Refuse, before anything runs, a request whose out buffers would not fit one result frame (MAX_OUT_HEX)."""
        need = out_hex_bytes(cp.buffers, vectors)
        if need > MAX_OUT_HEX:
            fit = MAX_OUT_HEX // out_hex_bytes(cp.buffers, 1)
            raise BridgeError("invalid_params", f"the out buffers of {vectors} vector(s) would return {need} bytes of "
                              f"hex; one result carries at most {MAX_OUT_HEX} (at most {fit} vector(s) with these out "
                              "buffers per request); out buffers are never truncated",
                              {"path": "params.vectors", "outHexBytes": need, "limit": MAX_OUT_HEX, "maxVectors": fit})

    def call(self, params, ctx):
        """emu.call: one vector with full detail."""
        cp = self.compile_plan(params.get("plan"), params.get("vectors"), "params", True)
        opts = self.parse_run_options(p_obj(params, "options", "params", required=False), "params.options", False)
        frm, writes, save_as = self.parse_state(p_obj(params, "state", "params", required=False), "params.state")
        if frm not in ("baseline", "current") and frm not in self.snaps.named:
            raise BridgeError("unknown_snapshot", f"no snapshot named {frm!r}", {"name": frm})
        self.check_out_budget(cp, 1)
        if ctx.cancelled():
            return self._cancelled_call(params)
        rc = self.new_rc(opts, False)
        flushes0 = self.tb_flushes
        self._prepare(rc, opts["maxInstructions"])
        self._position(frm)
        self.apply_writes(writes)
        status, addrs, wall = self.run_vector(cp, 0, opts, ctx)
        uc = self.uc
        out = {}
        for b in cp.buffers:
            if b.out:
                out[b.name] = bytes(uc.mem_read(addrs[b.name], b.size)).hex()
        stop = self.stop_record() if status != "returned" else None
        t = opts["trace"]
        metrics = {"wallUs": round(wall, 1), "tbFlushes": self.tb_flushes - flushes0}
        if rc.want_count or rc.want_blocks or rc.want_coverage:
            metrics["instructions"] = rc.icount
            metrics["blocks"] = rc.nblocks
        trace = {"truncated": {}}
        if rc.imports_mode == "full":
            trace["imports"] = rc.import_events
        if rc.blocks is not None:
            trace["blocks"] = [hx(a) for a in rc.blocks]
        if rc.want_coverage:
            trace["coverage"] = self.coverage_wire(rc)
        if rc.mem_events is not None:
            trace["memory"] = [{"pc": hx(pc), "access": acc, "address": hx(a), "size": n, "value": hx(v)}
                               for pc, acc, a, n, v in rc.mem_events]
        if rc.insns is not None:
            seen = {}
            listed = []
            for a in rc.insns:
                if t["disassemble"]:
                    if a not in seen:
                        d = self.disasm(a, 1)
                        seen[a] = d[0]["text"] if d else ""
                    listed.append({"va": hx(a), "text": seen[a]})
                else:
                    listed.append({"va": hx(a)})
            trace["instructions"] = listed
        for k in ("imports", "blocks", "coverage", "memory", "instructions"):
            if k in trace or (k == "coverage" and rc.want_coverage):
                trace["truncated"][k] = bool(rc.trunc.get(k))
        result = {
            "status": status, "attribution": None if status == "returned" else rc.stop["attribution"],
            "raw": {"rax": hx(uc.reg_read(REG["rax"])), "xmm0": hx(uc.reg_read(XMM[0])),
                    "mxcsr": hx(uc.reg_read(REG["mxcsr"])), "fpcw": hx(uc.reg_read(REG["fpcw"])),
                    "fpsw": hx(uc.reg_read(REG["fpsw"]))},
            "buffers": {n: hx(a) for n, a in addrs.items()}, "out": out, "stop": stop, "metrics": metrics,
            "trace": trace, "events": rc.events, "deviations": self.call_deviations(rc),
            "deterministic": not self.nondeterministic(rc, status), "provenance": self.provenance(cp.target, opts),
        }
        self.calls += 1
        self.vectors += 1
        if save_as is not None:
            self.snaps.save_named(save_as)
        return result

    def batch(self, params, ctx):
        """emu.batch: N vectors, columnar (S5 §3.14). Stops at the deadline or a cancel with the completed prefix, and
        (chain isolation) at a vector whose buffers no longer fit, with `summary.stopped` (review fix EMU-6)."""
        cp = self.compile_plan(params.get("plan"), params.get("vectors"), "params", False)
        o = p_obj(params, "options", "params", required=False)
        opts = self.parse_run_options(o, "params.options", True)
        isolation = p_enum(o, "isolation", "params.options", ("snapshot", "chain"), "snapshot")
        stop_on_fault = p_bool(o, "stopOnFault", "params.options", False)
        frm, writes, save_as = self.parse_state(p_obj(params, "state", "params", required=False), "params.state")
        if frm not in ("baseline", "current") and frm not in self.snaps.named:
            raise BridgeError("unknown_snapshot", f"no snapshot named {frm!r}", {"name": frm})
        self.check_out_budget(cp, cp.count)
        rc = self.new_rc(opts, True)
        t = opts["trace"]
        simple = rc.imports_mode != "full" and opts["timeoutMs"] == 0 and opts["faultPolicy"] == "stop" and not (
            t["coverage"] or t["countInstructions"])
        path = ("fast" if cp.scalar_only else "medium") if simple else "full"
        columns = {"status": [], "rax": [], "xmm0lo": [], "out": {b.name: [] for b in cp.buffers if b.out}}
        if t["countInstructions"]:
            columns["instructions"] = []
        faults, by_status, by_attr = [], {}, {"target": 0, "harness": 0}
        attr_col, pc_col = [], []  # per vector; sent only when `faults` cannot list every stop (EMU-9)
        dev_counts, deterministic, returned = {}, True, 0
        cancelled = deadline = False
        stopped = None
        t0 = time.perf_counter()
        if not ctx.cancelled():
            self._prepare(rc, opts["maxInstructions"])
            use_t = isolation == "snapshot" and (frm != "baseline" or bool(writes))
            self._position(frm)
            self.apply_writes(writes)
            if use_t:
                self.snaps.take_temp()
            uc = self.uc
            out_bufs = [b for b in cp.buffers if b.out]
            try:
                for i in range(cp.count):
                    if ctx.cancelled():
                        cancelled = True
                        break
                    if ctx.deadline_reached():
                        deadline = True
                        break
                    if isolation == "snapshot" and i > 0:  # vector 0 runs on the positioned state itself
                        if use_t:
                            self.snaps.restore_temp()
                        else:
                            self.snaps.restore_baseline()
                    try:
                        status, addrs, _wall = self.run_vector(cp, i, opts, ctx)
                    except VectorSetupError as e:
                        # Nothing of vector i ran and its allocations were rolled back: in a chain the session holds
                        # exactly the state after vector i-1, so the completed prefix is a valid (shorter) batch.
                        # Under snapshot isolation every vector starts from the same state, so only vector 0 can
                        # fail here, and nothing completed: an error.
                        if i == 0 or isolation != "chain":
                            raise
                        stopped = {"code": e.code, "message": str(e), "index": cp.offset + i}
                        if e.data:
                            stopped["data"] = e.data
                        break
                    code = STATUS_CODE[status]
                    columns["status"].append(code)
                    by_status[code] = by_status.get(code, 0) + 1
                    if status == "returned":
                        returned += 1
                        columns["rax"].append(hx(uc.reg_read(REG["rax"])))
                        columns["xmm0lo"].append(hx(uc.reg_read(XMM[0]) & MASK64))
                        attr_col.append("")
                        pc_col.append(None)
                    else:
                        columns["rax"].append("")
                        columns["xmm0lo"].append("")
                        attribution = rc.stop["attribution"]
                        by_attr[attribution] += 1
                        attr_col.append("t" if attribution == "target" else "h")
                        if len(faults) < MAX_BATCH_FAULTS:
                            f = self.compact_fault(cp.offset + i)
                            if len(faults) < BATCH_FAULT_DETAILS:
                                f["detail"] = self.stop_record()
                            faults.append(f)
                            pc_col.append(f["pcRva"])
                        else:
                            pc_col.append(self.stop_pc_rva())
                    for b in out_bufs:
                        columns["out"][b.name].append(bytes(uc.mem_read(addrs[b.name], b.size)).hex())
                    if "instructions" in columns:
                        columns["instructions"].append(rc.icount)
                    for kind in rc.vector_kinds():
                        dev_counts[kind] = dev_counts.get(kind, 0) + 1
                    if self.nondeterministic(rc, status):
                        deterministic = False
                    ctx.progress("batch", i + 1, cp.count)
                    if stop_on_fault and status != "returned":
                        break
            finally:
                if use_t:
                    self.snaps.end_batch()
        else:
            cancelled = True
        completed = len(columns["status"])
        if by_attr["target"] + by_attr["harness"] > len(faults):
            # review fix EMU-9: `faults` lists the first MAX_BATCH_FAULTS stops only; past them the host needs each
            # vector's attribution ("" returned, "t" target, "h" harness) and pc rva to keep harness stops apart
            columns["attr"] = attr_col
            columns["pcRva"] = pc_col
        if cancelled or deadline:
            deterministic = False if cancelled else deterministic
        elapsed = time.perf_counter() - t0
        aggregates = {"imports": rc.import_counts,
                      "deviations": {k: {"vectors": v} for k, v in sorted(dev_counts.items())}}
        for d in self.overlay_deviation():
            aggregates["deviations"][d["kind"]] = {"vectors": completed, "detail": d.get("detail")}
        if t["coverage"]:
            aggregates["coverage"] = self.coverage_wire(rc)
        self.calls += 1
        self.vectors += completed
        if save_as is not None and completed:
            self.snaps.save_named(save_as)
        summary = {"offset": cp.offset, "vectors": cp.count, "completed": completed, "returned": returned,
                   "byStatus": by_status, "byAttribution": by_attr, "elapsedMs": round(elapsed * 1000, 3),
                   "callsPerSecond": round(completed / elapsed, 1) if elapsed > 0 and completed else None,
                   "isolation": isolation, "from": frm, "path": path, "deterministic": deterministic,
                   "deadlineReached": deadline, "cancelled": cancelled}
        if stopped is not None:
            summary["stopped"] = stopped
        return {"summary": summary, "columns": columns, "faults": faults, "aggregates": aggregates,
                "provenance": self.provenance(cp.target, opts)}

    def sweep(self, params, ctx):
        """emu.sweep: many targets x few probe vectors from the baseline, with an optional matcher (S5 §3.15)."""
        cp = self.compile_plan(params.get("plan"), params.get("vectors"), "params", False)
        if cp.count > MAX_SWEEP_VECTORS:
            raise BridgeError("invalid_params", f"sweeps take at most {MAX_SWEEP_VECTORS} probe vectors. This "
                              "release has no runtime override.", {"path": "params.vectors.count"})
        opts = self.parse_run_options(p_obj(params, "options", "params", required=False), "params.options", True)
        fn = p_obj(params, "functions", "params")
        offset = 0
        if "targets" in fn:
            raw = p_list(fn, "targets", "params.functions", MAX_SWEEP_TARGETS, required=True)
            targets = [parse_hex(v, f"params.functions.targets[{i}]") for i, v in enumerate(raw)]
            total = len(targets)
            module_mode = False
        else:
            mname = p_str(fn, "module", "params.functions", 260)
            mod = next((m for m in self.modules if m.lname == mname.lower()), None)
            if mod is None:
                raise BridgeError("unknown_symbol", f"no module named {mname!r}",
                                  {"modules": [m.name for m in self.modules][:50]})
            lo = parse_hex(fn.get("rvaStart"), "params.functions.rvaStart")
            hi = parse_hex(fn.get("rvaEnd"), "params.functions.rvaEnd")
            offset = p_int(fn, "offset", "params.functions", 0, MAX_SWEEP_TARGETS, 0)
            limit = p_int(fn, "limit", "params.functions", 1, MAX_SWEEP_TARGETS, 5000)
            begins = [b for b, _e in mod.image.pdata if lo <= b < hi]
            total = len(begins)
            targets = [mod.base + b for b in begins[offset:offset + limit]]
            module_mode = True
        match = params.get("match")
        raw_vectors = params.get("vectors") if isinstance(params.get("vectors"), dict) else {}
        matcher = SweepMatcher(match, cp.count, raw_vectors.get("columns", {})) if match is not None else None
        rc = self.new_rc(opts, True)
        rc.imports_mode = "off"
        self._prepare(rc, opts["maxInstructions"])
        rows, profiles, matched = [], {}, 0
        cancelled = deadline = False
        uc = self.uc
        for va in targets:
            if ctx.cancelled():
                cancelled = True
                break
            if ctx.deadline_reached():
                deadline = True
                break
            cp.target = va
            statuses, rax, x0 = [], [], []
            for i in range(cp.count):
                self.snaps.restore_baseline()
                status, _addrs, _w = self.run_vector(cp, i, opts, ctx)
                statuses.append(STATUS_CODE[status])
                if status == "returned":
                    rax.append(hx(uc.reg_read(REG["rax"])))
                    x0.append(hx(uc.reg_read(XMM[0]) & MASK64))
                else:
                    rax.append("")
                    x0.append("")
            m, rva = self.rva_of(va)
            matches = matcher.match(statuses, x0) if matcher else []
            if matches:
                matched += 1
            rows.append({"rva": hx(rva) if m else hx(va), "module": m.name if m else "", "statuses": statuses,
                         "rax": rax, "xmm0lo": x0, "matches": matches})
            prof = "+".join(sorted(set(statuses))) or "none"
            profiles[prof] = profiles.get(prof, 0) + 1
            ctx.progress("sweep", len(rows), len(targets))
        self.snaps.restore_baseline()
        self.calls += 1
        self.vectors += len(rows) * cp.count
        done = len(rows)
        if module_mode:
            nxt = offset + done if offset + done < total else None
        else:
            nxt = done if done < total else None
        return {"summary": {"functions": total, "completed": done, "byOutcomeProfile": profiles, "matched": matched,
                            "deadlineReached": deadline, "cancelled": cancelled, "nextOffset": nxt},
                "rows": rows, "provenance": self.provenance(targets[0] if targets else 0, opts)}

    # ---------------------------------------------------------------- memory methods
    def mem_read(self, params):
        addr = parse_hex(params.get("address"), "params.address")
        size = p_int(params, "size", "params", 0, MAX_MEM_READ)
        enc = p_enum(params, "encoding", "params", ("hex", "base64"), "hex")
        try:
            data, restored = self.read_orig(addr, size) if size else (bytearray(), 0)
        except UcError:
            raise BridgeError("unmapped", f"{addr:#x}+{size:#x} is not (entirely) mapped",
                              {"region": self.describe(addr)}) from None
        text = bytes(data).hex() if enc == "hex" else base64.b64encode(bytes(data)).decode("ascii")
        return {"address": hx(addr), "size": size, "region": self.describe(addr), "data": text, "encoding": enc,
                "overlayRestored": restored}

    def mem_write(self, params):
        addr = parse_hex(params.get("address"), "params.address")
        if ("hex" in params) == ("base64" in params):
            raise BridgeError("invalid_params", "mem.write takes exactly one of hex or base64", {"path": "params"})
        if "hex" in params:
            data = parse_hexbytes(params["hex"], "params.hex", MAX_MEM_READ)
        else:
            try:
                data = base64.b64decode(params["base64"], validate=True)
            except (ValueError, TypeError):
                raise BridgeError("invalid_params", "params.base64 is not base64", {"path": "params.base64"}) from None
            if len(data) > MAX_MEM_READ:
                raise BridgeError("invalid_params", "mem.write takes at most 16 MiB", {"path": "params.base64"})
        flushed = self.host_write(addr, data, "mem.write")
        return {"written": len(data), "region": self.describe(addr), "tbFlushed": flushed}

    def mem_disassemble(self, params):
        addr = parse_hex(params.get("address"), "params.address")
        count = p_int(params, "count", "params", 1, MAX_DISASM, 16)
        whole = p_bool(params, "function", "params", False)
        f = self.pc_function(addr)
        fr = {"module": f["module"], "beginRva": f["beginRva"], "endRva": f["endRva"], "source": "pdata"} if f else None
        if whole:
            if f is None:
                raise BridgeError("invalid_params", f"{addr:#x} is not inside a .pdata function",
                                  {"path": "params.address"})
            m = self.module_at(addr)
            begin, end = m.base + int(f["beginRva"], 16), m.base + int(f["endRva"], 16)
            code = bytes(self._readable_prefix(begin, min(end - begin, MAX_FUNCTION_DISASM_BYTES)))
            insns = [self.insn_dict(i.address, i.size, i.mnemonic, i.op_str, i.bytes)
                     for i in self.cs.disasm(code, begin)]
            return {"instructions": insns, "function": fr}
        return {"instructions": self.disasm(addr, count), "function": fr}

    def mem_regions(self):
        out = []
        for r in self.regions:
            d = {"start": hx(r.start), "end": hx(r.end), "name": r.name,
                 "kind": r.kind if r.kind != "auto" else "runtime", "perms": r.perms}
            m = r.module or (self.module_at(r.start) if r.kind in ("image", "module") else None)
            if m is not None:
                d["module"] = m.name
            if r.capture:
                d["capture"] = r.capture
            out.append(d)
        return {"regions": out, "syntheticBase": hx(self.S)}

    def mem_functions(self, params):
        mname = p_str(params, "module", "params", 260)
        mod = next((m for m in self.modules if m.lname == mname.lower()), None)
        if mod is None:
            raise BridgeError("unknown_symbol", f"no module named {mname!r}",
                              {"modules": [m.name for m in self.modules][:50]})
        lo = parse_hex(params["rvaStart"], "params.rvaStart") if params.get("rvaStart") is not None else 0
        hi = parse_hex(params["rvaEnd"], "params.rvaEnd") if params.get("rvaEnd") is not None else MASK64
        offset = p_int(params, "offset", "params", 0, 1 << 24, 0)
        limit = p_int(params, "limit", "params", 1, MAX_SWEEP_TARGETS, 1000)
        fs = [(b, e) for b, e in mod.image.pdata if lo <= b < hi]
        page = fs[offset:offset + limit]
        return {"functions": [{"module": mod.name, "beginRva": hx(b), "endRva": hx(e), "source": "pdata"}
                              for b, e in page],
                "total": len(fs), "nextOffset": offset + len(page) if offset + len(page) < len(fs) else None}

    def info(self):
        out = dict(self.open_result)
        out["state"] = {"poisoned": self.poisoned, "named": self.snaps.listing(), "heapHigh": hx(self.hle["heap_top"]),
                        "calls": self.calls, "vectors": self.vectors}
        return out


class CompiledPlan:
    __slots__ = ("target", "offset", "count", "buffers", "slots", "nstack", "entry_rsp", "head", "scalar_only",
                 "writers")

    def __init__(self):
        self.buffers = []
        self.slots = []
        self.writers = {}


class BufferPlan:
    __slots__ = ("name", "size", "align", "placement", "template", "columns", "ptr_fields", "out")


SNAPSHOT_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")


def check_snapshot_name(name, path):
    ok = (isinstance(name, str) and 0 < len(name) <= 64 and (name[0].isascii() and (name[0].isalpha() or name[0] == "_"))
          and all(c in SNAPSHOT_NAME_CHARS for c in name) and name not in ("baseline", "current"))
    if not ok:
        raise BridgeError("invalid_params", f"{path}: snapshot names match ^[A-Za-z_][A-Za-z0-9_.-]{{0,63}}$ and are "
                          "not baseline/current", {"path": path})
    return name


# ------------------------------------------------------------------------------------------------- O. sweep matcher
def _safe_ref(fn):
    def f(*xs):
        try:
            return fn(*xs)
        except (ValueError, ZeroDivisionError):
            return math.nan
        except OverflowError:
            return math.inf
    return f


def _cbrt(x):
    if hasattr(math, "cbrt"):
        return math.cbrt(x)
    return math.copysign(abs(x) ** (1.0 / 3.0), x)


def _div(x, y):
    if y == 0.0:
        if x == 0.0 or math.isnan(x):
            return math.nan
        return math.copysign(math.inf, x) * math.copysign(1.0, y)
    return x / y


def _fmin(x, y):
    return y if math.isnan(x) else x if math.isnan(y) else min(x, y)


def _fmax(x, y):
    return y if math.isnan(x) else x if math.isnan(y) else max(x, y)


KNOWN_UNARY = {
    "sin": math.sin, "cos": math.cos, "tan": math.tan, "asin": math.asin, "acos": math.acos, "atan": math.atan,
    "sinh": math.sinh, "cosh": math.cosh, "tanh": math.tanh, "exp": math.exp, "exp2": lambda x: 2.0 ** x,
    "expm1": math.expm1, "log": _c_log(math.log), "log2": _c_log(math.log2), "log10": _c_log(math.log10),
    "log1p": lambda x: -math.inf if x == -1.0 else math.log1p(x), "sqrt": math.sqrt,
    "rsqrt": lambda x: _div(1.0, math.sqrt(x)), "recip": lambda x: _div(1.0, x), "cbrt": _cbrt, "floor": _c_floor,
    "ceil": _c_ceil, "trunc": _c_trunc, "round": _c_round, "fabs": math.fabs, "neg": lambda x: -x,
    "identity": lambda x: x,
}
KNOWN_BINARY = {
    "atan2": math.atan2, "pow": _c_pow, "fmod": math.fmod, "hypot": math.hypot, "fmin": _fmin, "fmax": _fmax,
    "copysign": math.copysign, "add": lambda x, y: x + y, "sub": lambda x, y: x - y, "mul": lambda x, y: x * y,
    "div": _div,
}


class SweepMatcher:
    """Behavioural identification (S5 §3.15): references computed in host double and rounded once to the return
    type; a target matches a known function when every probe vector returned and every result is within
    toleranceUlp (a NaN reference needs a NaN result; infinities must be exact)."""

    def __init__(self, match, cp_raw_vectors_count, columns):
        if not isinstance(match, dict):
            raise BridgeError("invalid_params", "params.match must be an object or null", {"path": "params.match"})
        mp = "params.match"
        self.fmt = FMT32 if p_enum(match, "returns", mp, ("f32", "f64")) == "f32" else FMT64
        args = p_list(match, "argsFrom", mp, 2, required=True)
        if not args or not all(isinstance(a, str) for a in args):
            raise BridgeError("invalid_params", f"{mp}.argsFrom needs 1 or 2 column names", {"path": f"{mp}.argsFrom"})
        self.tol = p_int(match, "toleranceUlp", mp, 0, 64, 1)
        known = match.get("known", ["all"])
        if not isinstance(known, list) or len(known) > 64:
            raise BridgeError("invalid_params", f"{mp}.known must be a list of names", {"path": f"{mp}.known"})
        table = KNOWN_UNARY if len(args) == 1 else KNOWN_BINARY
        names = []
        for k in known:
            if k in ("all", "unary", "binary"):
                if k == "all" or (k == "unary") == (len(args) == 1):
                    names.extend(table)
            elif k in KNOWN_UNARY or k in KNOWN_BINARY:
                if k in table:
                    names.append(k)
            else:
                raise BridgeError("invalid_params", f"{mp}.known: unknown function {k!r}",
                                  {"path": f"{mp}.known", "known": sorted(KNOWN_UNARY) + sorted(KNOWN_BINARY)})
        n = cp_raw_vectors_count
        argbits = []
        for a in args:
            col = columns.get(a) if isinstance(columns, dict) else None
            if not isinstance(col, list) or len(col) < n:
                raise BridgeError("invalid_params", f"{mp}.argsFrom: column {a!r} needs {n} cells",
                                  {"path": f"{mp}.argsFrom", "column": a})
            argbits.append([parse_hex(v, f"params.vectors.columns.{a}") & self.fmt.mask for v in col[:n]])
        self.refs = {}
        fmt = self.fmt
        for name in dict.fromkeys(names):
            fn = _safe_ref(table[name])
            bits = []
            for i in range(n):
                xs = [fmt.to_float(argbits[k][i]) for k in range(len(args))]
                bits.append(fmt.from_float(fn(*xs)))
            self.refs[name] = bits

    def match(self, statuses, xmm0lo):
        if not statuses or any(s != "ok" for s in statuses):
            return []
        fmt = self.fmt
        res = [int(x, 16) & fmt.mask for x in xmm0lo]
        out = []
        for name, refs in self.refs.items():
            for r, ref in zip(res, refs):
                if fmt.isnan(ref):
                    if not fmt.isnan(r):
                        break
                elif fmt.isnan(r):
                    break
                elif (ref & ~fmt.sign & fmt.mask) == (0x7F80_0000 if fmt.width == 4 else 0x7FF0_0000_0000_0000):
                    if r != ref:
                        break
                elif ulp_distance(r, ref, fmt) > self.tol:
                    break
            else:
                out.append(name)
        return out


# ------------------------------------------------------------------------------------------------- P. probe/selftest
BRIDGE_SHA256 = None
MEMORY_LIMIT = {"applied": False, "bytes": None, "mechanism": "none"}


def bridge_sha256():
    global BRIDGE_SHA256
    if BRIDGE_SHA256 is None:
        with open(os.path.abspath(__file__), "rb") as fh:
            BRIDGE_SHA256 = hashlib.sha256(fh.read()).hexdigest()
    return BRIDGE_SHA256


def python_info():
    return {"version": platform.python_version(), "executable": sys.executable, "inVenv": sys.prefix != sys.base_prefix}


def probe_line(missing, errors):
    py = {"version": platform.python_version(), "implementation": platform.python_implementation(),
          "executable": sys.executable, "prefix": sys.prefix, "basePrefix": sys.base_prefix,
          "inVenv": sys.prefix != sys.base_prefix, "bits": struct.calcsize("P") * 8, "platform": sys.platform}
    if missing:
        engines = {k: v for k, v in ((n, _dist_version(n, None)) for n in ("unicorn", "capstone", "pefile"))
                   if v is not None and k not in missing}
    else:
        engines = {k: v for k, v in engine_versions().items() if k != "python"}
    return {"probe": PROTOCOL, "ok": not missing, "bridge": {"version": BRIDGE_VERSION, "sha256": bridge_sha256()},
            "python": py, "engines": engines, "missing": missing, "errors": errors}


SELFTEST_EXPECTED_INSN_HOOKS = {"cpuid": True, "syscall": True, "rdtsc": False, "rdtscp": False}


def selftest():
    """Micro-checks that pin the engine gotchas BEA's design depends on (S5 §3.16)."""
    t0 = time.perf_counter()
    results = {}

    def check(name, expected, fn):
        try:
            observed = fn()
        except Exception as e:  # noqa: BLE001 - reported as an observation
            observed = {"error": f"{type(e).__name__}: {e}"}
        results[name] = {"ok": observed == expected, "observed": observed, "expected": expected}

    base = 0x10000

    def fresh(code=b""):
        uc = Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        uc.mem_map(base, 0x10000)
        uc.mem_write(base, code)
        uc.reg_write(REG["rsp"], base + 0xF000)
        return uc

    def fp_reset():
        uc = Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        return {"fpcw": hx(uc.reg_read(REG["fpcw"])), "mxcsr": hx(uc.reg_read(REG["mxcsr"]))}

    def vex128():
        uc = fresh(bytes.fromhex("c5f258c2"))  # vaddss xmm0, xmm1, xmm2
        uc.reg_write(XMM[0], f32_to_bits(100.0))
        uc.reg_write(XMM[1], f32_to_bits(1.0))
        uc.reg_write(XMM[2], f32_to_bits(2.0))
        uc.emu_start(base, base + 4)
        return (uc.reg_read(XMM[0]) & MASK32) != f32_to_bits(3.0)

    def vex256():
        uc = fresh(bytes.fromhex("c5f458c2"))  # vaddps ymm0, ymm1, ymm2
        try:
            uc.emu_start(base, base + 4)
        except UcError as e:
            return e.errno == U.UC_ERR_INSN_INVALID
        return False

    def bmi():
        uc = fresh(bytes.fromhex("c4e260f2c1"))  # andn eax, ebx, ecx
        uc.reg_write(REG["rbx"], 0xF0F0)
        uc.reg_write(REG["rcx"], 0xFFFF)
        uc.emu_start(base, base + 5)
        return uc.reg_read(REG["rax"]) & MASK32 == 0x0F0F

    sentinel = 0x30000

    def call_shape(code):
        """A function that returns to a sentinel on another page: the shape the call engine runs."""
        uc = fresh(code)
        uc.mem_map(sentinel, PAGE)
        uc.mem_write(sentinel, b"\xF4" * 16)

        def run(count=0, rax=0, rcx=0, stop_after=None):
            uc.reg_write(REG["rsp"], base + 0xF000 - 8)
            uc.mem_write(base + 0xF000 - 8, struct.pack("<Q", sentinel))
            uc.reg_write(REG["rax"], rax)
            uc.reg_write(REG["rcx"], rcx)
            timer = threading.Timer(stop_after, uc.emu_stop) if stop_after else None
            if timer:
                timer.start()
            try:
                uc.emu_start(base, sentinel, count=count)
            finally:
                if timer:
                    timer.cancel()
            return uc.reg_read(REG["rax"])
        return uc, run

    loop = bytes.fromhex("48ffc0" "4839c8" "72f8" "c3")  # L: inc rax; cmp rax, rcx; jb L; ret

    def tb_hook():
        uc, run = call_shape(loop)
        run(rcx=100)
        hits = [0]
        uc.hook_add(U.UC_HOOK_CODE, lambda *_a: hits.__setitem__(0, hits[0] + 1))
        run(rcx=100)
        before = hits[0]
        uc.ctl_flush_tb()
        run(rcx=100)
        return before == 0 and hits[0] > 0

    def count_budget():
        uc, run = call_shape(loop)
        run(rcx=1000)                                                    # warm, unbudgeted
        enforced_before = run(count=1000, rcx=1 << 40, stop_after=0.2) <= 1000
        uc.ctl_flush_tb()
        enforced_after = run(count=1000, rcx=1 << 40, stop_after=0.2) <= 1000
        return (not enforced_before) and enforced_after

    def cow_lifo():
        uc = fresh(b"")
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU_MEM)
        a = base + 0x8000
        uc.mem_write(a, b"\0")
        b0 = uc.context_save()
        uc.mem_write(a, b"\1")
        s1 = uc.context_save()
        uc.mem_write(a, b"\2")
        s2 = uc.context_save()
        uc.mem_write(a, b"\3")
        seen = []
        for ctx in (s2, s1, b0):  # LIFO only; the crashing order (older then newer) is never executed
            uc.context_restore(ctx)
            seen.append(bytes(uc.mem_read(a, 1))[0])
        return seen == [2, 1, 0]

    def mode_toggle():
        uc = fresh(b"")
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU_MEM)
        a = base + 0x8000
        uc.mem_write(a, b"\5")
        uc.reg_write(REG["rax"], 5)
        b0 = uc.context_save()
        uc.mem_write(a, b"\6")
        uc.reg_write(REG["rax"], 6)
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU)
        n = uc.context_save()
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU_MEM)
        uc.mem_write(a, b"\7")
        uc.reg_write(REG["rax"], 7)
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU)
        uc.context_restore(n)
        uc.ctl(U.UC_CTL_CONTEXT_MODE, U.UC_CTL_IO_WRITE, CTX_CPU_MEM)
        cpu_only = uc.reg_read(REG["rax"]) == 6 and bytes(uc.mem_read(a, 1))[0] == 7
        uc.context_restore(b0)
        return cpu_only and uc.reg_read(REG["rax"]) == 5 and bytes(uc.mem_read(a, 1))[0] == 5

    def int3_rip():
        uc = fresh(bytes.fromhex("90cc90"))
        seen = []

        def intr(u, n, _ud):
            seen.append((n, u.reg_read(REG["rip"])))
            u.emu_stop()
        uc.hook_add(U.UC_HOOK_INTR, intr)
        uc.emu_start(base, base + 3)
        return seen == [(3, base + 2)]

    def mxcsr_flags():
        uc = fresh(bytes.fromhex("f30f58c1"))  # addss xmm0, xmm1 (inexact)
        uc.reg_write(REG["mxcsr"], 0x1F80)
        uc.reg_write(XMM[0], f32_to_bits(1.0))
        uc.reg_write(XMM[1], f32_to_bits(1e-10))
        uc.emu_start(base, base + 4)
        return bool(uc.reg_read(REG["mxcsr"]) & 0x20)

    def x87_reset():
        code = bytes.fromhex("d9e8" * 8) + b"".join(bytes((0xDD, 0x5B, 8 * k)) for k in range(8))
        uc = fresh(code)
        uc.reg_write(REG["fptag"], 0xFFFF)
        uc.reg_write(REG["fpsw"], 0)
        uc.reg_write(REG["fpcw"], DEFAULT_FPCW)
        uc.reg_write(REG["rbx"], base + 0x8000)
        uc.emu_start(base, base + len(code))
        vals = struct.unpack("<8d", bytes(uc.mem_read(base + 0x8000, 64)))
        return all(v == 1.0 for v in vals)

    def gs_base():
        uc = fresh(bytes.fromhex("65488b042530000000"))  # mov rax, gs:[0x30]
        uc.mem_write(base + 0x8030, struct.pack("<Q", 0x1234))
        uc.reg_write(REG["gs_base"], base + 0x8000)
        uc.emu_start(base, base + 9)
        return uc.reg_read(REG["rax"]) == 0x1234

    check("fp_reset", {"fpcw": "0x0", "mxcsr": "0x0"}, fp_reset)
    check("vex128_misexecutes", True, vex128)
    check("vex256_rejected", True, vex256)
    check("bmi_ok", True, bmi)
    check("tb_hook_gotcha", True, tb_hook)
    check("count_budget_gotcha", True, count_budget)
    check("cow_lifo_ok", True, cow_lifo)
    check("context_mode_toggle", True, mode_toggle)
    check("int3_rip", True, int3_rip)
    check("mxcsr_flags_modeled", False, mxcsr_flags)
    check("x87_reset", True, x87_reset)
    check("insn_hooks", SELFTEST_EXPECTED_INSN_HOOKS, lambda: dict(insn_hook_support()))
    check("gs_base", True, gs_base)
    check("memory_limit", sys.platform == "win32" or sys.platform.startswith("linux"),
          lambda: bool(MEMORY_LIMIT.get("applied")))
    return {"selftest": PROTOCOL, "engines": engine_versions(), "ms": round((time.perf_counter() - t0) * 1000, 1),
            "results": results}


# ------------------------------------------------------------------------------------------------- Q. server
def _valid_id(rid):
    return isinstance(rid, int) and not isinstance(rid, bool) and rid > 0


EMU_METHODS = ("emu.call", "emu.batch", "emu.sweep")
QUEUED_METHODS = frozenset(("bridge.hello", "bridge.shutdown", "session.open", "session.info", "session.close",
                            "state.save", "state.restore", "state.list", "state.drop", "mem.read", "mem.write",
                            "mem.disassemble", "mem.regions", "mem.functions") + EMU_METHODS)


class Server:
    """Reader thread (frames, out-of-band cancel/ping, EOF) + strictly sequential dispatch on the main thread."""

    def __init__(self, cache_dir):
        self.sessions = {}
        self.next_sid = 1
        self.inbox = queue.Queue()
        self.lock = threading.Lock()
        self.cancels = {}
        self.active = None
        self.defaults = {"cache_dir": cache_dir, "memory_limit": MEMORY_LIMIT}

    # ---- reader thread
    def reader(self):
        try:
            for line in FrameReader().lines():
                if line is None:
                    self.inbox.put(("too_long", None))
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError) as e:
                    self.inbox.put(("parse_error", str(e)))
                    continue
                if isinstance(msg, dict):
                    method = msg.get("method")
                    if method == "bridge.cancel":
                        self._cancel(msg)
                        continue
                    if method == "bridge.ping":
                        self._ping(msg)
                        continue
                    if _valid_id(msg.get("id")):
                        with self.lock:
                            self.cancels[msg["id"]] = threading.Event()
                self.inbox.put(("msg", msg))
        finally:
            with self.lock:  # stdin EOF: cancel whatever is queued or running, then exit after it
                for ev in self.cancels.values():
                    ev.set()
                act = self.active
            if act is not None and act[1] is not None:
                try:
                    act[1].uc.emu_stop()
                except Exception:  # noqa: BLE001
                    pass
            self.inbox.put(None)

    def _cancel(self, msg):
        rid = msg.get("id")
        params = msg.get("params")
        target = params.get("requestId") if isinstance(params, dict) else None
        if not _valid_id(rid) or not _valid_id(target):
            write_frame({"id": rid if _valid_id(rid) else None, "error": {
                "code": "invalid_request", "message": "bridge.cancel needs {id, params: {requestId}}"}})
            return
        with self.lock:
            ev = self.cancels.get(target)
            act = self.active
            if ev is None:
                state, cancelled = "unknown", False
            else:
                ev.set()
                cancelled = True
                state = "running" if act is not None and act[0] == target else "queued"
        if state == "running" and act[1] is not None:
            try:
                act[1].uc.emu_stop()
            except Exception:  # noqa: BLE001
                pass
        write_frame({"id": rid, "result": {"cancelled": cancelled, "state": state}})

    def _ping(self, msg):
        rid = msg.get("id")
        if not _valid_id(rid):
            write_frame({"id": None, "error": {"code": "invalid_request", "message": "bridge.ping needs an id"}})
            return
        act = self.active
        write_frame({"id": rid, "result": {"pong": True, "busy": act[0] if act is not None else None,
                                           "sessions": len(self.sessions)}})

    def _cancel_probe(self):
        a = self.active
        if a is not None and a[1] is not None:
            ev = self.cancels.get(a[0])
            if ev is not None and ev.is_set():
                return a[1].uc
        return None

    # ---- main loop
    def run(self):
        WATCHDOG.probe = self._cancel_probe
        write_frame({"event": {"type": "ready", "protocol": PROTOCOL,
                               "bridge": {"version": BRIDGE_VERSION, "sha256": bridge_sha256()}, "pid": os.getpid(),
                               "engines": engine_versions(), "python": python_info(), "memoryLimit": MEMORY_LIMIT}})
        threading.Thread(target=self.reader, name="bea-emu-reader", daemon=True).start()
        while True:
            item = self.inbox.get()
            if item is None or _OUT_BROKEN.is_set():
                return 0
            kind, msg = item
            if kind != "msg":
                write_frame({"id": None, "error": {
                    "code": "parse_error" if kind == "parse_error" else "frame_too_large",
                    "message": msg or f"the frame exceeds {MAX_FRAME_BYTES} bytes"}})
                continue
            rid = msg.get("id") if isinstance(msg, dict) else None
            method = msg.get("method") if isinstance(msg, dict) else None
            params = msg.get("params", {}) if isinstance(msg, dict) else None
            if params is None:
                params = {}
            if not _valid_id(rid) or not isinstance(method, str) or not isinstance(params, dict):
                write_frame({"id": rid if _valid_id(rid) else None, "error": {
                    "code": "invalid_request",
                    "message": "a frame is {id: positive integer, method: string, params: object}"}})
                continue
            if self._handle(rid, method, params):
                return 0

    def _handle(self, rid, method, params):
        with self.lock:
            ev = self.cancels.get(rid) or threading.Event()
            self.active = (rid, None)
        ctx = RequestCtx(rid, ev, None, emit=lambda e: write_frame({"id": rid, "event": e}))
        session = None
        try:
            if isinstance(params.get("session"), str):
                session = self.sessions.get(params["session"])
            result = self.dispatch(method, params, ctx, time.monotonic())
            write_frame({"id": rid, "result": result})
            return method == "bridge.shutdown"
        except BridgeError as e:
            body = {"code": e.code, "message": str(e)}
            if e.data:
                body["data"] = e.data
            write_frame({"id": rid, "error": body})
        except MemoryError:
            write_frame({"id": rid, "error": {"code": "resource_exhausted", "message": "the emulator ran out of memory "
                                              "(the bridge memory limit or the host)", "data": {"resource": "memory"}}})
        except OSError as e:
            if str(e).startswith("exception: access violation"):
                if session is not None:
                    session.poisoned = True
                write_frame({"id": rid, "error": {"code": "engine_crashed", "message": f"the engine crashed: {e}",
                                                  "data": {"session": params.get("session")}}})
            else:
                self._internal(rid, e)
        except Exception as e:  # noqa: BLE001 - the bridge never exits because of a request
            if UcError is not None and isinstance(e, UcError) and e.errno == U.UC_ERR_NOMEM:
                write_frame({"id": rid, "error": {"code": "resource_exhausted", "message": "unicorn: UC_ERR_NOMEM",
                                                  "data": {"resource": "memory"}}})
            else:
                self._internal(rid, e)
        finally:
            with self.lock:
                self.cancels.pop(rid, None)
                self.active = None
        return False

    @staticmethod
    def _internal(rid, e):
        tb = traceback.format_exc(limit=12)
        write_frame({"id": rid, "error": {"code": "internal_error", "message": f"{type(e).__name__}: {e}",
                                          "data": {"traceback": tb[-4000:]}}})

    def session(self, params, allow_poisoned=False):
        sid = params.get("session")
        s = self.sessions.get(sid) if isinstance(sid, str) else None
        if s is None:
            raise BridgeError("unknown_session", f"no session {sid!r}", {"session": sid})
        if s.poisoned and not allow_poisoned:
            raise BridgeError("session_poisoned", f"session {sid} crashed the engine earlier; close it and open a new "
                              "one", {"session": sid})
        return s

    def hello(self, params):
        if params.get("protocol") != PROTOCOL:
            raise BridgeError("protocol_mismatch", f"this bridge speaks {PROTOCOL}",
                              {"expected": PROTOCOL, "got": params.get("protocol")})
        return {"protocol": PROTOCOL, "bridge": {"version": BRIDGE_VERSION, "sha256": bridge_sha256()},
                "engines": engine_versions(), "python": python_info(), "memoryLimit": MEMORY_LIMIT,
                "capabilities": {"arch": ["x86_64"], "formats": ["pe64", "bea.dump/1"], "abi": ["win64"],
                                 "snapshots": ["cow", "manual"],
                                 "trace": ["imports", "blocks", "coverage", "memory", "instructions"],
                                 "hle": sorted(BUILTIN),
                                 "insnHooks": {k: insn_hook_support()[k] for k in ("cpuid", "syscall", "rdtsc")},
                                 "sweepKnown": sorted(KNOWN_UNARY) + sorted(KNOWN_BINARY)},
                "limits": {"maxFrameBytes": MAX_FRAME_BYTES, "maxMemRead": MAX_MEM_READ,
                           "maxVectorsPerBatch": MAX_VECTORS_PER_BATCH, "maxSweepTargets": MAX_SWEEP_TARGETS,
                           "maxSweepVectors": MAX_SWEEP_VECTORS, "maxNamedSnapshots": MAX_NAMED_SNAPSHOTS,
                           "maxTraceEvents": MAX_TRACE_EVENTS, "maxPatches": MAX_PATCHES,
                           "maxOverrides": MAX_OVERRIDES, "maxOutHex": MAX_OUT_HEX}}

    def dispatch(self, method, params, ctx, dequeued):
        if method not in QUEUED_METHODS:
            raise BridgeError("unknown_method", f"unknown method {method!r}", {"method": method})
        if ctx.cancelled() and method not in EMU_METHODS:
            raise BridgeError("cancelled", "the request was cancelled before it started", {"reason": "cancelled"})
        if method == "bridge.hello":
            return self.hello(params)
        if method == "bridge.shutdown":
            return {"shutdown": True}
        if method == "session.open":
            ms = params.get("deadlineMs")
            if ms is not None:
                p_int(params, "deadlineMs", "params", 0, 600_000)
                if ms > 0:
                    ctx.deadline_at = dequeued + ms / 1000.0
            sid = f"s{self.next_sid}"
            self.next_sid += 1
            s = Session(sid, params, ctx, self.defaults)
            self.sessions[sid] = s
            return s.open_result
        if method == "session.close":
            sid = params.get("session")
            return {"closed": self.sessions.pop(sid, None) is not None if isinstance(sid, str) else False}
        if method == "session.info":
            return self.session(params, allow_poisoned=True).info()
        s = self.session(params)
        if method == "state.save":
            name = check_snapshot_name(params.get("name"), "params.name")
            return {"name": name, "bytes": s.snaps.save_named(name)}
        if method == "state.restore":
            name = params.get("name")
            if name == "baseline":
                s.snaps.restore_baseline()
            else:
                check_snapshot_name(name, "params.name")
                s.snaps.restore_named(name)
            return {"restored": name}
        if method == "state.list":
            return {"snapshots": s.snaps.listing(), "totalBytes": s.snaps.total, "limitBytes": s.snaps.limit}
        if method == "state.drop":
            return {"dropped": s.snaps.drop(check_snapshot_name(params.get("name"), "params.name"))}
        if method == "mem.read":
            return s.mem_read(params)
        if method == "mem.write":
            return s.mem_write(params)
        if method == "mem.disassemble":
            return s.mem_disassemble(params)
        if method == "mem.regions":
            return s.mem_regions()
        if method == "mem.functions":
            return s.mem_functions(params)
        if method in EMU_METHODS:
            with self.lock:
                self.active = (ctx.rid, s)
            if method != "emu.call":
                o = params.get("options")
                ms = o.get("deadlineMs") if isinstance(o, dict) else None
                if ms is not None:
                    p_int(o, "deadlineMs", "params.options", 0, 600_000)
                    if ms > 0:
                        ctx.deadline_at = dequeued + ms / 1000.0
            if method == "emu.call":
                return s.call(params, ctx)
            if method == "emu.batch":
                return s.batch(params, ctx)
            return s.sweep(params, ctx)
        raise BridgeError("unknown_method", f"unknown method {method!r}", {"method": method})


# ------------------------------------------------------------------------------------------------- main
class UsageError(Exception):
    pass


def parse_args(argv):
    opts = {"mem_limit": None, "cache_dir": None, "mode": "server"}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--mem-limit", "--cache-dir"):
            if i + 1 >= len(argv):
                raise UsageError(f"{a} needs a value")
            v = argv[i + 1]
            if a == "--mem-limit":
                try:
                    opts["mem_limit"] = int(v, 10)
                except ValueError:
                    raise UsageError("--mem-limit takes a byte count") from None
                if opts["mem_limit"] < 0:
                    raise UsageError("--mem-limit takes a byte count")
            else:
                opts["cache_dir"] = v
            i += 2
        elif a in ("--probe", "--selftest"):
            if opts["mode"] != "server":
                raise UsageError("--probe and --selftest are exclusive")
            opts["mode"] = a[2:]
            i += 1
        else:
            raise UsageError(f"unknown argument {a!r}")
    if opts["mem_limit"] is None:
        try:
            mb = int(os.environ.get("BEA_EMU_MEMORY_LIMIT_MB", "4096"), 10)
        except ValueError:
            mb = 4096
        opts["mem_limit"] = max(mb, 0) << 20
    return opts


def _print_line(obj):
    _write_all(1, json.dumps(obj, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n")


def main(argv):
    global MEMORY_LIMIT, WATCHDOG
    sys.stdout = sys.stderr  # the binary fd 1 is the frame channel; stray prints go to stderr (S5 §3.1 step 1)
    try:
        opts = parse_args(argv)
    except UsageError as e:
        sys.stderr.write(f"bea_emu_bridge: {e}\n")
        return 2
    MEMORY_LIMIT = apply_memory_limit(opts["mem_limit"])
    missing, errors = load_engines()
    if opts["mode"] == "probe":
        _print_line(probe_line(missing, errors))
        return 3 if missing else 0
    if missing:
        _print_line({"event": {"type": "fatal", "code": "engine_unavailable",
                               "message": f"cannot import {', '.join(missing)} (run `bea setup --emulator`)",
                               "data": {"missing": missing, "errors": errors}}})
        return 3
    bridge_sha256()
    if opts["mode"] == "selftest":
        _print_line(selftest())
        return 0
    if opts["cache_dir"]:
        prune_isa_cache(opts["cache_dir"])
    WATCHDOG = Watchdog()
    return Server(opts["cache_dir"]).run()


if __name__ == "__main__":
    try:
        code = main(sys.argv[1:])
    except BaseException:  # noqa: BLE001 - a bug: the host sees exit 70 plus stderr
        traceback.print_exc(file=sys.stderr)
        code = 70
    try:
        sys.stderr.flush()
    finally:
        os._exit(code)  # skip finalization: daemon threads and native engine handles go with the process
