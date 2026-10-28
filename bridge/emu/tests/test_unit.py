# bridge/emu/tests/test_unit.py: pure helpers of the bridge (no bridge process): framing, RFC 8785 for the dump
# manifest, the synthetic-window choice, HLE math bit rules, ulp distances, the mapped-image parser, ISA site
# classification, snapshot names and argv parsing.
from __future__ import annotations

import importlib.util
import json
import os
import random
import shutil
import struct
import threading
import unittest

import support

_SPEC = importlib.util.spec_from_file_location("bea_emu_bridge_under_test", support.BRIDGE)
B = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(B)


def bits32(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def bits64(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


class FramingTest(unittest.TestCase):
    def frames(self, chunks, limit=64):
        r, w = os.pipe()

        def writer():
            for c in chunks:
                os.write(w, c)
            os.close(w)

        t = threading.Thread(target=writer)
        t.start()
        try:
            return list(B.FrameReader(fd=r, limit=limit).lines())
        finally:
            t.join()
            os.close(r)

    def test_split_frames_crlf_and_trailing_line(self):
        out = self.frames([b'{"a"', b':1}\n{"b":2}\r', b"\n\n", b'{"c":3}'])
        self.assertEqual([x.strip() for x in out if x.strip()], [b'{"a":1}', b'{"b":2}', b'{"c":3}'])

    def test_oversize_frame_is_reported_once_and_reading_continues(self):
        out = self.frames([b"x" * 50, b"y" * 50, b"z" * 50, b"\n", b'{"ok":1}\n'], limit=64)
        self.assertEqual(out, [None, b'{"ok":1}'])

    def test_oversize_complete_line(self):
        out = self.frames([b"q" * 70 + b"\n" + b'{"ok":2}\n'], limit=64)
        self.assertEqual(out, [None, b'{"ok":2}'])


class JcsTest(unittest.TestCase):
    def test_matches_sorted_compact_json_for_ascii_keys(self):
        rnd = random.Random(7)
        for _ in range(200):
            doc = {f"k{rnd.randrange(50)}": rnd.choice([1, -3, "s\u00e9\n\"x", None, True, [1, {"z": 2, "a": "b"}]])
                   for _ in range(rnd.randrange(1, 8))}
            self.assertEqual(B.jcs(doc), json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False))

    def test_utf16_key_order(self):
        # By code point U+E000 sorts before U+1F600; by UTF-16 code units (0xE000 vs 0xD83D) it sorts after.
        doc = {"\U0001F600": 1, "\ue000": 2, "a": 3}
        self.assertEqual(B.jcs(doc), '{"a":3,"\U0001F600":1,"\ue000":2}')


class WindowTest(unittest.TestCase):
    def test_first_free_window_from_the_top(self):
        self.assertEqual(B.choose_window([]), B.WINDOW_TOP)
        self.assertEqual(B.choose_window([(B.WINDOW_TOP + 0x1000, B.WINDOW_TOP + 0x2000)]),
                         B.WINDOW_TOP - B.WINDOW_STEP)

    def test_no_window(self):
        with self.assertRaises(B.BridgeError) as cm:
            B.choose_window([(0, 1 << 47)])
        self.assertEqual(cm.exception.code, "layout_conflict")


class MathTest(unittest.TestCase):
    F, D = B.FMT32, B.FMT64

    def ev(self, name, fmt, *args):
        return B.eval_math(name, fmt, list(args))

    def test_sqrt_ieee_rules(self):
        self.assertEqual(self.ev("sqrt", self.F, bits32(-1.0)), 0xFFC00000)          # default NaN
        self.assertEqual(self.ev("sqrt", self.F, 0x7F800001), 0x7FC00001)            # sNaN quieted, payload kept
        self.assertEqual(self.ev("sqrt", self.F, 0x80000000), 0x80000000)            # -0
        self.assertEqual(self.ev("sqrt", self.F, bits32(2.0)), bits32(2.0 ** 0.5))   # rounded once
        self.assertEqual(self.ev("sqrt", self.D, bits64(-4.0)), 0xFFF8000000000000)

    def test_rounding_functions_keep_the_sign_of_zero(self):
        self.assertEqual(self.ev("floor", self.F, bits32(-0.5)), bits32(-1.0))
        self.assertEqual(self.ev("ceil", self.F, bits32(-0.5)), 0x80000000)
        self.assertEqual(self.ev("trunc", self.D, bits64(-0.75)), 0x8000000000000000)
        self.assertEqual(self.ev("floor", self.D, bits64(float("inf"))), bits64(float("inf")))

    def test_bitwise_functions(self):
        self.assertEqual(self.ev("fabs", self.F, 0xFFC12345), 0x7FC12345)
        self.assertEqual(self.ev("copysign", self.F, 0x7FC12345, bits32(-1.0)), 0xFFC12345)

    def test_fmod_and_pow_special_cases(self):
        self.assertEqual(self.ev("fmod", self.F, bits32(5.5), bits32(2.0)), bits32(1.5))
        self.assertEqual(self.ev("fmod", self.D, bits64(float("inf")), bits64(1.0)), 0xFFF8000000000000)
        self.assertEqual(self.ev("fmod", self.D, bits64(3.0), bits64(float("inf"))), bits64(3.0))
        self.assertEqual(self.ev("pow", self.D, bits64(1.0), 0x7FF8000000000001), bits64(1.0))
        self.assertEqual(self.ev("pow", self.D, bits64(0.0), bits64(-1.0)), bits64(float("inf")))
        self.assertEqual(self.ev("log", self.D, bits64(0.0)), bits64(float("-inf")))
        self.assertEqual(self.ev("exp", self.D, bits64(1e6)), bits64(float("inf")))
        self.assertEqual(self.ev("exp", self.F, bits32(100.0)), bits32(float("inf")))  # f32 overflow saturates

    def test_ulp_distance(self):
        self.assertEqual(B.ulp_distance(0x00000000, 0x80000000, self.F), 0)
        self.assertEqual(B.ulp_distance(bits32(1.0), bits32(1.0) + 1, self.F), 1)
        self.assertEqual(B.ulp_distance(0x00000001, 0x80000001, self.F), 2)
        self.assertEqual(B.ulp_distance(bits64(-1.0), bits64(1.0), self.D), 2 * bits64(1.0))


class SiteTest(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(B.classify_site("vaddss", "xmm0, xmm1, xmm2", 0xC5), "vex")
        self.assertEqual(B.classify_site("vaddps", "zmm0, zmm1, zmm2", 0x62), "evex")
        self.assertIsNone(B.classify_site("andn", "eax, ebx, ecx", 0xC4))   # BMI allow-list
        self.assertEqual(B.classify_site("fsin", "", None), "x87_inexact")
        self.assertEqual(B.classify_site("stmxcsr", "dword ptr [rsp]", None), "fp_status")
        self.assertEqual(B.classify_site("int", "0x2e", None), "syscall")
        self.assertEqual(B.classify_site("rdtscp", "", None), "tsc")
        self.assertEqual(B.classify_site("rdrand", "eax", None), "rng")
        self.assertIsNone(B.classify_site("addss", "xmm0, xmm1", None))
        # review fix EMU-1: legacy-SSE forms Unicorn computes differently from hardware are tagged; their VEX forms
        # stop at the guard; SSE arithmetic whose only difference is NaN payloads (haddps, mulss, ...) is not tagged
        for mn in ("rcpss", "rcpps", "rsqrtss", "rsqrtps", "dpps", "dppd"):
            self.assertEqual(B.classify_site(mn, "xmm0, xmm1", None), "sse_inexact", mn)
        self.assertEqual(B.classify_site("vrsqrtss", "xmm0, xmm1, xmm2", 0xC5), "vex")
        self.assertEqual(B.classify_site("vdpps", "xmm0, xmm1, xmm2, 0xf1", 0xC4), "vex")
        for mn in ("haddps", "hsubps", "addsubps", "sqrtss", "roundss", "minps"):
            self.assertIsNone(B.classify_site(mn, "xmm0, xmm1", None), mn)
        self.assertIn("sse_inexact", B.SITE_KINDS)
        self.assertEqual(B.TAG_DEVIATION_OF["sse_inexact"], "sse_approx_inexact")
        self.assertIn("sse_approx_inexact", B.DEVIATION_NOTES)
        self.assertIn("sse_tagging_incomplete", B.LOADER_ONLY)

    def test_vex_lead_skips_segment_prefixes(self):
        self.assertEqual(B._vex_lead(bytes.fromhex("2ec5f858c1"), 0, 5), 0xC5)
        self.assertIsNone(B._vex_lead(bytes.fromhex("f30f58c1"), 0, 4))


class HeapAllocatorTest(unittest.TestCase):
    """The HLE heap (review fix EMU-6) on a bare Session (no engine): freed chunks are coalesced and reused best fit
    (indexed by address and by size), realloc resizes in place where it can, every block keeps its 16-byte gap, and
    a guest allocation that does not fit is counted (hle_heap_exhausted) while a harness allocation is not."""

    HEAP = 0x1000_0000

    def session(self, size=1 << 20):
        s = B.Session.__new__(B.Session)
        s.heap, s.heap_size = self.HEAP, size
        s.hle = {"heap_top": self.HEAP, "heap_live": {}, "heap_free": [], "heap_sizes": []}
        s.hle_touched = False
        s.rc = B.RunCtx()
        return s

    def check(self, s):
        h = s.hle
        for p, (n, cs) in h["heap_live"].items():
            self.assertGreaterEqual(p - cs, 16, hex(p))
        pieces = sorted([(cs, p + n) for p, (n, cs) in h["heap_live"].items()] + list(h["heap_free"]))
        pos = self.HEAP
        for a, b in pieces:  # live chunks and free ranges tile [heap, heap_top) exactly
            self.assertEqual(a, pos)
            self.assertLess(a, b)
            pos = b
        self.assertEqual(pos, h["heap_top"])
        self.assertLessEqual(h["heap_top"], self.HEAP + s.heap_size)
        free = h["heap_free"]
        self.assertTrue(all(b1 < a2 for (_a1, b1), (a2, _b2) in zip(free, free[1:])))  # sorted and coalesced
        self.assertEqual(h["heap_sizes"], sorted((fe - fs, fs) for fs, fe in free))   # the size index agrees

    def test_a_malloc_free_loop_never_exhausts_the_heap(self):
        s = self.session(64 << 10)
        first = None
        for _ in range(10_000):  # 40 MiB in total through a 64 KiB heap
            p = s.heap_alloc(4096)
            self.assertNotEqual(p, 0)
            first = first or p
            self.assertEqual(p, first)
            s.heap_free(p)
        self.check(s)
        self.assertEqual((s.rc.heap_oom, s.rc.events), (0, []))
        self.assertEqual(s.hle["heap_top"], first + 4096)

    def test_best_fit_coalescing_and_alignment(self):
        s = self.session()
        a, b, c = (s.heap_alloc(100) for _ in range(3))
        self.assertEqual(a, self.HEAP + 16)
        s.heap_free(a)
        s.heap_free(b)
        self.assertEqual(s.hle["heap_free"], [(self.HEAP, b + 100)])   # a and b merged into one range
        d = s.heap_alloc(150)
        self.assertEqual(d, a)
        e = s.heap_alloc(16, 4096)
        self.assertEqual(e % 4096, 0)
        self.check(s)
        for p in (c, d, e):
            s.heap_free(p)
        self.assertEqual(s.hle["heap_free"], [(self.HEAP, s.hle["heap_top"])])
        self.check(s)

    def test_realloc_in_place(self):
        s = self.session()
        a = s.heap_alloc(64)
        self.assertTrue(s.heap_resize(a, 4096))          # the block ends at the high-water mark
        self.assertEqual(s.hle["heap_top"], a + 4096)
        b = s.heap_alloc(64)
        self.assertFalse(s.heap_resize(a, 8192))         # b follows: the block has to move
        s.heap_free(b)
        self.assertTrue(s.heap_resize(a, 8192))          # b's chunk and the space above the mark
        self.assertTrue(s.heap_resize(a, 32))            # shrink: the tail goes back to the free list
        self.assertEqual(s.hle["heap_live"][a][0], 32)
        self.check(s)
        self.assertFalse(s.heap_resize(a, 2 << 20))      # larger than the heap
        self.check(s)

    def test_exhaustion_is_counted_for_guest_allocations_only(self):
        s = self.session(4096)
        self.assertEqual(s.heap_alloc(8192), 0)
        self.assertEqual(s.rc.heap_oom, 1)
        self.assertEqual(s.rc.events, [{"type": "heap", "kind": "out_of_memory", "size": 8192}])
        self.assertEqual(s.heap_alloc(8192, harness=True), 0)
        self.assertEqual(s.rc.heap_oom, 1)
        s.rc.begin_vector()
        self.assertEqual(s.rc.vector_kinds(), set())
        s.rc.heap_oom = 2
        self.assertEqual(s.rc.vector_kinds(), {"hle_heap_exhausted"})

    def test_random_operations_keep_the_tiling(self):
        rnd = random.Random(5)
        s = self.session(256 << 10)
        live = []
        for _ in range(3000):
            k = rnd.random()
            if k < 0.45 or not live:
                p = s.heap_alloc(rnd.choice((1, 8, 24, 100, 1000, 5000)), rnd.choice((16, 16, 64, 4096)))
                if p:
                    live.append(p)
            elif k < 0.8:
                s.heap_free(live.pop(rnd.randrange(len(live))))
            else:
                p = rnd.choice(live)
                s.heap_resize(p, rnd.choice((1, 50, 300, 3000)))
            self.check(s)
        self.assertEqual(sorted(live), sorted(s.hle["heap_live"]))
        for p in live:
            s.heap_free(p)
        self.assertEqual(s.hle["heap_free"], [(self.HEAP, s.hle["heap_top"])])
        self.assertEqual({e["kind"] for e in s.rc.events} - {"out_of_memory"}, set())   # never an invalid free
        self.assertEqual(min(s.rc.heap_oom, B.MAX_CALL_EVENTS), sum(e["kind"] == "out_of_memory" for e in s.rc.events))

    def test_snapshots_copy_the_free_list(self):
        s = self.session()
        p = s.heap_alloc(64)
        s.heap_free(p)
        h = {**s.hle, "tls_next": 1, "tls_slots": {}, "qpc": 0, "tick": 0, "filetime": 0, "tsc": 0, "dyn": {},
             "dyn_keys": {}, "hmods": {}}
        c = B.hle_copy(h)
        s.hle = h
        s.heap_alloc(64)
        self.assertEqual(h["heap_free"], [])
        self.assertEqual(c["heap_free"], [(self.HEAP, p + 64)])


class OutBudgetTest(unittest.TestCase):
    """Review fix EMU-2: out buffers are never cut; a result whose out-buffer hex would exceed MAX_OUT_HEX is refused
    up front (with the vector count that fits)."""

    class Buf:
        def __init__(self, size, out):
            self.size, self.out = size, out

    class Plan:
        def __init__(self, *buffers):
            self.buffers = list(buffers)

    def test_budget(self):
        one = self.Plan(self.Buf(16 << 20, True), self.Buf(1 << 30, False))   # in-only buffers cost nothing
        B.Session.check_out_budget(one, 1)
        with self.assertRaises(B.BridgeError) as cm:
            B.Session.check_out_budget(one, 2)
        self.assertEqual((cm.exception.code, cm.exception.data["path"], cm.exception.data["maxVectors"]),
                         ("invalid_params", "params.vectors", 1))
        two = self.Plan(self.Buf(16 << 20, True), self.Buf(16 << 20, True))   # one single call: 64 MiB of hex
        with self.assertRaises(B.BridgeError) as cm:
            B.Session.check_out_budget(two, 1)
        self.assertEqual(cm.exception.data["maxVectors"], 0)
        self.assertEqual(B.out_hex_bytes([self.Buf(4096, True)], 10), 10 * (2 * 4096 + 3))


class MappedImageTest(unittest.TestCase):
    def test_garbage_is_reported_not_raised(self):
        data = bytes(random.Random(1).randrange(256) for _ in range(4096))
        img = B.MappedImage(lambda a, n: data[a - 0x10000:a - 0x10000 + n], 0x10000, len(data), "junk")
        self.assertFalse(img.headers_ok)
        self.assertEqual(img.malformed, ["headers"])

    def test_fixture_dll_mapped_layout(self):
        fx = support.emu_fixture()
        if isinstance(fx, str):
            self.skipTest(fx)
        if support.engines_available():
            self.skipTest(support.engines_available())
        import pefile

        pe = pefile.PE(fx["path"], fast_load=True)
        size = pe.OPTIONAL_HEADER.SizeOfImage
        image = bytearray(size)
        image[:pe.OPTIONAL_HEADER.SizeOfHeaders] = pe.__data__[:pe.OPTIONAL_HEADER.SizeOfHeaders]
        for s in pe.sections:
            raw = s.get_data()[:s.Misc_VirtualSize or s.SizeOfRawData]
            image[s.VirtualAddress:s.VirtualAddress + len(raw)] = raw
        base = pe.OPTIONAL_HEADER.ImageBase
        img = B.MappedImage(lambda a, n: bytes(image[a - base:a - base + n]), base, size, "fx")
        self.assertTrue(img.headers_ok)
        self.assertEqual(img.malformed, [])
        exports = fx["pe"]["exportRvas"]
        for name in ("bea_spring_damper", "bea_avx_dot", "g_gain"):
            want = exports[name] if isinstance(exports[name], int) else int(exports[name], 16)
            self.assertEqual(img.exports[name], want)
        names = {(i["dll"].lower(), i["name"]) for i in img.imports}
        self.assertIn(("msvcrt.dll", "malloc"), names)
        self.assertIn(("kernel32.dll", "CreateEventA"), names)
        self.assertGreater(len(img.pdata), 20)
        self.assertIsNotNone(img.tls)
        self.assertTrue(img.function_at(img.exports["bea_avx_dot"]))


class SourceTest(unittest.TestCase):
    def test_python_3_10_syntax_and_stdlib_only_imports(self):
        import ast

        with open(support.BRIDGE, encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src, feature_version=(3, 10))
        top = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                top.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                top.add(node.module.split(".")[0])
        allowed = {"__future__", "base64", "bisect", "ctypes", "hashlib", "importlib", "json", "math", "os",
                   "platform", "queue", "struct", "sys", "threading", "time", "traceback", "resource"}
        self.assertEqual(top - allowed, set())   # unicorn/capstone/pefile load through load_engines() only

    def test_isa_cache_pruning_keeps_the_newest(self):
        import tempfile
        import time

        d = tempfile.mkdtemp(prefix="bea-isa-prune-")
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "isa"))
        now = time.time()
        for i in range(5):
            p = os.path.join(d, "isa", f"{i}.json")
            with open(p, "wb") as fh:
                fh.write(b"x" * 1000)
            os.utime(p, (now - 100 + i, now - 100 + i))
        B.prune_isa_cache(d, limit=2500)
        self.assertEqual(sorted(os.listdir(os.path.join(d, "isa"))), ["3.json", "4.json"])
        B.prune_isa_cache(os.path.join(d, "missing"))  # never raises


class NamesAndArgsTest(unittest.TestCase):
    def test_snapshot_names(self):
        for ok in ("a", "_x.1-2", "N" * 64):
            self.assertEqual(B.check_snapshot_name(ok, "p"), ok)
        for bad in ("", "1a", "baseline", "current", "a b", "N" * 65, None, "é"):
            with self.assertRaises(B.BridgeError):
                B.check_snapshot_name(bad, "p")

    def test_argv(self):
        o = B.parse_args(["--mem-limit", "123", "--cache-dir", "C:/x", "--probe"])
        self.assertEqual((o["mem_limit"], o["cache_dir"], o["mode"]), (123, "C:/x", "probe"))
        for bad in (["--bogus"], ["--mem-limit"], ["--mem-limit", "x"], ["--probe", "--selftest"]):
            with self.assertRaises(B.UsageError):
                B.parse_args(bad)


if __name__ == "__main__":
    unittest.main()
