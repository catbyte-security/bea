# bridge/emu/tests/test_emulation.py: the S5 §14 `test:emu` lane on bea_emu_fixture.dll with the REAL bridge:
# every status with its attribution and stop record, the per-call CPU/FP environment, buffers (pointer fields, array
# cells, codecs, hidden struct return, by-value copies, heap placement), variadic and stack arguments, imports.
from __future__ import annotations

import json
import math
import os
import shutil
import statistics
import struct
import sys
import time

import support
from emu_case import EmuCase, buf, doubles, f32, f32b, floats


class StatusTest(EmuCase):
    def test_returned_bits_and_provenance(self):
        r = self.call("bea_spring_damper", ["f32"] * 4, {"kind": "f32"},
                      [support.f32(1.0), support.f32(2.0), support.f32(3.0), support.f32(4.0)])
        self.assertEqual((r["status"], r["attribution"], r["stop"]), ("returned", None, None))
        self.assertEqual(int(r["raw"]["xmm0"], 16) & 0xFFFFFFFF, f32b(-11.0))
        self.assertEqual((r["raw"]["mxcsr"], r["raw"]["fpcw"], r["raw"]["fpsw"]), ("0x1f80", "0x27f", "0x0"))
        self.assertTrue(r["deterministic"])
        p = r["provenance"]
        self.assertEqual(p["target"], {"va": self.hva("bea_spring_damper"), "module": "bea_emu_fixture.dll",
                                       "rva": hex(self.va("bea_spring_damper") - self.base),
                                       "export": "bea_spring_damper"})
        self.assertEqual(p["primary"]["sha256"], self.fx["artifactSha256"])
        self.assertEqual((p["source"], p["bundleId"], p["abi"], p["isaGuard"]), ("image", None, "win64", "stop"))
        self.assertEqual(r["trace"]["imports"], [])

    def test_int3_stop_on_the_first_vex_instruction(self):
        import capstone
        import pefile

        r = self.call("bea_avx_dot", ["int", "int", "int"], {"kind": "f32"}, ["0x0", "0x0", "0x4"])
        self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]), ("unsupported_instruction", "harness",
                                                                               "vex"))
        stop = r["stop"]
        # the first VEX instruction of the function, decoded from the FILE bytes (never a silent mis-execution)
        pe = pefile.PE(self.fx["path"], fast_load=True)
        begin, end = int(stop["pcFunction"]["beginRva"], 16), int(stop["pcFunction"]["endRva"], 16)
        code = pe.get_data(begin, end - begin)
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        first = next(i for i in cs.disasm(code, begin) if i.bytes[0] in (0xC4, 0xC5, 0x62))
        self.assertEqual(stop["isa"]["rva"], hex(first.address))
        self.assertEqual(stop["pc"], hex(self.base + first.address))
        self.assertEqual(stop["isa"]["mnemonic"], first.mnemonic)
        self.assertEqual(stop["instruction"][0]["bytes"], bytes(first.bytes).hex())  # original bytes, not the INT3
        self.assertIn("registers", stop)
        self.assertEqual(self.opened["isa"]["functionsWithVex"], [stop["pcFunction"]["beginRva"]])

    def test_x87_transcendental_is_tagged(self):
        x, y = 0.5, 0.25
        r = self.call("bea_trig", ["f32", "f32"], {"kind": "f32"}, [support.f32(x), support.f32(y)])
        self.assertEqual(r["status"], "returned")
        kinds = {d["kind"]: d for d in r["deviations"]}
        self.assertIn("x87_transcendental_inexact", kinds)
        self.assertTrue(kinds["x87_transcendental_inexact"]["detail"]["sites"])
        want = math.sin(x) + math.atan2(y, x) + math.pow(abs(x), 0.5)
        self.assertAlmostEqual(support.bits_f32(r["raw"]["xmm0"]), want, places=5)

    def test_unhandled_import_names_the_import_and_caller(self):
        r = self.call("bea_tls_counter", ["int"], {"kind": "int", "width": 4}, ["0x1"])
        self.assertEqual((r["status"], r["attribution"]), ("unhandled_import", "harness"))
        ic = r["stop"]["importCall"]
        self.assertEqual(ic["import"], "kernel32.dll!CreateEventA")
        self.assertEqual(r["stop"]["pcRegion"]["import"], "kernel32.dll!CreateEventA")
        self.assertTrue(0 < int(ic["callerRva"], 16) < self.opened["primary"]["size"])
        self.assertEqual(len(ic["args"]), 4)
        self.assertEqual(r["stop"]["stackScan"][0]["rva"], ic["callerRva"])

    def test_budget_exhausted_is_a_status(self):
        r = self.call("bea_spin", ["int"], {"kind": "int", "width": 4}, ["0x1"], maxInstructions=10_000)
        self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]),
                         ("budget_exhausted", "harness", "max_instructions"))
        self.assertTrue(r["deterministic"])

    def test_watchdog_timeout(self):
        t0 = time.perf_counter()
        r = self.call("bea_spin", ["int"], {"kind": "int", "width": 4}, ["0x1"], maxInstructions=0, timeoutMs=100)
        self.assertLess(time.perf_counter() - t0, 2.0)
        self.assertEqual((r["status"], r["stop"]["cause"], r["deterministic"]), ("timeout", "watchdog", False))

    def test_cancel_latency(self):
        plan = support.scalar_plan(self.hva("bea_spin"), ["int"], {"kind": "int", "width": 4})
        lat = []
        for _ in range(5):
            rid = self.b.send("emu.call", {"session": self.sid, "plan": plan, "vectors": support.vectors([["0x1"]]),
                                           "state": support.state(), "options": support.options(maxInstructions=0)})
            time.sleep(0.05)
            t0 = time.perf_counter()
            self.b.send("bridge.cancel", {"requestId": rid})
            final, _ = self.b.wait(rid, timeout=5)
            lat.append(time.perf_counter() - t0)
            self.assertEqual(final["result"]["status"], "cancelled")
            self.assertEqual(final["result"]["stop"]["cause"], "host_cancel")
        self.assertLess(statistics.median(lat), 0.050, lat)

    def test_divide_error(self):
        r = self.call("bea_div", ["int", "int"], {"kind": "int", "width": 4}, ["0x7", "0x0"])
        stop = r["stop"]
        self.assertEqual((r["status"], r["attribution"], stop["cause"]), ("cpu_exception", "target", "div_error"))
        self.assertEqual(stop["exception"], {"vector": 0, "name": "#DE divide error"})
        self.assertTrue(stop["instruction"][0]["text"].startswith("idiv"))
        self.assertEqual(stop["pcFunction"]["module"], "bea_emu_fixture.dll")
        self.assertIn("rip", stop["registers"])
        self.assertEqual(stop["stackScan"][0]["note"], "harness return sentinel")
        ok = self.call("bea_div", ["int", "int"], {"kind": "int", "width": 4}, ["0x7", "0x2"])
        self.assertEqual(int(ok["raw"]["rax"], 16) & 0xFFFFFFFF, 3)

    def test_inline_syscall(self):
        r = self.call("bea_syscall_stub", [], {"kind": "void"}, [])
        self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]), ("syscall", "harness", "syscall"))
        self.assertEqual(r["stop"]["syscall"]["number"], "0x50")
        self.assertEqual(int(r["stop"]["pc"], 16) - self.base, self.fx["expectations"]["syscallInsn"]["rva"])

    def test_terminated_on_abort(self):
        import pefile

        pe = pefile.PE(self.fx["path"])
        slot = next(i.address - pe.OPTIONAL_HEADER.ImageBase for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports
                    if i.name == b"abort")
        stub = struct.unpack("<Q", self.read(self.base + slot, 8))[0]
        plan = support.scalar_plan(hex(stub), [], {"kind": "void"})
        r = self.emu("emu.call", plan, support.vectors([[]]) | {"count": 1})
        self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]), ("terminated", "target", "abort"))
        self.assertEqual(r["stop"]["terminate"], {"via": "msvcrt.dll!abort", "code": None})

    def test_null_pointer_fault(self):
        r = self.call("bea_vec_sum", ["int"], {"kind": "f32"}, ["0x0"])
        stop = r["stop"]
        self.assertEqual((r["status"], r["attribution"], stop["cause"]), ("fault", "target", "read_unmapped"))
        self.assertEqual(stop["fault"]["address"], "0x0")
        self.assertEqual(stop["fault"]["addressRegion"]["region"], "null page")
        self.assertEqual(stop["fault"]["addressRegion"]["capture"], "unmapped-live")
        self.assertIn("registers", stop)

    def test_synthetic_window_fault_is_harness(self):
        fake = hex(int(self.opened["layout"]["syntheticBase"], 16) + 0x0F00_0000)  # a fake HMODULE address
        r = self.call("bea_vec_sum", ["int"], {"kind": "f32"}, [fake])
        self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]), ("fault", "harness",
                                                                               "synthetic_unmapped"))

    def test_cpuid_dispatch_takes_the_emulated_cpu_path(self):
        r = self.call("bea_dispatch", ["f32"], {"kind": "f32"}, [support.f32(2.0)])
        self.assertEqual(int(r["raw"]["xmm0"], 16) & 0xFFFFFFFF, f32b(6.0))  # x*3.0f: the emulated CPU has no AVX2
        dev = next(d for d in r["deviations"] if d["kind"] == "cpuid_executed")
        leaves = {d["leaf"] for d in dev["detail"]["leaves"]}
        self.assertIn("0x1", leaves)

    def test_rdtsc_is_nondeterministic(self):
        r = self.call("bea_rdtsc", [], {"kind": "int", "width": 8}, [])
        self.assertEqual(r["status"], "returned")
        self.assertIn("nondeterministic_tsc", [d["kind"] for d in r["deviations"]])
        self.assertFalse(r["deterministic"])

    def test_mxcsr_per_call_and_status_flags_cleared(self):
        r = self.call("bea_mxcsr_read", [], {"kind": "int", "width": 4}, [], mxcsr=0x9FC0)
        self.assertEqual(int(r["raw"]["rax"], 16) & 0xFFFFFFFF, 0x9FC0)
        self.assertIn("fp_status_flags_unmodeled", [d["kind"] for d in r["deviations"]])
        r = self.call("bea_mxcsr_read", [], {"kind": "int", "width": 4}, [], mxcsr=0x1FBF)
        self.assertEqual(int(r["raw"]["rax"], 16) & 0xFFFFFFFF, 0x1F80)  # status flags cleared before the call

    def test_ftz_daz(self):
        den = 1e-39
        args = [support.f32(den), support.f32(0.0), support.f32(1.0), support.f32(0.0)]
        plain = self.call("bea_spring_damper", ["f32"] * 4, {"kind": "f32"}, args)
        bits = int(plain["raw"]["xmm0"], 16) & 0xFFFFFFFF
        self.assertEqual(bits & 0x7F800000, 0)
        self.assertNotEqual(bits & 0x007FFFFF, 0)          # a negative denormal survives under 0x1F80
        daz = self.call("bea_spring_damper", ["f32"] * 4, {"kind": "f32"}, args, mxcsr=0x9FC0)
        self.assertEqual(int(daz["raw"]["xmm0"], 16) & 0xFFFFFFFF, 0x80000000)

    def test_teb_self_is_the_synthetic_teb(self):
        r = self.call("bea_read_teb_self", [], {"kind": "int", "width": 8}, [])
        self.assertEqual(r["raw"]["rax"], self.opened["layout"]["syntheticBase"])

    def test_stack_probe_function(self):
        n = 3
        data = [(i * 7 + n) & 0xFF for i in range(16384)]
        want = sum(data[i] for i in range(0, 16384, 97))
        r = self.call("bea_big_frame", ["int"], {"kind": "int", "width": 4}, [hex(n)])
        self.assertEqual(int(r["raw"]["rax"], 16) & 0xFFFFFFFF, want)

    def test_stack_arguments(self):
        r = self.call("bea_stack_args", ["f32", "f32", "f32", "f32", "f32", "f64", "int"], {"kind": "f64"},
                      [support.f32(1), support.f32(2), support.f32(3), support.f32(4), support.f32(0.5),
                       support.f64(2.0), "0x7"])
        self.assertEqual(support.bits_f64(r["raw"]["xmm0"]), 17.0)  # bits_f64 keeps the low 64 bits of XMM0

    def test_trace_options(self):
        r = self.call("bea_spring_damper", ["f32"] * 4, {"kind": "f32"}, [support.f32(1.0)] * 4,
                      trace={"blocks": True, "coverage": True, "countInstructions": True, "memory": "all",
                             "instructions": True, "disassemble": True, "maxEvents": 3})
        t = r["trace"]
        self.assertGreater(r["metrics"]["instructions"], 0)
        self.assertEqual(len(t["instructions"]), 3)
        self.assertTrue(t["truncated"]["instructions"])
        self.assertIn("text", t["instructions"][0])
        self.assertEqual(t["coverage"]["granularity"], "tb")
        self.assertGreaterEqual(t["coverage"]["distinct"], 1)
        self.assertTrue(t["blocks"])
        self.assertIsInstance(t["memory"], list)


class BufferTest(EmuCase):
    def test_pointer_fields_into_another_buffer(self):
        plan = {"target": self.hva("bea_vec_sum"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "vec", "offset": 0}}],
                "buffers": [buf("data", floats(1, 2, 3, 4)),
                            buf("vec", size=24, ptr_fields=[{"offset": 0, "buffer": "data", "plus": 0},
                                                            {"offset": 8, "buffer": "data", "plus": 16},
                                                            {"offset": 16, "buffer": "data", "plus": 16}])]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {}})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 10.0)
        self.assertEqual(set(r["buffers"]), {"data", "vec"})

    def test_array_cells_and_out_buffer(self):
        body = floats(0, 0, 0, 1, 2, 3, 2.0) + struct.pack("<I", 5)
        plan = {"target": self.hva("bea_body_step"), "returns": {"kind": "void"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "body", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "buffer", "buffer": "force", "offset": 0}},
                          {"reg": "xmm2", "source": {"kind": "column", "column": "dt"}}],
                "buffers": [buf("body", body, out=True),
                            buf("force", size=12, columns=[{"column": "f", "offset": 0, "width": 4, "count": 3}])]}
        vecs = {"offset": 0, "count": 1, "columns": {"dt": [support.f32(0.5)],
                                                     "f": [[support.f32(2), support.f32(4), support.f32(6)]]}}
        r = self.emu("emu.call", plan, vecs)
        out = bytes.fromhex(r["out"]["body"])
        vals = struct.unpack("<7fI", out)
        self.assertEqual(vals, (0.75, 1.5, 2.25, 1.5, 3.0, 4.5, 2.0, 6))

    def test_codec_field_from_a_column(self):
        key = 0x9E3779B1
        plan = {"target": self.hva("bea_codec_get"), "returns": {"kind": "int", "width": 4},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "obj", "offset": 0}}],
                "buffers": [buf("obj", size=12, columns=[{"column": "gear", "offset": 4, "width": 4, "count": 1}])]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {"gear": [hex((3 * key) & 0xFFFFFFFF)]}})
        self.assertEqual(int(r["raw"]["rax"], 16) & 0xFFFFFFFF, 3)

    def test_hidden_struct_return(self):
        plan = {"target": self.hva("bea_struct_ret"), "returns": {"kind": "struct", "size": 24, "via": "hidden",
                                                                  "buffer": "ret"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "ret", "offset": 0}},
                          {"reg": "xmm1", "source": {"kind": "column", "column": "x"}}],
                "buffers": [buf("ret", size=24, out=True)]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {"x": [support.f32(1.5)]}})
        self.assertEqual(struct.unpack("<6f", bytes.fromhex(r["out"]["ret"])), (1.5, 3.0, 4.5, 6.0, 7.5, 9.0))
        self.assertEqual(r["raw"]["rax"], r["buffers"]["ret"])  # the callee returns the hidden pointer

    def test_byval_copy_and_byval_register(self):
        plan = {"target": self.hva("bea_byval12"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "s", "offset": 0}}],
                "buffers": [buf("s", floats(1.5, 2.5) + struct.pack("<i", 3))]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {}})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 12.0)
        # a 4-byte by-value buffer travels in the register as an integer (bea_div(byval 7, 2))
        plan = {"target": self.hva("bea_div"), "returns": {"kind": "int", "width": 4},
                "slots": [{"reg": "rcx", "source": {"kind": "byval", "buffer": "a"}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": "0x2"}}],
                "buffers": [buf("a", struct.pack("<i", 7))]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {}})
        self.assertEqual(int(r["raw"]["rax"], 16) & 0xFFFFFFFF, 3)

    def test_variadic_doubles_duplicated_into_gprs(self):
        plan = {"target": self.hva("bea_variadic_sum"), "returns": {"kind": "f64"}, "buffers": [],
                "slots": [{"reg": "rcx", "source": {"kind": "const", "bits": "0x3"}},
                          {"reg": "xmm1", "dupGpr": "rdx", "source": {"kind": "column", "column": "a"}},
                          {"reg": "xmm2", "dupGpr": "r8", "source": {"kind": "column", "column": "b"}},
                          {"reg": "xmm3", "dupGpr": "r9", "source": {"kind": "column", "column": "c"}}]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {
            "a": [support.f64(1.5)], "b": [support.f64(2.5)], "c": [support.f64(3.0)]}})
        self.assertEqual(support.bits_f64(hex(int(r["raw"]["xmm0"], 16) & (2 ** 64 - 1))), 7.0)

    def test_imports_through_hle_models(self):
        plan = {"target": self.hva("bea_norm_copy"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "src", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": "0x2"}},
                          {"reg": "r8", "source": {"kind": "buffer", "buffer": "out", "offset": 0}}],
                "buffers": [buf("src", floats(3, 4)), buf("out", size=8, out=True)]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {}})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 5.0)
        self.assertEqual(struct.unpack("<2f", bytes.fromhex(r["out"]["out"])), (f32(0.6), f32(0.8)))
        names = [e["import"] for e in r["trace"]["imports"]]
        self.assertEqual(names, ["msvcrt.dll!malloc", "msvcrt.dll!memcpy", "msvcrt.dll!free"])
        self.assertTrue(all(e["model"] == "builtin" for e in r["trace"]["imports"]))
        self.assertEqual(r["events"], [])

    def test_heap_placement(self):
        plan = {"target": self.hva("bea_vec_sum"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "vec", "offset": 0}}],
                "buffers": [buf("data", floats(5, 6), placement="heap"),
                            buf("vec", size=24, placement="heap",
                                ptr_fields=[{"offset": 0, "buffer": "data", "plus": 0},
                                            {"offset": 8, "buffer": "data", "plus": 8},
                                            {"offset": 16, "buffer": "data", "plus": 8}])]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {}})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 11.0)
        heap = int(self.opened["layout"]["syntheticBase"], 16) + 0x1000_0000
        self.assertTrue(all(heap <= int(a, 16) < heap + (64 << 20) for a in r["buffers"].values()))

    def test_plan_validation_errors(self):
        bad_buffer = {"target": self.hva("bea_vec_sum"), "returns": {"kind": "f32"}, "buffers": [],
                      "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "nope", "offset": 0}}]}
        e = self.emu("emu.call", bad_buffer, {"offset": 0, "count": 1, "columns": {}}, expect_error=True)
        self.assertEqual((e["code"], e["data"]["buffer"]), ("invalid_params", "nope"))
        bad_col = support.scalar_plan(self.hva("bea_div"), ["int", "int"], {"kind": "int", "width": 4})
        e = self.emu("emu.call", bad_col, {"offset": 0, "count": 1, "columns": {"arg0": ["0x1"]}}, expect_error=True)
        self.assertEqual((e["code"], e["data"]["column"]), ("invalid_params", "arg1"))
        e = self.emu("emu.call", bad_col, support.vectors([["0x1", "0x2"], ["0x1", "0x2"]]), expect_error=True)
        self.assertEqual(e["code"], "invalid_params")  # emu.call takes exactly one vector
        e = self.emu("emu.call", bad_col, support.vectors([["0x1", "zz"]]), expect_error=True)
        self.assertEqual(e["code"], "invalid_params")


class HleTest(EmuCase):
    """The builtin import models, called directly through the stubs the image's IAT points at."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import pefile

        pe = pefile.PE(cls.fx["path"])
        cls.slots = {i.name.decode(): i.address - pe.OPTIONAL_HEADER.ImageBase
                     for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.name}

    def stub(self, name):
        return struct.unpack("<Q", self.read(self.base + self.slots[name], 8))[0]

    def hle(self, name, slots, ret, buffers=(), frm="baseline", columns=None):
        plan = {"target": hex(self.stub(name)), "returns": ret, "slots": slots, "buffers": list(buffers)}
        return self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": columns or {}}, support.state(frm))

    @staticmethod
    def c(bits, reg):
        return {"reg": reg, "source": {"kind": "const", "bits": bits}}

    @staticmethod
    def p(buffer, reg):
        return {"reg": reg, "source": {"kind": "buffer", "buffer": buffer, "offset": 0}}

    def test_strings_and_errno(self):
        r = self.hle("strlen", [self.p("s", "rcx")], {"kind": "int", "width": 8}, [buf("s", b"hello\0")])
        self.assertEqual(r["raw"]["rax"], "0x5")
        self.assertEqual(r["trace"]["imports"][0]["import"], "msvcrt.dll!strlen")
        r = self.hle("_errno", [], {"kind": "int", "width": 8})
        self.assertEqual(int(r["raw"]["rax"], 16), int(self.opened["layout"]["syntheticBase"], 16) + 0x2800)

    def test_heap_models_and_events(self):
        r = self.hle("calloc", [self.c("0x4", "rcx"), self.c("0x4", "rdx")], {"kind": "int", "width": 8})
        p = int(r["raw"]["rax"], 16)
        heap = int(self.opened["layout"]["syntheticBase"], 16) + 0x1000_0000
        self.assertTrue(heap < p < heap + (64 << 20))
        self.assertEqual(self.read(p, 16), bytes(16))
        r = self.hle("free", [self.c("0x1234", "rcx")], {"kind": "void"})
        self.assertEqual(r["events"], [{"type": "heap", "kind": "invalid_or_double_free", "ptr": "0x1234"}])
        r = self.hle("malloc", [self.c(hex(1 << 40), "rcx")], {"kind": "int", "width": 8})
        self.assertEqual((r["raw"]["rax"], r["events"][0]["kind"]), ("0x0", "out_of_memory"))

    def test_guest_memory_errors_are_target_faults(self):
        # memset into the read-only PE headers: the model refuses like the hardware would
        r = self.hle("memset", [self.c(hex(self.base), "rcx"), self.c("0x0", "rdx"), self.c("0x4", "r8")],
                     {"kind": "int", "width": 8})
        self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]), ("fault", "target", "import_arg"))
        self.assertEqual((r["stop"]["fault"]["access"], r["stop"]["fault"]["kind"]), ("write", "protected"))
        r = self.hle("strlen", [self.c("0x10", "rcx")], {"kind": "int", "width": 8})
        self.assertEqual((r["stop"]["cause"], r["stop"]["fault"]["kind"]), ("import_arg", "unmapped"))

    def test_stateful_models_chain_through_current(self):
        r = self.hle("TlsAlloc", [], {"kind": "int", "width": 4})
        idx = int(r["raw"]["rax"], 16)
        self.hle("TlsSetValue", [self.c(hex(idx), "rcx"), self.c("0x55", "rdx")], {"kind": "int", "width": 4},
                 frm="current")
        r = self.hle("TlsGetValue", [self.c(hex(idx), "rcx")], {"kind": "int", "width": 8}, frm="current")
        self.assertEqual(r["raw"]["rax"], "0x55")
        r = self.hle("TlsGetValue", [self.c(hex(idx), "rcx")], {"kind": "int", "width": 8})  # baseline: reset
        self.assertEqual(r["raw"]["rax"], "0x0")
        self.hle("SetLastError", [self.c("0x5", "rcx")], {"kind": "void"})
        r = self.hle("GetLastError", [], {"kind": "int", "width": 4}, frm="current")
        self.assertEqual(r["raw"]["rax"], "0x5")
        a = self.hle("QueryPerformanceCounter", [self.p("t", "rcx")], {"kind": "int", "width": 4},
                     [buf("t", size=8, out=True)])
        b = self.hle("QueryPerformanceCounter", [self.p("t", "rcx")], {"kind": "int", "width": 4},
                     [buf("t", size=8, out=True)], frm="current")
        ta, tb = (struct.unpack("<q", bytes.fromhex(x["out"]["t"]))[0] for x in (a, b))
        self.assertEqual((ta, tb - ta), (1_001_000, 1000))   # deterministic virtual counter
        r = self.hle("GetCurrentThreadId", [], {"kind": "int", "width": 4})
        self.assertEqual(r["raw"]["rax"], "0x1004")

    def test_dynamic_imports(self):
        r = self.hle("GetModuleHandleA", [self.c("0x0", "rcx")], {"kind": "int", "width": 8})
        self.assertEqual(r["raw"]["rax"], self.opened["primary"]["mappedBase"])
        r = self.hle("LoadLibraryA", [self.p("n", "rcx")], {"kind": "int", "width": 8}, [buf("n", b"ucrtbase.dll\0")])
        h = int(r["raw"]["rax"], 16)
        self.assertEqual(h, int(self.opened["layout"]["syntheticBase"], 16) + 0x0F00_0000)
        r = self.hle("GetProcAddress", [self.c(hex(h), "rcx"), self.p("n", "rdx")], {"kind": "int", "width": 8},
                     [buf("n", b"sqrtf\0")], frm="current")
        dyn = int(r["raw"]["rax"], 16)
        self.assertEqual(next(d for d in r["deviations"] if d["kind"] == "dynamic_import_resolved")["detail"],
                         {"names": ["ucrtbase.dll!sqrtf"]})
        plan = support.scalar_plan(hex(dyn), ["f32"], {"kind": "f32"})
        r = self.emu("emu.call", plan, support.vectors([[support.f32(9.0)]]), support.state("current"))
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 3.0)
        self.assertEqual(r["trace"]["imports"][0]["import"], "ucrtbase.dll!sqrtf")
        r = self.emu("emu.call", plan, support.vectors([[support.f32(9.0)]]))   # baseline: the slot is unbound
        self.assertEqual((r["status"], r["stop"]["cause"]), ("unhandled_import", "no_model"))


class OpenOptionsTest(EmuCase):
    def open(self, **params):
        return self.b.request("session.open", {"source": {"kind": "image", "path": self.fx["path"]}, **params})

    def test_relocation(self):
        o = self.open(source={"kind": "image", "path": self.fx["path"], "base": "0x200000000"})["result"]
        self.assertEqual((o["primary"]["mappedBase"], o["primary"]["relocated"]), ("0x200000000", True))
        rva = self.va("bea_global_gain") - self.base
        plan = support.scalar_plan(hex(0x200000000 + rva), ["f32"], {"kind": "f32"})
        r = self.b.result("emu.call", {"session": o["session"], "plan": plan,
                                       "vectors": support.vectors([[support.f32(2.0)]]), "state": support.state(),
                                       "options": support.options()})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 3.0)
        e = self.open(source={"kind": "image", "path": self.fx["path"], "base": "0x200001000"})
        self.assertEqual(e["error"]["code"], "relocation_unavailable")

    def test_unsupported_and_unreadable_images(self):
        pe32 = support.REPO + "/fixtures/golden/pe32-minimal.bin"
        e = self.open(source={"kind": "image", "path": pe32})["error"]
        self.assertEqual((e["code"], e["data"]["machine"], e["data"]["reason"]),
                         ("unsupported_image", "x86", "wow64_unsupported_v0.1"))
        e = self.open(source={"kind": "image", "path": support.BRIDGE})["error"]
        self.assertEqual(e["code"], "unsupported_image")
        e = self.open(source={"kind": "image", "path": support.BRIDGE + ".missing"})["error"]
        self.assertEqual(e["code"], "image_unreadable")

    def test_patches_and_symbolic_addresses(self):
        p = self.open(patches=[{"address": "bea_emu_fixture.dll!g_gain", "hex": struct.pack("<f", 2.5).hex()}])
        o = p["result"]
        self.assertIn("memory_patched", [d["kind"] for d in o["loaderDeviations"]])
        plan = support.scalar_plan(self.hva("bea_global_gain"), ["f32"], {"kind": "f32"})
        r = self.b.result("emu.call", {"session": o["session"], "plan": plan,
                                       "vectors": support.vectors([[support.f32(2.0)]]), "state": support.state(),
                                       "options": support.options()})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 5.0)
        e = self.open(patches=[{"address": "bea_emu_fixture.dll!no_such", "hex": "00"}])["error"]
        self.assertEqual(e["code"], "unknown_symbol")
        self.assertIn("bea_spin", e["data"]["exports_sample"])
        e = self.open(patches=[{"address": "other.dll+0x10", "hex": "00"}])["error"]
        self.assertEqual(e["code"], "unknown_symbol")

    def test_import_policies(self):
        o = self.open(imports={"unhandled": "return_zero"})["result"]
        r = self.b.result("emu.call", {"session": o["session"], "plan": support.scalar_plan(
            self.hva("bea_tls_counter"), ["int"], {"kind": "int", "width": 4}), "vectors": support.vectors([["0x1"]]),
            "state": support.state(), "options": support.options()})
        dev = next(d for d in r["deviations"] if d["kind"] == "unhandled_import_returned_zero")
        self.assertIn("kernel32.dll!CreateEventA", dev["detail"]["imports"])
        o = self.open(imports={"overrides": [{"key": "CreateEventA", "action": "stop"},
                                             {"key": "MSVCRT.dll!memcpy", "action": "model", "model": "memmove"}]})
        o = o["result"]
        self.assertEqual(o["imports"]["models"]["override"], 2)
        r = self.b.result("emu.call", {"session": o["session"], "plan": support.scalar_plan(
            self.hva("bea_tls_counter"), ["int"], {"kind": "int", "width": 4}), "vectors": support.vectors([["0x1"]]),
            "state": support.state(), "options": support.options()})
        self.assertEqual((r["status"], r["stop"]["cause"]), ("unhandled_import", "override_stop"))
        e = self.open(imports={"overrides": [{"key": "x", "action": "model", "model": "nope"}]})["error"]
        self.assertEqual(e["code"], "invalid_params")
        o = self.open(imports={"overrides": [{"key": "kernel32.dll!CreateEventA", "action": "return",
                                              "returns": {"kind": "int", "bits": "0x1234"}}]})["result"]
        r = self.b.result("emu.call", {"session": o["session"], "plan": support.scalar_plan(
            self.hva("bea_tls_counter"), ["int"], {"kind": "int", "width": 4}), "vectors": support.vectors([["0x1"]]),
            "state": support.state(), "options": support.options()})
        ev = [e for e in r["trace"]["imports"] if e["import"] == "kernel32.dll!CreateEventA"]
        self.assertEqual((ev[0]["model"], ev[0]["ret"]), ("override", "0x1234"))

    def test_isa_guard_off_and_rwx(self):
        o = self.open(isaGuard="off", protections="rwx")["result"]
        self.assertEqual(o["isa"]["guard"], "off")
        self.assertEqual(o["isa"]["guarded"]["int3"], 0)
        self.assertIn("isa_guard_off", [d["kind"] for d in o["loaderDeviations"]])
        r = self.b.result("emu.call", {"session": o["session"], "plan": support.scalar_plan(
            self.hva("bea_global_gain"), ["f32"], {"kind": "f32"}), "vectors": support.vectors([[support.f32(2.0)]]),
            "state": support.state(), "options": support.options()})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 3.0)

    def test_vex_in_a_gap_gets_a_hook_not_an_int3(self):
        # CT-M3: only sites reached by a skipdata-free decode from a .pdata start are INT3-patched; a VEX
        # instruction patched into the padding between two .pdata functions must be stopped by a per-address hook.
        import pefile

        pe = pefile.PE(self.fx["path"], fast_load=True)
        rva, size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress, pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size
        entries = sorted({(b, e) for b, e, _u in struct.iter_unpack("<III", pe.get_data(rva, size // 12 * 12)) if b})
        gap = next(e for (_b, e), (nb, _ne) in zip(entries, entries[1:]) if nb - e >= 8)
        code = bytes.fromhex("c5f258c2c3")   # vaddss xmm0, xmm1, xmm2 ; ret
        o = self.open(patches=[{"address": f"bea_emu_fixture.dll+{hex(gap)}", "hex": code.hex()}])["result"]
        self.assertEqual(o["isa"]["guarded"]["hooks"], 1)
        self.assertEqual(o["isa"]["guarded"]["int3"], self.opened["isa"]["guarded"]["int3"])
        plan = support.scalar_plan(hex(self.base + gap), [], {"kind": "f32"})
        r = self.b.result("emu.call", {"session": o["session"], "plan": plan, "vectors": support.vectors([[]]) |
                                       {"count": 1}, "state": support.state(), "options": support.options()})
        self.assertEqual((r["status"], r["stop"]["cause"], r["stop"]["pc"]),
                         ("unsupported_instruction", "vex", hex(self.base + gap)))
        m = self.b.result("mem.read", {"session": o["session"], "address": hex(self.base + gap), "size": 5})
        self.assertEqual((m["data"], m["overlayRestored"]), (code.hex(), 0))   # the bytes were never rewritten

    def test_approximate_sse_is_tagged(self):
        # review fix EMU-1: rsqrtss/rcpss/... and dpps/dppd run, but Unicorn's results are not the hardware's (exact
        # reciprocals; dpps sums the products sequentially), so every vector that executes one carries a deviation
        import pefile

        pe = pefile.PE(self.fx["path"], fast_load=True)
        rva, size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress, pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size
        entries = sorted({(b, e) for b, e, _u in struct.iter_unpack("<III", pe.get_data(rva, size // 12 * 12)) if b})
        gaps = [e for (_b, e), (nb, _ne) in zip(entries, entries[1:]) if nb - e >= 8][:2]
        rsqrt, dpps = bytes.fromhex("f30f52c0c3"), bytes.fromhex("660f3a40c1f1c3")  # rsqrtss xmm0,xmm0 / dpps 0xf1
        o = self.open(patches=[{"address": f"bea_emu_fixture.dll+{hex(g)}", "hex": h.hex()}
                               for g, h in zip(gaps, (rsqrt, dpps))])["result"]
        self.assertGreaterEqual(o["isa"]["sites"]["sse_inexact"], 2)

        def run(method, at, slots, count=1, **opts):
            plan = {"target": hex(self.base + at), "returns": {"kind": "f32"}, "slots": slots, "buffers": []}
            return self.b.result(method, {"session": o["session"], "plan": plan,
                                          "vectors": {"offset": 0, "count": count, "columns": {}},
                                          "state": support.state(), "options": support.options(**opts)})

        two = {"reg": "xmm0", "source": {"kind": "const", "bits": support.f32(2.0)}}
        r = run("emu.call", gaps[0], [two])
        self.assertEqual(r["status"], "returned")
        d = next(d for d in r["deviations"] if d["kind"] == "sse_approx_inexact")
        self.assertEqual(d["detail"]["sites"], [{"rva": hex(gaps[0]), "mnemonic": "rsqrtss"}])
        # the engine's value is the exact 1/sqrt(2); hardware returns its table approximation (0x3f350000 on the
        # test host): the reason for the tag
        self.assertEqual(int(r["raw"]["xmm0"], 16) & 0xFFFFFFFF, 0x3F3504F3)
        a = {"reg": "xmm0", "source": {"kind": "const", "bits": "0x3f800000ccbebc203f8000004cbebc20"}}  # 1e8,1,-1e8,1
        b = {"reg": "xmm1", "source": {"kind": "const", "bits": "0x3f8000003f8000003f8000003f800000"}}  # 1,1,1,1
        r = run("emu.call", gaps[1], [a, b])
        self.assertIn("sse_approx_inexact", [d["kind"] for d in r["deviations"]])
        self.assertEqual(int(r["raw"]["xmm0"], 16) & 0xFFFFFFFF, f32b(1.0))   # hardware: (1e8+1)+(-1e8+1) = 0.0
        r = run("emu.batch", gaps[0], [two], count=3, isolation="snapshot", stopOnFault=False, deadlineMs=0,
                trace={"imports": "counts"})
        self.assertEqual(r["aggregates"]["deviations"]["sse_approx_inexact"], {"vectors": 3})
        # the shared session's fixture has no such site: no deviation there
        r = self.call("bea_spring_damper", ["f32"] * 4, {"kind": "f32"}, [support.f32(1.0)] * 4)
        self.assertNotIn("sse_approx_inexact", [d["kind"] for d in r["deviations"]])

    def test_remaining_statuses_from_patched_code(self):
        import pefile

        pe = pefile.PE(self.fx["path"], fast_load=True)
        rva, size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress, pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size
        entries = sorted({(b, e) for b, e, _u in struct.iter_unpack("<III", pe.get_data(rva, size // 12 * 12)) if b})
        gaps = [e for (_b, e), (nb, _ne) in zip(entries, entries[1:]) if nb - e >= 8][:4]
        self.assertEqual(len(gaps), 4)
        cases = [("0f0400", "invalid_instruction", "target", "undecodable"),
                 ("0f0b", "cpu_exception", "target", "ud"),
                 ("f4", "cpu_exception", "target", "gp"),
                 ("c5f458c2c3", "unsupported_instruction", "harness", "engine_rejected")]  # vaddps ymm, guard off
        o = self.open(isaGuard="off", patches=[{"address": f"bea_emu_fixture.dll+{hex(g)}", "hex": h}
                                               for g, (h, *_r) in zip(gaps, cases)])["result"]
        for g, (_h, status, attribution, cause) in zip(gaps, cases):
            plan = support.scalar_plan(hex(self.base + g), [], {"kind": "void"})
            r = self.b.result("emu.call", {"session": o["session"], "plan": plan,
                                           "vectors": support.vectors([[]]) | {"count": 1},
                                           "state": support.state(), "options": support.options()})
            self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]), (status, attribution, cause))
            self.assertEqual(r["stop"]["pc"], hex(self.base + g))
            self.assertIn("registers", r["stop"])
        self.assertEqual(r["stop"]["isa"]["encoding"], "engine")
        # RaiseException: SEH dispatch is not modeled, a harness stop that names the import
        import_slot = next(i.address - pe.OPTIONAL_HEADER.ImageBase
                           for e in pefile.PE(self.fx["path"]).DIRECTORY_ENTRY_IMPORT for i in e.imports
                           if i.name == b"RaiseException")
        stub = struct.unpack("<Q", bytes.fromhex(self.b.result("mem.read", {
            "session": o["session"], "address": hex(self.base + import_slot), "size": 8})["data"]))[0]
        r = self.b.result("emu.call", {"session": o["session"],
                                       "plan": support.scalar_plan(hex(stub), ["int"], {"kind": "void"}),
                                       "vectors": support.vectors([["0xe06d7363"]]), "state": support.state(),
                                       "options": support.options()})
        self.assertEqual((r["status"], r["attribution"], r["stop"]["cause"]), ("raised", "harness", "raise_exception"))
        self.assertEqual(r["stop"]["importCall"]["args"][0], "0xe06d7363")

    def test_the_interpreter_itself_opens(self):
        # `bea doctor --probe` (emulation:start) opens the chosen python.exe: a PE64 every host has
        if not sys.executable.lower().endswith(".exe"):
            self.skipTest("not a PE interpreter")
        o = self.open(source={"kind": "image", "path": sys.executable})["result"]
        self.assertEqual(o["primary"]["path"].lower(), os.path.abspath(sys.executable).lower())
        self.assertGreater(o["imports"]["total"], 0)
        self.assertEqual(self.b.result("session.close", {"session": o["session"]}), {"closed": True})

    def test_open_deadline(self):
        e = self.open(deadlineMs=1)["error"]   # loading alone takes longer than 1 ms
        self.assertEqual((e["code"], e["data"]["reason"]), ("cancelled", "deadline"))
        self.assertIn("result", self.open(deadlineMs=60_000))

    def test_combination_and_parameter_errors(self):
        e = self.open(faultPolicy="map_zero")["error"]
        self.assertEqual(e["code"], "unsupported_combination")
        e = self.open(memory={"heapBytes": 1 << 40})["error"]
        self.assertEqual(e["code"], "invalid_params")


class CacheAndLimitTest(EmuCase):
    def test_isa_cache_hit_on_second_open(self):
        import tempfile

        cache = tempfile.mkdtemp(prefix="bea-isa-cache-")
        b = support.BridgeProc(cache_dir=cache)
        try:
            first = b.result("session.open", {"source": {"kind": "image", "path": self.fx["path"]}})
            second = b.result("session.open", {"source": {"kind": "image", "path": self.fx["path"]}})
            off = b.result("session.open", {"source": {"kind": "image", "path": self.fx["path"]}, "cacheDir": None})
        finally:
            b.close()
            self.addCleanup(shutil.rmtree, cache, True)
        self.assertEqual((first["isa"]["cache"], second["isa"]["cache"], off["isa"]["cache"]), ("miss", "hit", "off"))
        self.assertEqual(first["isa"]["sites"], second["isa"]["sites"])
        self.assertEqual(first["isa"]["guarded"], second["isa"]["guarded"])
        import os

        files = os.listdir(os.path.join(cache, "isa"))
        self.assertEqual(len(files), 1)
        with open(os.path.join(cache, "isa", files[0]), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["schema"], "bea.isa-scan/1")

    def test_memory_limit_gives_resource_exhausted(self):
        b = support.BridgeProc(mem_limit=128 << 20)
        try:
            f = b.request("session.open", {"source": {"kind": "image", "path": self.fx["path"]},
                                           "memory": {"heapBytes": 256 << 20}})
            self.assertEqual(f["error"]["code"], "resource_exhausted")
            self.assertTrue(b.request("bridge.ping")["result"]["pong"])  # the bridge survives
            ok = b.request("session.open", {"source": {"kind": "image", "path": self.fx["path"]},
                                            "memory": {"heapBytes": 1 << 20, "scratchBytes": 1 << 20}})
            self.assertIn("result", ok)
        finally:
            b.close()
