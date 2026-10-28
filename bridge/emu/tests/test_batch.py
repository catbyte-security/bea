# bridge/emu/tests/test_batch.py: emu.batch (fast / medium / full paths, isolation, faults, deadline, cancel,
# progress, coverage), emu.sweep with the known-function matcher, named state and the mem.* methods (S5 §3.11,
# §3.14, §3.15, §4.3).
from __future__ import annotations

import random
import struct
import time

import support
from emu_case import EmuCase, buf, f32, f32b, floats


def spring_ref(x, v, k, c):
    a = f32(-k * x)        # each product of two f32 is exact in double: rounding once gives the f32 product
    b = f32(c * v)
    f = f32(a - b)
    return max(-1000.0, min(1000.0, f))


class BatchTest(EmuCase):
    def spring(self, n, rnd, **opts):
        rows = [[support.f32(f32(rnd.uniform(-100, 100))) for _ in range(4)] for _ in range(n)]
        plan = support.scalar_plan(self.hva("bea_spring_damper"), ["f32"] * 4, {"kind": "f32"})
        return rows, self.emu("emu.batch", plan, support.vectors(rows),
                              opts=support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0,
                                                   trace={"imports": "counts"}, **opts))

    def test_fast_path_is_bit_exact(self):
        rnd = random.Random(42)
        rows, r = self.spring(1000, rnd)
        s = r["summary"]
        self.assertEqual((s["path"], s["completed"], s["returned"], s["byStatus"]), ("fast", 1000, 1000, {"ok": 1000}))
        self.assertEqual((s["deadlineReached"], s["cancelled"], s["deterministic"]), (False, False, True))
        for row, x0 in zip(rows, r["columns"]["xmm0lo"]):
            want = spring_ref(*(support.bits_f32(h) for h in row))
            self.assertEqual(int(x0, 16) & 0xFFFFFFFF, f32b(want), row)
        self.assertEqual(r["faults"], [])
        self.assertEqual(r["provenance"]["target"]["export"], "bea_spring_damper")

    def test_fast_path_throughput(self):
        rnd = random.Random(1)
        _rows, r = self.spring(20_000, rnd)
        rate = r["summary"]["callsPerSecond"]
        print(f"\n    fast path (snapshot isolation): {rate:,.0f} vectors/s", end=" ")
        self.assertGreaterEqual(rate, 15_000)  # S5 §16 E3 acceptance

    def test_isolation_snapshot_vs_chain(self):
        plan = support.scalar_plan(self.hva("bea_global_gain"), ["f32"], {"kind": "f32"})
        vecs = support.vectors([[support.f32(1.0)]] * 10)
        o = support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0)
        self.emu("emu.batch", plan, vecs, opts=o)
        self.assertEqual(self.u32_at("g_calls"), 1)   # each vector from the baseline: one increment survives
        o["isolation"] = "chain"
        r = self.emu("emu.batch", plan, vecs, opts=o)
        self.assertEqual(self.u32_at("g_calls"), 10)
        self.assertEqual(r["summary"]["isolation"], "chain")
        r = self.emu("emu.batch", plan, vecs, st=support.state("current"), opts=o)
        self.assertEqual(self.u32_at("g_calls"), 20)

    def test_medium_path_with_buffer_columns(self):
        plan = {"target": self.hva("bea_codec_get"), "returns": {"kind": "int", "width": 4},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "obj", "offset": 0}}],
                "buffers": [buf("obj", size=12, out=True,
                                columns=[{"column": "gear", "offset": 4, "width": 4, "count": 1}])]}
        gears = list(range(50))
        vecs = {"offset": 100, "count": 50, "columns": {"gear": [hex((g * 0x9E3779B1) & 0xFFFFFFFF) for g in gears]}}
        r = self.emu("emu.batch", plan, vecs, opts=support.options(isolation="snapshot", stopOnFault=False,
                                                                    deadlineMs=0, trace={"imports": "counts"}))
        self.assertEqual((r["summary"]["path"], r["summary"]["offset"]), ("medium", 100))
        self.assertEqual([int(x, 16) & 0xFFFFFFFF for x in r["columns"]["rax"]], gears)
        self.assertEqual(len(r["columns"]["out"]["obj"]), 50)
        out7 = bytes.fromhex(r["columns"]["out"]["obj"][7])
        self.assertEqual(struct.unpack_from("<I", out7, 4)[0], int(vecs["columns"]["gear"][7], 16))  # the cell

    def test_full_path_coverage_counts_and_imports(self):
        plan = {"target": self.hva("bea_norm_copy"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "src", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": "0x2"}},
                          {"reg": "r8", "source": {"kind": "buffer", "buffer": "out", "offset": 0}}],
                "buffers": [buf("src", size=8, columns=[{"column": "v", "offset": 0, "width": 4, "count": 2}]),
                            buf("out", size=8, out=True)]}
        vecs = {"offset": 0, "count": 3, "columns": {"v": [[support.f32(3), support.f32(4)],
                                                           [support.f32(6), support.f32(8)],
                                                           [support.f32(0), support.f32(0)]]}}
        r = self.emu("emu.batch", plan, vecs, opts=support.options(
            isolation="snapshot", stopOnFault=False, deadlineMs=0,
            trace={"imports": "counts", "coverage": True, "countInstructions": True}))
        s = r["summary"]
        self.assertEqual((s["path"], s["returned"]), ("full", 3))
        self.assertEqual([support.bits_f32(x) for x in r["columns"]["xmm0lo"]], [5.0, 10.0, 0.0])
        self.assertEqual(len(r["columns"]["instructions"]), 3)
        self.assertTrue(all(n > 0 for n in r["columns"]["instructions"]))
        cov = r["aggregates"]["coverage"]
        self.assertGreater(cov["distinct"], 3)
        self.assertEqual(cov["blocks"], sorted(cov["blocks"], key=lambda b: int(b[0], 16)))
        self.assertEqual(r["aggregates"]["imports"]["msvcrt.dll!malloc"], {"calls": 3, "model": "builtin"})

    def test_faults_columns_and_stop_on_fault(self):
        plan = support.scalar_plan(self.hva("bea_div"), ["int", "int"], {"kind": "int", "width": 4})
        rows = [["0x8", "0x2"], ["0x8", "0x0"], ["0x9", "0x3"], ["0x1", "0x0"]]
        o = support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0, trace={"imports": "counts"})
        r = self.emu("emu.batch", plan, support.vectors(rows, offset=10), opts=o)
        self.assertEqual(r["columns"]["status"], ["ok", "cpu", "ok", "cpu"])
        self.assertEqual(r["columns"]["rax"][1], "")      # no value for a non-returned vector
        self.assertEqual(r["summary"]["byAttribution"], {"target": 2, "harness": 0})
        self.assertEqual([f["index"] for f in r["faults"]], [11, 13])
        self.assertEqual(r["faults"][0]["cause"], "div_error")
        self.assertEqual(r["faults"][0]["detail"]["exception"]["vector"], 0)
        o["stopOnFault"] = True
        r = self.emu("emu.batch", plan, support.vectors(rows), opts=o)
        self.assertEqual((r["summary"]["completed"], r["columns"]["status"]), (2, ["ok", "cpu"]))
        self.assertNotIn("attr", r["columns"])   # every stop is listed in `faults`: no per-vector columns

    def test_attribution_columns_past_the_fault_list(self):
        # review fix EMU-9: `faults` stops at 1000 entries; past that the per-vector columns keep the attribution
        plan = support.scalar_plan(self.hva("bea_div"), ["int", "int"], {"kind": "int", "width": 4})
        rows = [["0x8", "0x2"]] + [["0x1", "0x0"]] * 1005
        o = support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0, trace={"imports": "counts"})
        r = self.emu("emu.batch", plan, support.vectors(rows), opts=o)
        c = r["columns"]
        self.assertEqual((r["summary"]["completed"], len(r["faults"])), (1006, 1000))
        self.assertEqual((len(c["attr"]), len(c["pcRva"])), (1006, 1006))
        self.assertEqual((c["attr"][0], c["pcRva"][0]), ("", None))
        self.assertEqual(set(c["attr"][1:]), {"t"})
        self.assertEqual(c["pcRva"][1005], r["faults"][0]["pcRva"])   # the same div instruction
        self.assertEqual(r["summary"]["byAttribution"], {"target": 1005, "harness": 0})

    def test_deadline_returns_the_completed_prefix(self):
        plan = support.scalar_plan(self.hva("bea_spin"), ["int"], {"kind": "int", "width": 4})
        o = support.options(isolation="snapshot", stopOnFault=False, deadlineMs=300, maxInstructions=3_000_000,
                            trace={"imports": "counts"})
        t0 = time.perf_counter()
        r = self.emu("emu.batch", plan, support.vectors([["0x1"]] * 1000), opts=o)
        self.assertLess(time.perf_counter() - t0, 3.0)
        s = r["summary"]
        self.assertTrue(s["deadlineReached"])
        self.assertLess(s["completed"], 1000)
        self.assertEqual(set(r["columns"]["status"]) - {"budget", "timeout"}, set())

    def test_cancel_returns_a_partial_batch_with_progress(self):
        plan = support.scalar_plan(self.hva("bea_spin"), ["int"], {"kind": "int", "width": 4})
        o = support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0, maxInstructions=1_000_000,
                            trace={"imports": "counts"})
        rid = self.b.send("emu.batch", {"session": self.sid, "plan": plan, "vectors": support.vectors([["0x1"]] * 5000),
                                        "state": support.state(), "options": o})
        time.sleep(0.8)
        self.b.send("bridge.cancel", {"requestId": rid})
        final, events = self.b.wait(rid, timeout=10)
        s = final["result"]["summary"]
        self.assertTrue(s["cancelled"])
        self.assertLess(s["completed"], 5000)
        self.assertEqual(len(final["result"]["columns"]["status"]), s["completed"])
        self.assertTrue(events)
        self.assertEqual(events[0]["phase"], "batch")
        self.assertEqual(events[0]["total"], 5000)

    def test_single_call_traces_are_rejected_in_batches(self):
        plan = support.scalar_plan(self.hva("bea_div"), ["int", "int"], {"kind": "int", "width": 4})
        e = self.emu("emu.batch", plan, support.vectors([["0x1", "0x1"]]), expect_error=True,
                     opts=support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0,
                                          trace={"imports": "counts", "blocks": True}))
        self.assertEqual(e["code"], "unsupported_combination")


class SweepTest(EmuCase):
    def test_sweep_finds_math_functions_by_behaviour(self):
        probes = [0.25, 0.5, 2.0, 3.0, 0.75]
        plan = support.scalar_plan("0x0", ["f32"], {"kind": "f32"})
        primary = self.opened["primary"]
        params = {"session": self.sid, "plan": plan, "vectors": support.vectors([[support.f32(x)] for x in probes]),
                  "functions": {"module": primary["name"], "rvaStart": "0x0", "rvaEnd": hex(primary["size"]),
                                "offset": 0, "limit": 20000},
                  "options": support.options(maxInstructions=100_000, deadlineMs=0, trace={"imports": "off"}),
                  "match": {"returns": "f32", "argsFrom": ["arg0"], "known": ["unary"], "toleranceUlp": 1}}
        r = self.b.result("emu.sweep", params, timeout=120)
        s = r["summary"]
        self.assertEqual(s["functions"], primary["pdataFunctions"])
        self.assertEqual(s["completed"], s["functions"])
        self.assertIsNone(s["nextOffset"])
        found = {m for row in r["rows"] for m in row["matches"]}
        self.assertTrue({"sqrt", "sin"} <= found, found)
        gain = next(row for row in r["rows"] if int(row["rva"], 16) == self.va("bea_global_gain") - self.base)
        self.assertEqual(gain["statuses"], ["ok"] * 5)
        self.assertEqual([support.bits_f32(x) for x in gain["xmm0lo"]], [x * 1.5 for x in probes])
        self.assertEqual(sum(s["byOutcomeProfile"].values()), s["completed"])
        # paging by offset/limit and explicit targets
        params["functions"].update({"offset": 3, "limit": 2})
        params["match"] = None
        r = self.b.result("emu.sweep", params)
        self.assertEqual((r["summary"]["completed"], r["summary"]["nextOffset"]), (2, 5))
        params["functions"] = {"targets": [self.hva("bea_global_gain"), self.hva("bea_div")]}
        r = self.b.result("emu.sweep", params)
        self.assertEqual([row["module"] for row in r["rows"]], ["bea_emu_fixture.dll"] * 2)
        self.assertIsNone(r["summary"]["nextOffset"])


class StateAndMemoryTest(EmuCase):
    def gain_call(self, st):
        plan = support.scalar_plan(self.hva("bea_global_gain"), ["f32"], {"kind": "f32"})
        return self.emu("emu.call", plan, support.vectors([[support.f32(2.0)]]), st)

    def test_named_state_and_writes(self):
        self.gain_call(support.state("baseline", save_as="one"))
        self.assertEqual(self.u32_at("g_calls"), 1)
        self.gain_call(support.state("one"))
        self.assertEqual(self.u32_at("g_calls"), 2)
        self.gain_call(support.state("one"))
        self.assertEqual(self.u32_at("g_calls"), 2)
        lst = self.b.result("state.list", {"session": self.sid})
        self.assertEqual([s["name"] for s in lst["snapshots"]], ["one"])
        self.assertEqual(lst["limitBytes"], 512 << 20)
        w = [{"address": self.hva("g_gain"), "hex": struct.pack("<f", 2.0).hex()}]
        r = self.gain_call(support.state("baseline", writes=w))
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 4.0)
        r = self.gain_call(support.state("baseline"))
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 3.0)  # the write was not part of the baseline
        self.assertEqual(self.b.result("state.restore", {"session": self.sid, "name": "one"}), {"restored": "one"})
        self.assertEqual(self.u32_at("g_calls"), 1)
        self.assertEqual(self.b.result("state.drop", {"session": self.sid, "name": "one"}), {"dropped": True})
        e = self.b.request("emu.call", {"session": self.sid, "plan": support.scalar_plan(
            self.hva("bea_global_gain"), ["f32"], {"kind": "f32"}), "vectors": support.vectors([[support.f32(1)]]),
            "state": support.state("one"), "options": support.options()})
        self.assertEqual(e["error"]["code"], "unknown_snapshot")
        e = self.b.request("state.save", {"session": self.sid, "name": "baseline"})
        self.assertEqual(e["error"]["code"], "invalid_params")
        info = self.b.result("session.info", {"session": self.sid})
        self.assertEqual(info["state"]["poisoned"], False)
        self.assertGreaterEqual(info["state"]["calls"], 5)
        self.assertEqual(info["session"], self.sid)

    def test_named_snapshot_cap(self):
        for i in range(16):
            self.b.result("state.save", {"session": self.sid, "name": f"n{i}"})
        e = self.b.request("state.save", {"session": self.sid, "name": "n16"})
        self.assertEqual((e["error"]["code"], e["error"]["data"]["resource"]), ("resource_exhausted", "memory"))
        for i in range(16):
            self.b.result("state.drop", {"session": self.sid, "name": f"n{i}"})

    def test_overlay_transparent_reads(self):
        r = self.call("bea_avx_dot", ["int", "int", "int"], {"kind": "f32"}, ["0x0", "0x0", "0x4"])
        site = int(r["stop"]["pc"], 16)
        m = self.b.result("mem.read", {"session": self.sid, "address": hex(site), "size": 4})
        self.assertEqual(m["overlayRestored"], 1)
        self.assertEqual(m["data"], r["stop"]["instruction"][0]["bytes"][:8])
        self.assertNotEqual(m["data"][:2], "cc")
        d = self.b.result("mem.disassemble", {"session": self.sid, "address": hex(site), "function": True})
        self.assertNotIn("int3", [i["text"] for i in d["instructions"]])
        self.assertEqual(d["function"]["beginRva"], r["stop"]["pcFunction"]["beginRva"])
        # COW + section protections: read-only memory cannot be host-written after the baseline (unicorn 2.1.4)
        e = self.b.request("mem.write", {"session": self.sid, "address": hex(site), "hex": "90"})
        self.assertEqual(e["error"]["code"], "unsupported_combination")
        w = [{"address": hex(site), "hex": "90"}]
        e = self.b.request("emu.call", {"session": self.sid, "plan": support.scalar_plan(
            self.hva("bea_div"), ["int", "int"], {"kind": "int", "width": 4}),
            "vectors": support.vectors([["0x1", "0x1"]]), "state": support.state(writes=w),
            "options": support.options()})
        self.assertEqual(e["error"]["code"], "unsupported_combination")

    def test_overlay_overwrite_in_rwx_and_manual_sessions(self):
        for extra in ({"protections": "rwx"}, {"snapshots": "manual"}):
            o = self.b.result("session.open", {"source": {"kind": "image", "path": self.fx["path"]}, **extra})
            sid = o["session"]
            plan = support.scalar_plan(self.hva("bea_avx_dot"), ["int", "int", "int"], {"kind": "f32"})

            def avx(st):
                return self.b.result("emu.call", {"session": sid, "plan": plan,
                                                  "vectors": support.vectors([["0x0", "0x0", "0x4"]]), "state": st,
                                                  "options": support.options()})
            r = avx(support.state())
            site = int(r["stop"]["pc"], 16)
            orig = r["stop"]["instruction"][0]["bytes"][:2]
            w = self.b.result("mem.write", {"session": sid, "address": hex(site), "hex": orig})
            self.assertTrue(w["tbFlushed"], extra)
            r2 = avx(support.state("current"))
            self.assertIn("isa_overlay_overwritten", [x["kind"] for x in r2["deviations"]], extra)
            r3 = avx(support.state())
            self.assertEqual(r3["stop"]["pc"], hex(site), extra)   # the baseline restore brings the guard back
            self.assertNotIn("isa_overlay_overwritten", [x["kind"] for x in r3["deviations"]], extra)
            self.b.result("session.close", {"session": sid})

    def test_regions_functions_and_unmapped_reads(self):
        regs = self.b.result("mem.regions", {"session": self.sid})
        kinds = {r["kind"] for r in regs["regions"]}
        self.assertTrue({"image", "teb", "stub", "heap", "scratch", "stack", "runtime"} <= kinds)
        self.assertEqual(regs["syntheticBase"], self.opened["layout"]["syntheticBase"])
        f = self.b.result("mem.functions", {"session": self.sid, "module": "BEA_EMU_FIXTURE.DLL", "limit": 5})
        self.assertEqual((len(f["functions"]), f["total"], f["nextOffset"]),
                         (5, self.opened["primary"]["pdataFunctions"], 5))
        e = self.b.request("mem.read", {"session": self.sid, "address": "0x10", "size": 4})
        self.assertEqual((e["error"]["code"], e["error"]["data"]["region"]["region"]), ("unmapped", "null page"))
        e = self.b.request("mem.read", {"session": self.sid, "address": "0x10", "size": (16 << 20) + 1})
        self.assertEqual(e["error"]["code"], "invalid_params")
        b64 = self.b.result("mem.read", {"session": self.sid, "address": self.hva("g_gain"), "size": 4,
                                         "encoding": "base64"})
        self.assertEqual(b64["data"], "AADAPw==")  # 1.5f


class OutBufferTest(EmuCase):
    """Review fix EMU-2: out buffers come back whole (the host decodes every declared field from them; a cut buffer
    read as zeros), and a request whose out-buffer hex would not fit one result is refused before anything runs."""

    def norm_plan(self, n, out_size):
        return {"target": self.hva("bea_norm_copy"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "src", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": hex(n)}},
                          {"reg": "r8", "source": {"kind": "buffer", "buffer": "out", "offset": 0}}],
                "buffers": [buf("src", floats(*([1.0] * n))), buf("out", size=out_size, out=True)]}

    def test_batch_out_buffers_beyond_4_kib(self):
        n = 2000  # f32[2000]: 8000 bytes, the reviewer's case (elements 1024.. used to come back as zeros)
        o = support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0, maxInstructions=5_000_000,
                            trace={"imports": "counts"})
        r = self.emu("emu.batch", self.norm_plan(n, 4 * n), {"offset": 0, "count": 2, "columns": {}}, opts=o)
        self.assertEqual(r["summary"]["byStatus"], {"ok": 2})
        want = f32(1.0 / f32(n ** 0.5))
        for cell in r["columns"]["out"]["out"]:
            self.assertEqual(len(cell), 2 * 4 * n)
            self.assertEqual(set(struct.unpack(f"<{n}f", bytes.fromhex(cell))), {want})

    def test_single_out_buffers_beyond_1_mib(self):
        size = (1 << 20) + 64
        plan = {"target": self.hva("bea_codec_get"), "returns": {"kind": "int", "width": 4},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "obj", "offset": 0}}],
                "buffers": [buf("obj", bytes(size - 64) + b"\xab" * 64, out=True)]}
        r = self.emu("emu.call", plan, {"offset": 0, "count": 1, "columns": {}})
        self.assertEqual(r["status"], "returned")
        self.assertEqual(len(r["out"]["obj"]), 2 * size)
        self.assertEqual(r["out"]["obj"][-128:], "ab" * 64)

    def test_over_budget_requests_are_refused_before_running(self):
        calls = self.u32_at("g_calls")
        plan = support.scalar_plan(self.hva("bea_global_gain"), ["f32"], {"kind": "f32"})
        plan["buffers"] = [buf("big", size=1 << 20, out=True)]   # 2 MiB of hex per vector: 27 fit one result
        o = support.options(isolation="chain", stopOnFault=False, deadlineMs=0, trace={"imports": "counts"})
        e = self.emu("emu.batch", plan, support.vectors([[support.f32(1.0)]] * 30), st=support.state("current"),
                     opts=o, expect_error=True)
        self.assertEqual((e["code"], e["data"]["path"], e["data"]["maxVectors"]),
                         ("invalid_params", "params.vectors", 27))
        self.assertEqual(self.u32_at("g_calls"), calls)   # nothing ran
        r = self.emu("emu.batch", plan, support.vectors([[support.f32(1.0)]] * 27), st=support.state("current"), opts=o)
        self.assertEqual((r["summary"]["completed"], len(r["columns"]["out"]["big"][26])), (27, 2 << 20))


class SmallHeapTest(EmuCase):
    """Review fix EMU-6 with a 1 MiB HLE heap: guest malloc/free reuses freed blocks in chains, a failed guest
    allocation is a counted deviation, and heap-placement buffers (which persist, S5 §7.4) that no longer fit end a
    chain with the completed prefix instead of discarding it."""

    open_params = {"memory": {"heapBytes": 1 << 20}}

    def setUp(self):
        self.b.result("state.restore", {"session": self.sid, "name": "baseline"})

    def norm(self, n, count, isolation, src_floats=1024):
        plan = {"target": self.hva("bea_norm_copy"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "src", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": hex(n)}},
                          {"reg": "r8", "source": {"kind": "buffer", "buffer": "out", "offset": 0}}],
                "buffers": [buf("src", floats(*([1.0] * src_floats))), buf("out", size=4 * src_floats)]}
        return self.emu("emu.batch", plan, {"offset": 0, "count": count, "columns": {}},
                        opts=support.options(isolation=isolation, stopOnFault=False, deadlineMs=0,
                                             maxInstructions=5_000_000, trace={"imports": "counts"}))

    def heap_high(self):
        return int(self.b.result("session.info", {"session": self.sid})["state"]["heapHigh"], 16)

    def test_chain_malloc_free_reuses_freed_blocks(self):
        # 300 x malloc(4 KiB)/free through a 1 MiB heap: the bump allocator ran dry at vector 255 and the function
        # took its out-of-memory path (-1.0) with status ok and no deviation
        r = self.norm(1024, 300, "chain")
        self.assertEqual(r["summary"]["byStatus"], {"ok": 300})
        self.assertEqual({support.bits_f32(x) for x in r["columns"]["xmm0lo"]}, {32.0})
        self.assertEqual(r["aggregates"]["deviations"], {})
        self.assertTrue(r["summary"]["deterministic"])

    def test_guest_heap_exhaustion_is_a_deviation(self):
        r = self.norm(1 << 20, 2, "snapshot", src_floats=4)   # malloc(4 MiB) cannot fit a 1 MiB heap
        self.assertEqual({support.bits_f32(x) for x in r["columns"]["xmm0lo"]}, {-1.0})
        self.assertEqual(r["aggregates"]["deviations"]["hle_heap_exhausted"], {"vectors": 2})

    def test_chain_of_heap_buffers_stops_with_the_completed_prefix(self):
        plan = support.scalar_plan(self.hva("bea_global_gain"), ["f32"], {"kind": "f32"})
        plan["buffers"] = [buf("blob", size=300 << 10, placement="heap")]   # held by the state: 3 fit, not 4
        vecs = support.vectors([[support.f32(1.0)]] * 5)
        chain = support.options(isolation="chain", stopOnFault=False, deadlineMs=0, trace={"imports": "counts"})
        r = self.emu("emu.batch", plan, vecs, opts=chain)
        s = r["summary"]
        self.assertEqual((s["completed"], s["returned"], s["vectors"]), (3, 3, 5))
        self.assertEqual((s["stopped"]["code"], s["stopped"]["index"], s["stopped"]["data"]["resource"]),
                         ("resource_exhausted", 3, "heap"))
        self.assertEqual(self.u32_at("g_calls"), 3)       # the session holds the state after the prefix
        high = self.heap_high()
        e = self.emu("emu.batch", plan, vecs, st=support.state("current"), opts=chain, expect_error=True)
        self.assertEqual((e["code"], e["data"]["resource"]), ("resource_exhausted", "heap"))
        self.assertEqual((self.u32_at("g_calls"), self.heap_high()), (3, high))   # nothing ran, nothing kept
        snap = support.options(isolation="snapshot", stopOnFault=False, deadlineMs=0, trace={"imports": "counts"})
        r = self.emu("emu.batch", plan, vecs, opts=snap)
        self.assertEqual((r["summary"]["completed"], "stopped" in r["summary"]), (5, False))
