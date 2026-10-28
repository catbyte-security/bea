# bridge/emu/tests/test_snapshots.py: the snapshot ordering suite (S5 §14.1): the verified E8b sequence plus 200
# random interleavings of save, restore, drop, single calls and snapshot/chain batches from every kind of `from`,
# in both COW and manual sessions. A model predicts the guest-visible state (g_calls, written by the guest) and the
# HLE heap high-water mark (moved by the malloc/free pair inside bea_norm_copy: the first pair of a lineage bumps it,
# later pairs reuse the freed block, review fix EMU-6); both are checked after every step, and the bridge must never
# crash or report engine_crashed.
from __future__ import annotations

import random
import struct

import support
from emu_case import EmuCase, buf, floats


def align16(x):
    return (x + 15) & ~15


class OrderingBase(EmuCase):
    def setUp(self):
        self.syn = int(self.opened["layout"]["syntheticBase"], 16)
        self.heap0 = self.syn + 0x1000_0000
        self.b.result("state.restore", {"session": self.sid, "name": "baseline"})
        for s in self.b.result("state.list", {"session": self.sid})["snapshots"]:
            self.b.result("state.drop", {"session": self.sid, "name": s["name"]})
        self.model = {"g": 0, "h": self.heap0, "free": False}
        self.named = {}

    # ---- the two guest operations
    def gain_plan(self):
        return support.scalar_plan(self.hva("bea_global_gain"), ["f32"], {"kind": "f32"})

    def norm_plan(self):
        return {"target": self.hva("bea_norm_copy"), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "src", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": "0x2"}},
                          {"reg": "r8", "source": {"kind": "buffer", "buffer": "out", "offset": 0}}],
                "buffers": [buf("src", floats(3, 4)), buf("out", size=8, out=True)]}

    @staticmethod
    def step(state, op):
        g, h, free = state
        if op == "gain":
            return g + 1, h, free
        # malloc(8) + free(): the first pair bumps the high-water mark; its freed chunk then serves every later one
        return (g, h, True) if free else (g, align16(h + 16) + 8, True)

    def start(self, frm):
        if frm == "baseline":
            return (0, self.heap0, False)
        if frm == "current":
            return (self.model["g"], self.model["h"], self.model["free"])
        return self.named[frm]

    def set_model(self, st):
        self.model["g"], self.model["h"], self.model["free"] = st

    def do_call(self, op, frm, save_as=None):
        plan = self.gain_plan() if op == "gain" else self.norm_plan()
        vecs = support.vectors([[support.f32(1.0)]]) if op == "gain" else {"offset": 0, "count": 1, "columns": {}}
        r = self.emu("emu.call", plan, vecs, support.state(frm, save_as=save_as))
        self.assertEqual(r["status"], "returned", r.get("stop"))
        st = self.step(self.start(frm), op)
        self.set_model(st)
        if save_as:
            self.named[save_as] = st

    def do_batch(self, op, frm, isolation, n):
        plan = self.gain_plan() if op == "gain" else self.norm_plan()
        vecs = (support.vectors([[support.f32(1.0)]] * n) if op == "gain"
                else {"offset": 0, "count": n, "columns": {}})
        r = self.emu("emu.batch", plan, vecs, support.state(frm),
                     support.options(isolation=isolation, stopOnFault=False, deadlineMs=0,
                                     trace={"imports": "counts"}))
        self.assertEqual(r["summary"]["returned"], n)
        st = self.start(frm)
        for _ in range(1 if isolation == "snapshot" else n):
            st = self.step(st, op)
        self.set_model(st)

    def do_save(self, name):
        self.b.result("state.save", {"session": self.sid, "name": name})
        self.named[name] = (self.model["g"], self.model["h"], self.model["free"])

    def do_restore(self, name):
        self.assertEqual(self.b.result("state.restore", {"session": self.sid, "name": name}), {"restored": name})
        self.set_model(self.start(name))

    def do_drop(self, name):
        self.assertTrue(self.b.result("state.drop", {"session": self.sid, "name": name})["dropped"])
        del self.named[name]

    def check(self, where):
        g = struct.unpack("<I", self.read(self.va("g_calls"), 4))[0]
        info = self.b.result("session.info", {"session": self.sid})
        self.assertFalse(info["state"]["poisoned"])
        self.assertEqual((g, int(info["state"]["heapHigh"], 16)), (self.model["g"], self.model["h"]), where)
        self.assertEqual(sorted(s["name"] for s in info["state"]["named"]), sorted(self.named), where)

    def e8b_sequence(self):
        """S5 §0.1 E8b: B, N2, N1, B, N2, a batch from N1, B, N1, T2 and B (plus the calls that build them)."""
        self.do_call("gain", "current")
        self.do_save("N1")
        self.do_call("norm", "current")
        self.do_call("gain", "current")
        self.do_save("N2")
        self.do_call("gain", "current")
        for name in ("baseline", "N2", "N1", "baseline", "N2"):
            self.do_restore(name)
            self.check(f"restore {name}")
        self.do_batch("gain", "N1", "snapshot", 3)
        self.check("batch from N1")
        self.do_restore("baseline")
        self.do_restore("N1")
        self.check("N1 after T")
        self.do_batch("norm", "current", "snapshot", 2)   # a second temporary context
        self.check("T2")
        self.do_restore("baseline")
        self.check("B final")

    def random_interleavings(self, seed, steps=200):
        rnd = random.Random(seed)
        names = ["a", "b", "c", "d"]
        for i in range(steps):
            frms = ["baseline", "current"] + list(self.named)
            k = rnd.randrange(10)
            if k < 3:
                save = rnd.choice(names) if rnd.random() < 0.2 else None
                self.do_call(rnd.choice(["gain", "norm"]), rnd.choice(frms), save)
            elif k < 5:
                self.do_batch(rnd.choice(["gain", "norm"]), rnd.choice(frms), rnd.choice(["snapshot", "chain"]),
                              rnd.randrange(1, 6))
            elif k < 7:
                self.do_save(rnd.choice(names))
            elif k < 9:
                self.do_restore(rnd.choice(["baseline"] + list(self.named)))
            elif self.named:
                self.do_drop(rnd.choice(list(self.named)))
            self.check(f"step {i}")
        self.assertIsNone(self.b.p.poll())


class CowOrderingTest(OrderingBase):
    def test_e8b_sequence(self):
        self.e8b_sequence()

    def test_random_interleavings(self):
        self.random_interleavings(2026)

    def test_many_current_batches_compact_cow_levels(self):
        # every from:"current" snapshot batch adds a COW level; past 8 the bridge compacts (same state)
        for _ in range(20):
            self.do_batch("gain", "current", "snapshot", 2)
            self.check("current batch")


class ManualOrderingTest(OrderingBase):
    open_params = {"snapshots": "manual"}

    def test_e8b_sequence(self):
        self.e8b_sequence()

    def test_random_interleavings(self):
        self.random_interleavings(7)


class MapZeroTest(EmuCase):
    open_params = {"snapshots": "manual", "faultPolicy": "map_zero"}

    def test_auto_mapped_zero_pages_come_and_go_with_snapshots(self):
        plan = {"target": self.hva("bea_body_step"), "returns": {"kind": "void"}, "buffers": [],
                "slots": [{"reg": "rcx", "source": {"kind": "const", "bits": "0x50000000"}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": "0x50002000"}},
                          {"reg": "xmm2", "source": {"kind": "const", "bits": support.f32(0.5)}}]}
        vec = {"offset": 0, "count": 1, "columns": {}}
        mz = support.options(faultPolicy="map_zero")  # RunOptions.faultPolicy is per call
        r = self.emu("emu.call", plan, vec, support.state(save_as="mapped"), mz)
        self.assertEqual(r["status"], "returned")
        dev = next(d for d in r["deviations"] if d["kind"] == "auto_mapped_zero_pages")
        self.assertEqual(sorted(dev["detail"]["pages"]), ["0x50000000", "0x50002000"])
        self.assertEqual(struct.unpack("<I", self.read(0x50000000 + 28, 4))[0], 1)  # steps++ on the zero page
        e = self.b.request("mem.read", {"session": self.sid, "address": "0x50000000", "size": 4})
        self.assertIn("result", e)
        self.b.result("state.restore", {"session": self.sid, "name": "baseline"})
        e = self.b.request("mem.read", {"session": self.sid, "address": "0x50000000", "size": 4})
        self.assertEqual(e["error"]["code"], "unmapped")   # the baseline predates the auto-mapped pages
        self.b.result("state.restore", {"session": self.sid, "name": "mapped"})
        self.assertEqual(struct.unpack("<I", self.read(0x50000000 + 28, 4))[0], 1)  # and the snapshot brings them back
        r = self.emu("emu.call", plan, vec, support.state("mapped"), mz)
        self.assertEqual(struct.unpack("<I", self.read(0x50000000 + 28, 4))[0], 2)
        r = self.emu("emu.call", plan, vec, None, mz)
        self.assertEqual(struct.unpack("<I", self.read(0x50000000 + 28, 4))[0], 1)
        stop = self.emu("emu.call", plan, vec)  # faultPolicy "stop" on the same session: a plain fault
        self.assertEqual((stop["status"], stop["stop"]["cause"]), ("fault", "read_unmapped"))
        fetch = self.emu("emu.call", support.scalar_plan("0x60000000", [], {"kind": "void"}), vec, None, mz)
        self.assertEqual((fetch["status"], fetch["stop"]["cause"]), ("fault", "fetch_unmapped"))  # never auto-mapped
