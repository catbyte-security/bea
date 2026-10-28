# bridge/emu/tests/test_dump.py: dump-backed emulation sessions (S5 §10, S5-D11/D16) on a REAL capture. The test
# loads bea_emu_fixture.dll into its own process with ctypes, changes runtime state (g_gain, a heap object), and
# writes a bea.dump/1 bundle of itself: the module's committed pages, this thread's TEB, KUSER_SHARED_DATA, the heap
# object's page, the readable memory map and the resolved IAT. The bridge then emulates at the runtime addresses and
# must equal native calls on the same state bit for bit; uncaptured memory is classified (harness vs target).
from __future__ import annotations

import ctypes
import datetime
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

import support
from emu_case import fixture_or_skip, rva_of

WIN = sys.platform == "win32"
if WIN:
    import ctypes.wintypes as w

    K32 = ctypes.WinDLL("kernel32", use_last_error=True)
    NTDLL = ctypes.WinDLL("ntdll")

    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", w.DWORD), ("PartitionId", w.WORD), ("RegionSize", ctypes.c_size_t),
                    ("State", w.DWORD), ("Protect", w.DWORD), ("Type", w.DWORD)]

    K32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    K32.VirtualQuery.restype = ctypes.c_size_t
    K32.GetCurrentThread.restype = w.HANDLE
    NTDLL.NtQueryInformationThread.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.ULONG, ctypes.c_void_p]

PROT = {0x02: "r--", 0x04: "rw-", 0x08: "rw-", 0x20: "r-x", 0x40: "rwx", 0x80: "rwx"}
PAGE = 0x1000


def vquery(addr):
    m = MBI()
    if not K32.VirtualQuery(addr, ctypes.byref(m), ctypes.sizeof(m)):
        return None
    return m


def readable(m):
    return m.State == 0x1000 and not (m.Protect & 0x100) and (m.Protect & 0xFF) in PROT


def memory_map(modules):
    out, addr = [], 0x10000
    while addr < 0x7FFF_FFFF_0000:
        m = vquery(addr)
        if m is None or not m.RegionSize:
            break
        base = m.BaseAddress or 0
        if readable(m):
            mod = next((n for n, b, s in modules if b <= base < b + s), None)
            out.append({"base": hex(base), "size": m.RegionSize, "protection": PROT[m.Protect & 0xFF], "module": mod})
        addr = base + m.RegionSize
    return out


def read_live(addr, n):
    return ctypes.string_at(addr, n)


def jcs(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Capture:
    """Builds a bea.dump/1 bundle of this process (the S5 §10.2 recipe, done with Win32 calls instead of Frida)."""

    def __init__(self, fx):
        self.fx = fx
        self.dll = ctypes.WinDLL(fx["path"])
        self.base = self.dll._handle
        import pefile

        self.pe = pefile.PE(fx["path"])
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.name = os.path.basename(fx["path"])
        tbi = (ctypes.c_ubyte * 48)()
        st = NTDLL.NtQueryInformationThread(K32.GetCurrentThread(), 0, tbi, 48, None)
        assert st == 0, hex(st & 0xFFFFFFFF)
        self.teb = struct.unpack_from("<Q", bytes(tbi), 8)[0]
        self.regions = []

    def va(self, name):
        return self.base + rva_of(self.fx, name)

    def add(self, base, size, tag, module=None, protection=None):
        m = vquery(base)
        self.regions.append((base, size, protection or PROT[m.Protect & 0xFF], tag, module))

    def write(self, out_dir, extra_threads=()):
        os.makedirs(os.path.join(out_dir, "regions"), exist_ok=True)
        regions = []
        for base, size, prot, tag, module in sorted(self.regions):
            data = read_live(base, size)
            sha = hashlib.sha256(data).hexdigest()
            with open(os.path.join(out_dir, "regions", f"{sha}.bin"), "wb") as fh:
                fh.write(data)
            regions.append({"base": hex(base), "size": size, "protection": prot, "tag": tag, "module": module,
                            "sha256": sha, "complete": True, "unreadable_pages": []})
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        imports = []
        for e in self.pe.DIRECTORY_ENTRY_IMPORT:
            for i in e.imports:
                slot = self.base + i.address - image_base
                imports.append({"importer": self.name, "slot": hex(slot),
                                "name": i.name.decode() if i.name else None,
                                "ordinal": None if i.name else i.ordinal, "dll": e.dll.decode(),
                                "target": hex(struct.unpack("<Q", read_live(slot, 8))[0])})
        with open(self.fx["path"], "rb") as fh:
            file_sha = hashlib.sha256(fh.read()).hexdigest()
        teb_bytes = read_live(self.teb, 0x68)
        thread = {"tid": K32.GetCurrentThreadId(), "primary": True, "teb": hex(self.teb),
                  "context": {r: "0x0" for r in ("rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8",
                                                  "r9", "r10", "r11", "r12", "r13", "r14", "r15")},
                  "stack": {"base": hex(struct.unpack_from("<Q", teb_bytes, 8)[0]),
                            "limit": hex(struct.unpack_from("<Q", teb_bytes, 0x10)[0])},
                  "tls": {"slots_array": hex(struct.unpack_from("<Q", teb_bytes, 0x58)[0]), "static_blocks": []}}
        man = {
            "schema": "bea.dump/1",
            "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z",
            "producer": {"tool": "bea", "version": "0.1.0", "operation": "dump_memory", "evidence_id": None,
                         "instance_id": None},
            "process": {"pid": os.getpid(), "image_path": sys.executable, "image_sha256": None, "arch": "x64",
                        "os": {"platform": "windows", "version": "10.0"}},
            "capture": {"mode": "running", "time_anchor": None, "duration_ms": 0},
            "modules": [{"name": self.name, "path": self.fx["path"], "base": hex(self.base), "size": self.size,
                         "file_sha256": file_sha, "preferred_base": hex(image_base), "timestamp": None,
                         "captured": "full"}],
            "regions": regions,
            "memory_map": memory_map([(self.name, self.base, self.size)]),
            "threads": [thread, *extra_threads],
            "peb": hex(struct.unpack_from("<Q", teb_bytes, 0x60)[0]),
            "imports": imports,
            "limitations": ["running capture: torn state is possible"],
        }
        man["bundle_id"] = "dump_" + hashlib.sha256(jcs(man).encode("utf-8")).hexdigest()
        with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(jcs(man))
        return man


@unittest.skipUnless(WIN, "dump capture via Win32 APIs (windows only)")
class DumpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixture_or_skip()
        cls.tmp = tempfile.mkdtemp(prefix="bea-dump-test-")
        cap = cls.cap = Capture(cls.fx)
        dll = cap.dll
        # runtime state the file image does not have
        ctypes.c_float.from_address(cap.va("g_gain")).value = 2.5
        gain = dll.bea_global_gain
        gain.restype, gain.argtypes = ctypes.c_float, [ctypes.c_float]
        cls.live_gain_first = gain(2.0)                       # g_calls 0 -> 1 in the live process
        # the heap Body (32 bytes) deliberately straddles a page boundary (page offset 0xff0), where a heap block can
        # land anyway: the capture must take every page of the object, and the struct then spans two captured pages
        cls.heap = ctypes.create_string_buffer(3 * PAGE)
        straddle = (0xFF0 - ctypes.addressof(cls.heap)) % PAGE
        cls.body = (ctypes.c_char * 64).from_buffer(cls.heap, straddle)
        ctypes.memmove(cls.body, struct.pack("<7fI", 1, 2, 3, 0.5, -1.25, 2.0, 3.0, 41), 32)
        cls.uncaptured = ctypes.create_string_buffer(1 << 20)
        # the module's committed pages, this thread's TEB, KUSER_SHARED_DATA and the heap object's pages
        addr = cap.base
        while addr < cap.base + cap.size:
            m = vquery(addr)
            end = min((m.BaseAddress or 0) + m.RegionSize, cap.base + cap.size)
            if readable(m):
                cap.add(addr, end - addr, "module", cap.name)
            addr = end
        tm = vquery(cap.teb)
        cap.add(tm.BaseAddress, tm.RegionSize, "teb")
        cap.add(0x7FFE0000, PAGE, "kuser_shared_data")
        # every page of the 32-byte Body (two here: see above)
        body = ctypes.addressof(cls.body)
        body_first, body_last = body & ~(PAGE - 1), (body + 32 - 1) & ~(PAGE - 1)
        assert body_last == body_first + PAGE, "the Body must straddle a page boundary"
        cap.add(body_first, body_last - body_first + PAGE, "heap")
        cls.body_addr = ctypes.addressof(cls.body)
        cls.bundle = os.path.join(cls.tmp, "bundle")
        cls.manifest = cap.write(cls.bundle)
        # native results on copies of the captured state (computed after the capture)
        cls.live_gain_second = gain(2.0)
        copy = ctypes.create_string_buffer(bytes(cls.body)[:32], 32)
        force = (ctypes.c_float * 3)(0.5, 1.0, -2.0)
        step = dll.bea_body_step
        step.restype, step.argtypes = None, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_float]
        step(ctypes.addressof(copy), ctypes.addressof(force), 0.016)
        cls.live_body_after = bytes(copy)[:32]
        cls.b = support.BridgeProc()
        cls.opened = cls.b.result("session.open", {"source": {"kind": "dump", "bundlePath": cls.bundle}})
        cls.sid = cls.opened["session"]

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "b", None) is not None:
            cls.b.close()
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def call(self, target, kinds, ret, args, sid=None, st=None, **opts):
        r = self.b.request("emu.call", {"session": sid or self.sid, "plan": support.scalar_plan(hex(target), kinds, ret),
                                        "vectors": support.vectors([args]), "state": st or support.state(),
                                        "options": support.options(**opts)})
        self.assertIn("result", r, r)
        return r["result"]

    def test_open_result(self):
        o = self.opened
        self.assertEqual(o["primary"]["name"], os.path.basename(self.fx["path"]))
        self.assertEqual(o["primary"]["mappedBase"], hex(self.cap.base))
        self.assertEqual(o["primary"]["sha256"], self.fx["artifactSha256"])
        self.assertEqual(o["primary"]["captured"], "full")
        self.assertEqual(o["thread"], {"tid": self.manifest["threads"][0]["tid"], "teb": hex(self.cap.teb)})
        kinds = [d["kind"] for d in o["loaderDeviations"]]
        self.assertIn("iat_rebound", kinds)
        self.assertIn("teb_stack_bounds_rewritten", kinds)
        self.assertNotIn("synthetic_kuser_shared_data", kinds)   # captured
        iat = next(d for d in o["loaderDeviations"] if d["kind"] == "iat_rebound")["detail"]
        self.assertGreater(iat["hle"], 0)
        self.assertEqual(o["imports"]["models"]["lle"], 0)          # no import target module was captured
        syn = int(o["layout"]["syntheticBase"], 16)
        for m in self.manifest["memory_map"]:
            b = int(m["base"], 16)
            self.assertTrue(b + m["size"] <= syn or b >= syn + (1 << 30))  # the window avoids live memory

    def test_runtime_state_equals_live_bit_for_bit(self):
        r = self.call(self.cap.va("bea_global_gain"), ["f32"], {"kind": "f32"}, [support.f32(2.0)])
        self.assertEqual(r["status"], "returned")
        bits = int(r["raw"]["xmm0"], 16) & 0xFFFFFFFF
        self.assertEqual(bits, struct.unpack("<I", struct.pack("<f", self.live_gain_second))[0])
        self.assertEqual(support.bits_f32(hex(bits)), 5.0)        # runtime g_gain 2.5, the file has 1.5
        g = self.b.result("mem.read", {"session": self.sid, "address": hex(self.cap.va("g_calls")), "size": 4})
        self.assertEqual(struct.unpack("<I", bytes.fromhex(g["data"]))[0], 2)  # captured counter 1, plus this call
        self.assertEqual(r["provenance"]["source"], "dump")
        self.assertEqual(r["provenance"]["bundleId"], self.manifest["bundle_id"])

    def test_struct_on_a_captured_heap_object_equals_live(self):
        plan = {"target": hex(self.cap.va("bea_body_step")), "returns": {"kind": "void"},
                "slots": [{"reg": "rcx", "source": {"kind": "const", "bits": hex(self.body_addr)}},
                          {"reg": "rdx", "source": {"kind": "buffer", "buffer": "force", "offset": 0}},
                          {"reg": "xmm2", "source": {"kind": "const", "bits": support.f32(0.016)}}],
                "buffers": [{"name": "force", "size": 12, "align": 16, "placement": "scratch",
                             "template": struct.pack("<3f", 0.5, 1.0, -2.0).hex(), "columns": [], "ptrFields": [],
                             "out": False}]}
        r = self.b.result("emu.call", {"session": self.sid, "plan": plan, "vectors": {"offset": 0, "count": 1,
                                                                                       "columns": {}},
                                       "state": support.state(), "options": support.options()})
        self.assertEqual(r["status"], "returned", (hex(self.body_addr), r.get("stop")))
        after = self.b.result("mem.read", {"session": self.sid, "address": hex(self.body_addr), "size": 32})
        self.assertEqual(bytes.fromhex(after["data"]), self.live_body_after)

    def test_uncaptured_memory_is_classified(self):
        target = self.cap.va("bea_body_step")
        far = ctypes.addressof(self.uncaptured) + 0x10000
        r = self.call(target, ["int", "int", "f32"], {"kind": "void"}, [hex(far), hex(far), support.f32(1.0)])
        f = r["stop"]["fault"]["addressRegion"]
        self.assertEqual((r["status"], r["attribution"]), ("fault", "harness"))
        self.assertEqual((f["capture"], f["kind"]), ("not-captured-mapped-live", "unmapped"))
        self.assertIn("re-run dump_memory including", f["remediation"])
        self.assertEqual(f["liveProtection"], "rw-")
        r = self.call(target, ["int", "int", "f32"], {"kind": "void"}, ["0x10", "0x10", support.f32(1.0)])
        self.assertEqual((r["status"], r["attribution"], r["stop"]["fault"]["addressRegion"]["capture"]),
                         ("fault", "target", "unmapped-live"))

    def test_teb_kusd_and_imports(self):
        r = self.call(self.cap.va("bea_read_teb_self"), [], {"kind": "int", "width": 8}, [])
        self.assertEqual(r["raw"]["rax"], hex(self.cap.teb))      # GS base = the captured TEB
        stack_top = self.b.result("mem.read", {"session": self.sid, "address": hex(self.cap.teb + 8), "size": 16})
        top, limit = struct.unpack("<QQ", bytes.fromhex(stack_top["data"]))
        syn = int(self.opened["layout"]["syntheticBase"], 16)
        self.assertEqual((limit, top - limit), (syn + 0x3000_0000, 1 << 20))   # rewritten to the synthetic stack
        k = self.b.result("mem.read", {"session": self.sid, "address": "0x7ffe0000", "size": 0x300})
        live = read_live(0x7FFE0000, 0x300)
        got = bytes.fromhex(k["data"])
        for off in (0x260, 0x26C, 0x270):   # NtBuildNumber, NtMajorVersion, NtMinorVersion (time fields move)
            self.assertEqual(got[off:off + 4], live[off:off + 4], hex(off))
        self.assertEqual((k["region"]["capture"], k["region"]["kind"]), ("captured", "captured"))
        plan = {"target": hex(self.cap.va("bea_norm_copy")), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "src", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": "0x2"}},
                          {"reg": "r8", "source": {"kind": "buffer", "buffer": "out", "offset": 0}}],
                "buffers": [{"name": "src", "size": 8, "align": 16, "placement": "scratch",
                             "template": struct.pack("<2f", 3, 4).hex(), "columns": [], "ptrFields": [], "out": False},
                            {"name": "out", "size": 8, "align": 16, "placement": "scratch", "template": "00" * 8,
                             "columns": [], "ptrFields": [], "out": True}]}
        r = self.b.result("emu.call", {"session": self.sid, "plan": plan,
                                       "vectors": {"offset": 0, "count": 1, "columns": {}},
                                       "state": support.state(), "options": support.options()})
        self.assertEqual(support.bits_f32(r["raw"]["xmm0"]), 5.0)
        self.assertEqual([e["import"] for e in r["trace"]["imports"]],
                         ["msvcrt.dll!malloc", "msvcrt.dll!memcpy", "msvcrt.dll!free"])

    def test_import_policies(self):
        plan = {"target": hex(self.cap.va("bea_norm_copy")), "returns": {"kind": "f32"},
                "slots": [{"reg": "rcx", "source": {"kind": "buffer", "buffer": "src", "offset": 0}},
                          {"reg": "rdx", "source": {"kind": "const", "bits": "0x2"}},
                          {"reg": "r8", "source": {"kind": "buffer", "buffer": "src", "offset": 0}}],
                "buffers": [{"name": "src", "size": 8, "align": 16, "placement": "scratch",
                             "template": struct.pack("<2f", 3, 4).hex(), "columns": [], "ptrFields": [], "out": False}]}
        for policy, status, attribution in (("stop_all", "unhandled_import", "harness"), ("lle", "fault", "harness")):
            o = self.b.result("session.open", {"source": {"kind": "dump", "bundlePath": self.bundle},
                                               "imports": {"dumpPolicy": policy}})
            r = self.b.result("emu.call", {"session": o["session"], "plan": plan,
                                           "vectors": {"offset": 0, "count": 1, "columns": {}},
                                           "state": support.state(), "options": support.options()})
            self.assertEqual((r["status"], r["attribution"]), (status, attribution), policy)
            if policy == "lle":   # the real msvcrt malloc was not captured: a fetch of live-but-uncaptured memory
                self.assertEqual(r["stop"]["fault"]["addressRegion"]["capture"], "not-captured-mapped-live")
                self.assertEqual(o["imports"]["models"]["lle"], o["imports"]["total"])
            else:
                self.assertEqual(r["stop"]["importCall"]["import"], "msvcrt.dll!malloc")
                self.assertEqual(o["imports"]["models"]["stop"], o["imports"]["total"])
            self.b.result("session.close", {"session": o["session"]})

    def test_invalid_bundles(self):
        def copy_bundle(name):
            d = os.path.join(self.tmp, name)
            shutil.copytree(self.bundle, d)
            return d

        bad = copy_bundle("corrupt-region")
        first = sorted(os.listdir(os.path.join(bad, "regions")))[0]
        with open(os.path.join(bad, "regions", first), "r+b") as fh:
            b0 = fh.read(1)
            fh.seek(0)
            fh.write(bytes([b0[0] ^ 0xFF]))
        e = self.b.request("session.open", {"source": {"kind": "dump", "bundlePath": bad}})
        self.assertEqual(e["error"]["code"], "dump_invalid")
        bad = copy_bundle("tampered-manifest")
        with open(os.path.join(bad, "manifest.json"), encoding="utf-8") as fh:
            man = json.load(fh)
        man["process"]["pid"] += 1
        with open(os.path.join(bad, "manifest.json"), "w", encoding="utf-8") as fh:
            fh.write(jcs(man))
        e = self.b.request("session.open", {"source": {"kind": "dump", "bundlePath": bad}})
        self.assertEqual(e["error"]["code"], "dump_invalid")
        e = self.b.request("session.open", {"source": {"kind": "dump", "bundlePath": self.bundle, "thread": 4}})
        self.assertEqual(e["error"]["code"], "dump_incomplete")
        e = self.b.request("session.open", {"source": {"kind": "dump", "bundlePath": self.bundle,
                                                       "primaryModule": "nope.dll"}})
        self.assertEqual(e["error"]["code"], "dump_incomplete")
        e = self.b.request("session.open", {"source": {"kind": "dump", "bundlePath": self.tmp + "/missing"}})
        self.assertEqual(e["error"]["code"], "dump_invalid")
