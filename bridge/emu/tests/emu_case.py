# bridge/emu/tests/emu_case.py: a unittest base class with one real bridge + one image session on
# bea_emu_fixture.dll per test class, and helpers that build the raw-bits plans TypeScript's classifier would send.
from __future__ import annotations

import os
import struct
import unittest

import support
from support import BridgeProc


def fixture_or_skip():
    reason = support.engines_available()
    if reason:
        raise unittest.SkipTest(reason)
    fx = support.emu_fixture()
    if isinstance(fx, str):
        raise unittest.SkipTest(fx)
    return fx


def rva_of(fx, name):
    v = fx["pe"]["exportRvas"][name]
    return v if isinstance(v, int) else int(v, 16)


class EmuCase(unittest.TestCase):
    open_params = {}
    bridge_kwargs = {}

    @classmethod
    def setUpClass(cls):
        cls.fx = fixture_or_skip()
        cls.b = BridgeProc(**cls.bridge_kwargs)
        params = {"source": {"kind": "image", "path": cls.fx["path"]}}
        params.update(cls.open_params)
        cls.opened = cls.b.result("session.open", params)
        cls.sid = cls.opened["session"]
        cls.base = int(cls.opened["primary"]["mappedBase"], 16)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "b", None) is not None:
            cls.b.close()

    # ---- addresses
    def va(self, name):
        return self.base + rva_of(self.fx, name)

    def hva(self, name):
        return hex(self.va(name))

    # ---- requests
    def emu(self, method, plan, vecs, st=None, opts=None, expect_error=False, timeout=60, **extra):
        params = {"session": self.sid, "plan": plan, "vectors": vecs, "state": st or support.state(),
                  "options": opts or support.options(), **extra}
        f = self.b.request(method, params, timeout=timeout)
        if expect_error:
            self.assertIn("error", f, f)
            return f["error"]
        self.assertIn("result", f, f)
        return f["result"]

    def call(self, name, kinds, ret, args, st=None, **opts):
        plan = support.scalar_plan(self.hva(name), kinds, ret)
        return self.emu("emu.call", plan, support.vectors([args]), st, support.options(**opts))

    def read(self, addr, size):
        r = self.b.result("mem.read", {"session": self.sid, "address": hex(addr), "size": size})
        return bytes.fromhex(r["data"])

    def u32_at(self, name):
        return struct.unpack("<I", self.read(self.va(name), 4))[0]


def f32b(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def f32(x):
    """Round a Python float to f32 (IEEE round-to-nearest)."""
    return struct.unpack("<f", struct.pack("<f", x))[0]


def buf(name, data=b"", size=None, out=False, columns=(), ptr_fields=(), placement="scratch", align=16):
    size = len(data) if size is None else size
    data = data + bytes(size - len(data))
    return {"name": name, "size": size, "align": align, "placement": placement, "template": data.hex(),
            "columns": list(columns), "ptrFields": list(ptr_fields), "out": out}


def floats(*xs):
    return struct.pack(f"<{len(xs)}f", *xs)


def doubles(*xs):
    return struct.pack(f"<{len(xs)}d", *xs)


def env_path(*parts):
    return os.path.join(*parts)
