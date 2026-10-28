# bridge/emu/tests/test_protocol.py: the bea-emu/0.1 process model and transport against the REAL bridge
# (S5 §3.1, §4.1-§4.3): ready event, hello and version strings, out-of-band ping/cancel, error frames, lifetime
# (shutdown, stdin EOF), --probe, --selftest, usage errors, and the engine-unavailable paths.
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

import support
from support import BRIDGE, BridgeProc

SKIP = support.engines_available()


def file_sha256():
    with open(BRIDGE, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def run_bridge(*args, flags=("-I", "-X", "utf8"), timeout=60, stdin=b""):
    p = subprocess.Popen([sys.executable, *flags, BRIDGE, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=tempfile.gettempdir())
    support.OWNED.append(p)
    out, err = p.communicate(stdin, timeout=timeout)
    return p.returncode, out, err


@unittest.skipIf(SKIP, SKIP or "")
class ProtocolTest(unittest.TestCase):
    def setUp(self):
        self.b = BridgeProc()

    def tearDown(self):
        self.b.close()

    def test_ready_event(self):
        ev = self.b.ready["event"]
        self.assertEqual(ev["type"], "ready")
        self.assertEqual(ev["protocol"], "bea-emu/0.1")
        self.assertEqual(ev["bridge"], {"version": "0.1.0", "sha256": file_sha256()})
        self.assertEqual(ev["pid"], self.b.p.pid)  # a real interpreter here (no launcher in between)
        self.assertEqual(set(ev["engines"]), {"python", "unicorn", "unicornCore", "capstone", "pefile"})
        self.assertEqual(set(ev["python"]), {"version", "executable", "inVenv"})
        if sys.platform == "win32":
            self.assertEqual(ev["memoryLimit"], {"applied": True, "bytes": 2 << 30, "mechanism": "win32-job"})

    def test_hello_and_protocol_mismatch(self):
        r = self.b.result("bridge.hello", {"protocol": "bea-emu/0.1", "client": {"name": "bea", "version": "0.1.0"}})
        self.assertEqual(r["protocol"], "bea-emu/0.1")
        self.assertEqual(r["capabilities"]["formats"], ["pe64", "bea.dump/1"])
        self.assertTrue(r["capabilities"]["insnHooks"]["cpuid"])
        self.assertIn("malloc", r["capabilities"]["hle"])
        self.assertIn("sqrt", r["capabilities"]["sweepKnown"])
        self.assertEqual(r["limits"]["maxFrameBytes"], 67108864)
        self.assertEqual(r["limits"]["maxOutHex"], 56 << 20)   # review fix EMU-2: the out-buffer budget per result
        e = self.b.request("bridge.hello", {"protocol": "bea-emu/0.2", "client": {"name": "bea", "version": "x"}})
        self.assertEqual(e["error"]["code"], "protocol_mismatch")

    def test_ping_is_out_of_band_while_busy(self):
        fx = support.emu_fixture()
        if isinstance(fx, str):
            self.skipTest(fx)
        o = self.b.result("session.open", {"source": {"kind": "image", "path": fx["path"]}})
        spin = self._spin_call(o)
        rid = self.b.send("emu.call", spin)
        time.sleep(0.2)
        t0 = time.perf_counter()
        ping, _ = self.b.wait(self.b.send("bridge.ping", {}), timeout=5)
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertEqual(ping["result"], {"pong": True, "busy": rid, "sessions": 1})
        c, _ = self.b.wait(self.b.send("bridge.cancel", {"requestId": rid}), timeout=5)
        self.assertEqual(c["result"], {"cancelled": True, "state": "running"})
        final, _ = self.b.wait(rid, timeout=10)
        self.assertEqual(final["result"]["status"], "cancelled")
        self.assertEqual(final["result"]["attribution"], "harness")
        self.assertFalse(final["result"]["deterministic"])

    def _spin_call(self, opened):
        fx = support.emu_fixture()
        base = int(opened["primary"]["mappedBase"], 16)
        rva = fx["pe"]["exportRvas"]["bea_spin"]
        target = hex(base + (rva if isinstance(rva, int) else int(rva, 16)))
        return {"session": opened["session"],
                "plan": support.scalar_plan(target, ["int"], {"kind": "int", "width": 4}),
                "vectors": support.vectors([["0x1"]]), "state": support.state(),
                "options": support.options(maxInstructions=0)}

    def test_cancel_queued_and_unknown(self):
        fx = support.emu_fixture()
        if isinstance(fx, str):
            self.skipTest(fx)
        o = self.b.result("session.open", {"source": {"kind": "image", "path": fx["path"]}})
        running = self.b.send("emu.call", self._spin_call(o))
        queued_call = self.b.send("emu.call", self._spin_call(o))
        queued_info = self.b.send("session.info", {"session": "s1"})
        time.sleep(0.2)
        for rid in (queued_call, queued_info):
            c, _ = self.b.wait(self.b.send("bridge.cancel", {"requestId": rid}), timeout=5)
            self.assertEqual(c["result"], {"cancelled": True, "state": "queued"})
        c, _ = self.b.wait(self.b.send("bridge.cancel", {"requestId": 999}), timeout=5)
        self.assertEqual(c["result"], {"cancelled": False, "state": "unknown"})
        self.b.wait(self.b.send("bridge.cancel", {"requestId": running}), timeout=5)
        self.assertEqual(self.b.wait(running)[0]["result"]["status"], "cancelled")
        queued, _ = self.b.wait(queued_call)
        self.assertEqual(queued["result"]["status"], "cancelled")      # emu.* -> a cancelled result
        info, _ = self.b.wait(queued_info)
        self.assertEqual(info["error"]["code"], "cancelled")          # anything else -> the cancelled error
        # queued methods deliver their final frames in request order
        finals = [rid for rid, kind in self.b.arrivals if kind != "event" and rid in (running, queued_call, queued_info)]
        self.assertEqual(finals, [running, queued_call, queued_info])

    def test_error_frames_and_recovery(self):
        self.b.raw(b"{not json}\n")
        self.b.raw(b'{"method":"bridge.hello"}\n')
        self.b.raw(b'{"id":0,"method":"bridge.ping"}\n')
        got = sorted((f["id"], f["error"]["code"]) for f in (self.b.frames.get(timeout=5) for _ in range(3)))
        # the bad ping is answered out of band by the reader thread, so arrival order is not fixed
        self.assertEqual(got, [(None, "invalid_request"), (None, "invalid_request"), (None, "parse_error")])
        self.assertEqual(self.b.request("no.such", {})["error"]["code"], "unknown_method")
        self.assertEqual(self.b.request("session.info", {"session": "s9"})["error"]["code"], "unknown_session")
        self.assertEqual(self.b.request("session.open", {"source": {"kind": "elf"}})["error"]["code"],
                         "invalid_params")
        rid = self.b.next_id = self.b.next_id + 1
        self.b.raw(json.dumps({"id": rid, "method": "bridge.ping", "params": {}}).encode() + b"\r\n")  # CRLF
        self.assertEqual(self.b.wait(rid)[0]["result"]["pong"], True)

    def test_oversize_frame(self):
        self.b.raw(b'{"id":1,"method":"bridge.ping","params":{"pad":"' + b"x" * (65 << 20) + b'"}}\n')
        f = self.b.frames.get(timeout=60)
        self.assertEqual((f["id"], f["error"]["code"]), (None, "frame_too_large"))
        self.assertTrue(self.b.request("bridge.ping")["result"]["pong"])

    def test_shutdown_then_exit_0(self):
        self.assertEqual(self.b.result("bridge.shutdown"), {"shutdown": True})
        self.assertEqual(self.b.p.wait(10), 0)

    def test_stdin_eof_exits_0(self):
        t0 = time.perf_counter()
        self.assertEqual(self.b.close(), 0)
        self.assertLess(time.perf_counter() - t0, 5)

    def test_stdin_eof_during_a_long_call_cancels_it(self):
        fx = support.emu_fixture()
        if isinstance(fx, str):
            self.skipTest(fx)
        o = self.b.result("session.open", {"source": {"kind": "image", "path": fx["path"]}})
        self.b.send("emu.call", self._spin_call(o))
        time.sleep(0.2)
        t0 = time.perf_counter()
        self.assertEqual(self.b.close(), 0)
        self.assertLess(time.perf_counter() - t0, 3)


@unittest.skipIf(SKIP, SKIP or "")
class ModesTest(unittest.TestCase):
    def test_probe(self):
        code, out, _err = run_bridge("--probe")
        self.assertEqual(code, 0)
        lines = out.decode().strip().splitlines()
        self.assertEqual(len(lines), 1)
        p = json.loads(lines[0])
        self.assertEqual(p["probe"], "bea-emu/0.1")
        self.assertTrue(p["ok"])
        self.assertEqual(p["bridge"], {"version": "0.1.0", "sha256": file_sha256()})
        self.assertEqual(set(p["python"]), {"version", "implementation", "executable", "prefix", "basePrefix",
                                            "inVenv", "bits", "platform"})
        self.assertEqual(p["python"]["bits"], 64)
        self.assertEqual(set(p["engines"]), {"unicorn", "unicornCore", "capstone", "pefile"})
        self.assertEqual((p["missing"], p["errors"]), ([], {}))

    def test_selftest_matches_the_validated_engine(self):
        code, out, err = run_bridge("--selftest")
        self.assertEqual(code, 0, err)
        s = json.loads(out.decode().strip().splitlines()[-1])
        self.assertEqual(s["selftest"], "bea-emu/0.1")
        names = {"fp_reset", "vex128_misexecutes", "vex256_rejected", "bmi_ok", "tb_hook_gotcha",
                 "count_budget_gotcha", "cow_lifo_ok", "context_mode_toggle", "int3_rip", "mxcsr_flags_modeled",
                 "x87_reset", "insn_hooks", "gs_base", "memory_limit"}
        self.assertEqual(set(s["results"]), names)
        if s["engines"]["unicorn"] == "2.1.4":
            bad = {k: v for k, v in s["results"].items() if not v["ok"]}
            self.assertEqual(bad, {})
        self.assertLess(s["ms"], 5000)

    def test_usage_error_exits_2(self):
        code, out, err = run_bridge("--bogus")
        self.assertEqual((code, out), (2, b""))
        self.assertIn(b"unknown argument", err)

    def test_engines_missing(self):
        # -S drops site-packages, so unicorn/capstone/pefile cannot be imported: the S5 §3.1 step 4 paths.
        code, out, _ = run_bridge("--probe", flags=("-I", "-S", "-X", "utf8"))
        self.assertEqual(code, 3)
        p = json.loads(out.decode().strip())
        self.assertFalse(p["ok"])
        self.assertEqual(sorted(p["missing"]), ["capstone", "pefile", "unicorn"])
        self.assertIn("unicorn", p["errors"])
        code, out, _ = run_bridge(flags=("-I", "-S", "-X", "utf8"))
        self.assertEqual(code, 3)
        ev = json.loads(out.decode().strip())["event"]
        self.assertEqual((ev["type"], ev["code"]), ("fatal", "engine_unavailable"))
        self.assertEqual(sorted(ev["data"]["missing"]), ["capstone", "pefile", "unicorn"])

    def test_memory_limit_off(self):
        b = BridgeProc(mem_limit=0)
        try:
            self.assertEqual(b.ready["event"]["memoryLimit"], {"applied": False, "bytes": None, "mechanism": "none"})
        finally:
            b.close()


if __name__ == "__main__":
    unittest.main()
