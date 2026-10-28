# =================================================================================================
# bridge/emu/tests/support.py: test helpers for the bea-emu/0.1 bridge (WP14-EMU, S5 §14 `test:emu` lane).
# BridgeProc spawns the REAL bridge as the host does (`<python> -I -X utf8 bea_emu_bridge.py --mem-limit ...`, never
# detached, a temp cwd) and speaks NDJSON to it; fixtures() finds the gcc-built emulator fixtures (WP0's
# scripts/build-fixtures.mjs cache, or BEA_EMU_FIXTURE_DIR). Every process a test starts is tracked in OWNED and
# killed by kill_owned() (the shared machine runs unrelated Python work: only our own pids are ever touched).
# =================================================================================================
from __future__ import annotations

import json
import os
import queue
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE_DIR = os.path.dirname(HERE)
BRIDGE = os.path.join(BRIDGE_DIR, "bea_emu_bridge.py")
REPO = os.path.dirname(os.path.dirname(BRIDGE_DIR))
OWNED = []  # subprocess.Popen objects started by the tests


def engines_available():
    """None when unicorn/capstone/pefile import under this interpreter, else the named-skip reason."""
    try:
        import capstone  # noqa: F401
        import pefile  # noqa: F401
        import unicorn  # noqa: F401
    except Exception as e:  # noqa: BLE001
        return f"python with unicorn 2.1.x not found ({type(e).__name__}: {e})"
    return None


_FIXTURES = None


def fixtures():
    """The fixture manifest (dict) with absolute paths, or a string: the named-skip reason."""
    global _FIXTURES
    if _FIXTURES is not None:
        return _FIXTURES
    d = os.environ.get("BEA_EMU_FIXTURE_DIR")
    manifest = None
    if d:
        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["dir"] = d
    else:
        node = shutil.which("node")
        if node is None:
            _FIXTURES = "node not found (needed to build the gcc fixtures)"
            return _FIXTURES
        r = subprocess.run([node, os.path.join(REPO, "scripts", "build-fixtures.mjs"), "--json"], cwd=REPO,
                           capture_output=True, timeout=900)
        if r.returncode != 0 or not r.stdout.strip():
            _FIXTURES = f"fixtures unavailable: {r.stderr.decode('utf-8', 'replace').strip()[:300]}"
            return _FIXTURES
        manifest = json.loads(r.stdout.decode("utf-8"))
        if "unavailable" in manifest:
            _FIXTURES = f"gcc toolchain unavailable: {manifest['unavailable']}"
            return _FIXTURES
    for a in manifest["artifacts"].values():
        a["path"] = os.path.join(manifest["dir"], a["file"])
    _FIXTURES = manifest
    return manifest


def emu_fixture():
    m = fixtures()
    if isinstance(m, str):
        return m
    return m["artifacts"]["bea_emu_fixture"]


class BridgeProc:
    """One real bridge process."""

    def __init__(self, mem_limit=2 << 30, cache_dir=None, extra=(), cwd=None, startup_timeout=30.0):
        self.own_cwd = cwd is None
        self.cwd = cwd or tempfile.mkdtemp(prefix="bea-emu-test-")
        cmd = [sys.executable, "-I", "-X", "utf8", BRIDGE, "--mem-limit", str(mem_limit)]
        if cache_dir:
            cmd += ["--cache-dir", cache_dir]
        cmd += list(extra)
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PYTHON")}
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  cwd=self.cwd, env=env)
        OWNED.append(self.p)
        self.frames = queue.Queue()
        self.by_id = {}
        self.arrivals = []  # (id, "result" | "error" | "event") in arrival order
        self.cond = threading.Condition()
        self.stderr = bytearray()
        self.next_id = 0
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()
        self.ready = self.frames.get(timeout=startup_timeout)

    def _read(self):
        for raw in self.p.stdout:
            frame = json.loads(raw.decode("utf-8"))
            if "id" in frame and frame["id"] is not None:
                with self.cond:
                    self.by_id.setdefault(frame["id"], []).append(frame)
                    self.arrivals.append((frame["id"], next(k for k in ("result", "error", "event") if k in frame)))
                    self.cond.notify_all()
            else:
                self.frames.put(frame)
        with self.cond:
            self.cond.notify_all()

    def _drain(self):
        for chunk in iter(lambda: self.p.stderr.read(4096), b""):
            self.stderr += chunk[-65536:]

    def send(self, method, params=None, rid=None):
        if rid is None:
            self.next_id += 1
            rid = self.next_id
        self.raw(json.dumps({"id": rid, "method": method, "params": params or {}}).encode() + b"\n")
        return rid

    def raw(self, data):
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def wait(self, rid, timeout=60.0):
        """(final frame, [progress events]) for request `rid`."""
        end = time.monotonic() + timeout
        with self.cond:
            while True:
                frames = self.by_id.get(rid, [])
                final = next((f for f in frames if "result" in f or "error" in f), None)
                if final is not None:
                    return final, [f["event"] for f in frames if "event" in f]
                left = end - time.monotonic()
                if left <= 0 or self.p.poll() is not None and not frames:
                    raise TimeoutError(f"no final frame for request {rid}; stderr: {bytes(self.stderr)[-2000:]!r}")
                self.cond.wait(min(left, 0.5))

    def request(self, method, params=None, timeout=60.0):
        final, _events = self.wait(self.send(method, params), timeout)
        return final

    def result(self, method, params=None, timeout=60.0):
        f = self.request(method, params, timeout)
        if "error" in f:
            raise AssertionError(f"{method} failed: {f['error']}")
        return f["result"]

    def close(self, timeout=10.0):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            code = self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            code = self.p.wait(5)
        if self.own_cwd:
            shutil.rmtree(self.cwd, ignore_errors=True)
        return code


def kill_owned():
    for p in OWNED:
        if p.poll() is None:
            p.kill()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                pass


# ---------------------------------------------------------------- plan helpers (what TypeScript's classifier emits)
def f32(x):
    return hex(struct.unpack("<I", struct.pack("<f", x))[0])


def f64(x):
    return hex(struct.unpack("<Q", struct.pack("<d", x))[0])


def bits_f32(h):
    return struct.unpack("<f", struct.pack("<I", int(h, 16) & 0xFFFFFFFF))[0]


def bits_f64(h):
    return struct.unpack("<d", struct.pack("<Q", int(h, 16) & (2 ** 64 - 1)))[0]


def u64(v):
    return hex(v & (2 ** 64 - 1))


ARG_REGS_INT = ("rcx", "rdx", "r8", "r9")
ARG_REGS_XMM = ("xmm0", "xmm1", "xmm2", "xmm3")


def scalar_plan(target, kinds, returns):
    """Positional Win64 plan for scalar args: kinds like ["f32", "int", ...]; column i is "arg{i}"."""
    slots = []
    for i, k in enumerate(kinds):
        src = {"kind": "column", "column": f"arg{i}"}
        if i < 4:
            reg = ARG_REGS_XMM[i] if k in ("f32", "f64") else ARG_REGS_INT[i]
            slots.append({"reg": reg, "source": src})
        else:
            slots.append({"reg": "stack", "stackIndex": i - 4, "source": src})
    return {"target": target, "slots": slots, "returns": returns, "buffers": []}


def vectors(rows, offset=0):
    """rows: list of lists of hex strings -> VectorsWire with columns arg0..argN."""
    n = len(rows)
    cols = {}
    for i in range(len(rows[0]) if rows else 0):
        cols[f"arg{i}"] = [r[i] for r in rows]
    return {"offset": offset, "count": n, "columns": cols}


def options(**kw):
    o = {"maxInstructions": 1_000_000, "timeoutMs": 0, "mxcsr": 0x1F80, "fpcw": 0x027F, "faultPolicy": "stop",
         "trace": {"imports": "full", "blocks": False, "coverage": False, "countInstructions": False, "memory": "off",
                   "instructions": False, "disassemble": False, "maxEvents": 10000}}
    trace = kw.pop("trace", None)
    if trace:
        o["trace"].update(trace)
    o.update(kw)
    return o


def state(frm="baseline", writes=(), save_as=None):
    return {"from": frm, "writes": list(writes), "saveAs": save_as}
