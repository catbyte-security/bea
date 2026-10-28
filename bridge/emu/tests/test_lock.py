# bridge/emu/tests/test_lock.py: requirements.lock is exactly the S5 §6.5 text, and its hashes re-derive from the
# vendored PyPI snapshot (tests/pypi-pins.json), so a lock edit cannot drift silently (S5 §6.5 "build test").
from __future__ import annotations

import json
import os
import re
import unittest

from support import BRIDGE, BRIDGE_DIR, HERE

S5_LOCK = """# BEA emulator bridge: exact pins, binary wheels only, hash-checked (win_amd64 + manylinux x86_64)
unicorn==2.1.4 \\
    --hash=sha256:d7107500c64ce5c168fbff6bef9485b5db1350050036f4cea568650cf8bdbdf5 \\
    --hash=sha256:9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239
capstone==5.0.9 \\
    --hash=sha256:732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0 \\
    --hash=sha256:273fd8d747d2e35c88f91450be51a603ecfaafb00d96d9f315dcb8689c86193e
pefile==2024.8.26 \\
    --hash=sha256:76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f
"""


def parse_lock(text):
    pins = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^ \\]+)", line)
        if m:
            current = m.group(1).lower()
            pins[current] = {"version": m.group(2), "hashes": []}
        for h in re.findall(r"--hash=sha256:([0-9a-f]{64})", line):
            pins[current]["hashes"].append(h)
    return pins


class LockTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(BRIDGE_DIR, "requirements.lock"), "rb") as fh:
            self.raw = fh.read()
        with open(os.path.join(HERE, "pypi-pins.json"), encoding="utf-8") as fh:
            self.pins = json.load(fh)

    def test_lock_is_the_s5_text_byte_for_byte(self):
        self.assertNotIn(b"\r", self.raw)
        self.assertEqual(self.raw.decode("utf-8"), S5_LOCK)

    def test_hashes_rederive_from_the_vendored_pypi_snapshot(self):
        lock = parse_lock(self.raw.decode("utf-8"))
        self.assertEqual(set(lock), {p["name"] for p in self.pins["packages"]})
        for pkg in self.pins["packages"]:
            entry = lock[pkg["name"]]
            self.assertEqual(entry["version"], pkg["version"], pkg["name"])
            wheels = [f for f in pkg["files"] if f["filename"].endswith(".whl")]
            self.assertTrue(wheels)
            self.assertTrue(all("-cp37-abi3-" in f["filename"] or "-py3-none-" in f["filename"] for f in wheels))
            self.assertEqual(sorted(entry["hashes"]), sorted(f["sha256"] for f in wheels), pkg["name"])

    def test_bridge_pins_match_the_lock(self):
        with open(BRIDGE, encoding="utf-8") as fh:
            src = fh.read()
        m = re.search(r'^EXACT_PINS = \{"unicorn": "([^"]+)", "capstone": "([^"]+)", "pefile": "([^"]+)"\}$', src, re.M)
        self.assertIsNotNone(m)
        lock = parse_lock(self.raw.decode("utf-8"))
        self.assertEqual((lock["unicorn"]["version"], lock["capstone"]["version"], lock["pefile"]["version"]),
                         m.groups())


if __name__ == "__main__":
    unittest.main()
