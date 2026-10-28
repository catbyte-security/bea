# bridge/emu/tests/test_build.py: scripts/build-bridge.mjs in an isolated copy of the package (its own build lock,
# its own dist/): version stamping, --check, and a manifest whose sha256 equals what the bridge reports about itself.
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import support

NODE = shutil.which("node")


@unittest.skipIf(NODE is None, "node not found")
class BuildBridgeTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bea-build-bridge-")
        repo = support.REPO
        os.makedirs(os.path.join(self.root, "scripts"))
        shutil.copy(os.path.join(repo, "scripts", "build-bridge.mjs"), os.path.join(self.root, "scripts"))
        shutil.copytree(os.path.join(repo, "scripts", "lib"), os.path.join(self.root, "scripts", "lib"))
        os.makedirs(os.path.join(self.root, "bridge", "emu"))
        for f in ("bea_emu_bridge.py", "requirements.lock", "README.md"):
            shutil.copy(os.path.join(support.BRIDGE_DIR, f), os.path.join(self.root, "bridge", "emu", f))
        with open(os.path.join(repo, "package.json"), encoding="utf-8") as fh:
            pkg = json.load(fh)
        pkg["version"] = "9.9.9-test"
        with open(os.path.join(self.root, "package.json"), "w", encoding="utf-8") as fh:
            json.dump(pkg, fh)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def node(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("BEA_LOCK_TOKEN")}
        return subprocess.run([NODE, os.path.join(self.root, "scripts", "build-bridge.mjs"), *args], cwd=self.root,
                              capture_output=True, text=True, timeout=120, env=env)

    def test_stamp_manifest_and_check(self):
        r = self.node("--check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("package version 9.9.9-test", r.stderr)
        r = self.node()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("stamped BRIDGE_VERSION", r.stderr)
        bridge = os.path.join(self.root, "bridge", "emu", "bea_emu_bridge.py")
        with open(bridge, encoding="utf-8") as fh:
            self.assertIn('BRIDGE_VERSION = "9.9.9-test"', fh.read())
        with open(os.path.join(self.root, "dist", "bridge-manifest.json"), encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual((m["schema"], m["protocol"], m["bridge_version"]),
                         ("bea.bridge-build/1", "bea-emu/0.1", "9.9.9-test"))
        self.assertEqual(m["engines"], {"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"})
        self.assertEqual(m["files"]["bea_emu_bridge.py"], m["sha256"])
        self.assertEqual(self.node("--check").returncode, 0)
        if support.engines_available() is None:
            p = subprocess.run([sys.executable, "-I", "-X", "utf8", bridge, "--probe"], capture_output=True,
                               timeout=60)
            probe = json.loads(p.stdout.decode().strip())
            self.assertEqual(probe["bridge"], {"version": "9.9.9-test", "sha256": m["sha256"]})
        with open(os.path.join(self.root, "bridge", "emu", "README.md"), "a", encoding="utf-8") as fh:
            fh.write("\nedited\n")
        r = self.node("--check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("stale", r.stderr)
