#!/usr/bin/env python3
"""CLI integration: real signing, file tampering and no-clobber behavior."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "--locked", "-q", "-p", "initrdctl"], cwd=ROOT, check=True)
        cls.exe = ROOT / "target/debug/initrdctl"

    def run_tool(self, *args, success=True):
        r = subprocess.run([str(self.exe), *map(str, args)], capture_output=True)
        self.assertEqual(r.returncode == 0, success, r.stderr.decode())
        return r

    def test_bare_output_filename(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "kernel").write_bytes(b"kernel")
            (p / "initrd").write_bytes(b"initrd")
            for args in (("keygen", "key", "public"),
                         ("sign", "key", "kernel", "initrd", "quiet", "manifest"),
                         ("verify", "manifest", "public", "kernel", "initrd")):
                result = subprocess.run([str(self.exe), *args], cwd=p, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_signatures_hashes_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "kernel").write_bytes(b"fixture-kernel")
            (p / "initrd").write_bytes(b"fixture-initrd")
            self.run_tool("keygen", p / "key", p / "public")
            key = (p / "key").read_bytes()
            self.run_tool("keygen", p / "key", p / "public", success=False)
            self.assertEqual((p / "key").read_bytes(), key)
            self.run_tool("sign", p / "key", p / "kernel", p / "initrd", "quiet", p / "manifest")
            self.run_tool("verify", p / "manifest", p / "public", p / "kernel", p / "initrd")
            for target in ("kernel", "initrd", "manifest"):
                original = (p / target).read_bytes()
                changed = bytearray(original)
                changed[0] ^= 1
                (p / target).write_bytes(changed)
                self.run_tool("verify", p / "manifest", p / "public", p / "kernel", p / "initrd", success=False)
                (p / target).write_bytes(original)
            self.run_tool("keygen", p / "other-key", p / "other-public")
            self.run_tool("verify", p / "manifest", p / "other-public", p / "kernel", p / "initrd", success=False)
            self.run_tool("enroll", success=False)
            self.assertFalse((p / "sealed.bin").exists())

if __name__ == "__main__":
    unittest.main()

