#!/usr/bin/env python3
"""Archive rejection tests; no builds, guest execution or proof verification."""
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

script = Path(__file__).with_name("verify-returned.py")
spec = importlib.util.spec_from_file_location("verify_returned", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
commit = subprocess.check_output(["git", "-C", str(script.parent), "rev-parse", "HEAD"], text=True).strip()


class ArchiveRejections(unittest.TestCase):
    def reject(self, members, message):
        with tempfile.TemporaryDirectory(prefix="dcap-returned-test-") as temp:
            archive = Path(temp) / "bad.tar.gz"
            output = Path(temp) / "output"
            with tarfile.open(archive, "w:gz") as tar:
                for name, kind in members:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/tmp/not-a-dcap-extraction-target" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                    member.size = 1 if kind == tarfile.REGTYPE else 0
                    tar.addfile(member, io.BytesIO(b"x") if member.size else None)
            with self.assertRaisesRegex(ValueError, message):
                module.verify("risc0", archive, commit, output)
            self.assertFalse(output.exists())

    def test_parent_path(self):
        self.reject([("../outside", tarfile.REGTYPE)], "unsafe")

    def test_absolute_path(self):
        self.reject([("/tmp/outside", tarfile.REGTYPE)], "unsafe")

    def test_symlink(self):
        self.reject([("a.log", tarfile.SYMTYPE)], "links/special")

    def test_hardlink(self):
        self.reject([("a.log", tarfile.LNKTYPE)], "links/special")

    def test_device(self):
        self.reject([("a.log", tarfile.CHRTYPE)], "links/special")

    def test_duplicate(self):
        self.reject([("a.log", tarfile.REGTYPE)] * 2, "duplicate")

    def test_unexpected_file(self):
        self.reject([("run-me.sh", tarfile.REGTYPE)], "unexpected")

    def test_incomplete(self):
        self.reject([("a.log", tarfile.REGTYPE)], "incomplete")


if __name__ == "__main__":
    unittest.main()
