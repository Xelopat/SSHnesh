import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("release", Path(__file__).resolve().parents[1] / "prototype/src/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        tree = tempfile.TemporaryDirectory()
        self.addCleanup(tree.cleanup)
        self.root = Path(tree.name).resolve()
        self.target = self.root / "service_runtime.py"
        self.target.write_bytes(b"old")
        # A non-root owner of the temporary project.
        patcher = patch.object(os, "geteuid", return_value=1000, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def archive(self, kind, entries):
        path = self.root / ("release." + kind)
        if kind == "zip":
            with zipfile.ZipFile(path, "w") as archive:
                for name, content in entries:
                    archive.writestr(name, content)
        else:
            with tarfile.open(path, "w:gz" if kind.endswith("gz") else "w") as archive:
                for name, content in entries:
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def apply(self, candidate):
        return release.install(self.root, *candidate, "qa.service", ["qa restart"])

    def test_formats_and_retry(self):
        for kind in ("zip", "tar", "tar.gz"):
            with self.subTest(kind=kind), patch.object(release,"health") as health:
                candidate = self.archive(kind, [("service_runtime.py",kind.encode()),("lib/new.py",b"new")])
                self.assertEqual(self.apply(candidate)["installed"],2)
                self.assertEqual(self.target.read_bytes(),kind.encode())
                self.assertEqual(self.apply(candidate)["sha256"],candidate[1])
                self.assertEqual(health.call_count,2)

    def test_python_module_timestamp(self):
        before = int(self.target.stat().st_mtime)
        with patch.object(release,"health"):
            self.apply(self.archive("zip",[("service_runtime.py",b"new")]))
        self.assertNotEqual(int(self.target.stat().st_mtime),before)

    def test_rollback(self):
        candidate = self.archive("tar.gz",[("lib/new.py",b"new"),("service_runtime.py",b"broken")])
        with patch.object(release,"health",side_effect=[RuntimeError("failed"),None]) as health:
            with self.assertRaisesRegex(RuntimeError,"Восстановлены"):
                self.apply(candidate)
        self.assertEqual(health.call_count,2)
        self.assertEqual(self.target.read_bytes(),b"old")
        self.assertFalse((self.root/"lib").exists())
        self.assertFalse(list(self.root.glob(".sshnesh-release-*")))

    def test_bad_path_and_hash(self):
        candidate = self.archive("zip",[("../outside",b"bad")])
        with self.assertRaises(ValueError):
            self.apply(candidate)
        with self.assertRaisesRegex(ValueError,"SHA256"):
            self.apply((candidate[0],"0"*64))
        self.assertEqual(self.target.read_bytes(),b"old")

    def test_preflight_denial(self):
        with patch.object(release,"service_info",return_value={"WorkingDirectory":str(self.root)}), patch.object(release,"restart_method",return_value=(None,"unconfirmed")):
            check, _ = release.preflight(self.root,"qa.service")
            self.assertFalse(check["ready"])
            self.assertTrue(check["writable"])
            self.assertEqual(check["restartPermission"],"unconfirmed")

if __name__=="__main__":
    unittest.main()
