"""Regression tests for the deterministic PQVPN update container."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("update_package", ROOT / "packaging/update/build-package.py")
update_package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update_package)


class UpdatePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "PQVPN-test~alpha-windows-x64.msi"
        self.payload.write_bytes(b"native installer bytes\n" * 32)

    def test_build_verify_and_extract(self):
        package = self.root / "PQVPN-test-windows-x86_64.pqvpnpkg"
        update_package.build(self.payload, "alpha-0.6-10142026-cybergun", "windows-x86_64", package)
        extracted = self.root / "extracted"
        manifest = update_package.verify(package, extracted)
        self.assertEqual(manifest["install_mode"], "msi")
        self.assertEqual((extracted / self.payload.name).read_bytes(), self.payload.read_bytes())

    def test_build_is_deterministic(self):
        first, second = self.root / "first.pqvpnpkg", self.root / "second.pqvpnpkg"
        update_package.build(self.payload, "0.7.0", "windows-x86_64", first)
        update_package.build(self.payload, "0.7.0", "windows-x86_64", second)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_corrupt_payload_is_rejected(self):
        package = self.root / "update.pqvpnpkg"
        update_package.build(self.payload, "0.7.0", "windows-x86_64", package)
        damaged = bytearray(package.read_bytes())
        damaged[-1] ^= 1
        package.write_bytes(damaged)
        with self.assertRaisesRegex(ValueError, "checksum"):
            update_package.verify(package)

    def test_unsafe_metadata_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe version"):
            update_package.build(self.payload, "../bad", "windows-x86_64", self.root / "bad.pqvpnpkg")
        with self.assertRaisesRegex(ValueError, "unsafe target"):
            update_package.build(self.payload, "0.7.0", "../windows", self.root / "bad.pqvpnpkg")


if __name__ == "__main__":
    unittest.main()
