"""Unit tests for the Linux distribution artifact gate.

Synthetic archives exercise fail-closed checks; native distro tooling and actual
compiled PQVPN payloads are tested by the Linux CI matrix.
"""
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "distribution_gate", ROOT / "tools/verify-distribution-artifact.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

VERSION = "0.6-beta-10142026-David0-OTA"


def elf(machine):
    buf = bytearray(20)
    buf[0:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", buf, 18, machine)
    return bytes(buf)


class DistributionArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.package = self.root / f"PQVPN-{VERSION}-linux-x86_64.tar.gz"

    def make_archive(self, node=None, entry=None):
        with tarfile.open(self.package, "w:gz") as tf:
            info = tarfile.TarInfo(entry or f"PQVPN-{VERSION}-linux-x86_64/bin/pqvpn_node")
            payload = elf(62) if node is None else node
            info.mode = 0o755
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

    def test_tar_accepts_correct_elf(self):
        self.make_archive()
        self.assertTrue(gate.verify("linux-x86_64", self.package, VERSION)["artifact_verified"])

    def test_wrong_architecture_rejected(self):
        self.make_archive(node=elf(183))
        with self.assertRaisesRegex(gate.GateError, "Wrong ELF architecture"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_unsafe_path_rejected(self):
        self.make_archive(entry="../bin/pqvpn_node")
        with self.assertRaisesRegex(gate.GateError, "Unsafe archive entry"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_missing_node_rejected(self):
        self.make_archive(entry=f"PQVPN-{VERSION}-linux-x86_64/bin/other")
        with self.assertRaisesRegex(gate.GateError, "packaged pqvpn_node"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_wrong_version_rejected(self):
        self.make_archive()
        with self.assertRaisesRegex(gate.GateError, "versioned tar.gz"):
            gate.verify("linux-x86_64", self.package, "0.6-beta-10152026-Different")

    def test_missing_package_rejected(self):
        with self.assertRaises(FileNotFoundError):
            gate.verify("linux-x86_64", self.root / "missing.tar.gz", VERSION)

    def test_incomplete_elf_rejected(self):
        self.make_archive(node=b"not-a-valid-elf")
        with self.assertRaisesRegex(gate.GateError, "ELF"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_rpm_exact_version_and_architecture(self):
        package = self.root / "pqvpn.rpm"
        with patch.object(gate, "run", side_effect=[
            "pqvpn\n0.6.0\n0.beta.10142026.David0.OTA\nx86_64",
            "/usr/bin/pqvpn_node",
        ]):
            gate.check_rpm(package, VERSION, "x86_64")

    def test_rpm_bad_release_rejected(self):
        package = self.root / "pqvpn.rpm"
        with patch.object(gate, "run", return_value=
                          "pqvpn\n0.6.0\n1\nx86_64"):
            with self.assertRaisesRegex(gate.GateError, "RPM version"):
                gate.check_rpm(package, VERSION, "x86_64")

    def test_arch_native_metadata(self):
        package = self.root / "pqvpn.pkg.tar.zst"
        with patch.object(gate, "run", side_effect=[
            "pkgname = pqvpn\n"
            "pkgver = 0.6.0.beta.10142026.David0.OTA-1\n"
            "arch = x86_64",
            "usr/bin/pqvpn_node",
        ]), patch.object(gate, "version_with_bash",
                         return_value="0.6.0.beta.10142026.David0.OTA"):
            gate.check_arch(package, VERSION, "x86_64")

    def test_arch_bad_architecture_rejected(self):
        package = self.root / "pqvpn.pkg.tar.zst"
        with patch.object(gate, "run", return_value=
                          "pkgname = pqvpn\npkgver = 0.6.0.beta.10142026.David0.OTA-1\narch = aarch64"), \
             patch.object(gate, "version_with_bash",
                          return_value="0.6.0.beta.10142026.David0.OTA"):
            with self.assertRaisesRegex(gate.GateError, "Arch package"):
                gate.check_arch(package, VERSION, "x86_64")

    def test_appimage_wrong_elf_architecture_rejected(self):
        package = self.root / f"PQVPN-{VERSION}-appimage-x86_64.AppImage"
        package.write_bytes(elf(183))
        with self.assertRaisesRegex(gate.GateError, "Wrong ELF"):
            gate.check_appimage(package, VERSION, "x86_64")

    def test_bad_version_rejected(self):
        self.make_archive()
        with self.assertRaisesRegex(gate.GateError, "Unsafe"):
            gate.verify("linux-x86_64", self.package, "../../invalid")


if __name__ == "__main__":
    unittest.main()
