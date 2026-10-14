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

    def test_bad_version_rejected(self):
        self.make_archive()
        with self.assertRaisesRegex(gate.GateError, "Unsafe"):
            gate.verify("linux-x86_64", self.package, "../../invalid")


if __name__ == "__main__":
    unittest.main()
