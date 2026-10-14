"""Fail-closed distribution artifact tests; no package payload is executed."""
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
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
LEGACY = "alpha-0.6-10142026-cybergun"


def elf(machine=62, *, truncated=False):
    """Small structurally valid ELF64/PIE fixture with one executable LOAD."""
    buf = bytearray(256)
    buf[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHIQQQIHHHHHH", buf, 16, 3, machine, 1,
                     0x1000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", buf, 64, 1, 5, 128, 0x1000, 0,
                     128, 128, 0x1000)
    return bytes(buf[:20] if truncated else buf)


class DistributionArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / f"PQVPN-{VERSION}-linux-x86_64.tar.gz"
        self.node_name = f"PQVPN-{VERSION}-linux-x86_64/bin/pqvpn_node"

    def make_archive(self, node=None, name=None, mode=0o755, extra=None):
        with tarfile.open(self.package, "w:gz") as archive:
            def add(path, payload, file_mode):
                item = tarfile.TarInfo(path)
                item.mode = file_mode
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            add(name if name is not None else self.node_name,
                elf() if node is None else node, mode)
            if extra:
                add(extra, b"additional", 0o644)

    def test_valid_tar_with_trusted_binary(self):
        self.make_archive()
        known = self.root / "known-node"
        known.write_bytes(elf())
        result = gate.verify("linux-x86_64", self.package, VERSION,
                             trusted_node=known)
        self.assertTrue(result["artifact_verified"])

    def test_tampered_binary_fails_known_build_match(self):
        self.make_archive()
        known = self.root / "known-node"
        known.write_bytes(elf() + b"changed")
        with self.assertRaisesRegex(gate.GateError, "differs"):
            gate.verify("linux-x86_64", self.package, VERSION, trusted_node=known)

    def test_wrong_elf_arch(self):
        self.make_archive(node=elf(183))
        with self.assertRaisesRegex(gate.GateError, "Wrong ELF architecture"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_header_only_elf_is_not_executable(self):
        self.make_archive(node=elf(truncated=True))
        with self.assertRaisesRegex(gate.GateError, "implausible|ELF"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_nonexecuting_elf_no_mapped_entry(self):
        node = bytearray(elf())
        struct.pack_into("<Q", node, 24, 0x9000)
        self.make_archive(node=bytes(node))
        with self.assertRaisesRegex(gate.GateError, "mapped executable"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_missing_executable_mode(self):
        self.make_archive(mode=0o644)
        with self.assertRaisesRegex(gate.GateError, "not an executable"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_path_traversal_rejected(self):
        self.make_archive(name="../bin/pqvpn_node")
        with self.assertRaisesRegex(gate.GateError, "Unsafe archive entry"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_incorrect_tar_root_rejected(self):
        self.make_archive(name="wrong-root/bin/pqvpn_node")
        with self.assertRaisesRegex(gate.GateError, "Unexpected archive root"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_incorrect_tar_filename_rejected(self):
        self.make_archive()
        wrong = self.root / f"other-{VERSION}.tar.gz"
        self.package.rename(wrong)
        with self.assertRaisesRegex(gate.GateError, "exact target-specific"):
            gate.verify("linux-x86_64", wrong, VERSION)

    def test_node_at_wrong_path_rejected(self):
        self.make_archive(name=f"PQVPN-{VERSION}-linux-x86_64/other/bin/pqvpn_node")
        with self.assertRaisesRegex(gate.GateError, "exactly one packaged"):
            gate.verify("linux-x86_64", self.package, VERSION)

    def test_missing_file_rejected(self):
        with self.assertRaises(FileNotFoundError):
            gate.verify("linux-x86_64", self.root / "missing.tar.gz", VERSION)

    def test_bad_version_rejected(self):
        self.make_archive()
        with self.assertRaisesRegex(gate.GateError, "Unsafe"):
            gate.verify("linux-x86_64", self.package, "../../invalid")

    def test_rpm_exact_beta_metadata(self):
        with patch.object(gate, "run", side_effect=[
            "pqvpn\n0.6.0\n0.beta.10142026.David0.OTA\nx86_64",
            "/usr/bin/pqvpn_node",
        ]):
            gate.check_rpm(self.root / "candidate.rpm", VERSION, "x86_64")

    def test_rpm_legacy_alpha_metadata(self):
        with patch.object(gate, "run", side_effect=[
            "pqvpn\n0.6.0\n0.alpha.10142026.cybergun\nx86_64",
            "/usr/bin/pqvpn_node",
        ]):
            gate.check_rpm(self.root / "candidate.rpm", LEGACY, "x86_64")

    def test_rpm_bad_release_rejected(self):
        with patch.object(gate, "run", return_value="pqvpn\n0.6.0\n1\nx86_64"):
            with self.assertRaisesRegex(gate.GateError, "RPM version"):
                gate.check_rpm(self.root / "candidate.rpm", VERSION, "x86_64")

    def test_arch_metadata(self):
        with patch.object(gate, "run", side_effect=[
            "pkgname = pqvpn\npkgver = 0.6.0.beta.10142026.David0.OTA-1\narch = x86_64",
            "usr/bin/pqvpn_node",
        ]), patch.object(gate, "version_with_bash",
                         return_value="0.6.0.beta.10142026.David0.OTA"):
            gate.check_arch(self.root / "candidate.pkg.tar.zst", VERSION, "x86_64")

    def test_arch_wrong_cpu_rejected(self):
        with patch.object(gate, "run", return_value=
                          "pkgname = pqvpn\npkgver = 0.6.0.beta.10142026.David0.OTA-1\narch = aarch64"), \
             patch.object(gate, "version_with_bash",
                          return_value="0.6.0.beta.10142026.David0.OTA"):
            with self.assertRaisesRegex(gate.GateError, "Arch package"):
                gate.check_arch(self.root / "candidate.pkg.tar.zst", VERSION, "x86_64")

    def test_appimage_wrong_cpu_rejected(self):
        package = self.root / f"PQVPN-{VERSION}-appimage-x86_64.AppImage"
        package.write_bytes(elf(183))
        with self.assertRaisesRegex(gate.GateError, "Wrong ELF"):
            gate.check_appimage(package, VERSION, "x86_64")

    def test_appimage_never_executes_itself(self):
        package = self.root / f"PQVPN-{VERSION}-appimage-x86_64.AppImage"
        package.write_bytes(elf())
        with patch.object(gate, "find_squashfs_offset", return_value=4096), \
             patch.object(gate, "run", return_value=
                          "squashfs-root/AppRun\nsquashfs-root/usr/bin/pqvpn_node") as run, \
             patch.object(gate, "run_binary_limited", return_value=elf()) as cat:
            gate.check_appimage(package, VERSION, "x86_64")
        self.assertEqual(run.call_args.args[:3], ("unsquashfs", "-l", "-o"))
        self.assertEqual(cat.call_args.args[0:2], ("unsquashfs", "-cat"))

    def test_appimage_missing_node_rejected(self):
        package = self.root / f"PQVPN-{VERSION}-appimage-x86_64.AppImage"
        package.write_bytes(elf())
        with patch.object(gate, "find_squashfs_offset", return_value=4096), \
             patch.object(gate, "run", return_value="squashfs-root/AppRun"):
            with self.assertRaisesRegex(gate.GateError, "lacks AppRun"):
                gate.check_appimage(package, VERSION, "x86_64")

    def make_deb_stream(self, malicious=False):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            def entry(path, payload=b"", mode=0o644, link=None):
                item = tarfile.TarInfo(path)
                item.mode = mode
                if link is not None:
                    item.type = tarfile.SYMTYPE
                    item.linkname = link
                    archive.addfile(item)
                else:
                    item.size = len(payload)
                    archive.addfile(item, io.BytesIO(payload))
            entry("../outside-file" if malicious else
                  "./usr/lib/pqvpn/bin/pqvpn_node", elf(), 0o755)
            entry("./etc/pqvpn/config.json.example", b"{}")
            entry("./usr/bin/pqvpn_node", link="../lib/pqvpn/bin/pqvpn_node")
        buffer.seek(0)
        return buffer

    def test_deb_stream_inspection_without_filesystem_extraction(self):
        fake = unittest.mock.MagicMock()
        fake.stdout = self.make_deb_stream()
        fake.wait.return_value = 0
        fake.poll.return_value = 0
        with patch.object(gate, "run", return_value=
                          "pqvpn\n0.6.0~beta-10142026-David0-OTA\namd64"), \
             patch.object(gate, "version_with_bash",
                          return_value="0.6.0~beta-10142026-David0-OTA"), \
             patch.object(gate.subprocess, "Popen", return_value=fake) as popen:
            gate.check_deb(self.root / "candidate.deb", VERSION, "x86_64")
        self.assertEqual(popen.call_args.args[0][1], "--fsys-tarfile")

    def test_deb_path_escape_rejected_before_writing(self):
        fake = unittest.mock.MagicMock()
        fake.stdout = self.make_deb_stream(malicious=True)
        fake.wait.return_value = 0
        fake.poll.return_value = 0
        with patch.object(gate, "run", return_value=
                          "pqvpn\n0.6.0~beta-10142026-David0-OTA\namd64"), \
             patch.object(gate, "version_with_bash",
                          return_value="0.6.0~beta-10142026-David0-OTA"), \
             patch.object(gate.subprocess, "Popen", return_value=fake):
            with self.assertRaisesRegex(gate.GateError, "Unsafe archive entry"):
                gate.check_deb(self.root / "candidate.deb", VERSION, "x86_64")


if __name__ == "__main__":
    unittest.main()
