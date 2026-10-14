"""Exercise fail-closed native release source prerequisites without native hardware."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("readiness", ROOT / "tools/check-release-readiness.py")
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "packaging/gates").mkdir(parents=True)
        (self.root / "packaging/release-targets.json").write_text(json.dumps(["linux-x86_64"]))
        (self.root / "PQVPN_VERSION.txt").write_text("0.0.6-alpha-test\n")
        self.gate = self.root / "packaging/gates/linux-x86_64"

    def test_missing_gate_is_rejected(self):
        report = readiness.inspect(self.root)
        self.assertFalse(report["ready"])
        self.assertIn("missing", report["issues"][0])

    def test_non_executable_gate_is_rejected(self):
        self.gate.write_text("#!/bin/sh\nexit 1\n")
        self.assertIn("not executable", readiness.inspect(self.root)["issues"][0])

    def test_provisional_false_evidence_is_rejected(self):
        self.gate.write_text('#!/bin/sh\necho \'{"privileged_tunnel_e2e": false}\'\n')
        self.gate.chmod(0o755)
        report = readiness.inspect(self.root)
        self.assertFalse(report["ready"])
        self.assertIn("privileged_tunnel_e2e", report["issues"][0])

    def test_invalid_target_cannot_escape_gate_directory(self):
        (self.root / "packaging/release-targets.json").write_text(json.dumps(["../elsewhere"]))
        self.assertIn("invalid target", readiness.inspect(self.root)["issues"][0])

    def test_duplicate_targets_are_rejected(self):
        (self.root / "packaging/release-targets.json").write_text(json.dumps(["linux-x86_64"] * 2))
        self.assertIn("duplicates", readiness.inspect(self.root)["issues"][0])


if __name__ == "__main__":
    unittest.main()
