"""Regression tests for cryptographically bound native qualification artifacts.

Fixtures exercise only the verifier's fail-closed data contract. They do not
represent successful live VPN, signature or native environment testing.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "evidence_validator", ROOT / "tools/validate-functional-evidence.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

SHA = "0123456789abcdef" * 2 + "01234567"
VERSION = "0.0.9-10152026-David0-beta-OTA"
TARGET = "linux-x86_64"


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


class FunctionalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.candidates = self.root / "candidates"
        self.evidence.mkdir()
        self.candidates.mkdir()
        self.payload = self.candidates / f"PQVPN-{VERSION}-linux-x86_64.tar.gz"
        self.payload.write_bytes(b"fixture release candidate - not a real executable")
        self.log = self.evidence / "verification.log"
        self.log.write_bytes(b"fixture log - no real native tests were performed\n")
        self.obj = {
            "schema": 2, "target": TARGET, "commit_sha": SHA,
            "version": VERSION, "candidate_name": self.payload.name,
            "candidate_size": self.payload.stat().st_size,
            "candidate_sha256": sha(self.payload.read_bytes()),
            "verification_log_sha256": sha(self.log.read_bytes()),
            "runner_os": "Linux", "runner_arch": "X64",
            **{key: True for key in validator.CHECKS},
        }
        self.save()

    def save(self):
        (self.evidence / "evidence.json").write_text(json.dumps(self.obj))

    def verify(self):
        return validator.inspect(self.evidence, self.candidates, TARGET, SHA, VERSION)

    def test_exact_byte_contract_is_structurally_valid(self):
        self.assertTrue(self.verify()["verified"])

    def test_one_false_functional_check_rejected(self):
        self.obj["privileged_tunnel_e2e"] = False
        self.save()
        with self.assertRaisesRegex(validator.EvidenceError, "privileged_tunnel_e2e"):
            self.verify()

    def test_integer_one_cannot_impersonate_boolean_true(self):
        self.obj["platform_signature_verified"] = 1
        self.save()
        with self.assertRaisesRegex(validator.EvidenceError, "platform_signature_verified"):
            self.verify()

    def test_wrong_exact_commit_rejected(self):
        with self.assertRaisesRegex(validator.EvidenceError, "commit_sha"):
            validator.inspect(self.evidence, self.candidates, TARGET, "f" * 40, VERSION)

    def test_candidate_tampering_rejected(self):
        self.payload.write_bytes(self.payload.read_bytes() + b"modified")
        with self.assertRaisesRegex(validator.EvidenceError, "candidate_size"):
            self.verify()

    def test_verification_log_tampering_rejected(self):
        self.log.write_bytes(self.log.read_bytes() + b"modified")
        with self.assertRaisesRegex(validator.EvidenceError, "verification_log_sha256"):
            self.verify()

    def test_runner_mismatch_rejected(self):
        self.obj["runner_arch"] = "ARM64"
        self.save()
        with self.assertRaisesRegex(validator.EvidenceError, "runner OS/CPU"):
            self.verify()

    def test_extra_candidate_rejected(self):
        (self.candidates / "unexpected").write_text("wrong")
        with self.assertRaisesRegex(validator.EvidenceError, "exactly one candidate"):
            self.verify()

    def test_missing_evidence_field_rejected(self):
        del self.obj["runtime_dependencies_verified"]
        self.save()
        with self.assertRaisesRegex(validator.EvidenceError, "runtime_dependencies_verified"):
            self.verify()

    def test_malformed_json_rejected(self):
        (self.evidence / "evidence.json").write_text("{")
        with self.assertRaisesRegex(validator.EvidenceError, "Malformed"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
