"""Exercise fail-closed native release source prerequisites without native hardware."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

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
        self.canonical_targets = readiness.EXPECTED_TARGETS
        manifest_fixture = patch.object(readiness, "EXPECTED_TARGETS", ("linux-x86_64",))
        manifest_fixture.start()
        self.addCleanup(manifest_fixture.stop)

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
        self.assertTrue(any("invalid target" in msg for msg in readiness.inspect(self.root)["issues"]))

    def test_duplicate_targets_are_rejected(self):
        (self.root / "packaging/release-targets.json").write_text(json.dumps(["linux-x86_64"] * 2))
        self.assertIn("duplicates", readiness.inspect(self.root)["issues"][0])


    def git_fixture(self):
        def git(*args):
            return subprocess.run(["git", *args], cwd=self.root,
                                  check=True, capture_output=True, text=True).stdout.strip()

        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=PQVPN Test",
            "-c", "user.email=release-test@example.invalid",
            "commit", "-qm", "initial release fixture")
        return git

    def test_issue_details_match_legacy_issues(self):
        report = readiness.inspect(self.root)
        self.assertEqual(report["issues"],
                         [issue["message"] for issue in report["issue_details"]])
        self.assertEqual(report["issue_details"][0]["code"], "gate_missing")
        self.assertEqual(report["issue_details"][0]["category"], "qualification")

    def test_matching_tag_with_missing_gate_is_only_qualification(self):
        git = self.git_fixture()
        git("tag", "v0.0.6-alpha-test")
        report = readiness.inspect(self.root, tag="v0.0.6-alpha-test")
        self.assertFalse(report["ready"])
        self.assertEqual([issue["code"] for issue in report["issue_details"]],
                         ["gate_missing"])
        self.assertTrue(all(issue["category"] == "qualification"
                            for issue in report["issue_details"]))

    def test_mismatched_tag_is_integrity_error_even_with_missing_gate(self):
        git = self.git_fixture()
        git("tag", "v0.0.6-alpha-test")
        report = readiness.inspect(self.root, tag="v0.0.6-alpha-OTHER")
        codes = {issue["code"] for issue in report["issue_details"]}
        self.assertIn("gate_missing", codes)
        self.assertIn("tag_version_mismatch", codes)
        self.assertIn("tag_commit_mismatch", codes)
        self.assertIn("integrity", {issue["category"]
                                    for issue in report["issue_details"]})

    def test_tag_pointing_to_older_commit_is_integrity_error(self):
        git = self.git_fixture()
        git("tag", "v0.0.6-alpha-test")
        (self.root / "new-file.txt").write_text("new revision\n")
        git("add", "new-file.txt")
        git("-c", "user.name=PQVPN Test",
            "-c", "user.email=release-test@example.invalid",
            "commit", "-qm", "new release fixture revision")
        report = readiness.inspect(self.root, tag="v0.0.6-alpha-test")
        self.assertIn("tag_commit_mismatch",
                      [issue["code"] for issue in report["issue_details"]])
        self.assertIn("integrity",
                      [issue["category"] for issue in report["issue_details"]])

    def test_duplicate_manifest_is_integrity_not_qualification(self):
        (self.root / "packaging/release-targets.json").write_text(
            json.dumps(["linux-x86_64", "linux-x86_64"]))
        report = readiness.inspect(self.root)
        self.assertIn("manifest_invalid",
                      [issue["code"] for issue in report["issue_details"]])
        self.assertIn("integrity",
                      [issue["category"] for issue in report["issue_details"]])

    def test_malformed_project_version_is_integrity_error(self):
        (self.root / "PQVPN_VERSION.txt").write_text("NOT_A_VERSION\n")
        report = readiness.inspect(self.root)
        self.assertIn("version_invalid",
                      [issue["code"] for issue in report["issue_details"]])
        self.assertIn("integrity",
                      [issue["category"] for issue in report["issue_details"]])


    def test_incomplete_canonical_manifest_is_integrity_failure(self):
        with patch.object(readiness, "EXPECTED_TARGETS", self.canonical_targets):
            report = readiness.inspect(self.root)
        self.assertFalse(report["integrity_valid"])
        self.assertIn("manifest_incomplete",
                      [entry["code"] for entry in report["issue_details"]])

    def test_missing_gate_does_not_invalidate_tag_integrity(self):
        report = readiness.inspect(self.root)
        self.assertFalse(report["ready"])
        self.assertTrue(report["integrity_valid"])
        self.assertFalse(report["qualification_ready"])

    def test_integrity_only_cli_allows_gate_gaps_but_not_bad_manifest(self):
        (self.root / "packaging/release-targets.json").write_text(
            json.dumps(list(self.canonical_targets)))
        tool = ROOT / "tools/check-release-readiness.py"
        good = subprocess.run(
            [sys.executable, str(tool), "--root", str(self.root), "--integrity-only"],
            text=True, capture_output=True, check=False)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        report = json.loads(good.stdout)
        self.assertFalse(report["ready"])
        self.assertTrue(report["integrity_valid"])
        bad = (self.root / "packaging/release-targets.json")
        bad.write_text(json.dumps(["linux-x86_64"]))
        rejected = subprocess.run(
            [sys.executable, str(tool), "--root", str(self.root), "--integrity-only"],
            text=True, capture_output=True, check=False)
        self.assertEqual(rejected.returncode, 1)

    def test_malformed_manifest_object_does_not_crash(self):
        (self.root / "packaging/release-targets.json").write_text('{"bad":1}')
        report = readiness.inspect(self.root)
        self.assertFalse(report["integrity_valid"])
        self.assertIn("manifest_invalid",
                      [entry["code"] for entry in report["issue_details"]])

    def test_invalid_calendar_date_is_integrity_failure(self):
        (self.root / "PQVPN_VERSION.txt").write_text("0.0.9-02302026-David0-beta-OTA")
        report = readiness.inspect(self.root)
        self.assertFalse(report["integrity_valid"])
        self.assertIn("invalid release calendar date", report["issues"])

if __name__ == "__main__":
    unittest.main()
