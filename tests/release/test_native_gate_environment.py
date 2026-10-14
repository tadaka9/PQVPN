"""Native gate environment checks are diagnostic and never release evidence."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "gate_environment", ROOT / "tools/verify-native-gate-environment.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class NativeGateEnvironmentTests(unittest.TestCase):
    def test_exact_target_manifest_set(self):
        import json
        manifest = set(json.loads((ROOT / "packaging/release-targets.json").read_text()))
        self.assertEqual(manifest, set(probe.TARGETS))

    def test_linux_native_capabilities_are_not_qualification(self):
        report = probe.inspect(
            "linux-x86_64", os_name="Linux", machine="x86_64",
            tool_lookup=lambda _: "/usr/bin/ip", elevated=True, tun_exists=True)
        self.assertTrue(report["environment_ready"])
        self.assertIs(report["qualification_passed"], False)

    def test_absent_kernel_device_fails(self):
        report = probe.inspect(
            "deb-arm64", os_name="Linux", machine="aarch64",
            tool_lookup=lambda _: "/usr/bin/tool", elevated=True, tun_exists=False)
        self.assertFalse(report["environment_ready"])
        self.assertIn("tun_missing", [x["code"] for x in report["blockers"]])

    def test_non_privileged_linux_fails(self):
        report = probe.inspect(
            "linux-arm64", os_name="Linux", machine="arm64",
            tool_lookup=lambda _: "/usr/bin/ip", elevated=False, tun_exists=True)
        self.assertFalse(report["environment_ready"])
        self.assertIn("not_elevated", [x["code"] for x in report["blockers"]])

    def test_wrong_cpu_fails_even_when_tools_exist(self):
        report = probe.inspect(
            "macos-arm64", os_name="Darwin", machine="x86_64",
            tool_lookup=lambda _: "/usr/bin/tool", elevated=True)
        self.assertFalse(report["environment_ready"])
        self.assertIn("wrong_arch", [x["code"] for x in report["blockers"]])

    def test_wrong_os_fails(self):
        report = probe.inspect(
            "windows-x86_64", os_name="Linux", machine="x86_64",
            tool_lookup=lambda _: "tool", elevated=True)
        self.assertFalse(report["environment_ready"])
        self.assertIn("wrong_os", [x["code"] for x in report["blockers"]])

    def test_missing_native_signing_tool_fails(self):
        report = probe.inspect(
            "windows-arm64", os_name="Windows", machine="ARM64",
            tool_lookup=lambda x: None if x == "signtool.exe" else x,
            elevated=True)
        self.assertFalse(report["environment_ready"])
        self.assertTrue(any("signtool" in x["reason"] for x in report["blockers"]))
        self.assertIs(report["qualification_passed"], False)

    def test_linux_rpm_builder_needed(self):
        report = probe.inspect(
            "rpm-x86_64", os_name="Linux", machine="amd64",
            tool_lookup=lambda tool: None if tool == "rpmbuild" else "/usr/bin/tool",
            elevated=True, tun_exists=True)
        self.assertFalse(report["environment_ready"])
        self.assertTrue(any("rpmbuild" in x["reason"] for x in report["blockers"]))

    def test_not_a_forged_evidence_report(self):
        report = probe.inspect(
            "linux-x86_64", os_name="Linux", machine="x86_64",
            tool_lookup=lambda _: "/usr/bin/tool", elevated=True, tun_exists=True)
        self.assertNotIn("passed", report)
        self.assertNotIn("platform_signature_verified", report)
        self.assertNotIn("privileged_tunnel_e2e", report)
        self.assertIn("host preconditions ONLY", report["scope"])

    def test_unknown_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            probe.inspect("linux-pc-unknown")


if __name__ == "__main__":
    unittest.main()
