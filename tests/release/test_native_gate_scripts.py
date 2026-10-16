"""Guard provisional Linux native gates against accidental qualification claims."""
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "release_preflight", ROOT / "tools/check-release-readiness.py")
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


class NativeGateSourceTests(unittest.TestCase):
    def test_both_linux_architectures_have_executable_bash_gates(self):
        for arch in ("x86_64", "arm64"):
            with self.subTest(arch=arch):
                driver = ROOT / "packaging/gates" / f"linux-{arch}"
                self.assertTrue(driver.is_file())
                self.assertTrue(driver.stat().st_mode & 0o111)
                result = subprocess.run(["bash", "-n", str(driver)],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_both_linux_drivers_are_explicitly_unqualified(self):
        report = readiness.inspect(ROOT)
        for target in ("linux-x86_64", "linux-arm64"):
            for key in ("privileged_tunnel_e2e", "bidirectional_traffic",
                        "route_dns_rollback", "platform_signature_verified",
                        "provenance_verified"):
                with self.subTest(target=target, check=key):
                    self.assertTrue(any(
                        issue["code"] == "gate_unverified" and
                        target in issue["message"] and
                        key in issue["message"]
                        for issue in report["issue_details"]))
        self.assertFalse(report["ready"])

    def test_native_debian_upgrade_script_is_safe_and_syntax_valid(self):
        script = ROOT / "tests/release/native-deb-lifecycle.sh"
        result = subprocess.run(["bash", "-n", str(script)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = script.read_text()
        for required in ("SHA256SUMS", "sha256(", "dpkg --compare-versions",
                         "apt-get install", "apt-get remove",
                         "apt-get purge", "--force-confold", "trap cleanup EXIT"):
            with self.subTest(required=required):
                self.assertIn(required, text)
        self.assertNotIn("privileged_tunnel_e2e\": True", text)

    def test_linux_native_scripts_run_real_source_regressions(self):
        for arch in ("x86_64", "arm64"):
            source = (ROOT / "packaging/gates" / f"linux-{arch}").read_text()
            self.assertIn("test_e2e_egress", source)
            self.assertIn("test_route_transaction", source)
            self.assertIn("verify-distribution-artifact.py", source)
            self.assertIn('"passed": False', source)
            self.assertIn("exit 1", source)

    def test_mainnet_updater_accepts_protected_gui_archives(self):
        updater = ROOT / "packaging/linux/pqvpn-mainnet-update"
        result = subprocess.run(["bash", "-n", str(updater)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('platform + "-desktop-test.tar.gz"', updater.read_text())
        service = (ROOT / "packaging/linux/pqvpn-mainnet.service").read_text()
        self.assertIn("--no-tunnel", service)


if __name__ == "__main__":
    unittest.main()
