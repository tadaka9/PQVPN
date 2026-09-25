"""Exercise the real child-process boundary without running the VPN suite."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "tools" / "pqvpn_hard_kernel.py"
SPEC = importlib.util.spec_from_file_location("pqvpn_hard_kernel", SOURCE)
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


class NestedCTestTests(unittest.TestCase):
    def test_parallelism_is_bounded_and_gate_is_excluded(self):
        build = Path("build with spaces")
        failed = subprocess.CompletedProcess([], 8, "a regression failed")
        with patch.dict(os.environ, {"CTEST_PARALLEL_LEVEL": "64"}), \
                patch.object(gate.subprocess, "run", return_value=failed) as run:
            result = gate.run_ctest(build)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--parallel") + 1], "2")
        self.assertEqual(command[command.index("-LE") + 1], "hardening")
        self.assertEqual(command[command.index("--test-dir") + 1], str(build))
        self.assertIn("--output-on-failure", command)
        self.assertIs(result, failed)
        self.assertEqual(result.returncode, 8)
        self.assertEqual(run.call_args.kwargs["cwd"], gate.ROOT)


if __name__ == "__main__":
    unittest.main()
