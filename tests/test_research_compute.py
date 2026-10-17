import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / "packaging/linux/pqvpn-research-compute"
loader = importlib.machinery.SourceFileLoader("research_compute", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class ResearchComputeTests(unittest.TestCase):
    def test_parses_and_classifies_only_trusted_attached_projects(self):
        projects = module.parse_projects("""1) -----------
   master URL: https://einsteinathome.org/
   project name: Einstein@Home
   suspended via GUI: no
2) -----------
   master URL: https://evil.invalid/rosetta
   project name: Rosetta clone
   suspended via GUI: yes
""")
        self.assertEqual(len(projects), 2)
        self.assertTrue(module.matches_topic(projects[0], "astronomy"))
        self.assertFalse(module.matches_topic(projects[1], "medicine"))

    def test_override_is_strictly_one_percent_cpu_and_gpu_off(self):
        xml = module.make_override()
        self.assertIn(module.MARKER, xml)
        self.assertIn("<cpu_usage_limit>1.0</cpu_usage_limit>", xml)
        self.assertIn("<run_on_batteries>0</run_on_batteries>", xml)
        self.assertNotIn("account", xml.lower())

    def test_atomic_state_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            module.atomic_write(path, "{}\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_reward_requires_success_and_is_deduplicable(self):
        tasks = module.parse_old_tasks("""1) -----------
   project URL: https://einsteinathome.org/
   result name: einstein_001
   exit status: 0
   completed time: 1792230000
2) -----------
   project URL: https://einsteinathome.org/
   result name: einstein_failed
   exit status: 1
   completed time: 1792230010
""")
        self.assertEqual(len(tasks), 2)
        self.assertTrue(module.successful_task(tasks[0], {"https://einsteinathome.org/"}))
        self.assertFalse(module.successful_task(tasks[1], {"https://einsteinathome.org/"}))
        self.assertEqual(module.reward_id(tasks[0]), module.reward_id(tasks[0]))
        receipt = module.privacy_receipt(tasks[0], "0" * 64)
        self.assertEqual(receipt["claim_pqc"], 1)
        self.assertEqual(receipt["kind"], "research-receipt-v2")
        self.assertNotIn("project_url", receipt)
        self.assertNotIn("result_name", receipt)
        self.assertNotIn("completed_time", receipt)
        self.assertEqual(receipt["completed_hour"] % 3600, 0)

    def test_client_modes_can_be_restored(self):
        modes = module.parse_cc_modes("""CPU status
   mode: always
GPU status
   mode: never
Network status
   mode: auto
""")
        self.assertEqual(modes, {"cpu": "always", "gpu": "never"})


if __name__ == "__main__":
    unittest.main()
