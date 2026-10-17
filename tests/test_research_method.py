import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest

SCRIPT = Path(__file__).parents[1] / "tools/pq-research-method.py"
loader = importlib.machinery.SourceFileLoader("research_method", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec); loader.exec_module(module)


class DistributedMethodTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name)
        self.protocol = self.root / "protocol.txt"; self.protocol.write_text("deterministic protocol")
        args = types.SimpleNamespace(root=self.root, title="A test", hypothesis="X changes Y",
            protocol=str(self.protocol), dataset_hash="a" * 64, metric="absolute error",
            falsification="error is not below one", licence="CC-BY-4.0")
        self.experiment = module.propose(args)["experiment_id"]
        self.plan = module.plan(types.SimpleNamespace(root=self.root, experiment=self.experiment,
                                                       units=1, replicas=3))
        self.plan_value = module.read_json(self.root / "experiments" / self.experiment / "plan.json")

    def tearDown(self): self.temporary.cleanup()

    def submit(self, replica, peer, payload):
        result = self.root / f"result-{replica}.bin"; result.write_bytes(payload)
        return module.submit(types.SimpleNamespace(root=self.root, experiment=self.experiment,
            task=self.plan_value["units"][0]["tasks"][replica], peer=peer * 64, result=str(result)))

    def test_two_independent_matching_results_are_reproduced(self):
        self.submit(0, "b", b"same"); self.submit(1, "c", b"same")
        report = module.evaluate(types.SimpleNamespace(root=self.root, experiment=self.experiment))
        self.assertEqual(report["summary"], {"pending": 0, "reproduced": 1, "conflict": 0})

    def test_disagreement_is_preserved_as_conflict(self):
        self.submit(0, "b", b"one"); self.submit(1, "c", b"two"); self.submit(2, "d", b"three")
        report = module.evaluate(types.SimpleNamespace(root=self.root, experiment=self.experiment))
        self.assertEqual(report["summary"]["conflict"], 1)
        self.assertEqual(len(report["units"][0]["result_support"]), 3)

    def test_same_peer_cannot_fake_independent_replication(self):
        self.submit(0, "b", b"same")
        with self.assertRaisesRegex(module.MethodError, "only one replica"):
            self.submit(1, "b", b"same")

    def test_manifest_is_deterministic_and_private_on_disk(self):
        manifest = self.root / "experiments" / self.experiment / "manifest.json"
        self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(module.digest(json.loads(manifest.read_text())), self.experiment)


if __name__ == "__main__": unittest.main()
