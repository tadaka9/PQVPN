import importlib.util
import json
import pathlib
import tempfile
import unittest


PATH = pathlib.Path(__file__).parents[1] / "tools" / "asgard-cloud.py"
SPEC = importlib.util.spec_from_file_location("asgard_cloud", PATH)
ASGARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASGARD)


class AsgardTests(unittest.TestCase):
    def test_roundtrip_and_replication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source.bin"
            source.write_bytes((b"asgard\0" * 700000) + b"tail")
            config = {"replicas": 2, "nodes": [
                {"name": "a", "root": str(root / "a")},
                {"name": "b", "root": str(root / "b")},
                {"name": "c", "root": str(root / "c")}]}
            key = bytes(range(32))
            manifest = ASGARD.put(source, config, key)
            self.assertGreaterEqual(len(manifest["chunks"]), 2)
            for chunk in manifest["chunks"]:
                self.assertEqual(len(chunk["nodes"]), 2)
                for name in chunk["nodes"]:
                    stored = root / name / "chunks" / chunk["id"][:2] / chunk["id"]
                    self.assertTrue(stored.is_file())
                    self.assertNotIn(b"asgard", stored.read_bytes())
            restored = root / "restored.bin"
            ASGARD.get(manifest, restored, config, key)
            self.assertEqual(restored.read_bytes(), source.read_bytes())

    def test_quorum_failure_is_explicit(self):
        with self.assertRaisesRegex(RuntimeError, "insufficient enabled storage peers"):
            ASGARD.select_nodes([{"name": "a", "root": "/tmp/a"}], "00", 2)

    def test_untrusted_manifest_is_rejected_before_path_access(self):
        config = {"nodes": [{"name": "a", "root": "/tmp/a"}]}
        manifest = {"schema": 1, "object_id": "00" * 16, "size": 1,
                    "chunks": [{"index": 0, "id": "../escape", "size": 1,
                                "nodes": ["a"]}]}
        with self.assertRaisesRegex(ValueError, "chunk id"):
            ASGARD.validate_manifest(manifest, config)

    def test_manifest_size_and_order_are_verified(self):
        config = {"nodes": [{"name": "a", "root": "/tmp/a"}]}
        manifest = {"schema": 1, "object_id": "00" * 16, "size": 2,
                    "chunks": [{"index": 1, "id": "ab" * 32, "size": 1,
                                "nodes": ["a"]}]}
        with self.assertRaisesRegex(ValueError, "unique and contiguous"):
            ASGARD.validate_manifest(manifest, config)


if __name__ == "__main__":
    unittest.main()
