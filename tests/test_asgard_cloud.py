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
    def test_erasure_codec_recovers_each_single_missing_shard(self):
        blob = bytes(range(251)) * 71
        encoded = ASGARD.erasure_encode(blob, 4)
        self.assertEqual(len(encoded), 5)
        for missing in range(len(encoded)):
            degraded = list(encoded)
            degraded[missing] = None
            self.assertEqual(ASGARD.erasure_reconstruct(degraded, len(blob)), blob)
        degraded = list(encoded)
        degraded[0] = None
        degraded[1] = None
        with self.assertRaisesRegex(RuntimeError, "more than one"):
            ASGARD.erasure_reconstruct(degraded, len(blob))

    def test_roundtrip_and_replication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source.bin"
            source.write_bytes((b"asgard\0" * 700000) + b"tail")
            config = {"replicas": 2, "nodes": [
                {"name": "a", "root": str(root / "a"), "failure_domain": "device-a"},
                {"name": "b", "root": str(root / "b"), "failure_domain": "device-b"},
                {"name": "c", "root": str(root / "c"), "failure_domain": "device-c"}]}
            for node in config["nodes"]:
                pathlib.Path(node["root"]).mkdir()
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

    def test_offline_device_is_repaired_from_an_independent_replica(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            nodes = [
                {"name": "a", "root": str(root / "a"), "failure_domain": "device-a"},
                {"name": "b", "root": str(root / "b"), "failure_domain": "device-b"},
                {"name": "c", "root": str(root / "c"), "failure_domain": "device-c"},
            ]
            for node in nodes:
                pathlib.Path(node["root"]).mkdir()
            config = {"replicas": 2, "nodes": nodes}
            source = root / "source.bin"
            source.write_bytes(b"survives-one-device-offline" * 4096)
            key = bytes(range(32))
            manifest = ASGARD.put(source, config, key)
            offline = manifest["chunks"][0]["nodes"][0]
            offline_node = next(node for node in nodes if node["name"] == offline)
            import shutil
            shutil.rmtree(offline_node["root"])

            report = ASGARD.replica_audit(manifest, config)
            self.assertEqual(report["state"], "degraded")
            repaired = ASGARD.repair_replicas(manifest, config)
            healthy = ASGARD.replica_audit(repaired, config)
            self.assertEqual(healthy["state"], "healthy")
            self.assertNotIn(offline, repaired["chunks"][0]["nodes"])
            restored = root / "restored-after-repair.bin"
            ASGARD.get(repaired, restored, config, key)
            self.assertEqual(restored.read_bytes(), source.read_bytes())

    def test_same_device_roots_do_not_count_as_independent_replicas(self):
        nodes = [
            {"name": "a", "root": "/tmp/a", "failure_domain": "device-one"},
            {"name": "b", "root": "/tmp/b", "failure_domain": "device-one"},
        ]
        with self.assertRaisesRegex(RuntimeError, "independent failure domains"):
            ASGARD.select_nodes(nodes, "00" * 32, 2)

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

    def test_signed_expiring_storage_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = ASGARD.load_identity(pathlib.Path(directory) / "identity.key", create=True)
            capability = ASGARD.issue_capability(
                "storage-a", 64 * ASGARD.CHUNK_BYTES, 8 * ASGARD.CHUNK_BYTES,
                expires_at=10_000, private=identity, now=9_000)
            ASGARD.verify_capability(capability, now=9_500)
            self.assertEqual(capability["transport"], "pqvpn-authenticated-session")
            self.assertNotIn("root", capability)
            self.assertNotIn("ip", capability)

            tampered = dict(capability)
            tampered["capacity_bytes"] += 1
            with self.assertRaisesRegex(ValueError, "verification failed"):
                ASGARD.verify_capability(tampered, now=9_500)
            with self.assertRaisesRegex(ValueError, "expired"):
                ASGARD.verify_capability(capability, now=10_001)

    def test_receipts_form_a_signed_tamper_evident_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = ASGARD.load_identity(pathlib.Path(directory) / "identity.key", create=True)
            capability = ASGARD.issue_capability(
                "storage-a", 64 * ASGARD.CHUNK_BYTES, 8 * ASGARD.CHUNK_BYTES,
                expires_at=10_000, private=identity, now=9_000)
            manifest = {"schema": 1, "object_id": "11" * 16, "size": 5,
                        "chunks": [{"index": 0, "id": "22" * 32,
                                    "size": 5, "nodes": ["storage-a"]}]}
            ledger = []
            first = ASGARD.append_receipt(ledger, capability, manifest, identity, now=9_100)
            second = ASGARD.append_receipt(ledger, capability, manifest, identity, now=9_200)
            ASGARD.verify_receipt_ledger(ledger)
            self.assertEqual(first["previous"], "0" * 64)
            self.assertEqual(second["previous"], ASGARD.record_digest(first))
            self.assertNotIn("object_id", second)
            self.assertNotIn("nodes", second)

            ledger[0] = dict(ledger[0])
            ledger[0]["bytes"] = 6
            with self.assertRaisesRegex(ValueError, "verification failed"):
                ASGARD.verify_receipt_ledger(ledger)

    def test_paranoid_bounds_and_private_key_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"{}" + b" " * 32)
            with self.assertRaisesRegex(ValueError, "oversized JSON"):
                ASGARD.read_json(oversized, 16)

            identity_path = root / "identity.key"
            ASGARD.load_identity(identity_path, create=True)
            identity_path.chmod(0o644)
            with self.assertRaisesRegex(PermissionError, "0600"):
                ASGARD.load_identity(identity_path)

            nodes = [{"name": f"n{i}", "root": f"/tmp/n{i}",
                      "failure_domain": f"d{i}"} for i in range(9)]
            with self.assertRaisesRegex(ValueError, "between 1 and 8"):
                ASGARD.validate_config({"replicas": 9, "nodes": nodes})


if __name__ == "__main__":
    unittest.main()
