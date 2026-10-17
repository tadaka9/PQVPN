import importlib.util
import pathlib
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "pqvpn-peer-rotation.py"
SPEC = importlib.util.spec_from_file_location("pqvpn_peer_rotation", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def node(name, host, roles):
    return {"name": name, "host": host, "port": 9090, "roles": roles,
            "health_command": ["true"]}


class RotationTests(unittest.TestCase):
    @mock.patch.object(MODULE, "healthy", return_value=True)
    def test_bootstrap_is_never_promoted_to_exit(self, _healthy):
        topology = {"nodes": [node("AEwarness", "65.108.251.110", ["bootstrap"]),
                               node("Awarness", "45.248.37.87", ["relay", "exit"])]}
        profile, state = MODULE.build_profile(
            topology, {"tunnel": {"interface_name": "pqvpn0"}}, {}, 1)
        self.assertEqual(state["selected_exit"], "Awarness")
        self.assertEqual(profile["tunnel"]["exit_host"], "45.248.37.87")

    @mock.patch.object(MODULE, "healthy", return_value=True)
    def test_exit_rotation_is_deterministic(self, _healthy):
        topology = {"nodes": [node("boot", "10.0.0.1", ["bootstrap"]),
                               node("exit-a", "10.0.0.2", ["relay", "exit"]),
                               node("exit-b", "10.0.0.3", ["relay", "exit"])]}
        first, state = MODULE.build_profile(topology, {}, {}, 1)
        second, _state = MODULE.build_profile(topology, {}, state, 1)
        self.assertNotEqual(first["tunnel"]["exit_host"], second["tunnel"]["exit_host"])

    @mock.patch.object(MODULE, "healthy",
                       side_effect=lambda candidate, timeout: "exit" not in candidate["roles"])
    def test_no_healthy_exit_fails_closed(self, _healthy):
        topology = {"nodes": [node("boot", "10.0.0.1", ["bootstrap"]),
                               node("exit", "10.0.0.2", ["exit"])]}
        with self.assertRaisesRegex(RuntimeError, "no healthy declared exit"):
            MODULE.build_profile(topology, {}, {}, 1)


if __name__ == "__main__":
    unittest.main()
