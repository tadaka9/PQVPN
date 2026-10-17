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


def healthy_probe(candidate, timeout):
    del timeout
    return {"healthy": True, "latency_ms": 20.0 if candidate["name"].endswith("a") else 30.0}


class RotationTests(unittest.TestCase):
    @mock.patch.object(MODULE, "probe", side_effect=healthy_probe)
    def test_bootstrap_is_never_promoted_to_exit(self, _healthy):
        topology = {"nodes": [node("AEwarness", "65.108.251.110", ["bootstrap"]),
                               node("Awarness", "45.248.37.87", ["relay", "exit"])]}
        profile, state = MODULE.build_profile(
            topology, {"tunnel": {"interface_name": "pqvpn0"}}, {}, 1)
        self.assertEqual(state["selected_exit"], "Awarness")
        self.assertEqual(profile["tunnel"]["exit_host"], "45.248.37.87")

    @mock.patch.object(MODULE, "probe", side_effect=healthy_probe)
    def test_exit_rotation_is_deterministic(self, _healthy):
        topology = {"nodes": [node("boot", "10.0.0.1", ["bootstrap"]),
                               node("exit-a", "10.0.0.2", ["relay", "exit"]),
                               node("exit-b", "10.0.0.3", ["relay", "exit"])]}
        first, state = MODULE.build_profile(topology, {}, {}, 1)
        second, _state = MODULE.build_profile(topology, {}, state, 1)
        self.assertNotEqual(first["tunnel"]["exit_host"], second["tunnel"]["exit_host"])

    @mock.patch.object(MODULE, "probe",
                       side_effect=lambda candidate, timeout: {
                           "healthy": "exit" not in candidate["roles"], "latency_ms": 20.0})
    def test_no_healthy_exit_fails_closed(self, _healthy):
        topology = {"nodes": [node("boot", "10.0.0.1", ["bootstrap"]),
                               node("exit", "10.0.0.2", ["exit"])]}
        with self.assertRaisesRegex(RuntimeError, "no healthy declared exit"):
            MODULE.build_profile(topology, {}, {}, 1)

    @mock.patch.object(MODULE, "probe", side_effect=healthy_probe)
    def test_capacity_weight_controls_new_session_share(self, _probe):
        boot = node("boot", "10.0.0.1", ["bootstrap"])
        large = node("exit-a", "10.0.0.2", ["relay", "exit"])
        large["capacity_weight"] = 2
        small = node("exit-b", "10.0.0.3", ["relay", "exit"])
        topology = {"nodes": [boot, large, small]}
        state = {}
        selected = []
        for _ in range(6):
            _profile, state = MODULE.build_profile(topology, {}, state, 1)
            selected.append(state["selected_exit"])
        self.assertEqual(selected.count("exit-a"), 4)
        self.assertEqual(selected.count("exit-b"), 2)


if __name__ == "__main__":
    unittest.main()
