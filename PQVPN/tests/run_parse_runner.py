#!/usr/bin/env python3
import importlib.util
import os
import sys

mod_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gui.py"))
spec = importlib.util.spec_from_file_location("gui_mod_for_tests", mod_path)
module = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(module)
except Exception as e:
    print("Failed to import gui module:", e)
    raise

print("Loaded gui module:", getattr(module, "__file__", "<unknown>"))


def run_assertions():
    txt = """
    INFO startup
    HELLO peerA@1.2.3.4:1234
    HELLO peerB@5.6.7.8:5678
    session: ABC123
    circuit: 42
    """
    peers, sessions, circuits = module.parse_peers_from_text(txt)
    assert len(peers) == 2, f"expected 2 peers, got {len(peers)}"
    ids = {p["peerid"] for p in peers}
    assert "peerA" in ids and "peerB" in ids, f"peers wrong: {ids}"
    assert "ABC123" in sessions, f"sessions wrong: {sessions}"
    assert "42" in circuits, f"circuits wrong: {circuits}"

    txt2 = '{"msg":"HELLO","peer":"peerC","addr":"9.9.9.9:9999"}\n'
    peers2, sessions2, circuits2 = module.parse_peers_from_text(txt2)
    assert isinstance(peers2, list)

    print("All parse tests passed")


if __name__ == "__main__":
    try:
        run_assertions()
    except AssertionError as e:
        print("ASSERTION FAILED:", e)
        sys.exit(2)
    except Exception as e:
        print("ERROR running tests:", e)
        raise
    sys.exit(0)
