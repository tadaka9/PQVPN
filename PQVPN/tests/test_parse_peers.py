import os
import importlib.util

mod_path = os.path.join(os.path.dirname(__file__), "..", "gui.py")
mod_path = os.path.abspath(mod_path)

# Load the gui module for tests in a modern, non-deprecated way
spec = importlib.util.spec_from_file_location("gui_mod_for_tests", mod_path)
gui = importlib.util.module_from_spec(spec)
if spec and spec.loader:
    spec.loader.exec_module(gui)
else:
    raise ImportError(f"Could not load module from {mod_path}")


def test_parse_simple():
    txt = """
    INFO startup
    HELLO peerA@1.2.3.4:1234
    HELLO peerB@5.6.7.8:5678
    session: ABC123
    circuit: 42
    """
    peers, sessions, circuits = gui.parse_peers_from_text(txt)
    assert len(peers) == 2
    ids = {p["peerid"] for p in peers}
    assert "peerA" in ids and "peerB" in ids
    assert "ABC123" in sessions
    assert "42" in circuits


def test_parse_json_line():
    # JSON line where HELLO present as values
    txt = '{"msg":"HELLO","peer":"peerC","addr":"9.9.9.9:9999"}\n'
    peers, sessions, circuits = gui.parse_peers_from_text(txt)
    # no HELLO matched because pattern expects HELLO and pid@addr together; still should not crash
    assert isinstance(peers, list)
