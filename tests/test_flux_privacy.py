import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "pqvpn-flux.py"
SPEC = importlib.util.spec_from_file_location("pqvpn_flux", MODULE_PATH)
FLUX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLUX)


class FluxPrivacyTests(unittest.TestCase):
    def test_remote_query_has_no_identity_or_payload_sources(self):
        lowered = FLUX.REMOTE.lower()
        for forbidden in ("journalctl", "hostname", "who ", "last ", "tcpdump", "authorized_keys"):
            self.assertNotIn(forbidden, lowered)

    def test_parser_accepts_only_aggregate_allowlist(self):
        self.assertNotIn("ip", FLUX.ALLOWED)
        self.assertNotIn("peer_id", FLUX.ALLOWED)
        self.assertNotIn("payload", FLUX.ALLOWED)


if __name__ == "__main__":
    unittest.main()
