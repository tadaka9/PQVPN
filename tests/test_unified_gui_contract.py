#!/usr/bin/env python3
"""Regression contract for the single cross-platform PQVPN GUI."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_QML = ROOT / "ui" / "Main.qml"


class UnifiedGuiContractTest(unittest.TestCase):
    def test_exactly_one_application_qml_exists(self) -> None:
        application_qml = sorted(
            path
            for path in ROOT.glob("**/Main.qml")
            if not any(part.startswith("build-") for part in path.relative_to(ROOT).parts)
        )
        self.assertEqual(application_qml, [CANONICAL_QML])

    def test_mobile_package_consumes_canonical_gui(self) -> None:
        cmake = (ROOT / "mobile" / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn('../ui', cmake)
        self.assertIn('PQVPN.App', cmake)
        self.assertNotIn('PQVPN.Mobile', cmake)

    def test_gui_has_no_operating_system_fork(self) -> None:
        qml = CANONICAL_QML.read_text(encoding="utf-8")
        forbidden = (
            "Qt.platform.os",
            "Q_OS_",
            "Mobile Preview",
            "MOBILE PREVIEW",
            "Android",
            "iOS",
            "mobile devices",
            "mobile transport",
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, qml)

    def test_status_copy_is_sober_and_does_not_overclaim(self) -> None:
        qml = CANONICAL_QML.read_text(encoding="utf-8")
        for marker in ("Best where", "strong default", "AI formal", "PREVIEW"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, qml)
        self.assertIn("Formal logic check · automated · no scientific verdict", qml)
        self.assertIn("Not connected", qml)

    def test_shared_launcher_loads_canonical_module(self) -> None:
        launcher = (ROOT / "ui" / "main.cpp").read_text(encoding="utf-8")
        self.assertIn('loadFromModule("PQVPN.App", "Main")', launcher)
        self.assertIn('"--smoke-test"', launcher)
        self.assertIn('"--screenshot"', launcher)
        self.assertIn('"--page"', launcher)


if __name__ == "__main__":
    unittest.main()
