#!/usr/bin/env python3
"""Fail when mobile candidates are disconnected from beta publication."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def require(path: str, fragments: list[str]) -> list[str]:
    text = (ROOT / path).read_text(encoding="utf-8")
    return [f"{path}: missing {fragment!r}" for fragment in fragments if fragment not in text]


def main() -> int:
    errors: list[str] = []
    errors += require(".github/workflows/mobile.yml", [
        "workflow_call:",
        "release-candidate-android-arm64",
        "PQVPN-$PQVPN_VERSION-android-arm64-preview-unsigned.apk",
        "release-candidate-ios-arm64",
        "PQVPN-$PQVPN_VERSION-ios-arm64-preview-unsigned.zip",
    ])
    errors += require(".github/workflows/ci.yml", [
        "uses: ./.github/workflows/mobile.yml",
        "needs: [unix, windows, mobile]",
        'test "$MOBILE_RESULT" = success',
    ])
    errors += require(".github/workflows/publish-test-prerelease.yml", [
        "android-arm64 ios-arm64",
        "PQVPN-$version-android-arm64-preview-unsigned.apk",
        "PQVPN-$version-ios-arm64-preview-unsigned.zip",
        '= 17',
    ])
    promotion = (ROOT / ".github/workflows/promote-beta-prerelease.yml").read_text(encoding="utf-8")
    for target in ("android-arm64", "ios-arm64"):
        if promotion.count(target) < 2:
            errors.append(f"promote-beta-prerelease.yml: {target} must gate new and resumed publication")
    errors += require("site/index.html", [
        'data-download-key="android-arm64"',
        'data-download-key="ios-arm64"',
        'id="mobile-android-qr"',
        'id="mobile-ios-qr"',
        "No QR tracking service is contacted",
    ])
    errors += require("site/app.js", [
        "android-arm64-preview-unsigned.apk",
        "ios-arm64-preview-unsigned.zip",
        "assets/mobile-${platform}-qr.svg",
    ])
    errors += require(".github/workflows/pages.yml", [
        "qrencode --type=SVG --output=public/assets/mobile-android-qr.svg",
        "qrencode --type=SVG --output=public/assets/mobile-ios-qr.svg",
        "public/mobile-downloads.json",
    ])
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Mobile release contract is connected end to end.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
