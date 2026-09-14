#!/usr/bin/env python3
"""
PQVPN hard kernel gate.

This script is deliberately hostile to fake progress.  It checks the C++23
tree for properties that must be true before a Path-Quilt VPN implementation
can be called production-runnable:

* mandatory hybrid algorithms only:
  - KEM: Kyber1024 / ML-KEM-1024 crossed with X25519
  - signatures: Ed25519 crossed with ML-DSA-87
* no fallback, fake, stub, placeholder, simulated crypto or hollow tests
* liboqs must be present for post-quantum operations; random bytes with the
  right sizes are not accepted as PQ cryptography. Discovery is platform-aware:
  pkg-config (Linux/macOS) or a CMake CONFIG package (Windows/vcpkg, the
  mechanism CMakeLists.txt itself uses via find_package(liboqs CONFIG))
* runtime must not be a config-only demo
* UDP receive path must dispatch into node packet processing
* tests must be meaningful, not unconditional success fixtures

The blockchain/controller may mine or advance only when this gate passes.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TESTS = ROOT / "tests"
REPORT = ROOT / ".loop-engineering" / "hard_kernel_report.json"


@dataclass
class Finding:
    severity: str
    gate: str
    path: str
    line: int
    message: str


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def iter_code_files() -> list[Path]:
    suffixes = {".cpp", ".hpp", ".h", ".ixx", ".c", ".cc"}
    return sorted(
        path for base in (SRC, TESTS)
        for path in base.rglob("*")
        if path.is_file() and path.suffix in suffixes
    )


def add(finding: list[Finding], severity: str, gate: str, path: Path, line: int, message: str) -> None:
    finding.append(Finding(severity, gate, rel(path), line, message))


def line_hits(path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    for index, text in enumerate(lines, 1):
        if pattern.search(text):
            hits.append((index, text.strip()))
    return hits


def pkg_config_available(package: str) -> bool:
    if not shutil.which("pkg-config"):
        return False
    return subprocess.run(
        ["pkg-config", "--exists", package],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def pkg_config_include_dirs(package: str) -> list[Path]:
    if not shutil.which("pkg-config"):
        return []
    completed = subprocess.run(
        ["pkg-config", "--cflags-only-I", package],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        return []
    roots: list[Path] = []
    for part in completed.stdout.split():
        if part.startswith("-I"):
            roots.append(Path(part[2:]))
    return roots


def existing_build_dirs() -> list[Path]:
    """Build directories with a CMake cache, honoring PQVPN_BUILD_DIR."""
    candidates: list[Path] = []
    env_dir = os.environ.get("PQVPN_BUILD_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    # CTest runs each test from its binary directory. When the project is
    # configured into a custom location (cmake -S . -B out) that directory is
    # the active build and must be recognized, or the gate would skip the
    # nested CTest run entirely.
    candidates.append(Path.cwd())
    for name in ("build", "build-test"):
        candidates.append(ROOT / name)
    return [d for d in candidates if (d / "CMakeCache.txt").is_file()]


def cmake_config_oqs_prefixes() -> list[Path]:
    """liboqs CMake CONFIG package prefixes referenced by existing build caches.

    On Windows/vcpkg the project resolves liboqs with find_package(liboqs CONFIG)
    (see CMakeLists.txt); each build cache records it as liboqs_DIR=<pkg-dir>.
    The layout varies: <prefix>/lib/cmake/liboqs for system builds and
    <prefix>/share/liboqs for vcpkg. Derive both candidates and accept only a
    prefix that actually carries the oqs headers, so a wrong guess can never
    masquerade as a valid installation.
    """
    prefixes: list[Path] = []
    for build_dir in existing_build_dirs():
        try:
            text = (build_dir / "CMakeCache.txt").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r"^liboqs_DIR:PATH=(.+)$", text, re.MULTILINE)
        if not match:
            continue
        oqs_dir = Path(match.group(1).strip())
        for strip_depth in (2, 3):
            if len(oqs_dir.parts) <= strip_depth:
                continue
            candidate = Path(*oqs_dir.parts[:-strip_depth])
            if (candidate / "include" / "oqs").is_dir():
                prefixes.append(candidate)
                break
    return prefixes


def oqs_include_roots() -> list[Path]:
    roots: list[Path] = []
    roots.extend(pkg_config_include_dirs("liboqs"))
    for prefix in cmake_config_oqs_prefixes():
        roots.append(prefix / "include")
    # Conventional system locations (WSL/CI images install liboqs there).
    roots += [Path("/usr/local/include"), Path("/usr/include")]
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root).lower()
        if key not in seen and (root / "oqs").is_dir():
            seen.add(key)
            unique.append(root)
    return unique


def oqs_header_text(roots: list[Path]) -> str:
    chunks: list[str] = []
    for root in roots:
        oqs_dir = root / "oqs"
        if not oqs_dir.is_dir():
            continue
        for header in sorted(oqs_dir.rglob("*.h"))[:500]:
            try:
                chunks.append(header.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    return "\n".join(chunks)


def main() -> int:
    findings: list[Finding] = []
    files = iter_code_files()

    forbidden = re.compile(
        r"\b("
        r"stub|placeholder|fake|dummy|simulate|simulation|simulated|"
        r"for now|not implemented|no-op|hollow|fallback to random|"
        r"return true\s*;?\s*(?://.*placeholder)?|"
        r"REQUIRE\s*\(\s*true\s*\)|EXPECT_TRUE\s*\(\s*true\s*\)|SUCCEED\s*\("
        r")\b",
        re.IGNORECASE,
    )
    for path in files:
        for line, text in line_hits(path, forbidden):
            add(findings, "error", "no_fake_progress", path, line, f"forbidden fake/stub marker: {text[:180]}")

    weak_algorithms = re.compile(r"\b(Kyber512|Kyber768|ML-KEM-512|ML-KEM-768|Dilithium2|Dilithium3|Dilithium5|ML-DSA-44|ML-DSA-65)\b")
    for path in files:
        for line, text in line_hits(path, weak_algorithms):
            add(findings, "error", "mandatory_algorithms_only", path, line, f"non-mandatory PQ algorithm reference: {text[:180]}")

    required_tokens = {
        "Kyber1024_or_ML-KEM-1024": re.compile(r"\b(Kyber1024|ML-KEM-1024|ML_KEM_1024|ml_kem_1024)\b"),
        "X25519": re.compile(r"\bX25519\b"),
        "Ed25519": re.compile(r"\bEd25519|ed25519\b"),
        "ML-DSA-87": re.compile(r"\bML-DSA-87|ML_DSA_87|ml_dsa_87\b"),
    }
    all_source = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files)
    for name, pattern in required_tokens.items():
        if not pattern.search(all_source):
            add(findings, "error", "mandatory_algorithms_present", ROOT / "CMakeLists.txt", 1, f"required algorithm token absent: {name}")

    oqs_via_pkg_config = pkg_config_available("liboqs")
    oqs_cmake_prefixes = cmake_config_oqs_prefixes()
    if not oqs_via_pkg_config and not oqs_cmake_prefixes:
        add(findings, "error", "liboqs_required", ROOT / "CMakeLists.txt", 1,
            "neither pkg-config nor a CMake CONFIG package can find liboqs; install/build liboqs and link the C API before PQ blocks can pass")

    oqs_headers = oqs_header_text(oqs_include_roots())
    if "OQS_KEM_alg" not in oqs_headers or "OQS_SIG_alg" not in oqs_headers:
        add(findings, "error", "liboqs_algorithms", ROOT / "CMakeLists.txt", 1,
            "liboqs OQS_KEM/OQS_SIG C API declarations were not found")
    if "ml_kem_1024" not in oqs_headers.lower() and "kyber_1024" not in oqs_headers.lower():
        add(findings, "error", "liboqs_algorithms", ROOT / "CMakeLists.txt", 1, "liboqs headers with ML-KEM-1024/Kyber1024 were not found")
    if "ml_dsa_87" not in oqs_headers.lower():
        add(findings, "error", "liboqs_algorithms", ROOT / "CMakeLists.txt", 1, "liboqs headers with ML-DSA-87 were not found")

    crypto_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in [SRC / "crypto_utils.cpp", SRC / "crypto_signature.cpp", SRC / "modules" / "crypto_module.hpp", SRC / "modules" / "crypto_kem.cpp"]
        if path.exists()
    )
    if "OQS_KEM" not in crypto_text:
        add(findings, "error", "real_oqs_kem", SRC / "modules" / "crypto_module.hpp", 1, "KEM implementation does not call liboqs OQS_KEM APIs")
    if "OQS_SIG" not in crypto_text:
        add(findings, "error", "real_oqs_signature", SRC / "crypto_signature.cpp", 1, "signature implementation does not call liboqs OQS_SIG APIs")
    if "EVP_PKEY-X25519" not in crypto_text and "EVP_PKEY_X25519" not in crypto_text and "X25519" not in crypto_text:
        add(findings, "error", "real_x25519", SRC / "modules" / "crypto_module.hpp", 1, "hybrid KEM path does not implement X25519")

    main_text = (SRC / "main.cpp").read_text(encoding="utf-8", errors="replace")
    if "--smoke-test" not in main_text:
        add(findings, "error", "runtime_modes", SRC / "main.cpp", 1, "runtime must keep smoke-test separate from default node mode")
    if "io.run()" not in main_text:
        add(findings, "error", "runtime_liveness", SRC / "main.cpp", 1, "default executable must run an event loop")

    network_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in [SRC / "modules" / "network_module.hpp", SRC / "modules" / "udp_protocol.cpp", SRC / "modules" / "node_module.hpp"]
        if path.exists()
    )
    if "async_receive_from" not in network_text:
        add(findings, "error", "udp_receive_dispatch", SRC / "modules" / "network_module.hpp", 1, "UDP listener does not receive datagrams asynchronously")
    if "datagram_received" not in network_text or "co_spawn" not in network_text:
        add(findings, "error", "udp_receive_dispatch", SRC / "modules" / "udp_protocol.cpp", 1, "UDP receive path is not wired into PQVPNNode::datagram_received")

    build_dir = next(
        (d for d in existing_build_dirs() if (d / "CTestTestfile.cmake").is_file()),
        None,
    )
    if build_dir is None:
        add(findings, "warning", "build_state", ROOT / "build", 1,
            "no CMake build directory with a test configuration found; run cmake before full gate")
    else:
        ctest = subprocess.run(
            ["ctest", "--test-dir", str(build_dir), "-LE", "hardening", "--output-on-failure"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if ctest.returncode != 0:
            add(findings, "error", "ctest", build_dir, 1, "CTest failed")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": not any(item.severity == "error" for item in findings),
        "summary": {
            "errors": sum(item.severity == "error" for item in findings),
            "warnings": sum(item.severity == "warning" for item in findings),
            "files_scanned": len(files),
            "liboqs_pkg_config": oqs_via_pkg_config,
            "liboqs_cmake_config": bool(oqs_cmake_prefixes),
            "cmake": shutil.which("cmake") is not None,
            "ctest": shutil.which("ctest") is not None,
        },
        "findings": [asdict(item) for item in findings],
    }
    REPORT.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(json.dumps(payload["summary"], indent=2))
    for item in findings[:80]:
        print(f"{item.severity.upper()} {item.gate} {item.path}:{item.line} {item.message}")
    if len(findings) > 80:
        print(f"... {len(findings) - 80} additional findings written to {rel(REPORT)}")
    if payload["ok"]:
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
