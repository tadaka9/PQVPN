"""Validate pinned engine downloads; optionally smoke the native catalog entries."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("--platform")
args = parser.parse_args()
catalog = json.loads((Path(__file__).parent.parent / "packaging/transports/engines.json").read_text())
assert catalog["schema"] == 1
seen = set()
for entry in catalog["engines"]:
    key = (entry["engine"], entry["platform"])
    assert key not in seen
    seen.add(key)
    assert entry["engine"] in {"udp2raw", "shadowsocks", "v2ray", "obfs4"}
    assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    assert entry["url"].startswith(("https://github.com/", "https://deb.debian.org/debian/pool/"))
    assert ".." not in PurePosixPath(entry["member"]).parts and not entry["member"].startswith("/")
    if args.platform != entry["platform"]:
        continue
    with tempfile.TemporaryDirectory(prefix="pqvpn-engine-smoke-") as directory:
        with urllib.request.urlopen(entry["url"], timeout=120) as response:
            archive = response.read(64 * 1024 * 1024 + 1)
        assert len(archive) <= 64 * 1024 * 1024, "oversized archive"
        assert hashlib.sha256(archive).hexdigest() == entry["sha256"], "archive checksum mismatch"
        if entry["format"] == "deb":
            deb = Path(directory) / "package.deb"
            deb.write_bytes(archive)
            archive = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(deb)], timeout=30)
        if zipfile.is_zipfile(io.BytesIO(archive)):
            with zipfile.ZipFile(io.BytesIO(archive)) as package:
                binary = package.read(entry["member"])
        else:
            with tarfile.open(fileobj=io.BytesIO(archive)) as package:
                member = next(m for m in package.getmembers() if m.name.removeprefix("./") == entry["member"])
                assert member.isfile(), "engine member must be a regular file"
                binary = package.extractfile(member).read(128 * 1024 * 1024 + 1)
        assert 0 < len(binary) <= 128 * 1024 * 1024
        executable = Path(directory) / Path(entry["member"]).name
        executable.write_bytes(binary)
        executable.chmod(0o700)
        option = {"udp2raw": "--help", "shadowsocks": "--version", "v2ray": "version", "obfs4": "-version"}[entry["engine"]]
        result = subprocess.run([str(executable), option], cwd=directory,
                                capture_output=True, timeout=20)
        assert result.returncode == 0, entry["engine"] + " cannot start on native runner"
        print(entry["engine"], entry["version"], "verified download and native executable smoke passed")
print("Transport catalog validation passed")
