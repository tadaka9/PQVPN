#!/usr/bin/env bash
set -euo pipefail

# PQVPN helper: build & install liboqs and oqs-python (oqs binding)
# This script attempts to handle common Linux/macOS setups. It is
# intended as a convenience for development environments only.

usage() {
  cat <<EOF
Usage: $0 [--prefix DIR] [--venv PATH]

Options:
  --prefix DIR   Install liboqs into DIR (default: /usr/local)
  --venv PATH    If provided, install Python bindings into the given venv
                 (pip of the venv will be used). If omitted, system pip is used.

This script will:
  - clone liboqs
  - build liboqs (cmake + ninja/make)
  - install liboqs into the specified prefix
  - install the Python binding (oqs-python) via pip

Note: you may need sudo for system-wide installs. Review the commands
before running in production systems.
EOF
}

PREFIX=/usr/local
PY_VENV=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --prefix)
      PREFIX="$2"; shift 2;;
    --venv)
      PY_VENV="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

echo "liboqs install prefix: $PREFIX"
if [[ -n "$PY_VENV" ]]; then
  echo "Python venv: $PY_VENV"
fi

# Helpers: prefer system package managers when available
if command -v apt-get >/dev/null 2>&1; then
  echo "Detected apt-get. Installing build deps (sudo may be required)..."
  sudo apt-get update
  sudo apt-get install -y build-essential cmake ninja-build git python3-dev python3-pip libssl-dev pkg-config
elif command -v brew >/dev/null 2>&1; then
  echo "Detected Homebrew. Installing build deps..."
  brew install cmake ninja openssl pkg-config
else
  echo "No known package manager detected. Ensure you have: cmake, ninja/make, git, python3-dev, pip, libssl headers."
fi

# Build liboqs
TMP_DIR=$(mktemp -d -t liboqs-build-XXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Cloning liboqs into $TMP_DIR/liboqs"
git clone https://github.com/open-quantum-safe/liboqs.git "$TMP_DIR/liboqs"
mkdir -p "$TMP_DIR/liboqs/build"
cd "$TMP_DIR/liboqs/build"

# Configure: prefer Ninja when available
if command -v ninja >/dev/null 2>&1; then
  cmake -GNinja -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON ..
  ninja
  if [[ $EUID -ne 0 && "$PREFIX" = "/usr/local" ]]; then
    echo "Installing to $PREFIX requires privileges. You may be prompted for sudo."
    sudo ninja install
  else
    ninja install
  fi
else
  cmake -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON ..
  make -j"$(nproc || echo 2)"
  if [[ $EUID -ne 0 && "$PREFIX" = "/usr/local" ]]; then
    echo "Installing to $PREFIX requires privileges. You may be prompted for sudo."
    sudo make install
  else
    make install
  fi
fi

# Install Python binding (oqs-python).
# There are different Python packages/installation methods; prefer a direct
# Git install which matches the liboqs we built.

# choose pip
if [[ -n "$PY_VENV" ]]; then
  PIP="$PY_VENV/bin/pip"
else
  PIP=$(command -v pip3 || command -v pip)
fi

if [[ -z "$PIP" ]]; then
  echo "pip not found; please install pip or provide --venv PATH" >&2
  exit 1
fi

# Upgrade build tools
"$PIP" install --upgrade pip setuptools wheel

# Install oqs-python from upstream (source) to ensure it picks local liboqs
"$PIP" install --no-cache-dir git+https://github.com/open-quantum-safe/oqs-python

cat <<EOF
Done. Notes:
- liboqs was installed to: $PREFIX
- Python oqs binding installed via: $PIP

If the Python binding cannot find liboqs at runtime, ensure the
runtime linker can locate the library (LD_LIBRARY_PATH on Linux, or
install into a system path). On macOS you may need to adjust DYLD_LIBRARY_PATH
or use install_name_tool.

If you want to build a wheel for distribution or CI, consider using
"python -m pip wheel ..." or following the oqs-python project's docs.
EOF
