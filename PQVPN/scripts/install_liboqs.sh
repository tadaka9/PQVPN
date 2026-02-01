#!/usr/bin/env bash
set -euo pipefail

# install_liboqs.sh
# Idempotent installer: tries pip install of Python binding first; if not available,
# builds liboqs from source and then installs the Python binding into the active venv.

# Usage: ./install_liboqs.sh [--no-sudo]

NO_SUDO=0
for arg in "$@"; do
  case "$arg" in
    --no-sudo) NO_SUDO=1 ;;
  esac
done

SUDO_CMD="sudo"
if [ "$NO_SUDO" -eq 1 ]; then
  SUDO_CMD=""
fi

# Detect virtualenv
if [ -n "${VIRTUAL_ENV-}" ]; then
  VENV_ACTIVATE=""
  PIP="${VIRTUAL_ENV}/bin/pip"
  PYTHON="${VIRTUAL_ENV}/bin/python"
else
  # prefer .venv in repo
  if [ -x ".venv/bin/activate" ] || [ -f ".venv/bin/activate" ]; then
    VENV_ACTIVATE=". .venv/bin/activate"
    PIP=".venv/bin/pip"
    PYTHON=".venv/bin/python"
  else
    echo "No virtualenv detected. It's recommended to run inside your project venv (.venv)."
    PIP="pip"
    PYTHON="python3"
  fi
fi

echo "Using python: $(which ${PYTHON} 2>/dev/null || true)"
if [ -n "${VENV_ACTIVATE}" ]; then
  echo "Activating venv .venv"
  source .venv/bin/activate
fi

set -x

# Step 1: try pip install liboqs-python (prebuilt wheel)
if ${PIP} --version >/dev/null 2>&1; then
  echo "Attempting to pip install liboqs-python (python binding) into venv..."
  if ${PIP} install --upgrade pip setuptools wheel >/dev/null 2>&1; then
    if ${PIP} install liboqs-python >/dev/null 2>&1; then
      echo "Successfully installed 'liboqs-python' Python package via pip."
      # Verify import
      if ${PYTHON} -c "import oqs; print('oqs import OK, lib:', oqs.__file__)" 2>/dev/null; then
        echo "liboqs-python import OK"
        exit 0
      else
        echo "liboqs-python import failed; will build liboqs from source."
      fi
    else
      echo "pip install liboqs-python failed or no prebuilt wheel available; will build liboqs from source."
    fi
  fi
fi

# Step 2: install system build deps (Debian/Ubuntu). We'll try apt-get; if not exists, we continue.
if command -v apt-get >/dev/null 2>&1; then
  echo "Installing build dependencies via apt-get (requires sudo)..."
  ${SUDO_CMD} apt-get update
  ${SUDO_CMD} apt-get install -y build-essential cmake ninja-build git libssl-dev python3-dev python3-venv pkg-config autoconf automake libtool libsqlite3-dev
else
  echo "apt-get not available. Please install build dependencies manually: build-essential, cmake, ninja, git, libssl-dev, python3-dev"
fi

# Step 3: clone and build liboqs
WORKDIR="${PWD}/.oqs_build"
mkdir -p "$WORKDIR"
cd "$WORKDIR"
if [ ! -d liboqs ]; then
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
else
  echo "liboqs repo already present; pulling updates"
  cd liboqs
  git fetch --depth=1 origin
  git reset --hard origin/main || true
  cd ..
fi

cd liboqs
mkdir -p build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON ..
# Build
ninja -j$(nproc)
# Install (may require sudo)
if [ "$NO_SUDO" -eq 1 ]; then
  ninja install
else
  ${SUDO_CMD} ninja install
  ${SUDO_CMD} ldconfig || true
fi

# Step 4: install Python binding
cd "$WORKDIR"
# Try pip install oqs again (now that liboqs libs are in place)
if ${PIP} install liboqs-python; then
  echo "Installed python binding 'liboqs-python' after building liboqs."
else
  # try alternative package names
  if ${PIP} install python-oqs; then
    echo "Installed python-oqs package."
  elif ${PIP} install pyoqs; then
    echo "Installed pyoqs package."
  else
    echo "Failed to install python oqs binding via pip. You may need to build binding manually or use a compatible wheel."
    exit 2
  fi
fi

# Verify import
${PYTHON} - <<'PY'
try:
    import oqs
    print('SUCCESS: oqs imported, backend:', oqs)
except Exception as e:
    print('ERROR: oqs import failed:', e)
    raise
PY

echo "Installation finished. If oqs import is successful, restart your PQVPN nodes; remove existing PQ key files to regenerate real PQ keys (kyber1024.key, dilithium3.key)."
exit 0

