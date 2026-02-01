import types
import sys
from pathlib import Path

# replicate test's oqs stub
oqs_pkg = types.ModuleType("oqs")
oqs_impl = types.ModuleType("oqs.oqs")


def _get_enabled_kems():
    return ["Kyber1024"]


def _get_enabled_sigs():
    return ["ML-DSA-65"]


setattr(oqs_impl, "get_enabled_kem_mechanisms", _get_enabled_kems)
setattr(oqs_impl, "get_enabled_sig_mechanisms", _get_enabled_sigs)


class KeyEncapsulation:
    def __init__(self, alg, secret_key=None):
        self.length_public_key = 1568
        self.length_secret_key = 3168
        self.length_ciphertext = 800
        self.length_shared_secret = 32
        self._alg = alg

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def generate_keypair(self):
        return (b"K" * self.length_public_key, b"k" * self.length_secret_key)

    def export_secret_key(self):
        return b"k" * self.length_secret_key

    def encap_secret(self, pk):
        return (b"c" * self.length_ciphertext, b"s" * self.length_shared_secret)

    def decap_secret(self, ct):
        return b"s" * self.length_shared_secret


class Signature:
    def __init__(self, alg, secret_key=None):
        self.length_public_key = 1312
        self.length_secret_key = 4032
        self.length_signature = 3309
        self._alg = alg

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def generate_keypair(self):
        return (b"S" * self.length_public_key, b"sk" * int(self.length_secret_key / 2))

    def export_secret_key(self):
        return b"sk" * int(self.length_secret_key / 2)

    def sign(self, data):
        return b"sig"

    def verify(self, data, sig, pk):
        return True


setattr(oqs_impl, "KeyEncapsulation", KeyEncapsulation)
setattr(oqs_impl, "Signature", Signature)
setattr(oqs_pkg, "oqs", oqs_impl)
setattr(oqs_pkg, "KeyEncapsulation", KeyEncapsulation)
setattr(oqs_pkg, "Signature", Signature)

sys.modules["oqs"] = oqs_pkg
sys.modules["oqs.oqs"] = oqs_impl

cfg = Path("tmp_cfg.yaml")
cfg.write_text(
    "peer:\n  nickname: test\nnetwork:\n  bind_host: 127.0.0.1\n  listen_port: 9001\n"
)

import importlib
import traceback

try:
    m = importlib.import_module("main")
    Node = getattr(m, "PQVPNNode")
    n = Node(str(cfg))
    print("INST CREATED")
    print("has circuits", hasattr(n, "circuits"))
    print("keys:", sorted(n.__dict__.keys()))
except Exception as e:
    print("EXC", e)
    traceback.print_exc()
