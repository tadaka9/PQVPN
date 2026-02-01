from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64
import hashlib

with open("bob_x25519.key", "rb") as f:
    raw = f.read()
    priv = x25519.X25519PrivateKey.from_private_bytes(raw)

pub = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
)
peerid = base64.urlsafe_b64encode(hashlib.sha256(pub).digest()[:8]).decode().rstrip("=")
print("Peerid di bob:", peerid)
