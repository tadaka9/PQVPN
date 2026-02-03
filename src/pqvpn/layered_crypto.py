"""
pqvpn.layered_crypto - Layered ChaChaPoly1305 encryption for onion routing.

This module implements layered encryption/decryption using ChaChaPoly1305
for enhanced onion-like routing security.
"""

from __future__ import annotations

import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .robustness import log_with_context

logger = logging.getLogger(__name__)


def derive_layer_keys(master_key: bytes, route: list[bytes], info: bytes = b"relay_key") -> list[bytes]:
    """
    Derive per-hop keys from master_key using HKDF.

    Args:
        master_key: The master session key.
        route: List of relay identifiers (e.g., peer_ids).
        info: HKDF info parameter.

    Returns:
        List of derived keys, one per hop.
    """
    keys = []
    for i, relay_id in enumerate(route):
        # Use relay_id and hop index as salt
        salt = relay_id + i.to_bytes(4, 'big')
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # ChaCha20Poly1305 key length
            salt=salt,
            info=info,
        )
        key = hkdf.derive(master_key)
        keys.append(key)
    return keys


def encrypt_layered_packet(payload: bytes, route: list[bytes], master_key: bytes) -> bytes:
    """
    Encrypt a packet in layered fashion for onion routing.

    Args:
        payload: The inner payload (final destination data).
        route: List of relay identifiers.
        master_key: Master key for key derivation.

    Returns:
        The fully encrypted packet with layers.
    """
    if not route:
        return payload  # No encryption if no route

    try:
        keys = derive_layer_keys(master_key, route)
        current_payload = payload

        # Encrypt from innermost to outermost
        for key in reversed(keys):
            nonce = os.urandom(12)  # Unique nonce per layer
            aead = ChaCha20Poly1305(key)
            # AAD can include next hop info, but for simplicity, use empty AAD
            encrypted = aead.encrypt(nonce, current_payload, b"")
            # Packet format: nonce (12) + encrypted_payload
            current_payload = nonce + encrypted

        logger.debug(f"Encrypted layered packet for {len(route)} hops")
        return current_payload
    except Exception as e:
        log_with_context(f"Layered encryption failed: {e}", "error", {"route_length": len(route)})
        raise


def decrypt_layered_packet(packet: bytes, my_relay_id: bytes, master_key: bytes) -> tuple[bytes, bytes | None]:
    """
    Decrypt the outermost layer of a layered packet.

    Args:
        packet: The encrypted packet.
        my_relay_id: This relay's identifier.
        master_key: Master key for key derivation.

    Returns:
        Tuple of (decrypted_inner_packet, next_hop_id or None if final).
        If decryption fails, returns (packet, None).
    """
    if len(packet) < 12:
        return packet, None  # Invalid packet

    nonce = packet[:12]
    encrypted_payload = packet[12:]

    # Derive key for this hop (assuming first hop, but in general, need hop index)
    # For simplicity, assume route is known or derive based on position.
    # In practice, the route needs to be communicated or stored.
    # For now, assume single hop or known position.

    # Since route is not passed, we'll need to modify the API.
    # For this implementation, assume the key is derived from master_key and my_relay_id.

    salt = my_relay_id + (0).to_bytes(4, 'big')  # Assuming first hop
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"relay_key",
    )
    key = hkdf.derive(master_key)

    aead = ChaCha20Poly1305(key)
    try:
        decrypted = aead.decrypt(nonce, encrypted_payload, b"")
        # Assume the decrypted payload is the inner packet, and no next_hop_id embedded yet.
        # In full implementation, parse next_hop_id from decrypted data.
        logger.debug("Decrypted layered packet layer")
        return decrypted, None  # None means this is the final layer or no next hop specified
    except Exception as e:
        log_with_context(f"Layered decryption failed: {e}", "error", {"relay_id": my_relay_id.hex()})
        return packet, None


# For multi-hop, we need to pass the route to the decryption function or embed next hop in payload.

def encrypt_layered_packet_with_route(payload: bytes, route: list[bytes], master_key: bytes) -> bytes:
    """
    Encrypt with route embedded in layers.
    """
    keys = derive_layer_keys(master_key, route)
    current_payload = payload

    for i in range(len(route) - 1, -1, -1):
        key = keys[i]
        next_hop = route[i + 1] if i + 1 < len(route) else None
        routing_info = b"NEXT_HOP:" + next_hop + b"\n" + current_payload if next_hop else current_payload
        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(key)
        encrypted = aead.encrypt(nonce, routing_info, b"")
        current_payload = nonce + encrypted

    return current_payload


def decrypt_layered_packet_with_route(packet: bytes, my_relay_id: bytes, master_key: bytes, hop_index: int = 0) -> tuple[bytes, bytes | None]:
    """
    Decrypt outermost layer and extract next hop.
    """
    if len(packet) < 12:
        return packet, None

    nonce = packet[:12]
    encrypted_payload = packet[12:]

    # Find my position in route. For simplicity, assume known or try keys.
    # In practice, need better way. For now, assume first relay.

    salt = my_relay_id + hop_index.to_bytes(4, 'big')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"relay_key",
    )
    key = hkdf.derive(master_key)

    aead = ChaCha20Poly1305(key)
    try:
        decrypted = aead.decrypt(nonce, encrypted_payload, b"")
        # Parse routing info
        if decrypted.startswith(b"NEXT_HOP:"):
            newline_pos = decrypted.find(b"\n")
            if newline_pos != -1:
                next_hop = decrypted[9:newline_pos]
                inner_payload = decrypted[newline_pos + 1:]
                return inner_payload, next_hop
            else:
                return decrypted, None
        else:
            return decrypted, None
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return packet, None