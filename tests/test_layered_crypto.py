"""
Unit tests for layered_crypto module.
"""

from pqvpn.layered_crypto import (
    decrypt_layered_packet_with_route,
    derive_layer_keys,
    encrypt_layered_packet_with_route,
)


def test_derive_layer_keys():
    master_key = b"master_key_32_bytes_long!!!!!!"
    route = [b"relay1", b"relay2", b"relay3"]
    keys = derive_layer_keys(master_key, route)
    assert len(keys) == 3
    assert all(len(k) == 32 for k in keys)
    # Keys should be different
    assert keys[0] != keys[1] != keys[2]


def test_encrypt_decrypt_single_layer():
    master_key = b"master_key_32_bytes_long!!!!!!"
    route = [b"relay1"]
    payload = b"Hello, world!"
    encrypted = encrypt_layered_packet_with_route(payload, route, master_key)
    assert encrypted != payload
    decrypted, next_hop = decrypt_layered_packet_with_route(encrypted, b"relay1", master_key, 0)
    assert decrypted == payload
    assert next_hop is None


def test_encrypt_decrypt_multi_layer():
    master_key = b"master_key_32_bytes_long!!!!!!"
    route = [b"relay1", b"relay2", b"relay3"]
    payload = b"Hello, final destination!"
    encrypted = encrypt_layered_packet_with_route(payload, route, master_key)

    # Decrypt at relay1
    decrypted1, next_hop1 = decrypt_layered_packet_with_route(encrypted, b"relay1", master_key, 0)
    assert next_hop1 == b"relay2"
    # decrypted1 should be the packet for relay2

    # Decrypt at relay2
    decrypted2, next_hop2 = decrypt_layered_packet_with_route(decrypted1, b"relay2", master_key, 1)
    assert next_hop2 == b"relay3"

    # Decrypt at relay3
    decrypted3, next_hop3 = decrypt_layered_packet_with_route(decrypted2, b"relay3", master_key, 2)
    assert decrypted3 == payload
    assert next_hop3 is None


def test_invalid_decrypt():
    master_key = b"master_key_32_bytes_long!!!!!!"
    route = [b"relay1"]
    payload = b"Hello"
    encrypted = encrypt_layered_packet_with_route(payload, route, master_key)
    # Try decrypt with wrong key
    wrong_master = b"wrong_key_32_bytes_long!!!!!!!"
    decrypted, next_hop = decrypt_layered_packet_with_route(encrypted, b"relay1", wrong_master)
    assert decrypted == encrypted  # Should return original if decrypt fails
    assert next_hop is None