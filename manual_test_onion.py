#!/usr/bin/env python3
"""
Manual test for layered crypto onion routing.
"""

import sys

sys.path.insert(0, "src")

from pqvpn.layered_crypto import (
    decrypt_layered_packet_with_route,
    encrypt_layered_packet_with_route,
)


def main():
    print("Manual Testing: Layered Crypto Onion Routing")

    master_key = b"master_key_32_bytes_long!!!!!!"
    route = [b"relay1", b"relay2", b"relay3"]
    payload = b"Hello, this is a test payload for onion routing!"

    print(f"Original payload: {payload}")

    # Encrypt
    encrypted = encrypt_layered_packet_with_route(payload, route, master_key)
    print(f"Encrypted size: {len(encrypted)} bytes")

    # Decrypt at each hop
    current_packet = encrypted
    hop_index = 0
    for relay in route:
        print(f"Decrypting at {relay} (hop {hop_index})")
        decrypted, next_hop = decrypt_layered_packet_with_route(
            current_packet, relay, master_key, hop_index
        )
        if next_hop:
            print(f"Next hop: {next_hop}")
            current_packet = decrypted
            hop_index += 1
        else:
            print(f"Final payload: {decrypted}")
            assert decrypted == payload
            break

    print("Manual test passed: Onion routing works correctly.")

    # Performance test
    import time

    start = time.time()
    for _ in range(1000):
        enc = encrypt_layered_packet_with_route(payload, route, master_key)
        dec, _ = decrypt_layered_packet_with_route(enc, route[-1], master_key, 2)
    end = time.time()
    print(f"Performance: 1000 enc/dec cycles took {end - start:.2f} seconds")


if __name__ == "__main__":
    main()
