#!/usr/bin/env python3
"""
PQVPN Performance Benchmark Script

Runs performance tests for key PQVPN components.
"""

import os
import time

from pqvpn.anti_dpi import AntiDPI
from pqvpn.crypto import OQSPY_AVAILABLE, pq_kem_decaps, pq_kem_encaps, pq_kem_keygen
from pqvpn.layered_crypto import encrypt_layered_packet
from pqvpn.traffic_shaper import TrafficShaper


def benchmark_crypto():
    """Benchmark post-quantum crypto operations."""
    print("Benchmarking PQ crypto operations...")

    if not OQSPY_AVAILABLE:
        print("OQS not available, skipping crypto benchmark")
        return

    # KEM operations
    kem_times = []
    for i in range(10):
        start = time.time()
        pk, sk = pq_kem_keygen()
        ct, ss = pq_kem_encaps(pk)
        ss_dec = pq_kem_decaps(ct, sk)
        assert ss == ss_dec
        end = time.time()
        kem_times.append(end - start)

    avg_kem = sum(kem_times) / len(kem_times)
    print(f"Kyber1024 KEM round-trip: {avg_kem*1000:.2f} ms per operation")


def benchmark_layered_crypto():
    """Benchmark layered encryption."""
    print("Benchmarking layered ChaChaPoly1305...")

    master_key = os.urandom(32)
    route = [os.urandom(32) for _ in range(3)]  # 3-hop route
    payload = os.urandom(1400)  # Typical packet size

    # Encrypt
    start = time.time()
    for _ in range(100):
        encrypted = encrypt_layered_packet(payload, route, master_key)
    encrypt_time = time.time() - start

    print(f"Layered encryption (3 hops): {(encrypt_time/100)*1000:.2f} ms per packet")


def benchmark_traffic_shaping():
    """Benchmark traffic shaping."""
    print("Benchmarking traffic shaping...")

    shaper = TrafficShaper(rate_limit=1000000.0)  # 1 MB/s
    packets = [os.urandom(1400) for _ in range(1000)]
    addr = ('127.0.0.1', 9000)

    start = time.time()
    # Enqueue packets
    for packet in packets:
        shaper.enqueue_packet(packet, addr)

    # Process packets
    processed = 0
    while processed < 1000:
        pkt = shaper.get_next_packet()
        if pkt:
            processed += 1
        else:
            break  # No more packets or rate limited

    end = time.time()
    throughput = (processed * 1400 * 8) / (end - start) / 1e6  # Mbps

    print(f"Traffic shaping throughput: {throughput:.2f} Mbps")


def benchmark_anti_dpi():
    """Benchmark anti-DPI operations."""
    print("Benchmarking anti-DPI padding...")

    anti_dpi = AntiDPI(max_padding=255)
    packets = [os.urandom(100 + i*10) for i in range(100)]  # Varying sizes

    start = time.time()
    padded_packets = [anti_dpi.apply_padding(pkt) for pkt in packets]
    padding_time = time.time() - start

    start = time.time()
    stripped_packets = [anti_dpi.strip_padding(pkt) for pkt in padded_packets]
    stripping_time = time.time() - start

    assert packets == stripped_packets

    avg_padding = (padding_time / len(packets)) * 1000
    avg_stripping = (stripping_time / len(packets)) * 1000

    print(f"Anti-DPI padding: {avg_padding:.2f} ms per packet")
    print(f"Anti-DPI stripping: {avg_stripping:.2f} ms per packet")


if __name__ == "__main__":
    print("PQVPN Performance Benchmarks")
    print("=" * 40)

    benchmark_crypto()
    print()

    benchmark_layered_crypto()
    print()

    benchmark_traffic_shaping()
    print()

    benchmark_anti_dpi()
    print()

    print("Benchmarks completed.")