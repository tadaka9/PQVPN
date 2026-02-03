#!/usr/bin/env python3
"""
PQVPN Performance Benchmarks
"""

import random
import threading
import time

import matplotlib.pyplot as plt
import numpy as np


# Mock PQVPN class for simulation
class PQVPN:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def encrypt(self, data):
        # Simulate PQ encryption overhead
        time.sleep(random.uniform(0.001, 0.005) if self.enabled else 0.0001)
        return data

    def decrypt(self, data):
        # Simulate PQ decryption overhead
        time.sleep(random.uniform(0.001, 0.005) if self.enabled else 0.0001)
        return data

def benchmark_throughput(vpn, data_size=1000000):
    """Benchmark throughput: MB/s"""
    data = b'x' * data_size
    start = time.time()
    for _ in range(100):
        encrypted = vpn.encrypt(data)
        decrypted = vpn.decrypt(encrypted)
    end = time.time()
    total_data = data_size * 100 * 2  # encrypt and decrypt
    throughput = total_data / (end - start) / 1e6  # MB/s
    return throughput

def benchmark_latency(vpn):
    """Benchmark latency: ms"""
    latencies = []
    for _ in range(100):
        start = time.time()
        vpn.encrypt(b'ping')
        vpn.decrypt(b'ping')
        end = time.time()
        latencies.append((end - start) * 1000)
    return np.mean(latencies), np.std(latencies)

def benchmark_crypto_overhead():
    """Crypto overhead: time per operation"""
    vpn_on = PQVPN(True)
    vpn_off = PQVPN(False)
    data = b'x' * 1000
    times_on = []
    times_off = []
    for _ in range(1000):
        start = time.time()
        vpn_on.encrypt(data)
        end = time.time()
        times_on.append(end - start)
        start = time.time()
        vpn_off.encrypt(data)
        end = time.time()
        times_off.append(end - start)
    overhead = np.mean(times_on) - np.mean(times_off)
    return overhead * 1000  # ms

def benchmark_scalability(max_threads=10):
    """Scalability: throughput vs threads"""
    throughputs = []
    for threads in range(1, max_threads + 1):
        vpn = PQVPN(True)
        results = []
        def worker():
            results.append(benchmark_throughput(vpn, 100000))
        start = time.time()
        ts = [threading.Thread(target=worker) for _ in range(threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        end = time.time()
        total_throughput = sum(results) / (end - start)  # average
        throughputs.append(total_throughput)
    return list(range(1, max_threads + 1)), throughputs

def run_benchmarks():
    print("Running PQVPN Benchmarks...")

    # Throughput
    vpn_on = PQVPN(True)
    vpn_off = PQVPN(False)
    throughput_on = benchmark_throughput(vpn_on)
    throughput_off = benchmark_throughput(vpn_off)
    print(f"Throughput VPN ON: {throughput_on:.2f} MB/s")
    print(f"Throughput VPN OFF: {throughput_off:.2f} MB/s")

    # Latency
    lat_mean, lat_std = benchmark_latency(vpn_on)
    print(f"Latency: {lat_mean:.2f} ± {lat_std:.2f} ms")

    # Crypto overhead
    overhead = benchmark_crypto_overhead()
    print(f"Crypto Overhead: {overhead:.4f} ms per operation")

    # Scalability
    threads, throughputs = benchmark_scalability(5)
    print("Scalability:")
    for t, tp in zip(threads, throughputs):
        print(f"  {t} threads: {tp:.2f} MB/s")

    # Plots
    fig, axs = plt.subplots(2, 2, figsize=(12, 8))

    # Throughput bar
    axs[0,0].bar(['VPN OFF', 'VPN ON'], [throughput_off, throughput_on])
    axs[0,0].set_title('Throughput (MB/s)')
    axs[0,0].set_ylabel('MB/s')

    # Latency bar
    axs[0,1].bar(['Latency'], [lat_mean], yerr=lat_std)
    axs[0,1].set_title('Latency (ms)')
    axs[0,1].set_ylabel('ms')

    # Crypto overhead bar
    axs[1,0].bar(['Overhead'], [overhead])
    axs[1,0].set_title('Crypto Overhead (ms)')
    axs[1,0].set_ylabel('ms')

    # Scalability line
    axs[1,1].plot(threads, throughputs, marker='o')
    axs[1,1].set_title('Scalability (Throughput vs Threads)')
    axs[1,1].set_xlabel('Threads')
    axs[1,1].set_ylabel('MB/s')

    plt.tight_layout()
    plt.savefig('benchmarks.png')
    print("Plots saved to benchmarks.png")

if __name__ == '__main__':
    run_benchmarks()