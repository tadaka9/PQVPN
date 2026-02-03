#!/usr/bin/env python3
"""
Manual test for traffic shaping and anti-DPI.
"""

import asyncio
import time

from src.pqvpn.anti_dpi import AntiDPI
from src.pqvpn.traffic_shaper import TrafficShaper


async def test_shaping():
    print("Testing traffic shaping...")
    shaper = TrafficShaper(1000, 3)  # 1000 bytes/s
    await shaper.start()

    # Enqueue packets
    for i in range(5):
        await shaper.enqueue_packet(f"data{i}".encode(), ("127.0.0.1", 9000))

    packets = []
    for _ in range(5):
        p = await shaper.get_next_packet()
        if p:
            packets.append(p)

    print(f"Shaped {len(packets)} packets")
    await shaper.stop()


def test_anti_dpi():
    print("Testing anti-DPI...")
    anti_dpi = AntiDPI(10, 5)
    data = b"test data"
    padded = anti_dpi.apply_padding(data)
    stripped = anti_dpi.strip_padding(padded)
    assert stripped == data
    delay = anti_dpi.get_send_delay()
    print(f"Padded from {len(data)} to {len(padded)}, delay {delay:.3f}s")


async def test_compute_usage():
    print("Testing compute usage...")
    start = time.time()
    anti_dpi = AntiDPI(255, 10)
    shaper = TrafficShaper(1000000, 3)
    await shaper.start()

    for i in range(1000):
        data = b"x" * 100
        padded = anti_dpi.apply_padding(data)
        stripped = anti_dpi.strip_padding(padded)
        assert stripped == data
        await shaper.enqueue_packet(data, ("127.0.0.1", 9000))
        packet = await shaper.get_next_packet()

    elapsed = time.time() - start
    print(f"Processed 1000 packets in {elapsed:.2f}s, {1000/elapsed:.1f} packets/s")

    await shaper.stop()


if __name__ == "__main__":
    asyncio.run(test_shaping())
    test_anti_dpi()
    asyncio.run(test_compute_usage())
    print("Manual tests completed.")