# tests/test_traffic_shaper.py
"""
Unit tests for traffic_shaper module.
"""

import pytest

from pqvpn.traffic_shaper import TokenBucket, TrafficShaper


class TestTokenBucket:
    def test_consume_within_limit(self):
        bucket = TokenBucket(100, 200)
        assert bucket.consume(50)
        assert bucket.tokens == 150

    def test_consume_over_limit(self):
        bucket = TokenBucket(100, 100)
        assert not bucket.consume(150)
        assert bucket.tokens == 100

    def test_refill(self):
        bucket = TokenBucket(100, 100)
        bucket.consume(50)
        import time
        time.sleep(0.1)  # 10 tokens refill
        assert bucket.consume(60)  # 50 + 10 = 60 < 100


class TestTrafficShaper:
    @pytest.mark.asyncio
    async def test_enqueue_and_get(self):
        shaper = TrafficShaper(1000, 3)
        await shaper.start()
        await shaper.enqueue_packet(b'data', ('127.0.0.1', 9000), 0)
        packet = await shaper.get_next_packet()
        assert packet == (b'data', ('127.0.0.1', 9000))
        await shaper.stop()

    @pytest.mark.asyncio
    async def test_priority(self):
        shaper = TrafficShaper(1000, 3)
        await shaper.start()
        await shaper.enqueue_packet(b'low', ('127.0.0.1', 9000), 2)
        await shaper.enqueue_packet(b'high', ('127.0.0.1', 9000), 0)
        packet = await shaper.get_next_packet()
        assert packet[0] == b'high'
        packet = await shaper.get_next_packet()
        assert packet[0] == b'low'
        await shaper.stop()