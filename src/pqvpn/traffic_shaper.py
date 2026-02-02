# src/pqvpn/traffic_shaper.py
"""
Traffic shaping module for PQVPN.

Provides rate limiting and prioritization for outgoing packets.
"""

import asyncio
import time
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket for rate limiting."""

    def __init__(self, rate: float, capacity: float):
        """
        rate: tokens per second (e.g., bytes per second)
        capacity: max tokens
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()

    def _update_tokens(self):
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now

    def consume(self, tokens: float = 1.0) -> bool:
        self._update_tokens()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class TrafficShaper:
    """Manages traffic shaping with prioritization and rate limiting."""

    def __init__(self, rate_limit: float = 1000000.0, priority_levels: int = 3):  # 1MB/s default
        self.rate_limiter = TokenBucket(rate_limit, rate_limit * 2)  # capacity = 2 seconds worth
        self.priority_queues = [asyncio.PriorityQueue() for _ in range(priority_levels)]
        self._running = False

    async def start(self):
        self._running = True

    async def stop(self):
        self._running = False

    async def enqueue_packet(self, data: bytes, addr: Tuple[str, int], priority: int = 1):
        """Enqueue a packet with given priority (0 = highest)."""
        if 0 <= priority < len(self.priority_queues):
            await self.priority_queues[priority].put((time.time(), data, addr))
        else:
            logger.warning(f"Invalid priority {priority}, using default 1")
            await self.priority_queues[1].put((time.time(), data, addr))

    async def get_next_packet(self) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        """Get the next packet to send, respecting rate limits."""
        for queue in self.priority_queues:
            if not queue.empty():
                timestamp, data, addr = queue.get_nowait()
                packet_size = len(data)
                if self.rate_limiter.consume(packet_size):
                    return data, addr
                else:
                    # Re-enqueue at end
                    await queue.put((time.time(), data, addr))
                    break  # Wait a bit? For now, return None
        return None