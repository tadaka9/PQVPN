# src/pqvpn/anti_dpi.py
"""
Anti-DPI module for PQVPN.

Provides low-overhead techniques to evade Deep Packet Inspection.
"""

import os
import random
import time
from typing import Tuple
import logging

logger = logging.getLogger(__name__)


class PaddingAlgorithm:
    """Handles packet padding for obfuscation."""

    def __init__(self, max_padding: int = 255):
        self.max_padding = max_padding

    def apply_padding(self, data: bytes) -> bytes:
        """Add random padding to data."""
        padding_len = random.randint(0, self.max_padding)
        padding = os.urandom(padding_len)
        # Prefix with padding length (1 byte, assuming <256)
        return bytes([padding_len]) + padding + data

    def strip_padding(self, data: bytes) -> bytes:
        """Remove padding from data."""
        if len(data) < 1:
            return data
        padding_len = data[0]
        if len(data) < 1 + padding_len:
            logger.warning("Invalid padding length")
            return data
        return data[1 + padding_len:]


class TimingObfuscator:
    """Introduces randomization in packet timing."""

    def __init__(self, max_jitter_ms: float = 10.0):
        self.max_jitter_ms = max_jitter_ms

    def get_delay(self) -> float:
        """Get random delay in seconds."""
        return random.uniform(0, self.max_jitter_ms / 1000.0)


class AntiDPI:
    """Main anti-DPI class."""

    def __init__(self, max_padding: int = 255, max_jitter_ms: float = 10.0):
        self.padder = PaddingAlgorithm(max_padding)
        self.timer = TimingObfuscator(max_jitter_ms)

    def apply_padding(self, data: bytes) -> bytes:
        return self.padder.apply_padding(data)

    def strip_padding(self, data: bytes) -> bytes:
        return self.padder.strip_padding(data)

    def get_send_delay(self) -> float:
        return self.timer.get_delay()