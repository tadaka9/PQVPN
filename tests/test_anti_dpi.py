# tests/test_anti_dpi.py
"""
Unit tests for anti_dpi module.
"""

from pqvpn.anti_dpi import AntiDPI, PaddingAlgorithm, TimingObfuscator


class TestPaddingAlgorithm:
    def test_apply_strip(self):
        padder = PaddingAlgorithm(10)
        data = b'hello'
        padded = padder.apply_padding(data)
        stripped = padder.strip_padding(padded)
        assert stripped == data

    def test_strip_invalid(self):
        padder = PaddingAlgorithm()
        data = b'\xff'  # padding len 255 but data short
        stripped = padder.strip_padding(data)
        assert stripped == data  # returns as is


class TestTimingObfuscator:
    def test_get_delay(self):
        timer = TimingObfuscator(100)
        delay = timer.get_delay()
        assert 0 <= delay <= 0.1


class TestAntiDPI:
    def test_integration(self):
        anti_dpi = AntiDPI(10, 100)
        data = b'test'
        padded = anti_dpi.apply_padding(data)
        stripped = anti_dpi.strip_padding(padded)
        assert stripped == data
        delay = anti_dpi.get_send_delay()
        assert 0 <= delay <= 0.1