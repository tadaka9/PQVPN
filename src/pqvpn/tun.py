"""
TUN Interface module for PQVPN - OS-agnostic TUN/TAP interface handling.

This module provides cross-platform TUN interface creation and management
for VPN traffic routing.
"""

import asyncio
import logging
import platform
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class TunInterface(ABC):
    """Abstract base class for TUN interface operations."""

    @abstractmethod
    async def create(self, name: str, ip: str, netmask: str) -> None:
        """Create and configure the TUN interface."""
        pass

    @abstractmethod
    async def read_packet(self) -> bytes:
        """Read a packet from the TUN interface."""
        pass

    @abstractmethod
    async def write_packet(self, packet: bytes) -> None:
        """Write a packet to the TUN interface."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the TUN interface."""
        pass

class LinuxTun(TunInterface):
    """Linux-specific TUN interface implementation using pytun."""

    def __init__(self):
        self._tun = None
        self._loop = None

    async def create(self, name: str, ip: str, netmask: str) -> None:
        try:
            import pytun
        except ImportError:
            raise RuntimeError("pytun not installed. Install with: pip install pytun")

        self._tun = pytun.TunTapDevice(name=name)
        self._tun.addr = ip
        self._tun.netmask = netmask
        self._tun.mtu = 1500
        self._tun.up()

        self._loop = asyncio.get_running_loop()
        logger.info(f"Created TUN interface {name} with IP {ip}")

    async def read_packet(self) -> bytes:
        if not self._tun:
            raise RuntimeError("TUN interface not created")

        # Use asyncio to read from the file descriptor
        loop = asyncio.get_running_loop()
        packet = await loop.run_in_executor(None, self._tun.read, 65535)
        return packet

    async def write_packet(self, packet: bytes) -> None:
        if not self._tun:
            raise RuntimeError("TUN interface not created")

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._tun.write, packet)

    async def close(self) -> None:
        if self._tun:
            self._tun.close()
            self._tun = None
            logger.info("Closed TUN interface")

class WindowsTun(TunInterface):
    """Windows-specific TUN interface implementation."""

    def __init__(self):
        self._tun = None

    async def create(self, name: str, ip: str, netmask: str) -> None:
        # Placeholder for Windows implementation
        # Would use wintun-python or similar
        raise NotImplementedError("Windows TUN interface not yet implemented")

    async def read_packet(self) -> bytes:
        raise NotImplementedError()

    async def write_packet(self, packet: bytes) -> None:
        raise NotImplementedError()

    async def close(self) -> None:
        raise NotImplementedError()

class MacTun(TunInterface):
    """macOS-specific TUN interface implementation."""

    def __init__(self):
        self._tun = None

    async def create(self, name: str, ip: str, netmask: str) -> None:
        # Placeholder for macOS implementation
        # Similar to Linux but may need adjustments
        raise NotImplementedError("macOS TUN interface not yet implemented")

    async def read_packet(self) -> bytes:
        raise NotImplementedError()

    async def write_packet(self, packet: bytes) -> None:
        raise NotImplementedError()

    async def close(self) -> None:
        raise NotImplementedError()

def create_tun_interface() -> TunInterface:
    """Factory function to create platform-specific TUN interface."""
    system = platform.system().lower()
    if system == "linux":
        return LinuxTun()
    elif system == "windows":
        return WindowsTun()
    elif system == "darwin":  # macOS
        return MacTun()
    else:
        raise RuntimeError(f"Unsupported platform: {system}")

# VPN Traffic Routing Integration
class VpnRouter:
    """Handles routing between TUN interface and VPN sessions."""

    def __init__(self, tun: TunInterface, node):
        self.tun = tun
        self.node = node
        self._running = False
        self._tasks = []

    async def start(self):
        """Start the routing loops."""
        self._running = True
        self._tasks = [
            asyncio.create_task(self._tun_to_vpn()),
            asyncio.create_task(self._vpn_to_tun()),
        ]
        logger.info("Started VPN routing")

    async def stop(self):
        """Stop the routing loops."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("Stopped VPN routing")

    async def _tun_to_vpn(self):
        """Route packets from TUN to VPN sessions."""
        while self._running:
            try:
                packet = await self.tun.read_packet()
                # Parse IP packet to determine destination
                # For now, assume routing to a specific peer or broadcast
                # TODO: Implement proper IP routing logic
                logger.debug(f"Received packet from TUN: {len(packet)} bytes")
                # Route to appropriate session
            except Exception as e:
                logger.error(f"Error reading from TUN: {e}")
                await asyncio.sleep(1)

    async def _vpn_to_tun(self):
        """Route packets from VPN sessions to TUN."""
        while self._running:
            try:
                # Wait for packets from sessions
                # TODO: Integrate with node's session management
                await asyncio.sleep(1)  # Placeholder
            except Exception as e:
                logger.error(f"Error in VPN to TUN routing: {e}")

def check_tun_health() -> bool:
    """Health check for TUN interface."""
    try:
        system = platform.system().lower()
        if system == "linux":
            import pytun
            # Try to create a test TUN interface
            tun = pytun.TunTapDevice()
            tun.close()
            return True
        elif system == "darwin":
            # macOS check
            return True  # Placeholder
        elif system == "windows":
            # Windows check
            return True  # Placeholder
        else:
            return False
    except Exception:
        return False