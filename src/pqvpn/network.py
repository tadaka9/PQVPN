# src/pqvpn/network.py
"""
Networking module for PQVPN.

Handles connections, sessions, peers, and low-level network operations.
"""

import asyncio
import socket
import time
from typing import Dict, Optional, Tuple, List, Any, Set
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

from .traffic_shaper import TrafficShaper
from .anti_dpi import AntiDPI
from .robustness import circuit_breaker, log_with_context, ErrorType
FT_HELLO = 0x00
FT_S1 = 0x01
FT_S2 = 0x02
FT_DATA = 0x03
FT_KEEPALIVE = 0x04
FT_ECHO = 0x05
FT_ECHO_RESPONSE = 0x06
FT_RELAY = 0x07
FT_PEER_ANNOUNCE = 0x10
FT_ROUTE_QUERY = 0x11
FT_ROUTE_REPLY = 0x12
FT_RELAY_HEARTBEAT = 0x13
FT_HEALTH_CHECK = 0x14
FT_HEALTH_RESPONSE = 0x15
FT_PATH_SWITCH = 0x16
FT_TELEMETRY = 0x17
FT_REKEY_PROPOSAL = 0x19
FT_REKEY_ACK = 0x1A
FT_ZK_CHALLENGE = 0x1C
FT_ZK_RESPONSE = 0x1D
FT_AUDIT_LOG = 0x21
FT_PATH_PROBE = 0x1E
FT_PATH_PONG = 0x1F

# Constants
NONCE_LENGTH = 12
SESSION_TIMEOUT = 3600
HANDSHAKE_TIMEOUT = 30
KEEPALIVE_INTERVAL = 30
MAX_PACKET_SIZE = 65535
MAX_HOPS = 3
PEER_ANNOUNCE_INTERVAL = 10
HEALTH_CHECK_INTERVAL = 10
DEFAULT_PPS_LIMIT = 1000

# Session states
SESSION_STATE_PENDING = "PENDING"
SESSION_STATE_HANDSHAKING = "HANDSHAKING"
SESSION_STATE_ESTABLISHED = "ESTABLISHED"
SESSION_STATE_REKEYING = "REKEYING"
SESSION_STATE_CLOSED = "CLOSED"


@dataclass
class PeerInfo:
    peer_id: bytes
    nickname: str
    address: Tuple[str, int]
    ed25519_pk: bytes
    brainpoolP512r1_pk: bytes
    kyber_pk: bytes
    mldsa_pk: bytes
    kyber_alg: Optional[str] = None
    sig_alg: Optional[str] = None
    last_seen: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    hops: int = 0
    route_quality: float = 1.0
    is_relay: bool = False


@dataclass
class AuditLogEntry:
    timestamp: float
    event_type: str
    peer_id: bytes
    description: str


class NetworkTransport:
    """Abstract base for network transport implementations."""

    async def start(self):
        raise NotImplementedError

    async def stop(self):
        raise NotImplementedError

    async def send_datagram(self, data: bytes, addr: Tuple[str, int]):
        raise NotImplementedError

    async def receive_datagram(self) -> Tuple[bytes, Tuple[str, int]]:
        raise NotImplementedError


class UDPTransport(NetworkTransport):
    """UDP-based transport implementation."""

    def __init__(self, bind_host: str = "127.0.0.1", listen_port: int = 9000, max_concurrent: int = 200):
        self.bind_host = bind_host
        self.listen_port = listen_port
        self.max_concurrent = max_concurrent
        self.sock: Optional[socket.socket] = None
        self._running = False
        self._receive_queue = asyncio.Queue()

    async def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_host, self.listen_port))
        self.sock.setblocking(False)
        self._running = True
        asyncio.create_task(self._receive_loop())
        logger.info(f"UDP transport started on {self.bind_host}:{self.listen_port}")

    async def stop(self):
        self._running = False
        if self.sock:
            self.sock.close()
        logger.info("UDP transport stopped")

    async def _receive_loop(self):
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, MAX_PACKET_SIZE)
                await self._receive_queue.put((data, addr))
            except Exception as e:
                if self._running:
                    logger.error(f"UDP receive error: {e}")

    async def send_datagram(self, data: bytes, addr: Tuple[str, int]):
        if not self.sock:
            raise RuntimeError("Transport not started")
        loop = asyncio.get_running_loop()
        await loop.sock_sendto(self.sock, data, addr)

    async def receive_datagram(self) -> Tuple[bytes, Tuple[str, int]]:
        return await self._receive_queue.get()


class NetworkManager:
    """Manages network operations, peers, and sessions."""

    def __init__(self, transport: NetworkTransport, config: Dict[str, Any]):
        self.transport = transport
        self.config = config
        self.peers: Dict[bytes, PeerInfo] = {}
        self.sessions: Dict[bytes, Any] = {}  # Will be SessionInfo from session.py
        self.relay_manager: Optional[Any] = None  # RelayManager if acting as relay
        self.my_relay_id: Optional[bytes] = None
        self._running = False
        self._tasks = []
        self.traffic_shaper = TrafficShaper(config.get('rate_limit', 1000000.0))
        self.anti_dpi = AntiDPI(config.get('max_padding', 255), config.get('max_jitter_ms', 10.0))

    async def start(self):
        await self.transport.start()
        await self.traffic_shaper.start()
        self._running = True
        self._tasks.append(asyncio.create_task(self._receive_loop()))
        self._tasks.append(asyncio.create_task(self._keepalive_loop()))
        self._tasks.append(asyncio.create_task(self._sending_loop()))
        logger.info("Network manager started")

    async def stop(self):
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.traffic_shaper.stop()
        await self.transport.stop()
        logger.info("Network manager stopped")

    async def _receive_loop(self):
        while self._running:
            try:
                data, addr = await asyncio.wait_for(self.transport.receive_datagram(), timeout=HANDSHAKE_TIMEOUT)
                await self._handle_packet(data, addr)
            except asyncio.TimeoutError:
                log_with_context("Receive timeout", "warning", {"timeout": HANDSHAKE_TIMEOUT})
                continue
            except Exception as e:
                log_with_context(f"Packet handling error: {e}", "error", {"error_type": type(e).__name__})
                await asyncio.sleep(1)  # Auto-recovery: backoff on error

    async def _handle_packet(self, data: bytes, addr: Tuple[str, int]):
        # Strip anti-DPI padding
        data = self.anti_dpi.strip_padding(data)
        # Parse frame type
        if len(data) < 1:
            log_with_context("Received packet too short", "warning", {"addr": addr})
            return
        frame_type = data[0]
        payload = data[1:]

        # Dispatch based on frame type
        handlers = {
            FT_HELLO: self._handle_hello,
            FT_DATA: self._handle_data,
            FT_KEEPALIVE: self._handle_keepalive,
            FT_RELAY: self._handle_relay,
            # Add more handlers
        }

        handler = handlers.get(frame_type)
        if handler:
            try:
                await handler(payload, addr)
            except Exception as e:
                log_with_context(f"Handler error for frame {frame_type}: {e}", "error", {"addr": addr, "frame_type": frame_type})
        else:
            log_with_context(f"Unknown frame type: {frame_type}", "debug", {"addr": addr})

    async def _handle_hello(self, payload: bytes, addr: Tuple[str, int]):
        # Placeholder for hello handling
        logger.debug(f"Hello from {addr}")

    async def _handle_data(self, payload: bytes, addr: Tuple[str, int]):
        # Placeholder for data handling
        logger.debug(f"Data packet from {addr}")

    async def _handle_keepalive(self, payload: bytes, addr: Tuple[str, int]):
        # Placeholder for keepalive
        logger.debug(f"Keepalive from {addr}")

    async def _handle_relay(self, payload: bytes, addr: Tuple[str, int]):
        # Handle relay packet with layered crypto
        if self.relay_manager and self.my_relay_id:
            try:
                await circuit_breaker.call(self.relay_manager.handle_relay_packet, payload, addr, self.my_relay_id)
            except Exception as e:
                log_with_context(f"Relay handling failed: {e}", "error", {"addr": addr})
                # Auto-recovery: could switch relays
        else:
            log_with_context("Relay packet received but no relay manager configured", "warning", {"addr": addr})

    async def _sending_loop(self):
        while self._running:
            packet = await self.traffic_shaper.get_next_packet()
            if packet:
                data, addr = packet
                # Apply anti-DPI padding
                padded_data = self.anti_dpi.apply_padding(data)
                # Get delay
                delay = self.anti_dpi.get_send_delay()
                if delay > 0:
                    await asyncio.sleep(delay)
                # Send
                try:
                    await circuit_breaker.call(self._send_with_circuit, padded_data, addr)
                except Exception as e:
                    log_with_context(f"Send failed: {e}", "error", {"addr": addr})
                    # Auto-recovery: could retry or mark peer as bad
            else:
                await asyncio.sleep(0.01)

    async def _send_with_circuit(self, data: bytes, addr: Tuple[str, int]):
        await self.transport.send_datagram(data, addr)

    async def _keepalive_loop(self):
        while self._running:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            # Send keepalives to active sessions

    def add_peer(self, peer: PeerInfo):
        self.peers[peer.peer_id] = peer

    def get_peer(self, peer_id: bytes) -> Optional[PeerInfo]:
        return self.peers.get(peer_id)

    async def send_packet(self, data: bytes, addr: Tuple[str, int], priority: int = 1):
        """Send a packet through the shaper and anti-DPI."""
        await self.traffic_shaper.enqueue_packet(data, addr, priority)

    @staticmethod
    def check_network_health() -> bool:
        """Health check for network connectivity."""
        try:
            # Simple socket test
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b"test", ("8.8.8.8", 53))  # DNS query to Google
            sock.close()
            return True
        except Exception as e:
            log_with_context(f"Network health check failed: {e}", "warning")
            return False