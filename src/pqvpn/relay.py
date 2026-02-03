"""
pqvpn.relay - Relay functionality for onion routing with layered crypto.
"""

from __future__ import annotations

import logging

from . import layered_crypto, network

logger = logging.getLogger(__name__)


class RelayManager:
    """Manages relay operations for onion routing."""

    def __init__(self, network_manager: network.NetworkManager, master_key: bytes):
        self.network_manager = network_manager
        self.master_key = master_key
        self.routes: dict[bytes, list[bytes]] = {}  # session_id -> route

    async def handle_relay_packet(self, packet: bytes, from_addr: tuple[str, int], my_relay_id: bytes) -> None:
        """
        Handle an incoming relay packet: decrypt outer layer and forward.
        """
        inner_packet, next_hop = layered_crypto.decrypt_layered_packet_with_route(packet, my_relay_id, self.master_key)
        if next_hop:
            # Forward to next hop
            next_peer = self.network_manager.get_peer(next_hop)
            if next_peer:
                await self.network_manager.send_datagram(inner_packet, next_peer.address)
            else:
                logger.error(f"Next hop {next_hop.hex()} not found")
        else:
            # This is the final destination, process the payload
            logger.info("Received final payload")
            # TODO: Process the inner_packet as data

    def register_route(self, session_id: bytes, route: list[bytes]) -> None:
        """Register a route for a session."""
        self.routes[session_id] = route

    def encrypt_for_route(self, payload: bytes, session_id: bytes) -> bytes:
        """Encrypt payload for the registered route."""
        route = self.routes.get(session_id)
        if not route:
            raise ValueError(f"No route registered for session {session_id.hex()}")
        return layered_crypto.encrypt_layered_packet_with_route(payload, route, self.master_key)