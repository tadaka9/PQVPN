"""
Integration tests for relay and multi-hop routing.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from pqvpn.network import NetworkManager, UDPTransport
from pqvpn.relay import RelayManager


@pytest.mark.asyncio
async def test_relay_packet_handling():
    # Mock transport
    transport = MagicMock()
    transport.send_datagram = AsyncMock()

    config = {}
    network_manager = NetworkManager(transport, config)
    master_key = b"master_key_32_bytes_long!!!!!!"
    relay_manager = RelayManager(network_manager, master_key)
    network_manager.relay_manager = relay_manager
    network_manager.my_relay_id = b"relay1"

    # Register a route
    session_id = b"session123"
    route = [b"relay1", b"relay2", b"relay3"]
    relay_manager.register_route(session_id, route)

    # Encrypt a payload for the route
    payload = b"Test payload"
    encrypted = relay_manager.encrypt_for_route(payload, session_id)

    # Simulate receiving the packet
    from_addr = ("127.0.0.1", 9001)
    await relay_manager.handle_relay_packet(encrypted, from_addr, b"relay1")

    # Check that it was forwarded to next hop
    transport.send_datagram.assert_called_once()
    sent_data, sent_addr = transport.send_datagram.call_args[0]
    # sent_data should be the decrypted inner packet
    assert sent_data != encrypted
    # In this case, since it's multi-layer, it should have forwarded the inner encrypted packet