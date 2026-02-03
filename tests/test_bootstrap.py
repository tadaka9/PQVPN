from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pqvpn.bootstrap import BootstrapClient, get_bootstrap_peers


class TestBootstrapClient:
    @pytest.mark.asyncio
    async def test_get_bootstrap_peers_success(self):
        """Test successful bootstrap peer retrieval."""
        client = BootstrapClient(seed_nodes=["seed1"], relays=["relay1"])

        with patch.object(client, '_query_seed', return_value=[("192.168.1.1", 9000)]) as mock_seed, \
             patch.object(client, '_query_relay', return_value=[("192.168.1.2", 9001)]) as mock_relay:

            peers = await client.get_bootstrap_peers()
            assert len(peers) == 2
            assert ("192.168.1.1", 9000) in peers
            assert ("192.168.1.2", 9001) in peers
            mock_seed.assert_called_once_with("seed1")
            mock_relay.assert_called_once_with("relay1")

    @pytest.mark.asyncio
    async def test_get_bootstrap_peers_deduplication(self):
        """Test that duplicate peers are removed."""
        client = BootstrapClient(seed_nodes=["seed1"], relays=["relay1"])

        with patch.object(client, '_query_seed', return_value=[("192.168.1.1", 9000)]) as mock_seed, \
             patch.object(client, '_query_relay', return_value=[("192.168.1.1", 9000)]) as mock_relay:

            peers = await client.get_bootstrap_peers()
            assert len(peers) == 1
            assert peers[0] == ("192.168.1.1", 9000)

    @pytest.mark.asyncio
    async def test_get_bootstrap_peers_failure(self):
        """Test handling of query failures."""
        client = BootstrapClient(seed_nodes=["seed1"], relays=["relay1"])

        with patch.object(client, '_query_seed', side_effect=Exception("Network error")) as mock_seed, \
             patch.object(client, '_query_relay', return_value=[("192.168.1.2", 9001)]) as mock_relay:

            peers = await client.get_bootstrap_peers()
            assert len(peers) == 1
            assert peers[0] == ("192.168.1.2", 9001)

    @pytest.mark.asyncio
    async def test_query_seed_success(self):
        """Test querying a seed node."""
        client = BootstrapClient()

        mock_response = MagicMock()
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_response.json = AsyncMock(return_value={"peers": [{"host": "1.2.3.4", "port": 9000}]})
        mock_response.status = 200

        async with client:
            with patch.object(client.session, 'get', return_value=mock_response) as mock_get:
                peers = await client._query_seed("seed1")
                assert peers == [("1.2.3.4", 9000)]
                mock_get.assert_called_once()

    @pytest.mark.asyncio
    async def test_query_seed_failure(self):
        """Test seed query failure."""
        client = BootstrapClient()

        async with client:
            with patch.object(client.session, 'get', side_effect=Exception("Connection failed")):
                peers = await client._query_seed("seed1")
                assert peers == []

    @pytest.mark.asyncio
    async def test_query_relay_success(self):
        """Test querying a relay."""
        client = BootstrapClient()

        mock_response = MagicMock()
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        mock_response.json = AsyncMock(return_value={"bootstrap_peers": [{"host": "5.6.7.8", "port": 9001}]})
        mock_response.status = 200

        async with client:
            with patch.object(client.session, 'get', return_value=mock_response) as mock_get:
                peers = await client._query_relay("relay1")
                assert peers == [("5.6.7.8", 9001)]
                mock_get.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        client = BootstrapClient()
        async with client:
            assert client.session is not None
        # Session is closed after context manager


@pytest.mark.asyncio
async def test_get_bootstrap_peers_function():
    """Test the convenience function."""
    with patch('src.pqvpn.bootstrap.BootstrapClient') as mock_client_class:
        mock_client = AsyncMock()
        mock_client.get_bootstrap_peers.return_value = [("1.1.1.1", 9000)]
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = None

        peers = await get_bootstrap_peers()
        assert peers == [("1.1.1.1", 9000)]
        mock_client.get_bootstrap_peers.assert_called_once()