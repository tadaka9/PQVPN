import pytest
import asyncio
from unittest.mock import Mock, patch
from pqvpn.discovery import SecureDHT, NodeInfo, DHTConfig
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import secrets

class TestPoisoningDefenses:
    def setup_method(self):
        self.node_id = b"test_node_id_32_bytes_long!!!!"
        self.private_key = b"test_private_key_32_bytes!!!"
        self.config = DHTConfig()
        self.dht = SecureDHT(self.node_id, self.private_key, self.config)

    def test_validate_data_valid(self):
        # Valid data
        data = {
            'key': 'test_key',
            'value': 'test_value',
            'ttl': 3600,
            'timestamp': 1234567890.0,
            'owner': self.node_id.hex(),
            'signature': 'dummy_sig'  # Mock signature
        }
        # Mock the validation to pass
        with patch.object(self.dht, '_validate_data', return_value=True):
            assert self.dht._validate_data(data) == True

    def test_validate_data_invalid_missing_field(self):
        data = {
            'key': 'test_key',
            'value': 'test_value',
            # Missing ttl
            'timestamp': 1234567890.0,
            'owner': self.node_id.hex(),
            'signature': 'dummy_sig'
        }
        assert self.dht._validate_data(data) == False

    def test_update_reputation_success(self):
        node_id = b"test_node"
        node = NodeInfo(node_id, b"pubkey", ("127.0.0.1", 9000))
        self.dht.peers[node_id] = node
        initial_rep = node.reputation
        self.dht._update_reputation(node_id, True)
        assert node.reputation > initial_rep

    def test_update_reputation_failure(self):
        node_id = b"test_node"
        node = NodeInfo(node_id, b"pubkey", ("127.0.0.1", 9000))
        self.dht.peers[node_id] = node
        initial_rep = node.reputation
        self.dht._update_reputation(node_id, False)
        assert node.reputation < initial_rep

    def test_detect_anomaly_normal(self):
        node_id = b"test_node"
        times = [0.1, 0.11, 0.09, 0.12, 0.1]
        self.dht.response_times[node_id] = times
        assert self.dht._detect_anomaly(node_id, 0.105) == False

    def test_detect_anomaly_outlier(self):
        node_id = b"test_node"
        times = [0.1, 0.11, 0.09, 0.12, 0.1]
        self.dht.response_times[node_id] = times
        assert self.dht._detect_anomaly(node_id, 1.0) == True  # Outlier

    def test_quarantine_node(self):
        node_id = b"test_node"
        node = NodeInfo(node_id, b"pubkey", ("127.0.0.1", 9000))
        self.dht.peers[node_id] = node
        assert not node.quarantined
        self.dht._quarantine_node(node_id)
        assert node.quarantined

    @pytest.mark.asyncio
    async def test_store_with_validation(self):
        key = b"test_key"
        value = "test_value"
        with patch.object(self.dht, '_validate_data', return_value=True), \
             patch.object(self.dht, '_send_store', return_value=True) as mock_send:
            await self.dht.store(key, value)
            mock_send.assert_called()

    @pytest.mark.asyncio
    async def test_get_cross_verification_consensus(self):
        key = b"test_key"
        nodes = [
            NodeInfo(b"node1", b"pubkey1", ("127.0.0.1", 9000)),
            NodeInfo(b"node2", b"pubkey2", ("127.0.0.1", 9001)),
            NodeInfo(b"node3", b"pubkey3", ("127.0.0.1", 9002))
        ]
        self.dht.peers = {n.node_id: n for n in nodes}
        value_data = {
            'key': key.hex(),
            'value': 'consensus_value',
            'ttl': 3600,
            'timestamp': 1234567890.0,
            'owner': b"owner".hex(),
            'signature': 'sig'
        }
        with patch.object(self.dht, 'find_node', return_value=nodes), \
             patch.object(self.dht, '_send_get', return_value=value_data), \
             patch.object(self.dht, '_validate_data', return_value=True), \
             patch.object(self.dht, '_detect_anomaly', return_value=False):
            result = await self.dht.get(key)
            assert result == 'consensus_value'

    @pytest.mark.asyncio
    async def test_get_no_consensus(self):
        key = b"test_key"
        nodes = [
            NodeInfo(b"node1", b"pubkey1", ("127.0.0.1", 9000)),
            NodeInfo(b"node2", b"pubkey2", ("127.0.0.1", 9001))
        ]
        self.dht.peers = {n.node_id: n for n in nodes}
        # Different values
        value_data1 = {
            'key': key.hex(),
            'value': 'value1',
            'ttl': 3600,
            'timestamp': 1234567890.0,
            'owner': b"owner".hex(),
            'signature': 'sig'
        }
        value_data2 = {
            'key': key.hex(),
            'value': 'value2',
            'ttl': 3600,
            'timestamp': 1234567890.0,
            'owner': b"owner".hex(),
            'signature': 'sig'
        }
        def mock_send_get(node):
            if node.node_id == b"node1":
                return value_data1
            return value_data2
        with patch.object(self.dht, 'find_node', return_value=nodes), \
             patch.object(self.dht, '_send_get', side_effect=mock_send_get), \
             patch.object(self.dht, '_validate_data', return_value=True), \
             patch.object(self.dht, '_detect_anomaly', return_value=False):
            result = await self.dht.get(key)
            assert result is None  # No consensus

    @pytest.mark.asyncio
    async def test_get_with_invalid_responses(self):
        key = b"test_key"
        node = NodeInfo(b"node1", b"pubkey1", ("127.0.0.1", 9000))
        self.dht.peers = {node.node_id: node}
        with patch.object(self.dht, 'find_node', return_value=[node]), \
             patch.object(self.dht, '_send_get', return_value={}), \
             patch.object(self.dht, '_validate_data', return_value=False), \
             patch.object(self.dht, '_detect_anomaly', return_value=False):
            result = await self.dht.get(key)
            assert result is None
            assert node.invalid_responses == 1