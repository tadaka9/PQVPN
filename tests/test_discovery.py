# tests/test_discovery.py
"""Tests for discovery module."""

import asyncio
import pytest
from unittest.mock import Mock, AsyncMock
from pqvpn.discovery import Discovery, SecureDHT, NodeInfo, DHTConfig


@pytest.fixture
def mock_node():
    node = Mock()
    node.config = {"discovery": {"enabled": True, "dht_port": 8468}}
    node.my_id = b"test_id" * 8  # 64 bytes
    node.nickname = "test_node"
    return node


def test_discovery_init(mock_node):
    """Test discovery initialization."""
    discovery = Discovery(mock_node)
    assert discovery.enabled == True


def test_discovery_disabled():
    """Test discovery when disabled."""
    node = Mock()
    node.config = {"discovery": {"enabled": False}}

    discovery = Discovery(node)
    assert discovery.enabled == False


@pytest.fixture
def dht_config():
    return DHTConfig(k=5, alpha=2, id_bits=256, pow_difficulty=8)


@pytest.fixture
def node_id():
    return b"node_id" * 8


@pytest.fixture
def private_key():
    return b"private_key" * 8


@pytest.fixture
def public_key():
    return b"public_key" * 8


def test_secure_dht_init(node_id, private_key, dht_config):
    """Test SecureDHT initialization."""
    dht = SecureDHT(node_id, private_key, dht_config)
    assert dht.node_id == node_id
    assert dht.private_key == private_key
    assert dht.config == dht_config


def test_distance(node_id):
    """Test distance calculation."""
    dht = SecureDHT(node_id, b"priv", DHTConfig())
    other_id = b"other_id" * 8
    dist = dht._distance(node_id, other_id)
    assert isinstance(dist, int)
    assert dist >= 0


def test_bucket_index(node_id):
    """Test bucket index calculation."""
    dht = SecureDHT(node_id, b"priv")
    idx = dht._bucket_index(node_id)
    assert idx == 0  # Same ID

    other_id = bytes((node_id[0] ^ 1,) + node_id[1:])  # Flip LSB
    idx = dht._bucket_index(other_id)
    assert idx == 0  # Small distance


def test_verify_pow(node_id):
    """Test PoW verification."""
    dht = SecureDHT(node_id, b"priv", DHTConfig(pow_difficulty=8))
    nonce = dht.generate_pow(node_id)
    assert dht._verify_pow(node_id, nonce)


@pytest.mark.asyncio
async def test_add_node(node_id, private_key):
    """Test adding a node to routing table."""
    dht = SecureDHT(node_id, private_key)
    node_info = NodeInfo(
        node_id=b"peer_id" * 8,
        public_key=b"pub_key" * 8,
        address=("127.0.0.1", 8468)
    )
    await dht._add_node(node_info)
    assert node_info.node_id in dht.peers


@pytest.mark.asyncio
async def test_find_node(node_id, private_key):
    """Test finding nodes."""
    dht = SecureDHT(node_id, private_key)
    # Add some nodes
    for i in range(3):
        peer_id = bytes((node_id[0] ^ (i+1),) + node_id[1:])
        node_info = NodeInfo(peer_id, b"pub", ("127.0.0.1", 8468 + i))
        await dht._add_node(node_info)

    target = b"target" * 8
    nodes = await dht.find_node(target)
    assert len(nodes) <= dht.config.k


@pytest.mark.asyncio
async def test_store_and_get(node_id, private_key):
    """Test storing and retrieving data."""
    dht = SecureDHT(node_id, private_key)
    key = b"test_key"
    value = {"data": "test"}

    # Mock send_store and send_get
    dht._send_store = AsyncMock()
    dht._send_get = AsyncMock(return_value=value)

    await dht.store(key, value)
    retrieved = await dht.get(key)
    assert retrieved == value


@pytest.mark.asyncio
async def test_discovery_publish(mock_node):
    """Test discovery publish peer record."""
    discovery = Discovery(mock_node)
    discovery.dht = Mock()
    discovery.dht.store = AsyncMock()

    await discovery.publish_peer_record()
    discovery.dht.store.assert_called_once()


@pytest.mark.asyncio
async def test_discovery_start_stop(mock_node):
    """Test discovery start and stop."""
    discovery = Discovery(mock_node)
    discovery._get_bootstrap_nodes = AsyncMock(return_value=[])

    await discovery.start()
    assert discovery._started

    await discovery.stop()
    assert not discovery._started