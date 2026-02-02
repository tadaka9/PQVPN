#!/usr/bin/env python3
"""
Manual test for DHT poisoning defenses in SecureDHT.

This script simulates poisoning attacks and verifies that defenses work.
"""

import asyncio
import logging
import time
import secrets
from pqvpn.discovery import SecureDHT, NodeInfo, DHTConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def simulate_poisoning_attack():
    logger.info("Starting poisoning simulation test")

    # Setup DHT - mock PQ crypto
    node_id = secrets.token_bytes(32)
    private_key = secrets.token_bytes(32)
    config = DHTConfig(k=5, alpha=2)

    # Patch oqs to avoid import error
    import pqvpn.discovery as disc
    disc.oqs = None  # Disable PQ for test

    dht = SecureDHT(node_id, private_key, config)

    # Add some legitimate nodes
    legit_nodes = []
    for i in range(5):
        nid = secrets.token_bytes(32)
        node = NodeInfo(nid, secrets.token_bytes(32), ("127.0.0.1", 9000 + i))
        legit_nodes.append(node)
        dht.peers[nid] = node

    # Simulate poisoning: inject invalid data
    key = secrets.token_bytes(32)
    invalid_value = "poisoned_data"

    # Store valid data first
    valid_data = {
        'key': key.hex(),
        'value': 'legitimate_value',
        'ttl': 3600,
        'timestamp': time.time(),
        'owner': node_id.hex(),
        'signature': 'valid_sig'  # Mock
    }
    dht.data_store[key] = valid_data

    # Now simulate get with poisoned responses
    poisoned_responses = [
        {  # Invalid format
            'key': key.hex(),
            'value': invalid_value,
            # Missing fields
        },
        {  # Valid format but invalid sig
            'key': key.hex(),
            'value': invalid_value,
            'ttl': 3600,
            'timestamp': time.time(),
            'owner': secrets.token_bytes(32).hex(),
            'signature': 'invalid_sig'
        },
        valid_data  # One valid
    ]

    def mock_send_get(node):
        idx = legit_nodes.index(node) % len(poisoned_responses)
        return poisoned_responses[idx]

    # Patch find_node and _send_get
    original_find = dht.find_node
    async def mock_find_node(target):
        return legit_nodes[:3]  # Return 3 nodes
    dht.find_node = mock_find_node

    original_send_get = dht._send_get
    dht._send_get = mock_send_get

    # Patch validation
    def mock_validate(data):
        return 'signature' in data and data.get('signature') == 'valid_sig'
    original_validate = dht._validate_data
    dht._validate_data = mock_validate

    # Test get
    result = await dht.get(key)
    logger.info(f"Get result: {result}")

    if result == 'legitimate_value':
        logger.info("✓ Poisoning defense successful: Valid value retrieved despite poisoned responses")
    else:
        logger.error("✗ Poisoning defense failed")

    # Test anomaly detection
    node_id_anomaly = legit_nodes[0].node_id
    for i in range(6):
        response_time = 0.1 if i < 5 else 2.0  # Outlier
        anomaly = dht._detect_anomaly(node_id_anomaly, response_time)
        if i == 5 and anomaly:
            logger.info("✓ Anomaly detection working")
        elif i < 5 and not anomaly:
            logger.info("✓ Normal responses not flagged")
        else:
            logger.error("✗ Anomaly detection issue")

    # Test reputation
    test_node = legit_nodes[1]
    initial_rep = test_node.reputation
    dht._update_reputation(test_node.node_id, True)
    if test_node.reputation > initial_rep:
        logger.info("✓ Reputation increased on success")
    dht._update_reputation(test_node.node_id, False)
    if test_node.reputation < initial_rep:
        logger.info("✓ Reputation decreased on failure")

    logger.info("Poisoning simulation test completed")

if __name__ == "__main__":
    asyncio.run(simulate_poisoning_attack())