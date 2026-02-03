# src/pqvpn/iot.py
"""
IoT integration for PQVPN.

Enables low-power IoT devices to join the PQVPN network securely,
with optimizations for constrained resources, battery efficiency, and IoT protocols.
"""

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass

# For lightweight crypto, use ECC instead of PQ for IoT (faster, smaller)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Optional: for MQTT/CoAP if available
try:
    import paho.mqtt.client as mqtt  # type: ignore
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

try:
    import aiocoap  # type: ignore
    COAP_AVAILABLE = True
except ImportError:
    COAP_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class IoTDeviceConfig:
    device_id: bytes
    battery_optimized: bool = True  # Enable battery saving modes
    constrained_mode: bool = True  # Use smaller keys/messages
    protocol: str = "dht"  # "dht", "mqtt", "coap"
    sleep_interval: int = 300  # Seconds between wakeups
    max_payload: int = 512  # Max message size in bytes
    gateway_address: tuple[str, int] | None = None  # For proxy mode

class IoTClient:
    """
    Lightweight client for IoT devices to join PQVPN network.
    """

    def __init__(self, config: IoTDeviceConfig):
        self.config = config
        self.running = False
        self.session_key: bytes | None = None
        self.peers: dict[bytes, dict] = {}
        self.gateway = None

        # Generate ECC keys
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    async def start(self):
        self.running = True
        if self.config.protocol == "mqtt" and MQTT_AVAILABLE:
            await self._start_mqtt()
        elif self.config.protocol == "coap" and COAP_AVAILABLE:
            await self._start_coap()
        else:
            await self._start_light_dht()

        # Start periodic tasks
        asyncio.create_task(self._heartbeat())
        asyncio.create_task(self._sleep_cycle())

    async def stop(self):
        self.running = False

    async def _start_mqtt(self):
        # Use MQTT for discovery and messaging
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self._on_mqtt_connect
        self.mqtt_client.on_message = self._on_mqtt_message
        if self.config.gateway_address:
            self.mqtt_client.connect(self.config.gateway_address[0], self.config.gateway_address[1])
        else:
            # Assume default broker
            self.mqtt_client.connect("broker.hivemq.com", 1883)
        self.mqtt_client.loop_start()

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        logger.info("IoT MQTT connected")
        client.subscribe("pqvpn/discovery")

    def _on_mqtt_message(self, client, userdata, msg):
        # Handle incoming MQTT messages
        payload = json.loads(msg.payload.decode())
        asyncio.create_task(self._handle_message(payload))

    async def _start_coap(self):
        # Use CoAP for lightweight comm
        self.coap_context = await aiocoap.Context.create_client_context()
        # Register for discovery
        pass  # Implement CoAP discovery

    async def _start_light_dht(self):
        # Simplified DHT for IoT: connect to gateway or known peers
        if self.config.gateway_address:
            await self._connect_gateway()

    async def _connect_gateway(self):
        # Establish secure connection to gateway
        # Use ECC handshake for speed
        pass

    async def _heartbeat(self):
        while self.running:
            # Send heartbeat to maintain connection
            if self.config.battery_optimized:
                # Batch heartbeats
                await asyncio.sleep(self.config.sleep_interval // 2)
            else:
                await asyncio.sleep(60)
            await self._send_heartbeat()

    async def _sleep_cycle(self):
        while self.running and self.config.battery_optimized:
            # Simulate sleep: reduce activity
            await asyncio.sleep(self.config.sleep_interval)
            # Wake up and sync

    async def _send_heartbeat(self):
        message = {
            'type': 'heartbeat',
            'device_id': self.config.device_id.hex(),
            'timestamp': time.time()
        }
        encrypted = self._encrypt_message(json.dumps(message).encode())
        # Send via protocol
        if self.config.protocol == "mqtt":
            self.mqtt_client.publish("pqvpn/heartbeat", json.dumps({'encrypted': encrypted.hex()}))

    async def _handle_message(self, payload: dict):
        # Decrypt and handle
        if 'encrypted' in payload:
            plaintext = self._decrypt_message(bytes.fromhex(payload['encrypted']))
            msg = json.loads(plaintext.decode())
            if msg['type'] == 'peer_update':
                self._update_peers(msg['peers'])

    def _update_peers(self, peers: list[dict]):
        for peer in peers:
            self.peers[bytes.fromhex(peer['id'])] = peer

    def _encrypt_message(self, plaintext: bytes) -> bytes:
        if not self.session_key:
            self.session_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(self.session_key)
        ciphertext = cipher.encrypt(nonce, plaintext, b'')
        return nonce + ciphertext

    def _decrypt_message(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        cipher = ChaCha20Poly1305(self.session_key)
        return cipher.decrypt(nonce, ct, b'')

    async def join_network(self):
        # Announce presence
        from cryptography.hazmat.primitives import serialization
        announce = {
            'type': 'join',
            'device_id': self.config.device_id.hex(),
            'public_key': self.public_key.public_key_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            'capabilities': ['low_power', 'constrained']
        }
        encrypted = self._encrypt_message(json.dumps(announce).encode())
        # Send to gateway or broadcast
        if self.config.protocol == "mqtt":
            self.mqtt_client.publish("pqvpn/join", json.dumps({'encrypted': encrypted.hex()}))

    async def send_data(self, data: bytes):
        # Send data through VPN, with size limits
        if len(data) > self.config.max_payload:
            logger.warning("Data exceeds max payload, truncating")
            data = data[:self.config.max_payload]
        encrypted = self._encrypt_message(data)
        # Tunnel through gateway or direct
        pass