# src/pqvpn/bootstrap.py
"""
Bootstrap module for PQVPN.

Provides initial peer discovery for decentralized joining.
"""

import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)


class BootstrapClient:
    """Client for querying bootstrap nodes to get initial peers."""

    def __init__(self, seed_nodes: list[str] = None, relays: list[str] = None):
        self.seed_nodes = seed_nodes or ["seed1.pqvpn.net", "seed2.pqvpn.net", "seed3.pqvpn.net"]
        self.relays = relays or ["relay-us.pqvpn.net", "relay-eu.pqvpn.net", "relay-asia.pqvpn.net"]
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def get_bootstrap_peers(self) -> list[tuple[str, int]]:
        """Query seed nodes and relays to get initial peer list."""
        peers = []
        tasks = []

        # Query seeds
        for seed in self.seed_nodes:
            tasks.append(self._query_seed(seed))

        # Query relays
        for relay in self.relays:
            tasks.append(self._query_relay(relay))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Bootstrap query failed: {result}")
                continue
            peers.extend(result)

        # Deduplicate
        seen = set()
        unique_peers = []
        for peer in peers:
            key = f"{peer[0]}:{peer[1]}"
            if key not in seen:
                seen.add(key)
                unique_peers.append(peer)

        logger.info(f"Bootstrap found {len(unique_peers)} unique peers")
        return unique_peers

    async def _query_seed(self, seed: str) -> list[tuple[str, int]]:
        """Query a seed node for peers."""
        url = f"https://{seed}/peers"
        try:
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [(p["host"], p["port"]) for p in data.get("peers", [])]
        except Exception as e:
            logger.debug(f"Query seed {seed} failed: {e}")
        return []

    async def _query_relay(self, relay: str) -> list[tuple[str, int]]:
        """Query a relay for bootstrap peers."""
        url = f"https://{relay}/bootstrap"
        try:
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [(p["host"], p["port"]) for p in data.get("bootstrap_peers", [])]
        except Exception as e:
            logger.debug(f"Query relay {relay} failed: {e}")
        return []


async def get_bootstrap_peers(
    seed_nodes: list[str] = None, relays: list[str] = None
) -> list[tuple[str, int]]:
    """Convenience function to get bootstrap peers."""
    async with BootstrapClient(seed_nodes, relays) as client:
        return await client.get_bootstrap_peers()
