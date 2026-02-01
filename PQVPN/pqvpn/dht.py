"""pqvpn.dht

A small hardened wrapper around the kademlia Server for controlled DHT access.
Provides start/stop, bootstrap, get, set with rate limiting and strict startup.
This wrapper intentionally fails fast when kademlia is not available and strict
mode is requested by the caller.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, List, Optional, Tuple

logger = logging.getLogger("pqvpn.dht")

try:
    from kademlia.network import Server as _KademliaServer  # type: ignore
except Exception:  # pragma: no cover - external dependency
    _KademliaServer = None  # type: ignore


class DHTUnavailableError(RuntimeError):
    pass


class DHTClient:
    """Hardened DHT client used by discovery.

    Usage:
        d = DHTClient(bootstrap=[(host,port)], bind='0.0.0.0', port=8468, strict=True)
        await d.start()
        await d.set(key, value)
        v = await d.get(key)
        await d.stop()
    """

    def __init__(
        self,
        bootstrap: Optional[List[Tuple[str, int]]] = None,
        bind: str = "0.0.0.0",
        port: int = 8468,
        strict: bool = True,
        max_concurrent_sets: int = 4,
        allowed_prefixes: Optional[List[str]] = None,
    ) -> None:
        self.bootstrap = bootstrap or []
        self.bind = bind
        self.port = int(port)
        self._server: Optional[Any] = None
        self._started = False
        self.strict = bool(strict)
        self._set_sem = asyncio.Semaphore(max_concurrent_sets)
        # When strict, optionally only allow setting keys that start with one of these prefixes
        self.allowed_prefixes = allowed_prefixes

    async def start(self) -> None:
        if _KademliaServer is None:
            msg = "kademlia package not available"
            logger.debug(msg)
            if self.strict:
                logger.critical(msg)
                raise DHTUnavailableError(msg)
            # Provide a simple in-memory fallback server for local demos when not strict.
            logger.info("kademlia package not available: using in-memory DHT fallback (local demo only)")
            # Simple in-memory server implementation
            class _InMemoryServer:
                def __init__(self):
                    self._store = {}
                    self._lock = asyncio.Lock()

                async def listen(self, port):
                    # no networking, do nothing
                    return

                async def bootstrap(self, bootstrap_nodes):
                    # nothing to do for in-memory
                    return

                async def set(self, key, value):
                    async with self._lock:
                        self._store[key] = value

                async def get(self, key):
                    async with self._lock:
                        return self._store.get(key)

                def stop(self):
                    # nothing to close
                    return

            self._server = _InMemoryServer()
            self._started = True
            logger.info("In-memory DHT client started for local demo")
            return

        if self._started:
            return

        # type: ignore - _KademliaServer may be None at static analysis time
        self._server = _KademliaServer()  # type: ignore
        try:
            await self._server.listen(self.port)
            if self.bootstrap:
                try:
                    await self._server.bootstrap(self.bootstrap)
                    logger.info(f"DHT bootstrapped to {len(self.bootstrap)} nodes")
                except Exception as e:
                    logger.debug(f"DHT bootstrap failure: {e}")
            self._started = True
            logger.info(f"DHT client started on port {self.port}")
        except Exception as e:
            logger.exception(f"DHT start failed: {e}")
            self._server = None
            if self.strict:
                raise

    async def stop(self) -> None:
        if not self._started:
            return
        try:
            if self._server:
                self._server.stop()
        except Exception:
            pass
        self._server = None
        self._started = False
        logger.info("DHT client stopped")

    async def set(self, key: str, value: Any) -> None:
        """Set a key in the DHT with rate limiting. Value must be JSON-serializable."""
        if _KademliaServer is None and self.strict:
            raise DHTUnavailableError("kademlia package not available")
        if not self._started or not self._server:
            raise RuntimeError("DHT client not started")

        # enforce allowed prefixes when operating in strict mode
        if self.strict and self.allowed_prefixes:
            ok = False
            for p in self.allowed_prefixes:
                if key.startswith(p):
                    ok = True
                    break
            if not ok:
                raise RuntimeError(f"DHTClient.set: key '{key}' not allowed by allowed_prefixes")

        async with self._set_sem:
            try:
                # store JSON string for portability
                if not isinstance(value, str):
                    payload = json.dumps(value, separators=(",", ":"), sort_keys=True)
                else:
                    payload = value
                await self._server.set(key, payload)
            except Exception as e:
                logger.debug(f"DHT set failed for key={key}: {e}")
                raise

    async def get(self, key: str) -> Optional[Any]:
        """Get a key from the DHT and return parsed JSON or raw value."""
        if _KademliaServer is None and self.strict:
            raise DHTUnavailableError("kademlia package not available")
        if not self._started or not self._server:
            raise RuntimeError("DHT client not started")
        try:
            val = await self._server.get(key)
            if val is None:
                return None
            # Try parsing JSON
            if isinstance(val, str):
                try:
                    return json.loads(val)
                except Exception:
                    return val
            return val
        except Exception as e:
            logger.debug(f"DHT get failed for key={key}: {e}")
            return None


# end of pqvpn.dht

