"""TokenRefreshManager

Conservative candidate fix for race conditions during auth-token refresh.
Provides per-peer async locks to ensure only one refresh runs at a time.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Awaitable, Callable, Dict


class TokenRefreshManager:
    """Manage per-peer refresh locks.

    - Uses asyncio.Lock for async contexts.
    - Provides a sync fallback that uses threading.Lock for code paths that
      cannot run inside the event loop.
    """

    def __init__(self) -> None:
        # Map key->asyncio.Lock. Keys are normalized strings (hex for bytes)
        self._async_locks: Dict[str, asyncio.Lock] = {}
        # Guard for creating async locks
        self._async_locks_guard = asyncio.Lock()

        # Map key->threading.Lock for sync fallback
        self._sync_locks: Dict[str, threading.Lock] = {}
        # Guard for creating sync locks
        self._sync_locks_guard = threading.Lock()

    @staticmethod
    def _normalize_key(key: Any) -> str:
        if isinstance(key, (bytes, bytearray)):
            return key.hex()
        return str(key)

    async def _get_async_lock(self, key: Any) -> asyncio.Lock:
        k = self._normalize_key(key)
        # Double-checked locking with async guard
        if k in self._async_locks:
            return self._async_locks[k]
        async with self._async_locks_guard:
            if k not in self._async_locks:
                self._async_locks[k] = asyncio.Lock()
            return self._async_locks[k]

    def _get_sync_lock(self, key: Any) -> threading.Lock:
        k = self._normalize_key(key)
        if k in self._sync_locks:
            return self._sync_locks[k]
        with self._sync_locks_guard:
            if k not in self._sync_locks:
                self._sync_locks[k] = threading.Lock()
            return self._sync_locks[k]

    async def refresh_token(self, key: Any, refresh_coro: Callable[[], Awaitable[Any]]) -> Any:
        """Run an async refresh_coro under a per-key asyncio.Lock.

        refresh_coro: a callable returning an awaitable that performs the
        refresh and returns the token/credential object.
        """
        lock = await self._get_async_lock(key)
        async with lock:
            # Caller may implement double-check semantics inside refresh_coro
            return await refresh_coro()

    def refresh_token_sync(self, key: Any, refresh_fn: Callable[[], Any]) -> Any:
        """Run a synchronous refresh function under a per-key threading.Lock.

        This is a safe fallback for code paths that cannot operate inside the
        event loop. Keep refresh_fn short/blocking to avoid long-held locks.
        """
        lock = self._get_sync_lock(key)
        with lock:
            return refresh_fn()


# Provide a module-level instance for simple wiring
_default_manager: TokenRefreshManager | None = None


def get_default_manager() -> TokenRefreshManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = TokenRefreshManager()
    return _default_manager
