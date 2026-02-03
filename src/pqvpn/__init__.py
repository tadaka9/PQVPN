"""PQVPN package namespace.

This package is intentionally minimal today.
Core protocol and networking modules will live here as the project evolves.

All rights reserved. Copyright (c) 2026 Davide Di Pino.
"""

from . import config, crypto, discovery, iot, network, session
from .__about__ import __version__

__all__ = ["__version__", "config", "crypto", "network", "session", "discovery", "plugins", "iot"]
