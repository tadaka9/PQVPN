"""PQVPN package namespace.

This package is intentionally minimal today.
Core protocol and networking modules will live here as the project evolves.

All rights reserved. Copyright (c) 2026 Davide Di Pino.
"""

from .__about__ import __version__
from . import config
from . import crypto
from . import network
from . import session
from . import discovery
from . import iot

__all__ = ["__version__", "config", "crypto", "network", "session", "discovery", "plugins", "iot"]
