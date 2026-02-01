"""PQVPN package init"""
# Avoid importing submodules at import time to keep package import lightweight and
# prevent pytest/import-time failures when optional components (like transports)
# are not available. Import CLI lazily via pqvpn.cli.main when needed.

__version__ = "0.2.0"

__all__ = ["main"]


def main(*args, **kwargs):
    """Lazy entrypoint to pqvpn.cli.main to avoid import-time side-effects."""
    from . import cli as _cli

    return _cli.main(*args, **kwargs)
