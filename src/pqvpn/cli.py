"""Command-line interface for PQVPN.

This module provides a stable entry point for running the node without relying
on importing/patching the giant top-level main.py.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
from typing import Optional


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pqvpn", description="PQVPN node")
    p.add_argument("--config", default="config.yaml", help="Path to config YAML")
    p.add_argument(
        "--loglevel",
        default="INFO",
        help="Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
    )
    p.add_argument("--logfile", default=None, help="Optional log file path")
    p.add_argument("--pidfile", default=None, help="Optional pidfile path")
    p.add_argument(
        "--disable-discovery",
        action="store_true",
        help="Disable DHT-based discovery",
    )
    p.add_argument(
        "--iot",
        action="store_true",
        help="Run in IoT mode for low-power devices",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    m = importlib.import_module("main")

    # Preferred: reuse main.py async runtime if present.
    main_loop = getattr(m, "main_loop", None)
    if callable(main_loop):
        asyncio.run(
            main_loop(
                configfile=args.config,
                logfile=args.logfile,
                loglevel=args.loglevel,
                pidfile=args.pidfile,
                disable_discovery=bool(args.disable_discovery),
                enable_relay=bool(args.enable_relay),
                iot=bool(args.iot),
            )
        )
        return 0

    raise RuntimeError(
        "PQVPN CLI could not find main_loop() in main.py. "
        "Either add main_loop() or update pqvpn/cli.py to match the new runtime entry." 
    )


if __name__ == "__main__":
    raise SystemExit(main())
