"""PQVPN entrypoint.

This file intentionally contains a minimal, professional scaffold so the repo has a
single obvious entrypoint while the actual VPN design and implementation evolve.

All rights reserved. Copyright (c) 2026 Davide Di Pino.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass


__version__ = "0.1.0"


@dataclass(frozen=True)
class AppConfig:
    log_level: str = "INFO"


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return 0


def cmd_doctor(_: argparse.Namespace) -> int:
    """Basic environment checks; extend as PQVPN grows."""
    print("PQVPN doctor")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {sys.platform}")
    print(f"CWD: {os.getcwd()}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Placeholder run command.

    In the future this will likely orchestrate:
    - key management
    - peer discovery / signaling
    - transport (UDP/TCP/QUIC?)
    - encryption + authentication handshake
    - tunnel interface integration
    """
    log = logging.getLogger("pqvpn")
    log.info("Starting PQVPN (scaffold) on bind=%s:%s", args.bind, args.port)
    log.warning("This is a scaffold. Networking/tunnel logic not implemented yet.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pqvpn",
        description="PQVPN - Path Quilt VPN (WIP)",
    )
    p.add_argument(
        "--log-level",
        default=os.environ.get("PQVPN_LOG_LEVEL", "INFO"),
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    p_version = sub.add_parser("version", help="Print version")
    p_version.set_defaults(func=cmd_version)

    p_doctor = sub.add_parser("doctor", help="Run basic environment checks")
    p_doctor.set_defaults(func=cmd_doctor)

    p_run = sub.add_parser("run", help="Run PQVPN (placeholder)")
    p_run.add_argument("--bind", default="127.0.0.1", help="Bind address")
    p_run.add_argument("--port", type=int, default=51820, help="Bind port")
    p_run.set_defaults(func=cmd_run)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.log_level)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
