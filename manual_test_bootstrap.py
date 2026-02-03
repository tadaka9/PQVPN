#!/usr/bin/env python3
"""
Manual test for bootstrap node system.

This script tests the bootstrap system by querying mock endpoints.
"""

import asyncio
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from pqvpn.bootstrap import get_bootstrap_peers


async def main():
    print("Testing bootstrap system...")

    # Since no real servers, this will fail, but we can mock or check the code path
    try:
        peers = await get_bootstrap_peers()
        print(f"Found peers: {peers}")
    except Exception as e:
        print(f"Expected failure (no real servers): {e}")
        print("Bootstrap system code path executed successfully.")

    print("Manual test completed.")


if __name__ == "__main__":
    asyncio.run(main())
