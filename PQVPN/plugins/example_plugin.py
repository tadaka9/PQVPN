"""
Example plugin for PQVPN demonstrating the available hooks.
"""

import logging

logger = logging.getLogger("pqvpn.plugin.example")

# Called once when node starts. May be async or sync.
async def on_start(node, cfg=None):
    logger.info("example_plugin: on_start called")
    # perform optional initialization
    node.example_plugin_active = True
    return False

# Called once on shutdown. May be async or sync.
def on_stop(node):
    logger.info("example_plugin: on_stop called")
    try:
        node.example_plugin_active = False
    except Exception:
        pass
    return False

# Inspect raw datagrams before parsing. Return True to consume.
def on_datagram(node, data, addr):
    # simple filter: log short packets
    if len(data) < 24:
        logger.debug(f"example_plugin: short datagram from {addr}")
    return False

# Inspect parsed outer frames. Return True to consume and stop core processing.
def on_outer_frame(node, ftype, payload, addr, next_hash, circuit_id):
    # example: ignore keepalive frames
    try:
        if ftype == 0x04:
            logger.debug(f"example_plugin: ignoring keepalive from {addr}")
            return True
    except Exception:
        pass
    return False

# Optional teardown
def teardown(node):
    logger.debug("example_plugin: teardown called")

