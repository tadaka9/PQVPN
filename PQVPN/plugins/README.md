PQVPN Plugin Directory

Place plugin .py files here. Each plugin module may implement any of the following callables (sync or async):

- on_start(node, cfg=None)
- on_stop(node)
- on_datagram(node, data, addr) -> True to consume
- on_outer_frame(node, ftype, payload, addr, next_hash, circuit_id) -> True to consume
- teardown(node)

Example: see example_plugin.py

