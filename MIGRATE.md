# PQVPN C++23 Migration Roadmap

## Authority

- `main.py` is the immutable behavioral specification.
- `MIGRATION_MANIFEST.md` is the weighted parity ledger.
- This document is controller-owned; development miners must not edit it.
- A contract completes only after build/test and security/evidence validators approve 2/2.

## Verified contracts

- [x] `ColoredFormatter.format`
- [x] `setup_logger`
- [x] `_create_kademlia_server`
- [x] `_normalize_sig_config_name`
- [x] `MeshTopology.__init__`
- [x] `KeyRotationManager.__init__`
- [x] `ZeroKnowledgeAuth.__init__`
- [x] `LoadBalancer.__init__`
- [x] `AuditTrail.__init__`
- [x] `PQVPNNode.peer_hash8`

## Remaining work

- [ ] Continue smallest-first contracts from `MIGRATION_MANIFEST.md`.
- [ ] Replace all placeholder or fallback cryptography with exact supported algorithms and known-answer tests.
- [ ] Complete network, DHT, handshake, session, relay, and runtime parity.
- [ ] Run the full CMake/CTest and security gates for every accepted block.

## Local contribution chain

- Mode: two alternating miners plus two mandatory validators.
- Reward units: local PQV credits with no external or monetary value.
- Controller alone updates this roadmap, the manifest, journal, and chain.

- [x] `MeshTopology.add_peer` — controller-verified parity contract (`main.py:1422-1426`).

- [x] `ZeroKnowledgeAuth.issue_credential` — controller-verified parity contract (`main.py:1629-1633`).

- [x] `GeographicFailover.__init__` — controller-verified parity contract (`main.py:1453-1458`).

- [x] `GeographicFailover.add_backup_path` — controller-verified parity contract (`main.py:1460-1465`).

- [x] `ZeroKnowledgeAuth.issue_challenge` — controller-verified parity contract (`main.py:1605-1610`).

- [x] `PluginManager.__init__` — controller-verified parity contract (`main.py:1810-1815`).

- [x] `MeshTopology.update_peer_quality` — controller-verified parity contract (`main.py:1428-1434`).

- [x] `MeshTopology.compute_best_path` — controller-verified parity contract (`main.py:1436-1442`).

- [x] `TrafficObfuscation.__init__` — controller-verified parity contract (`main.py:1677-1683`).

- [x] `TrafficObfuscation.choose_bucket` — controller-verified parity contract (`main.py:1685-1691`).

- [x] `GeographicFailover.get_active_path` — controller-verified parity contract (`main.py:1467-1474`).

- [x] `NetworkAnalytics.record_packet` — controller-verified parity contract (`main.py:1504-1511`).

- [x] `PQVPNNode.make_outer_frame` — controller-verified parity contract (`main.py:3255-3264`).

- [x] `DHTClient.stop` — controller-verified parity contract (`main.py:520-530`).

- [x] `Discovery.publish_peer_record` — controller-verified parity contract (`main.py:741-752`).

- [x] `KeyRotationManager.should_rekey` — controller-verified parity contract (`main.py:1559-1570`).

- [x] `PQVPNNode.datagram_received` — controller-verified parity contract (`main.py:4480-4491`).

- [x] `_delayed_bootstrap` — controller-verified parity contract (`main.py:5152-5164`).

- [x] `PQVPNNode.session_salt` — controller-verified parity contract (`main.py:3173-3185`).

- [x] `AuditTrail.verify_integrity` — controller-verified parity contract (`main.py:1774-1787`).

- [x] `PQVPNNode.is_peer_allowed` — controller-verified parity contract (`main.py:3128-3141`).

- [x] `Discovery.stop` — controller-verified parity contract (`main.py:656-671`).

- [x] `ZeroKnowledgeAuth.verify_response` — controller-verified parity contract (`main.py:1612-1627`).

- [x] `TrafficObfuscation.decompress_payload` — controller-verified parity contract (`main.py:1723-1738`).

- [x] `DHTClient.__init__` — controller-verified parity contract (`main.py:415-431`).

- [x] `PluginManager.unload_plugins` — controller-verified parity contract (`main.py:1888-1904`).

- [x] `pq_kem_encaps` — controller-verified parity contract (`main.py:969-986`).

- [x] `pq_kem_decaps` — controller-verified parity contract (`main.py:989-1006`).

- [x] `DHTClient.get` — controller-verified parity contract (`main.py:555-572`).

- [x] `NetworkAnalytics.__init__` — controller-verified parity contract (`main.py:1485-1502`).

- [x] `KeyRotationManager.perform_rekey` — controller-verified parity contract (`main.py:1572-1589`).

- [x] `LoadBalancer.select_session` — controller-verified parity contract (`main.py:1649-1666`).

- [x] `AuditTrail.log_event` — controller-verified parity contract (`main.py:1754-1772`).

- [x] `PQVPNNode.choose_relay` — controller-verified parity contract (`main.py:3235-3253`).

- [x] `DHTClient.set` — controller-verified parity contract (`main.py:532-553`).

- [x] `Discovery._publish_loop` — controller-verified parity contract (`main.py:673-694`).

- [x] `canonical_sign_bytes` — controller-verified parity contract (`main.py:1202-1224`).

- [x] `TrafficObfuscation.compress_payload` — controller-verified parity contract (`main.py:1693-1721`).

- [x] `PQVPNNode.register_peer_tofu` — controller-verified parity contract (`main.py:3143-3171`).

- [x] `PluginManager.call_hook_async` — controller-verified parity contract (`main.py:1857-1886`).

- [x] `PQVPNNode.send_onion` — controller-verified parity contract (`main.py:3361-3390`).

- [x] `NetworkAnalytics.export_prometheus` — controller-verified parity contract (`main.py:1513-1543`).

- [x] `Discovery.__init__` — controller-verified parity contract (`main.py:581-614`).

- [x] `_safe_serialize_private_key` — controller-verified parity contract (`main.py:4822-4859`).

- [x] `Discovery.start` — controller-verified parity contract (`main.py:616-654`).

- [x] `PluginManager.load_plugins` — controller-verified parity contract (`main.py:1817-1855`).

- [x] `PQVPNNode.save_known_peers` — controller-verified parity contract (`main.py:3087-3126`).

- [x] `PQVPNNode.check_and_record_nonce` — controller-verified parity contract (`main.py:3187-3229`).

- [x] `Discovery._build_record` — controller-verified parity contract (`main.py:696-739`).

- [x] `PQVPNNode.build_onion_frame` — controller-verified parity contract (`main.py:3266-3310`).

- [x] `PQVPNNode.build_onion_frame_with_circuit` — controller-verified parity contract (`main.py:3312-3359`).

- [x] `PQVPNNode.find_known_peer_by_pubkeys` — controller-verified parity contract (`main.py:2366-2417`).

- [x] `pq_sig_sign` — controller-verified parity contract (`main.py:1065-1117`).

- [x] `pq_sig_keygen` — controller-verified parity contract (`main.py:1009-1062`).

- [x] `PQVPNNode.load_known_peers` — controller-verified parity contract (`main.py:3030-3085`).

- [x] `_make_udp_protocol` — controller-verified parity contract (`main.py:4865-4921`).

- [x] `pq_kem_keygen` — controller-verified parity contract (`main.py:904-966`).

- [x] `argon2_derive_key_material` — controller-verified parity contract (`main.py:1227-1300`).

- [x] `pq_sig_verify` — controller-verified parity contract (`main.py:1120-1199`).

- [x] `PQVPNNode.send_bootstrap_hellos` — controller-verified parity contract (`main.py:3481-3561`).

- [x] `DHTClient.start` — controller-verified parity contract (`main.py:433-518`).

- [x] `PQVPNNode.handle_relay` — controller-verified parity contract (`main.py:3392-3479`).

- [x] `PQVPNNode.send_to` — controller-verified parity contract (`main.py:4727-4819`).

- [x] `PQVPNNode.register_peer_from_hello` — controller-verified parity contract (`main.py:2419-2520`).

- [x] `PQVPNNode._process_outer_datagram` — controller-verified parity contract (`main.py:4493-4608`).

- [x] `PQVPNNode.session_maintenance` — controller-verified parity contract (`main.py:4610-4725`).

- [x] `PQVPNNode.initiate_handshake` — controller-verified parity contract (`main.py:3762-3927`).

- [x] `PQVPNNode.__init__` — controller-verified parity contract (`main.py:1940-2364`).

- [x] `PQVPNNode.handle_s1` — controller-verified parity contract (`main.py:3929-4264`).

- [x] `PQVPNNode.handle_hello` — controller-verified parity contract (`main.py:3563-3760`).

- [x] `PQVPNNode.handle_s2` — controller-verified parity contract (`main.py:4266-4478`).

- [x] `main_loop` — controller-verified parity contract (`main.py:4924-5149`).

- [x] `PQVPNNode.load_keys` — controller-verified parity contract (`main.py:2522-3028`).
