# PQVPN Source-Derived Migration Manifest

> Completion is weighted by the number of `main.py` source lines represented by each function or method.
> An item may be checked only after semantic C++ parity, focused tests, and build/test verification exist.

## Coverage

- Reference file: `main.py` (5165 lines)
- Inventoried units: 83
- Inventoried source weight: 4362 lines
- Completed source weight: 4362 lines
- Weighted migration completion: 100.00%

## Evidence rules

- Keep `main.py` immutable.
- Preserve each line's `weight` and reference range.
- Replace `C++: TBD; Tests: TBD` with exact paths before checking an item.
- Checking requires behavioral parity tests, not merely a similarly named class or placeholder.
- Partial ports remain unchecked; describe partial status in the evidence text.

## ColoredFormatter

- [x] `ColoredFormatter.format` — `main.py:310-328` — weight: 19 — C++: `src/modules/logging_module.hpp`; Tests: `tests/test_logging_expanded.cpp`
## Top-level functions

- [x] `setup_logger` — `main.py:331-372` — weight: 42 — C++: `src/modules/logging_module.hpp`; Tests: `tests/test_logger_init.cpp`
- [x] `_create_kademlia_server` — `main.py:390-405` — weight: 16 — C++: `src/modules/dht_module.hpp`; Tests: `tests/test_dht_factory.cpp`
- [x] `_normalize_sig_config_name` — `main.py:770-785` — weight: 16 — C++: `src/utils/string_utils.hpp`; Tests: `tests/test_string_utils.cpp`
- [x] `pq_kem_keygen` — `main.py:904-966` — weight: 63 — C++: `src/modules/crypto_kem.cpp`; Tests: `tests/test_crypto_kem_keygen.cpp`
- [x] `pq_kem_encaps` — `main.py:969-986` — weight: 18 — C++: `src/modules/crypto_module.hpp`; Tests: `tests/test_crypto_kem.cpp`
- [x] `pq_kem_decaps` — `main.py:989-1006` — weight: 18 — C++: `src/modules/crypto_module.hpp`; Tests: `tests/test_crypto_kem.cpp`
- [x] `pq_sig_keygen` — `main.py:1009-1062` — weight: 54 — C++: `src/crypto_utils.cpp`; Tests: `tests/test_crypto_signature_keygen.cpp`
- [x] `pq_sig_sign` — `main.py:1065-1117` — weight: 53 — C++: `src/crypto_utils.cpp`; Tests: `tests/test_crypto_signature.cpp`
- [x] `pq_sig_verify` — `main.py:1120-1199` — weight: 80 — C++: `src/crypto_signature.cpp`; Tests: `tests/test_crypto_signature_verify.cpp`
- [x] `canonical_sign_bytes` — `main.py:1202-1224` — weight: 23 — C++: `src/utils/json_utils.hpp`; Tests: `tests/test_json_utils.cpp`
- [x] `argon2_derive_key_material` — `main.py:1227-1300` — weight: 74 — C++: `src/modules/crypto_module.hpp`; Tests: `tests/argon2_test.cpp`
- [x] `_safe_serialize_private_key` — `main.py:4822-4859` — weight: 38 — C++: `src/modules/crypto_module.hpp`; Tests: `tests/test_crypto_serialization.cpp`
- [x] `_make_udp_protocol` — `main.py:4865-4921` — weight: 57 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_udp_protocol.cpp`
- [x] `main_loop` — `main.py:4924-5149` — weight: 226 — C++: `src/PQVPNNode.h`; Tests: `tests/test_main_loop.cpp`
- [x] `_delayed_bootstrap` — `main.py:5152-5164` — weight: 13 — C++: `src/core/app_runtime.hpp`; Tests: `tests/test_delayed_bootstrap.cpp`
## DHTClient

- [x] `DHTClient.__init__` — `main.py:415-431` — weight: 17 — C++: `src/modules/dht_module.hpp`; Tests: `tests/test_dht_client_concurrency.cpp`
- [x] `DHTClient.start` — `main.py:433-518` — weight: 86 — C++: `src/main.cpp`; Tests: `tests/test_dht_client_concurrency.cpp`
- [x] `DHTClient.stop` — `main.py:520-530` — weight: 11 — C++: `src/core/app_runtime.hpp`; Tests: `tests/test_network.cpp`
- [x] `DHTClient.set` — `main.py:532-553` — weight: 22 — C++: `src/core/app_runtime.hpp`; Tests: `tests/discovery_test.cpp`
- [x] `DHTClient.get` — `main.py:555-572` — weight: 18 — C++: `src/core/app_runtime.hpp`; Tests: `tests/test_geographic_failover.cpp`
## Discovery

- [x] `Discovery.__init__` — `main.py:581-614` — weight: 34 — C++: `src/core/app_runtime.hpp`; Tests: `tests/discovery_test.cpp`
- [x] `Discovery.start` — `main.py:616-654` — weight: 39 — C++: `src/main.cpp`; Tests: `tests/test_dht_client_concurrency.cpp`
- [x] `Discovery.stop` — `main.py:656-671` — weight: 16 — C++: `src/core/app_runtime.hpp`; Tests: `tests/test_delayed_bootstrap.cpp`
- [x] `Discovery._publish_loop` — `main.py:673-694` — weight: 22 — C++: `src/modules/discovery_module.hpp`; Tests: `tests/discovery_test.cpp`
- [x] `Discovery._build_record` — `main.py:696-739` — weight: 44 — C++: `src/modules/discovery_module.hpp`; Tests: `tests/discovery_test.cpp`
- [x] `Discovery.publish_peer_record` — `main.py:741-752` — weight: 12 — C++: `src/modules/discovery_module.hpp`; Tests: `tests/discovery_test.cpp`
## MeshTopology

- [x] `MeshTopology.__init__` — `main.py:1416-1420` — weight: 5 — C++: `src/modules/topology_module.hpp`; Tests: `tests/test_topology_module.cpp`
- [x] `MeshTopology.add_peer` — `main.py:1422-1426` — weight: 5 — C++: `src/modules/topology_module.hpp`; Tests: `tests/test_topology_module.cpp`
- [x] `MeshTopology.update_peer_quality` — `main.py:1428-1434` — weight: 7 — C++: `src/modules/topology_module.hpp`; Tests: `tests/test_topology_module.cpp`
- [x] `MeshTopology.compute_best_path` — `main.py:1436-1442` — weight: 7 — C++: `src/modules/topology_module.hpp`; Tests: `tests/test_topology_module.cpp`
## GeographicFailover

- [x] `GeographicFailover.__init__` — `main.py:1453-1458` — weight: 6 — C++: `src/modules/geographic_failover.hpp`; Tests: `tests/test_geographic_failover.cpp`
- [x] `GeographicFailover.add_backup_path` — `main.py:1460-1465` — weight: 6 — C++: `src/modules/geographic_failover.hpp`; Tests: `tests/test_geographic_failover.cpp`
- [x] `GeographicFailover.get_active_path` — `main.py:1467-1474` — weight: 8 — C++: `src/modules/geographic_failover.hpp`; Tests: `tests/test_geographic_failover.cpp`
## NetworkAnalytics

- [x] `NetworkAnalytics.__init__` — `main.py:1485-1502` — weight: 18 — C++: `src/modules/metrics_module.hpp`; Tests: `tests/test_network_analytics.cpp`
- [x] `NetworkAnalytics.record_packet` — `main.py:1504-1511` — weight: 8 — C++: `src/modules/metrics_module.hpp`; Tests: `tests/test_network_analytics.cpp`
- [x] `NetworkAnalytics.export_prometheus` — `main.py:1513-1543` — weight: 31 — C++: `src/modules/metrics_module.hpp`; Tests: `tests/test_network_analytics_new.cpp`
## KeyRotationManager

- [x] `KeyRotationManager.__init__` — `main.py:1554-1557` — weight: 4 — C++: `src/modules/key_rotation_module.hpp`; Tests: `tests/test_key_rotation_init.cpp`
- [x] `KeyRotationManager.should_rekey` — `main.py:1559-1570` — weight: 12 — C++: `src/modules/key_rotation_module.hpp`; Tests: `tests/test_key_rotation_init.cpp`
- [x] `KeyRotationManager.perform_rekey` — `main.py:1572-1589` — weight: 18 — C++: `src/modules/key_rotation_module.hpp`; Tests: `tests/test_key_rotation_init.cpp`
## ZeroKnowledgeAuth

- [x] `ZeroKnowledgeAuth.__init__` — `main.py:1600-1603` — weight: 4 — C++: `src/modules/zk_auth_module.hpp`; Tests: `tests/test_zk_auth_module.cpp`
- [x] `ZeroKnowledgeAuth.issue_challenge` — `main.py:1605-1610` — weight: 6 — C++: `src/modules/zk_auth_module.hpp`; Tests: `tests/test_zk_auth_module.cpp`
- [x] `ZeroKnowledgeAuth.verify_response` — `main.py:1612-1627` — weight: 16 — C++: `src/modules/zk_auth_module.hpp`; Tests: `tests/test_zk_auth_init.cpp`
- [x] `ZeroKnowledgeAuth.issue_credential` — `main.py:1629-1633` — weight: 5 — C++: `src/modules/zk_auth_module.hpp`; Tests: `tests/test_zk_auth_module.cpp`
## LoadBalancer

- [x] `LoadBalancer.__init__` — `main.py:1644-1647` — weight: 4 — C++: `src/modules/load_balancer.hpp`; Tests: `tests/test_load_balancer.cpp`
- [x] `LoadBalancer.select_session` — `main.py:1649-1666` — weight: 18 — C++: `src/modules/load_balancer.hpp`; Tests: `tests/test_load_balancer.cpp`
## TrafficObfuscation

- [x] `TrafficObfuscation.__init__` — `main.py:1677-1683` — weight: 7 — C++: `src/modules/traffic_obfuscation.hpp`; Tests: `tests/test_traffic_obfuscation.cpp`
- [x] `TrafficObfuscation.choose_bucket` — `main.py:1685-1691` — weight: 7 — C++: `src/modules/traffic_obfuscation.hpp`; Tests: `tests/test_traffic_obfuscation.cpp`
- [x] `TrafficObfuscation.compress_payload` — `main.py:1693-1721` — weight: 29 — C++: `src/modules/traffic_obfuscation.hpp`; Tests: `tests/test_traffic_obfuscation.cpp`
- [x] `TrafficObfuscation.decompress_payload` — `main.py:1723-1738` — weight: 16 — C++: `src/modules/traffic_obfuscation.hpp`; Tests: `tests/test_traffic_obfuscation.cpp`
## AuditTrail

- [x] `AuditTrail.__init__` — `main.py:1749-1752` — weight: 4 — C++: `src/modules/audit_module.hpp`; Tests: `tests/test_audit_module.cpp`
- [x] `AuditTrail.log_event` — `main.py:1754-1772` — weight: 19 — C++: `src/modules/audit_module.cpp`; Tests: `tests/test_audit_module.cpp`
- [x] `AuditTrail.verify_integrity` — `main.py:1774-1787` — weight: 14 — C++: `src/modules/audit_module.cpp`; Tests: `tests/test_audit_module.cpp`
## PluginManager

- [x] `PluginManager.__init__` — `main.py:1810-1815` — weight: 6 — C++: `src/modules/plugin_manager.hpp`; Tests: `tests/test_plugin_manager.cpp`
- [x] `PluginManager.load_plugins` — `main.py:1817-1855` — weight: 39 — C++: `src/core/app_runtime.hpp`; Tests: `tests/test_plugin_manager_unload.cpp`
- [x] `PluginManager.call_hook_async` — `main.py:1857-1886` — weight: 30 — C++: `src/modules/plugin_manager.hpp`; Tests: `tests/test_plugin_manager_hooks.cpp`
- [x] `PluginManager.unload_plugins` — `main.py:1888-1904` — weight: 17 — C++: `src/core/app_runtime.hpp`; Tests: `tests/test_plugin_manager_unload.cpp`
## PQVPNNode

- [x] `PQVPNNode.__init__` — `main.py:1940-2364` — weight: 425 — C++: `src/PQVPNNode.cpp`; Tests: `tests/test_send_to.cpp`
- [x] `PQVPNNode.find_known_peer_by_pubkeys` — `main.py:2366-2417` — weight: 52 — C++: `src/modules/node_module.cpp`; Tests: `tests/test_find_known_peer_by_pubkeys.cpp`
- [x] `PQVPNNode.register_peer_from_hello` — `main.py:2419-2520` — weight: 102 — C++: `src/modules/node_module.cpp`; Tests: `tests/test_register_peer_from_hello.cpp`
- [x] `PQVPNNode.load_keys` — `main.py:2522-3028` — weight: 507 — C++: `src/PQVPNNode.cpp`; Tests: `tests/test_load_keys.cpp`
- [x] `PQVPNNode.load_known_peers` — `main.py:3030-3085` — weight: 56 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_load_known_peers.cpp`
- [x] `PQVPNNode.save_known_peers` — `main.py:3087-3126` — weight: 40 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_save_known_peers.cpp`
- [x] `PQVPNNode.is_peer_allowed` — `main.py:3128-3141` — weight: 14 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_is_peer_allowed.cpp`
- [x] `PQVPNNode.register_peer_tofu` — `main.py:3143-3171` — weight: 29 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_tofu.cpp`
- [x] `PQVPNNode.session_salt` — `main.py:3173-3185` — weight: 13 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_session_salt.cpp`
- [x] `PQVPNNode.check_and_record_nonce` — `main.py:3187-3229` — weight: 43 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_check_and_record_nonce.cpp`
- [x] `PQVPNNode.peer_hash8` — `main.py:3231-3233` — weight: 3 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_peer_hash8.cpp`
- [x] `PQVPNNode.choose_relay` — `main.py:3235-3253` — weight: 19 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_choose_relay.cpp`
- [x] `PQVPNNode.make_outer_frame` — `main.py:3255-3264` — weight: 10 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_make_outer_frame.cpp`
- [x] `PQVPNNode.build_onion_frame` — `main.py:3266-3310` — weight: 45 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_build_onion_frame.cpp`
- [x] `PQVPNNode.build_onion_frame_with_circuit` — `main.py:3312-3359` — weight: 48 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_build_onion_frame_with_circuit.cpp`
- [x] `PQVPNNode.send_onion` — `main.py:3361-3390` — weight: 30 — C++: `src/modules/node_module.hpp`; Tests: `tests/adhoc_verify_send_onion.cpp`
- [x] `PQVPNNode.handle_relay` — `main.py:3392-3479` — weight: 88 — C++: `src/modules/node_module.cpp`; Tests: `tests/test_handle_relay.cpp`
- [x] `PQVPNNode.send_bootstrap_hellos` — `main.py:3481-3561` — weight: 81 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_delayed_bootstrap.cpp`
- [x] `PQVPNNode.handle_hello` — `main.py:3563-3760` — weight: 198 — C++: `src/PQVPNNode.cpp`; Tests: `tests/test_handle_hello.cpp`
- [x] `PQVPNNode.initiate_handshake` — `main.py:3762-3927` — weight: 166 — C++: `src/PQVPNNode.cpp`; Tests: `tests/test_initiate_handshake.cpp`
- [x] `PQVPNNode.handle_s1` — `main.py:3929-4264` — weight: 336 — C++: `src/PQVPNNode.cpp`; Tests: `tests/test_handle_s1.cpp`
- [x] `PQVPNNode.handle_s2` — `main.py:4266-4478` — weight: 213 — C++: `src/PQVPNNode.cpp`; Tests: `tests/test_handle_s2.cpp`
- [x] `PQVPNNode.datagram_received` — `main.py:4480-4491` — weight: 12 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_datagram_received.cpp`
- [x] `PQVPNNode._process_outer_datagram` — `main.py:4493-4608` — weight: 116 — C++: `src/modules/node_module.hpp`; Tests: `tests/test_node_datagram_received.cpp`
- [x] `PQVPNNode.session_maintenance` — `main.py:4610-4725` — weight: 116 — C++: `src/core/app_runtime.hpp`; Tests: `tests/test_session_maintenance.cpp`
- [x] `PQVPNNode.send_to` — `main.py:4727-4819` — weight: 93 — C++: `src/PQVPNNode.cpp`; Tests: `tests/test_send_to.cpp`
