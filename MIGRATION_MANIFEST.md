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
- Intentional behavioral differences from `main.py` are recorded under "Documented deviations" with rationale and test evidence; they do not change completion weights.

## Documented deviations

Intentional places where the C++ contract is deliberately stricter or self-consistent than `main.py`. Each entry records the reference behavior, the reason for deviating, and focused test evidence. `main.py` itself remains immutable per the rules above.

- **Onion builder single-hop paths** — `PQVPNNode.build_onion_frame`, `PQVPNNode.build_onion_frame_with_circuit` (`main.py:3266-3359`). The reference accepts a one-element path and emits a RELAY frame whose payload is raw content, because its encryption loop never runs for such paths. Every RELAY receiver parses its payload as session hint + nonce + ciphertext and drops unknown sessions (`main.py:4493-4608`, `main.py:3392-3479`), so that shape can never be delivered — and a sender API would report success for content that provably never arrives. The C++ builder therefore rejects paths shorter than two elements (fail-closed); direct delivery to a single peer uses `build_tunnel_datagram`. Evidence: `tests/test_build_onion_frame_with_circuit.cpp` ("single-hop and empty onion paths are rejected", including the case where an established session to the peer exists).
- **Wrapped relay forwarding** — `PQVPNNode.handle_relay` forward branch (`main.py:3456-3479`). The reference re-sends the peeled layer as a raw `session_hint+nonce+ciphertext` blob with no outer frame, yet every dispatcher in the reference requires the 16-byte outer header before routing to the relay handler at all (`main.py:4493-4508`) — so a forwarded layer is undeliverable at hop two and multi-hop onion chains cannot complete there. The C++ forward branch wraps the peeled layer in a fresh RELAY_FRAME instead: next peeler's identity hash, the circuit id preserved (the builder binds it into every layer's AAD), payload length set by `encode_outer_frame`. Each subsequent hop then receives exactly the shape its dispatcher requires and can peel its own layer. This is strictly more capable than the reference — single-hop relay behavior is unchanged, and chains that could never be delivered in main.py now work end-to-end. Evidence: `tests/test_handle_relay.cpp` (`HandleRelay.RelaysPeeledLayerToTheNextHop` asserts the wrapped frame shape on the wire; `HandleRelay.MultiPeelDeliversThroughRealDispatchers` drives a two-peeler chain through both nodes' real dispatchers and observes final delivery).
- **Relay sender binding** — `PQVPNNode.handle_relay` (`main.py:3392-3479`). The reference handler takes no sender address, so a relay layer is accepted from any source once its session material verifies. The C++ handler requires BOTH an endpoint-qualified origin and identity verification: hop one must come directly from the endpoint the session was established with — the same posture as the direct tunnel path in `datagram_received`; forwarded layers (hop two and later) may arrive only from a mesh-registered peer address; and in both cases the AEAD tag must verify under that identity's hash, because the layer's AAD names its expected forwarder (see Onion AEAD additional data). Mesh membership alone does not authorize injection: a captured valid layer replayed by another registered peer fails the identity check, and the monotonic nonce window rejects replays after first delivery. Evidence: `tests/test_handle_relay.cpp` (`HandleRelay.RelayLayerFromForeignEndpointIsRejected` pins hop-one rejection; `HandleRelay.ForwardedLayerFromUnregisteredSenderIsRejected` shows forwarded layers from unknown senders are still rejected; `HandleRelay.ReplayedLayerByARogueRegisteredPeerIsRejected` shows a valid layer replayed by another registered peer fails AEAD identity verification; `HandleRelay.MultiPeelDeliversThroughRealDispatchers` shows a discovery-registered relay origin is accepted and peeled).
- **Onion AEAD additional data** — `PQVPNNode.build_onion_frame_with_circuit`, `PQVPNNode.handle_relay` (`main.py:3312-3479`). The reference builder binds the next hop's identity hash into the AEAD additional data, while its own handler reconstructs that data from the outer header's peeler field; the pair cannot decrypt each other's layers. The C++ implementation instead uses a five-part AAD on both sides: session id + peeling hop's identity hash + expected sender's identity hash (the onion source for the outermost layer, the preceding relay for inner layers) + circuit id. Binding the expected forwarder's identity stops a registered peer from injecting a captured layer that was built for a different forwarder — the handler verifies the AEAD tag only under identities whose registered endpoint matches the actual UDP sender. Evidence: `tests/test_handle_relay.cpp` (RelaysPeeledLayerToTheNextHop, MisroutedLayerIsRejected, ReplayedLayerByARogueRegisteredPeerIsRejected).
- **Onion builder session state** — `PQVPNNode.build_onion_frame_with_circuit` (`main.py:3266-3359`). The reference encrypts a layer with whatever session object it finds for the hop, regardless of lifecycle state. A layer built on a handshaking/closing/closed session could never be peeled, because the receiving relay resolves its hint against established sessions only. The C++ builder therefore requires `SessionState::ESTABLISHED` for every hop (fail-closed). Evidence: `tests/test_build_onion_frame_with_circuit.cpp` ("onion layers require established sessions").
- **Relay next-hop ambiguity** — `PQVPNNode.handle_relay` (`main.py:3456-3479`). The reference forwards to the first mesh peer whose 8-byte identity hash matches, in dict iteration order. If a truncated hash ever matched two known peers, that choice would be arbitrary and could deliver encrypted content to the wrong node. The C++ implementation counts matches and fails closed unless exactly one known peer matches (practically unreachable without a SHA-256 collision, but explicit). Evidence: `tests/test_handle_relay.cpp` (RefusesForwardWhenNextHopIsUnknown covers the zero-match branch; the single-match path is exercised by RelaysPeeledLayerToTheNextHop).
- **Node identity derivation** — `PQVPNNode::establish_identity` (new; reference behavior at `main.py:2193-2209`). The reference derives the node id from the brainpoolP512r1 public key (`my_id = SHA256(brainpool pk)`). This port instead derives it from the ed25519 public key (`my_id = SHA256(ed25519 pk)`) — the node's primary authentication/identity key — so identity stays tied to the auth key rather than a secondary signature curve. Production startup calls `establish_identity` before the UDP listener and logs an explicit warning when no ed25519 key is available, instead of silently rejecting every relay (the finding that production nodes reject all relays). Evidence: `tests/test_node_establish_identity.cpp` (known-answer SHA-256 over a fixed ed25519 key; fails closed without one; keeps an explicitly set identity).

Note on relay forwarding and sender binding: in the reference, a non-final relay re-sends the peeled content as raw `session_hint+nonce+ciphertext` with no 16-byte outer frame (`main.py:3456-3479`) while every dispatcher requires that header to route anything (`main.py:4493-4508`) — a forwarded onion layer is undeliverable in the reference itself, so multi-hop chains cannot complete there. The C++ port deviates on both points (wrapped forwarding; two-tier sender binding) precisely because it makes those chains deliverable while keeping every origin check the single-hop model implies: hop one still requires the session's registered endpoint, and later hops require a discovery-registered relay as sender.

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
