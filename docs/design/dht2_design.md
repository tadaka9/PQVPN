# DHT 2.0 Design Document

## Overview
DHT 2.0 is a complete rewrite of the Distributed Hash Table (DHT) component in PQVPN, designed to provide secure, decentralized peer discovery while incorporating comprehensive security measures. It builds on the need for censorship-resistant, quantum-safe peer finding, integrating with PQ (post-quantum) cryptography and the bootstrap system.

## Core Components

### 1. Secure Routing
- **Authenticated Connections**: All DHT communications use mutual TLS-like authentication with PQ certificates. Each node has a long-term identity keypair (e.g., PQ signature scheme like Dilithium) for signing messages.
- **Encrypted Channels**: End-to-end encryption for all messages using ChaChaPoly1305 with ephemeral PQ key exchange (e.g., Kyber) for forward secrecy.
- **Message Integrity**: Each DHT message includes a digital signature to prevent tampering and spoofing.
- **Routing Table Management**: Maintain a k-bucket structure with security checks: verify node responsiveness, age out stale entries, and prioritize trusted nodes.

### 2. Key Management
- **Identity Keys**: Each node generates a PQ signature keypair at startup. Public keys are distributed via DHT stores.
- **Ephemeral Keys**: For each session or message batch, derive ephemeral encryption keys using HKDF from shared secrets.
- **Key Rotation**: Periodic rotation of identity keys with announcement via DHT. Old keys are retained for a grace period.
- **Certificate Authority**: Decentralized CA using DHT-stored certificates, with revocation lists maintained in the DHT.

### 3. Attack Mitigations
- **Sybil Resistance**:
  - Proof-of-Work (PoW): Require a small PoW for node registration to deter mass creation of fake nodes.
  - Reputation System: Nodes build reputation through successful interactions; low-rep nodes are deprioritized.
  - Stake-Based: Optional stake (e.g., computational resources) to participate actively.

- **Eclipse Attacks Prevention**:
  - Diversified Routing: Use multiple paths for queries, not relying on a single k-bucket.
  - Random Walks: Periodic random queries to discover new nodes outside immediate vicinity.
  - Bootstrap Diversity: Connect to multiple bootstrap nodes initially to populate routing table broadly.

- **Other Mitigations**:
  - Rate Limiting: Limit query rates per IP/node to prevent DoS.
  - Sybil Detection: Statistical analysis of node distribution to detect anomalies.
  - Censorship Resistance: Use pluggable transports and onion-like routing for DHT traffic.

### 4. Bootstrap Integration
- **Initial Discovery**: Nodes query bootstrap nodes for initial DHT peers. Bootstrap nodes provide signed lists of known good DHT nodes.
- **Fallback Mechanism**: If DHT is partitioned, bootstrap nodes act as relays for cross-partition communication.
- **Geo-Distribution**: Bootstrap nodes are geo-distributed, ensuring global accessibility.
- **Secure Bootstrapping**: Bootstrap connections use PQ crypto, with bootstrap nodes verifying node identities before adding to lists.

## Protocol Details

### DHT Operations
- **PUT/GET/STORE**: Standard DHT operations with added security layers.
  - PUT: Store value with owner's signature.
  - GET: Retrieve with integrity verification.
- **Node Lookup**: Iterative or recursive with security hops.

### Integration with PQ Crypto
- Use liboqs for PQ primitives: Kyber for KEM, Dilithium for signatures.
- Ensure efficient handling of larger key sizes (e.g., 3KB for Dilithium public keys).

## Performance Considerations
- Optimize for low-latency operations, as DHT is critical for peer discovery.
- Batch operations to reduce overhead.
- Caching of frequently accessed data.

## Deployment and Testing
- Gradual rollout with backward compatibility.
- Extensive testing for security and performance.