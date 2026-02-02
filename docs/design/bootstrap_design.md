# Bootstrap Node System Design

## Overview
The bootstrap node system enables decentralized peer discovery for PQVPN by providing initial entry points into the network. It uses DHT-based seed nodes, geo-distributed relays, and censorship-resistant mechanisms to ensure robust, secure joining.

## Components

### Seed Nodes
- **Role**: Initial contact points stored in a DHT for peer lookup.
- **Implementation**: Use a simple DHT like Kademlia for key-value storage of peer IDs and addresses.
- **Functionality**: Nodes query seed nodes to find nearby peers or relays.

### Geo-Distributed Relays
- **Role**: Handle bootstrap queries and peer introductions across regions.
- **Deployment**: Relays hosted in multiple geographic locations (e.g., US, EU, Asia) for fault tolerance.
- **Load Balancing**: Distribute queries to prevent overload on single relays.

### Censorship-Resistant Joining
- **Mechanisms**: 
  - Domain fronting for initial connections.
  - Pluggable transports (e.g., obfs4) to disguise traffic.
  - Onion routing for multi-hop connections to bootstrap nodes.
- **Fallbacks**: If direct connection fails, use proxies or VPN tunnels.

## Integration with Discovery Module
- **Existing Discovery**: Assume discovery.py handles local peer finding (e.g., via multicast or local DHT).
- **Bootstrap Integration**: Bootstrap provides a list of initial peers to discovery.py, which then expands the network graph.
- **API**: discovery.py will have a `bootstrap_peers()` method that queries the bootstrap system.

## Security
- **Authentication**: Use PKI to verify bootstrap nodes; sign responses.
- **Anti-Sybil**: Implement proof-of-work for node registration or reputation systems.
- **Anonymity**: Ensure queries don't reveal user identity; use anonymous channels.

## Architecture Diagram
[Placeholder for diagram]

## Implementation Plan
1. Implement DHT library integration (use existing Python DHT lib like kademlia).
2. Create BootstrapClient class in bootstrap.py for querying seeds.
3. Update discovery.py to call bootstrap on initialization.
4. Add configuration for known seed node IPs.
5. Test with geo-distributed setup.