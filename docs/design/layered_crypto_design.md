# Layered Crypto ChaChaPoly1305 Structure for Onion Routing

## Overview

This design outlines the implementation of a layered encryption scheme using ChaChaPoly1305 for onion-like routing in PQVPN. The goal is to provide enhanced security where each relay in the route only decrypts its specific layer, limiting exposure of the payload.

## Key Concepts

- **Onion Routing**: Inspired by Tor, packets are wrapped in multiple layers of encryption. Each relay peels off one layer.
- **ChaChaPoly1305**: Authenticated Encryption with Associated Data (AEAD) cipher for confidentiality, integrity, and authenticity.
- **Key Derivation**: Use HKDF to derive per-hop keys from a master key, ensuring forward secrecy.

## Structure

### Packet Format

A packet consists of a series of encrypted layers:

```
[Layer 1 (Outer)] [Layer 2] ... [Layer N (Inner)] [Payload]
```

Where:
- Layer 1 is encrypted with the key for Relay 1 (entry relay).
- Layer 2 is encrypted with the key for Relay 2, and so on.
- The inner layer contains the final payload or routing information for the destination.

### Encryption Process (At Sender)

1. Determine the route: [Relay1, Relay2, ..., RelayN]
2. Derive keys: For each relay, derive a subkey from the master session key using HKDF.
   - Key_i = HKDF(master_key, salt=i, info="relay_key")
3. Start with the innermost payload (e.g., the actual data or next hop info).
4. For i from N downto 1:
   - Encrypt the current (inner) data with ChaChaPoly1305 using Key_i and a nonce.
   - Add routing metadata (next hop) as AAD.
5. The result is the onion-encrypted packet.

### Decryption Process (At Each Relay)

1. Receive the packet.
2. Use the relay's key to decrypt the outermost layer.
3. Verify integrity using the authentication tag.
4. Extract the next hop information from the decrypted layer.
5. Forward the remaining (inner) encrypted layers to the next hop.

### Key Management

- Master key shared between sender and entry relay (or via PQ key exchange).
- Per-hop keys derived on-the-fly to avoid storing multiple keys.
- Nonces: Unique per packet and layer, incremented or randomized securely.

## Integration with Existing Code

- Build on the existing ChaChaPoly1305 implementation in the crypto module.
- Extend the networking/relay modules to handle layered encryption/decryption.
- Ensure compatibility with post-quantum crypto if needed.

## Security Benefits

- **Compartmentalization**: Each relay sees only its layer, not the full route or payload.
- **Forward Secrecy**: Keys are derived per hop/session.
- **Integrity**: AEAD prevents tampering.
- **Efficiency**: ChaChaPoly1305 is fast and suitable for high-throughput VPN.

## Potential Challenges

- Overhead: Multiple encryptions add latency.
- Key Distribution: Securely sharing master keys.
- Route Discovery: How to build the route securely.