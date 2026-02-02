# Design for DHT Poisoning Defenses in SecureDHT

## Overview
This design outlines the implementation of defenses against DHT poisoning attacks in PQVPN's SecureDHT. Poisoning involves false data injection to disrupt discovery. Defenses include value signatures, reputation scoring, cross-verification, and detection algorithms.

## Components

### 1. Value Signatures
- **Purpose**: Ensure authenticity and integrity of stored values.
- **Implementation**:
  - All values stored in DHT are signed by the owner using PQ signature (Dilithium5).
  - Signature covers key, value, TTL, timestamp, and owner ID.
  - Verification on store and get operations.
  - Invalid signatures reject the value.

### 2. Reputation Scoring
- **Purpose**: Track node trustworthiness to mitigate Sybil and bad actor attacks.
- **Implementation**:
  - Each NodeInfo has a reputation score (float, 0.0-1.0).
  - Increase score for successful pings, valid data provision, positive peer reports.
  - Decrease for invalid data, failed pings, negative reports.
  - Use reputation in node selection: prefer high-rep nodes.
  - Decay over time if inactive.

### 3. Cross-Verification
- **Purpose**: Confirm data from multiple sources to prevent single-source poisoning.
- **Implementation**:
  - For get operations, query multiple nodes and aggregate responses.
  - Accept value only if confirmed by majority (e.g., >50% of responses match).
  - For store, require confirmation from k/2 nodes before considering stored.
  - Handle conflicts by choosing highest-rep sources.

### 4. Poisoning Detection Algorithms
- **Purpose**: Detect anomalous behavior indicating poisoning.
- **Implementation**:
  - Statistical anomaly detection: Monitor response times, data consistency (e.g., IP validity, key formats).
  - Flag nodes with high invalid response rates.
  - Quarantine suspicious nodes: Temporarily exclude from routing.
  - Log anomalies for review.

## Integration
- Extend SecureDHT class with methods for validation, rep scoring, verification, detection.
- Update store/get to incorporate defenses.
- Add logging for security events.

## Performance Considerations
- Low overhead: Use efficient crypto, cached reps, batched verifications.
- Configurable thresholds for scalability.