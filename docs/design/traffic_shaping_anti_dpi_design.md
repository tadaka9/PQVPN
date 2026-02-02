# Traffic Shaping and Anti-DPI Design

## Overview

This document outlines the design for traffic shaping and anti-DPI modules to enhance PQVPN's ability to circumvent censorship while maintaining efficient resource usage.

## Components

### Traffic Shaper Module

**Purpose:** Control bandwidth usage through rate limiting and traffic prioritization to ensure QoS.

**Key Features:**
- Rate Limiting: Implement token bucket algorithm for bandwidth control.
- Prioritization: Use priority queues to handle different traffic types (control packets > data packets).
- Configuration: Allow configurable limits per session or globally.

**Classes/Functions:**
- `TrafficShaper`: Main class with methods for enqueue_packet, dequeue_packet, check_rate_limit.
- TokenBucket: Helper class for rate limiting.

**Integration:** Hook into NetworkManager.send_datagram to shape outgoing packets.

### Anti-DPI Module

**Purpose:** Evade Deep Packet Inspection using low-overhead techniques.

**Key Features:**
- Padding: Add random padding to packets to obscure sizes.
- Timing Randomization: Introduce jitter in packet send times to avoid patterns.
- Low Compute: Use efficient random number generation and minimal processing.

**Classes/Functions:**
- `AntiDPI`: Main class with methods for apply_padding, randomize_timing.
- PaddingAlgorithm: Simple random padding up to max size.
- TimingObfuscator: Add random delays with low overhead.

**Integration:** Apply before encryption in packet sending pipeline.

## Packet Processing Pipeline

1. Application data -> Traffic Shaper (prioritize/enqueue)
2. -> Anti-DPI (padding)
3. -> Encryption (existing)
4. -> Send via transport

For incoming: Receive -> Decrypt -> Anti-DPI (strip padding) -> Application

## Minimal Compute Overhead

- Use os.urandom or similar for randomness.
- Padding limited to small amounts.
- Timing jitter in milliseconds, not seconds.