# StrangeNet universal encrypted chat

StrangeNet v2 is a bounded, session-only chat carried by authenticated PQVPN mainnet sessions. The desktop console joins `mainnet` as a universal room and fans each outbound item out to as many as 512 established authenticated peers. Each recipient gets a separately encrypted frame; there is no shared plaintext broadcast packet.

## Security boundary

StrangeNet derives a dedicated 256-bit application key from each directional PQVPN session key with HKDF-SHA3-512 and the session identifier as salt. The fixed context `PQVPN StrangeNet E2E v2` separates chat encryption from tunnel-packet encryption. The outer frame header is AEAD associated data, the nonce counter is shared with the session's authenticated data domain, and the decoded sender must match the identity bound to the receiving session.

This provides end-to-end protection between directly authenticated session peers. The implementation does not let a hub decrypt and re-publish a message while still calling that path E2E. Universal reach therefore depends on the mainnet discovery layer establishing authenticated mesh sessions to the participants. A future store-and-forward relay must carry an origin-signed envelope before it can be enabled.

The Privacy Console maintains a live directory from `peer.connected` and
`peer.disconnected` events emitted by the node after hybrid authentication and
configured admission policy succeed. A room can target all such sessions or
one full 32-byte peer identity. A pinned room never silently falls back to a
different peer if that identity disconnects. Discovery alone never places an
entry in this directory and never grants chat access.

Messages are never persisted by the node or GUI. The GUI retains at most 1,000 rendered blocks in memory. Notifications are local, optional and content-free.

## Antiflood behavior

Every authenticated sender has a process-lifetime token bucket (eight-item
burst, two tokens per second). Each room also has an aggregate bucket (128-item
burst, 32 tokens per second). Text and stickers consume more capacity as their payload
approaches 2 KiB; acknowledgements and compact reactions cost less. These checks
run after session authentication and sender binding, but before the message
reaches the UI or produces a delivery receipt. Outbound GUI and CLI messages use
the same limits. When the local sender exhausts a bucket, the node returns the
calculated retry delay and the GUI keeps the draft instead of using a fixed
five-second timer.

Flood state is memory-only and bounded to 4,096 sender streams and 256 rooms;
idle entries expire after five minutes. One broadcast is capped at 512 directly
authenticated sessions, bounding encryption and UDP work per click. Larger
communities require an authenticated room distribution layer; the current
direct-session protocol does not claim unbounded global fanout.

## Optional blockchain anchor

The Privacy Console can build a private StrangeNet proof chain when the user
explicitly enables **Build a private session proof chain**. Each accepted,
sent, delivered, sticker, or reaction event becomes a salted SHA-256
commitment. Every block binds its index, the previous block, and the new
commitment. The chain is bounded to 4,096 events and exists only in memory.

**Copy chain anchor** copies a compact JSON record with the algorithm, block
count, and 32-byte root. That root can be timestamped with a blockchain or
notary tool without sending the room, peer identities, message text, or the
private salt. PQVPN does not select a chain, access a wallet, pay a fee, or
publish a transaction. A root proves continuity only after an external system
anchors it; by itself it is a local commitment, not decentralized consensus.
Starting another node session resets an enabled chain, and closing the console
discards it.

## Wire behavior

Version 2 frames support:

- UTF-8 text and emoji, up to 2,048 bytes;
- delivery acknowledgements tied to the original sequence;
- compact custom sticker specifications;
- reactions tied to a sender and message sequence;
- a 64-packet per-room, per-sender replay window that tolerates bounded UDP reordering;
- a hard limit of 4,096 replay streams per process;
- bounded per-sender and aggregate room token buckets;
- a maximum of 512 direct recipients per broadcast operation.

Version 1 text frames remain decodable. New senders emit version 2.

Sticker payloads contain only an emoji, a caption of at most 48 characters and one color from the built-in palette. The GUI escapes all text before rendering and rejects arbitrary colors or malformed JSON. No HTML, script, URL, remote image or executable attachment crosses the chat protocol.

## Delivery semantics

`Sent` means at least one authenticated session accepted the datagram for transmission. `Delivered` means that peer decrypted, authenticated, replay-checked and accepted the item, then returned an encrypted acknowledgement. UDP delivery remains best effort; missing receipts are not fabricated. Reactions and stickers use the same receipt path.

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)
