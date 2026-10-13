# StrangeNet universal encrypted chat

StrangeNet v2 is a bounded, session-only chat carried by authenticated PQVPN mainnet sessions. The desktop console joins `mainnet` as a universal room and fans each outbound item out to every established authenticated peer. Each recipient gets a separately encrypted frame; there is no shared plaintext broadcast packet.

## Security boundary

StrangeNet derives a dedicated 256-bit application key from each directional PQVPN session key with HKDF-SHA3-512 and the session identifier as salt. The fixed context `PQVPN StrangeNet E2E v2` separates chat encryption from tunnel-packet encryption. The outer frame header is AEAD associated data, the nonce counter is shared with the session's authenticated data domain, and the decoded sender must match the identity bound to the receiving session.

This provides end-to-end protection between directly authenticated session peers. The implementation does not let a hub decrypt and re-publish a message while still calling that path E2E. Universal reach therefore depends on the mainnet discovery layer establishing authenticated mesh sessions to the participants. A future store-and-forward relay must carry an origin-signed envelope before it can be enabled.

Messages are never persisted by the node or GUI. The GUI retains at most 1,000 rendered blocks in memory. Notifications are local, optional and content-free.

## Wire behavior

Version 2 frames support:

- UTF-8 text and emoji, up to 2,048 bytes;
- delivery acknowledgements tied to the original sequence;
- compact custom sticker specifications;
- reactions tied to a sender and message sequence;
- a 64-packet per-room, per-sender replay window that tolerates bounded UDP reordering;
- a hard limit of 4,096 replay streams per process.

Version 1 text frames remain decodable. New senders emit version 2.

Sticker payloads contain only an emoji, a caption of at most 48 characters and one color from the built-in palette. The GUI escapes all text before rendering and rejects arbitrary colors or malformed JSON. No HTML, script, URL, remote image or executable attachment crosses the chat protocol.

## Delivery semantics

`Sent` means at least one authenticated session accepted the datagram for transmission. `Delivered` means that peer decrypted, authenticated, replay-checked and accepted the item, then returned an encrypted acknowledgement. UDP delivery remains best effort; missing receipts are not fabricated. Reactions and stickers use the same receipt path.

