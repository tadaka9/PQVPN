# StrangeNet universal encrypted chat

StrangeNet is a bounded, session-only social chat carried by authenticated PQVPN mainnet sessions. It is designed for borderless friendship, conversation and consensual romantic connection without turning location or network metadata into a profile. Rooms use hierarchical paths such as `mainnet/friends/poetry`, with at most eight levels. Each outbound item is encrypted separately for as many as 512 established authenticated peers; there is no shared plaintext broadcast packet.

The GUI is room-first and also supports direct text to one authenticated Peer
ID. A participant is shown only by a self-certifying 32-byte Peer ID after
hybrid authentication and admission-policy checks. Participant, bootstrap and
local-listener IP addresses are not shown in chat UI or peer lifecycle events.
An exit address may be shown separately as a connection fact because it is the
public address websites observe; it is never presented as a participant
identity.

Version 0.0.15 adds explicit groups. Selecting at least two authenticated
remote identities creates a group of at least three participants including the
local user. Membership is canonical, bounded to 64 participants and pinned for
the joined room. Every send targets exactly that set and fails closed for an
offline member; it never substitutes another peer or falls back to universal
fan-out. There is no common group secret to escrow or split. Instead, each
member contributes to an independent X25519 + ML-KEM hybrid session, and the
sender produces a different authenticated ciphertext for every recipient. A
member's session key cannot decrypt another member's copy. This beta remains
live-session P2P: it does not yet claim asynchronous
store-and-forward delivery or unbounded global reach.

Public-identity verification is implemented as an optional hybrid-signed claim
for organizations, national political parties and public figures. Claims bind a
display name and evidence URI to a PQVPN peer identity and an expiry time. A
badge is valid only under issuers explicitly trusted by the local user; PQVPN
has no global verifier, does not transmit identity documents, and verification
never grants access to encrypted messages.

## Security boundary

StrangeNet derives a dedicated 256-bit application key from each directional PQVPN session key with HKDF-SHA3-512 and the session identifier as salt. The fixed context `PQVPN StrangeNet E2E v2` separates chat encryption from tunnel-packet encryption. The outer frame header is AEAD associated data, the nonce counter is shared with the session's authenticated data domain, and the decoded sender must match the identity bound to the receiving session.

This provides end-to-end protection between directly authenticated session peers. The implementation does not let a hub decrypt and re-publish a message while still calling that path E2E. Universal reach therefore depends on the mainnet discovery layer establishing authenticated mesh sessions to the participants. A future store-and-forward relay must carry an origin-signed envelope before it can be enabled.

This per-recipient construction is intentionally different from secret sharing:
splitting one group key into N-of-N fragments would make every send depend on
every member being online and would not by itself provide authenticated
membership, forward secrecy or post-compromise recovery. Future scalable group
epochs will use a reviewed contributory group-key protocol, rotate on every
membership change and remain disabled until the post-quantum construction has
interoperability vectors and independent review. Standard MLS/TreeKEM must not
be advertised as post-quantum without such an extension.

The Privacy Console maintains a live directory from `peer.connected` and
`peer.disconnected` events emitted by the node after hybrid authentication and
configured admission policy succeed. A room can target all such sessions or
one full 32-byte peer identity. A pinned room never silently falls back to a
different peer if that identity disconnects. Discovery alone never places an
entry in this directory and never grants chat access.

Messages are never persisted by the node or GUI. The GUI retains at most 1,000 rendered blocks in memory. Notifications are local, optional and content-free.

## Writing experience

The Privacy Console presents StrangeNet as a conversation rather than a raw
event log. Authenticated messages and local messages use distinct bubbles;
receipts, rate limits and room changes remain visually separate so operational
status cannot be mistaken for something another person wrote.

The **Pixel Commons** is an optional retro social-lobby view over that same
transport. Its spaces map to ordinary validated StrangeNet room paths, and its
figures represent the local user plus currently authenticated Peer IDs. It is
not a separate service, directory, account system, or source of presence data:
selecting a space updates the canonical room field, while join, antiflood,
direct messages, group fanout, voice and delivery receipts continue through
the normal StrangeNet controls. The scene is drawn locally by PQVPN and uses no
third-party game assets.

The GUI also provides visible-session search, content-free notification levels
and a session-only peer block list. Blocking is enforced in the node before an
incoming message reaches the GUI handler and excludes that Peer ID from direct,
pinned-group and room fanout. See the
[social feature matrix](strangenet-feature-matrix.md) for the cross-application
comparison and for features intentionally deferred or rejected.

The composer has two explicit keyboard modes:

- **Conversation** sends with Enter and inserts a line break with Shift+Enter.
- **Poem** preserves Enter for line breaks and sends with Ctrl+Enter (or
  Command+Enter on macOS).

Both modes transmit the same bounded UTF-8 plaintext inside StrangeNet's
authenticated encryption. The mode is local presentation state, adds no wire
metadata and makes no inference about the writer. Pasting text beyond the
2,048-byte protocol limit is truncated at the composer boundary; blank or
whitespace-only messages are not sent. **Clear view** removes rendered content
from this process without changing the room or claiming remote deletion.

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

## Decentralized identity, Web3 and optional blockchain anchor

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

The wider [Privacy City](privacy-city.md) pixel navigation maps Gateway,
Transit Lab, Commons and Shield to real PQVPN subsystems. The scene remains
outside the cryptographic trust boundary and cannot invent peer trust or mark
a tunnel protected.

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

Version 1 text frames remain decodable. Text, replies and reactions use version 2. Version 3 extends the same bounded envelope with live 16 kHz mono voice chunks. The GUI provides hold-to-talk audio only: chunks are played from memory and are not saved as files. There is no image, video, HTML, arbitrary attachment or remote-media wire kind.

Sticker payloads contain only an emoji, a caption of at most 48 characters and one color from the built-in palette. The GUI escapes all text before rendering and rejects arbitrary colors or malformed JSON. No HTML, script, URL, remote image or executable attachment crosses the chat protocol.

## Delivery semantics

`Sent` means at least one authenticated session accepted the datagram for transmission. `Delivered` means that peer decrypted, authenticated, replay-checked and accepted the item, then returned an encrypted acknowledgement. UDP delivery remains best effort; missing receipts are not fabricated. Reactions and stickers use the same receipt path.

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)
