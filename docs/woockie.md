# Woockie capability addresses

A **Woockie** is the sum of a URL-shaped resource path and an authenticated
PQVPN peer identity:

```text
woockie://<64-hex-peer-id>/<service>/<resource>
```

For example:

```text
woockie://7ad9…64-hex…91c2/strangenet/mainnet/friends/poetry
```

Unlike `https://host/path`, a Woockie contains no DNS hostname, IP address,
port, username, password, query or fragment. The 32-byte Peer ID is the
cryptographic destination. The service is an allowlisted capability
(`strangenet`, `asgard` or `node`) and the remaining path is interpreted only
by that service after PQVPN has authenticated the peer and local policy allows
it.

The parser is deliberately side-effect free. It canonicalizes the peer ID,
rejects traversal and ambiguous URL syntax, and performs no network request.
Possessing an address grants no session, payment, storage or command authority.
Asgard object retrieval, StrangeNet room entry and node inspection must each
define a separate authorization step before a Woockie can open them.

Woockie is original PQVPN terminology. It is not HTTP, DNS, a blockchain name
service or a promise that a peer is online.
