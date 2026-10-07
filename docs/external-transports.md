# External transports

The C++23 node supports attaching to an external UDP forwarder. The engine is
not linked into PQVPN. Version 1 uses `mode: attach`: an administrator starts
and supervises the external process independently. There is no shell command
execution, automatic privilege elevation or automatic firewall modification.

## udp2raw

Use `config.udp2raw.json` on the client. Its listener is 127.0.0.1:9090 and its
only bootstrap endpoint is udp2raw's local listener at 127.0.0.1:9091.
Start udp2raw in client mode with that local listener and the remote udp2raw
server address. On the server, udp2raw's destination is the server PQVPN node's
loopback listener. Configure matching keys and raw mode in the external
engine. Prefer udp2raw's configuration file to putting a key in process args.

Official setup and privilege requirements:
[udp2raw upstream](https://github.com/wangyu-/udp2raw).

PQVPN pins its connected UDP socket to the external endpoint. It rejects
outgoing mesh destinations other than that endpoint and receives datagrams
only from the attached engine. If the engine disappears, delivery fails;
PQVPN does not retry through a public UDP endpoint. This is a single-peer
transport, not a multi-peer UDP mux. Configuration rejects a non-loopback
listener, additional bootstrap peers and non-loopback engine endpoints.
Attaching a UDP socket does not prove the external process is ready: the
authenticated PQVPN handshake remains the end-to-end readiness check.

## TCP engines

obfs4, Xray/V2Ray and Shadowsocks are not implemented by this adapter.
Their SOCKS TCP endpoints cannot receive raw PQVPN UDP frames. A separate
authenticated UDP-over-TCP relay and SOCKS integration are required before
those transports can be declared supported. Naming one of these engines in
the UDP configuration is rejected instead of silently sending raw UDP.

## Local traffic shaping

`traffic_shaping.enabled` activates two small online linear predictors,
trained with bounded SGD on packet sizes and arrival intervals. The model
chooses bounded delay and encrypted padding buckets; it does not inspect
payloads, download a model, send telemetry or train against an ISP classifier.
The FIFO preserves nonce ordering, limits memory and drops overflow without
an unshaped fallback. Padding is inside the existing authenticated encrypted
data frame (new frame type 9); malformed padding, tampering and replay are
rejected. Both peers must run the new receiver. Default configuration keeps
legacy frame type 5; shaping is explicitly enabled in the udp2raw example.

This changes size/timing patterns but does not replace an outer transport.
Website access still uses the selected server's existing egress facility.
No interoperability claim with real udp2raw is made until an external-engine
client/server test has run; the C++ tests exercise attachment policy and the
encrypted shaping path.
