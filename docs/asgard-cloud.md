# Asgard Cloud

Asgard Cloud is PQVPN's zero-telemetry distributed-storage foundation. It
encrypts every 4 MiB chunk locally with AES-256-GCM, derives a distinct key per
object and chunk with HKDF-SHA-256, addresses encrypted blobs by SHA-256, and
places replicas with deterministic rendezvous hashing. More healthy storage
peers allow independent chunks to be written concurrently; they do not weaken
encryption or expose plaintext to a peer.

`tools/asgard-cloud.py` currently targets local paths and operator-mounted
remote volumes. It is a functional storage core, not yet a public cloud: PQVPN
wire transport, signed storage capability advertisements, quotas, garbage
collection, erasure coding, repair and adversarial integration testing remain
release gates. Bootstrap and exit roles never imply storage consent.

Example two-root development configuration:

```json
{
  "replicas": 2,
  "nodes": [
    {"name": "asgard-a", "root": "/srv/asgard/a", "enabled": true},
    {"name": "asgard-b", "root": "/srv/asgard/b", "enabled": true}
  ]
}
```

Store and restore:

```bash
tools/asgard-cloud.py --config asgard.json --key asgard.key put file.bin file.asgard.json
tools/asgard-cloud.py --config asgard.json --key asgard.key get file.asgard.json restored.bin
```

The key and manifest are mode `0600`. Losing the key loses access; leaking it
exposes every object encrypted under it. Production must use an OS keystore or
hardware-backed secret, not synchronization of the raw key to storage peers.
The manifest reveals object size, chunk count and placement names; keep it
private. It is validated as hostile input before any chunk path is accessed.
