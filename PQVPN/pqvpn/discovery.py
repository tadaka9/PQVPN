"""pqvpn.discovery

Minimal Kademlia DHT discovery integration for Path Quilt VPN.
This module implements a small Discovery class that can (when kademlia
is installed) publish a signed peer record into the DHT and look up
peer records by peer id. Records are canonical JSON with ML-DSA and
Ed25519 signatures produced by the node's keys.

This implementation is intentionally minimal for Phase 1: it focuses on
correct signing/verifying, DHT set/get, and integration points for the
main node lifecycle. It can be extended later with mDNS and richer
caching/refresh policies.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, Optional, Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import os
from pqvpn.dht import DHTClient, DHTUnavailableError

# Optional zeroconf import for mDNS
try:
    from zeroconf import ServiceInfo, Zeroconf
except Exception:
    ServiceInfo = None  # type: ignore
    Zeroconf = None  # type: ignore

# For static analysis, ensure names exist
ServiceInfo: Any  # type: ignore
Zeroconf: Any  # type: ignore

# Optional Argon2 KDF for cache encryption
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
except Exception:
    hash_secret_raw = None  # type: ignore
    Argon2Type = None  # type: ignore

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("pqvpn.discovery")

# Runtime helper stubs (assigned at runtime by importing from main)
canonical_sign_bytes: Any = None
pq_sig_sign: Any = None
pq_sig_verify: Any = None


class Discovery:
    """Discovery subsystem backed by Kademlia DHT (optional).

    Usage: d = Discovery(node); await d.start(); await d.publish_peer_record()
    """

    def __init__(self, node: Any):
        self.node = node
        self.config = node.config.get("discovery", {}) if node and getattr(node, "config", None) else {}
        self.enabled = bool(self.config.get("enabled", True))
        self.dht_bind = self.config.get("dht_bind", "0.0.0.0")
        self.dht_port = int(self.config.get("dht_port", 8468))
        # Ensure bootstrap is always a list (may be provided as [] or omitted)
        tmp_bs = self.config.get("bootstrap", None)
        if tmp_bs is None:
            try:
                tmp_bs = self.node.bootstrap_peers if getattr(self.node, 'bootstrap_peers', None) is not None else []
            except Exception:
                tmp_bs = []
        self.bootstrap = tmp_bs or []
        self.publish_interval = int(self.config.get("publish_interval", 600))
        self.ttl = int(self.config.get("ttl", 1800))
        # persist cache path
        self.cache_file = self.config.get("cache_file", os.path.join(self.node.keys_dir if hasattr(self.node, 'keys_dir') else '.', "discovery_cache.json"))
        self.publish_addr = bool(self.config.get("publish_addr", False))  # by default do NOT publish raw IPs
        self.mdns_enabled = bool(self.config.get("mdns_enabled", False))
        # cache encryption settings
        self.cache_encrypt = bool(self.config.get("cache_encryption", {}).get("enabled", False))
        self.cache_passphrase = self.config.get("cache_encryption", {}).get("passphrase", "")
        self.cache_argon = {
            "time_cost": int(self.config.get("cache_encryption", {}).get("time_cost", 2)),
            "memory_cost_kib": int(self.config.get("cache_encryption", {}).get("memory_cost_kib", 65536)),
            "parallelism": int(self.config.get("cache_encryption", {}).get("parallelism", 1)),
        }
        self._zeroconf: Optional[Any] = None
        self._mdns_info: Optional[Any] = None
        # Safety: require a token derived from node id to enable publishing addresses.
        # This prevents accidental code edits or config tampering from leaking IPs.
        if self.publish_addr:
            try:
                token = self.config.get("publish_addr_token", "")
                expected = ""
                if getattr(self.node, "my_id", None):
                    import hashlib as _hash

                    expected = _hash.sha256(self.node.my_id + b"ALLOW_PUBLISH").hexdigest()
                if not token or token != expected:
                    logger.critical(
                        "Discovery: publish_addr requested but publish_addr_token missing or invalid - refusing to publish raw IPs"
                    )
                    self.publish_addr = False
            except Exception:
                logger.critical(
                    "Discovery: publish_addr token check failed - refusing to publish raw IPs"
                )
                self.publish_addr = False
        self._server: Optional[DHTClient] = None
        self._publish_task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._started = False
        # in-memory cache of validated records
        self._cache: Dict[str, Dict[str, Any]] = {}
        # Quorum/anti-poison settings
        self.quorum_attempts = int(self.config.get('quorum_attempts', 3))
        self.quorum_interval = float(self.config.get('quorum_interval', 0.25))

    async def start(self) -> None:
        """Start the discovery subsystem (DHT server + background tasks).

        If kademlia is not installed the subsystem becomes a no-op but available
        via the same API (lookup will return None).
        """
        # enforce strict hybrid-only fast-fail if node requires hybrid
        if getattr(self.node, 'require_hybrid_handshake', False):
            missing = []
            if not getattr(self.node, 'kyber_pk', None):
                missing.append('kyber_pk')
            if not getattr(self.node, 'mldsa_pk', None):
                missing.append('mldsa_pk')
            if not getattr(self.node, 'brainpoolP512r1_pk', None):
                missing.append('brainpoolP512r1_pk')
            if not getattr(self.node, 'ed25519_pk', None):
                missing.append('ed25519_pk')
            # ensure ML-DSA verifier available
            try:
                from main import pq_sig_verify
            except Exception:
                pq_sig_verify = None
            if pq_sig_verify is None:
                missing.append('pq_sig_verify (oqs nested Signature)')

            if missing:
                msg = f"Discovery: missing required hybrid components for strict mode: {', '.join(missing)}"
                logger.critical(msg)
                raise RuntimeError(msg)

        # load cache if present (support encrypted cache)
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    data = f.read()
                # attempt to parse as JSON first (unencrypted)
                try:
                    raw = json.loads(data.decode())
                except Exception:
                    raw = None

                if raw is None and self.cache_encrypt and hash_secret_raw is not None and self.cache_passphrase:
                    # parse envelope JSON with salt/nonce/ct
                    try:
                        env = json.loads(data.decode())
                        salt = base64.b64decode(env.get('salt', ''))
                        nonce = base64.b64decode(env.get('nonce', ''))
                        ct = base64.b64decode(env.get('ct', ''))
                        key = self._derive_cache_key(self.cache_passphrase.encode(), salt)
                        aes = AESGCM(key)
                        plain = aes.decrypt(nonce, ct, None)
                        raw = json.loads(plain.decode())
                    except Exception as e:
                        logger.debug(f"Discovery: failed to decrypt cache {self.cache_file}: {e}")
                        raw = None

                if isinstance(raw, dict):
                    self._cache = raw
                    logger.info(f"Discovery loaded {len(self._cache)} cached records from {self.cache_file}")
        except Exception as e:
            logger.debug(f"Discovery: failed to load cache {self.cache_file}: {e}")

        if not self.enabled:
            logger.info("Discovery disabled by configuration")
            return

        # Start DHT client (use strict mode when hybrid required)
        strict = bool(getattr(self.node, "require_hybrid_handshake", False))
        # build bootstrap tuples normalized to (host,str->int port)
        bootstrap_tuples = []
        for bs in self.bootstrap:
            try:
                if isinstance(bs, dict) and bs.get("host") and bs.get("port"):
                    bootstrap_tuples.append((str(bs.get("host")), int(bs.get("port"))))
                elif isinstance(bs, str):
                    # support [ipv6]:port and host:port
                    if bs.startswith("["):
                        # bracketed IPv6
                        end = bs.find("]")
                        if end != -1 and bs[end + 1] == ":":
                            host = bs[1:end]
                            port = int(bs[end + 2 :])
                            bootstrap_tuples.append((host, port))
                    else:
                        host, port_s = bs.rsplit(":", 1)
                        bootstrap_tuples.append((host, int(port_s)))
            except Exception:
                continue

        try:
            self._server = DHTClient(
                bootstrap=bootstrap_tuples,
                port=self.dht_port,
                strict=strict,
                allowed_prefixes=["pqvpn:peer:"] if strict else None,
            )
            await self._server.start()
        except DHTUnavailableError as e:
            logger.warning(f"Discovery: DHT unavailable: {e}")
            self._server = None
            return
        except Exception as e:
            logger.warning(f"Discovery: failed to initialize DHT client: {e}")
            self._server = None
            return

        loop = asyncio.get_running_loop()
        self._stopping.clear()
        self._publish_task = loop.create_task(self._publish_loop())

        # start mDNS advertiser if requested and zeroconf available
        if self.mdns_enabled:
            if Zeroconf is None or ServiceInfo is None:
                logger.warning("Discovery: mdns_enabled set but zeroconf not installed; skipping mDNS advertising")
            else:
                try:
                    self._zeroconf = Zeroconf()
                    # publish immediately
                    self._mdns_publish()
                    logger.info("Discovery: mDNS advertising started")
                except Exception as e:
                    logger.debug(f"Discovery: mDNS start failed: {e}")

        self._started = True
        logger.info("Discovery started")

    async def stop(self) -> None:
        """Stop discovery: cancel tasks and stop DHT server."""
        # persist cache to disk (optionally encrypted with Argon2+AES-GCM)
        try:
            os.makedirs(os.path.dirname(self.cache_file) or '.', exist_ok=True)
            raw_bytes = json.dumps(self._cache, separators=(',', ':'), sort_keys=True).encode()
            if self.cache_encrypt and hash_secret_raw is not None and self.cache_passphrase:
                try:
                    salt = os.urandom(16)
                    key = self._derive_cache_key(self.cache_passphrase.encode(), salt)
                    aes = AESGCM(key)
                    nonce = os.urandom(12)
                    ct = aes.encrypt(nonce, raw_bytes, None)
                    env = {
                        'salt': base64.b64encode(salt).decode(),
                        'nonce': base64.b64encode(nonce).decode(),
                        'ct': base64.b64encode(ct).decode(),
                    }
                    with open(self.cache_file, 'w') as f:
                        json.dump(env, f, separators=(',', ':'), sort_keys=True)
                    try:
                        os.chmod(self.cache_file, 0o600)
                    except Exception:
                        pass
                    logger.debug(f"Discovery: persisted encrypted cache {self.cache_file}")
                except Exception as e:
                    logger.debug(f"Discovery: failed to encrypt+persist cache: {e}")
                    # fallback to writing plain (best-effort)
                    with open(self.cache_file, 'w') as f:
                        f.write(raw_bytes.decode())
            else:
                with open(self.cache_file, 'w') as f:
                    f.write(raw_bytes.decode())
                try:
                    os.chmod(self.cache_file, 0o600)
                except Exception:
                    pass
                logger.debug(f"Discovery: persisted cache {self.cache_file}")
        except Exception as e:
            logger.debug(f"Discovery: failed to persist cache: {e}")

        # stop mDNS
        if getattr(self, '_zeroconf', None) and getattr(self, '_mdns_info', None):
            try:
                self._zeroconf.unregister_service(self._mdns_info)
            except Exception:
                pass
            try:
                self._zeroconf.close()
            except Exception:
                pass
            self._zeroconf = None
            self._mdns_info = None

        if not self._started:
            return
        self._stopping.set()
        if self._publish_task:
            self._publish_task.cancel()
            try:
                await self._publish_task
            except Exception:
                pass
            self._publish_task = None

        if self._server:
            try:
                await self._server.stop()
            except Exception:
                pass
            self._server = None

        self._started = False
        logger.info("Discovery stopped")

    async def _publish_loop(self) -> None:
        """Background task that periodically republishes our peer record."""
        try:
            # immediate publish
            try:
                await self.publish_peer_record()
            except Exception as e:
                logger.debug(f"Discovery: initial publish failed: {e}")

            while not self._stopping.is_set():
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=self.publish_interval)
                    break
                except asyncio.TimeoutError:
                    # time to republish
                    try:
                        await self.publish_peer_record()
                    except Exception as e:
                        logger.debug(f"Discovery: publish failed: {e}")
                        # continue loop
                        pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.exception(f"Discovery publish loop error: {e}")

    def _build_record(self) -> Tuple[str, Dict[str, Any]]:
        """Return (dht_key, record_dict) for our local peer.

        The record is canonical JSON (dict) and will be signed by available
        keys. The DHT key is 'pqvpn:peer:<peerid_hex>'.
        """
        # peer id hex
        pid_hex = (self.node.my_id.hex() if getattr(self.node, "my_id", None) else "")
        key = f"pqvpn:peer:{pid_hex}"

        # address: prefer first bootstrap interface or the transport sockname
        addr = ""
        try:
            if getattr(self.node, "transport", None) and getattr(self.node.transport, "_sock", None):
                try:
                    sockname = self.node.transport._sock.getsockname()
                    if sockname:
                        host, port = sockname[0], sockname[1]
                        addr = f"{host}:{port}"
                except Exception:
                    addr = ""
        except Exception:
            addr = ""

        rec = {
            "peerid": pid_hex,
            "nickname": getattr(self.node, "nickname", "") or "",
            "addr": addr,
            "ed25519_pk": (getattr(self.node, "ed25519_pk", b"") or b"").hex(),
            "brainpoolP512r1_pk": (getattr(self.node, "brainpoolP512r1_pk_bytes", b"") or b"").hex() if hasattr(self.node, "brainpoolP512r1_pk_bytes") else (getattr(self.node, "brainpoolP512r1_pk", b"") and getattr(self.node, "brainpoolP512r1_pk").public_bytes(encoding=self.node.brainpoolP512r1_pk.encoding, format=self.node.brainpoolP512r1_pk.format).hex() if getattr(self.node, "brainpoolP512r1_pk", None) else ""),
            "kyber_pk": (getattr(self.node, "kyber_pk", b"") or b"").hex(),
            "mldsa_pk": (getattr(self.node, "mldsa_pk", b"") or b"").hex(),
            "ts": int(time.time()),
            "ttl": int(self.ttl),
            "seq": int(self.config.get("seq", 0)),
            "relay": bool(self.config.get("relay", False)),
        }

        return key, rec

    async def publish_peer_record(self) -> bool:
        """Build, sign and publish our peer record into the DHT.

        Returns True on success.
        """
        if not self.enabled or self._server is None:
            logger.debug("Discovery.publish_peer_record skipped: disabled or no server")
            return False

        key, rec = self._build_record()

        # By default we must not include a direct address in the published record
        if not self.publish_addr:
            # Ensure addr is not present or is empty
            rec['addr'] = ''

        # canonical bytes for signing
        canonical_sign_bytes = None
        pq_sig_sign = None
        try:
            from main import canonical_sign_bytes as _csb, pq_sig_sign as _pqs

            canonical_sign_bytes = _csb
            pq_sig_sign = _pqs
        except Exception:
            logger.debug("Discovery: signing helpers unavailable")
            return False

        try:
            payload_bytes = canonical_sign_bytes(rec)
        except Exception:
            payload_bytes = json.dumps(rec, separators=(",", ":"), sort_keys=True).encode()

        # produce signatures if keys available
        try:
            if getattr(self.node, "mldsa_sk", None):
                try:
                    msig = pq_sig_sign(self.node.mldsa_sk, payload_bytes)
                    rec["mldsa_sig"] = msig.hex()
                except Exception as e:
                    logger.debug(f"Discovery: ML-DSA signing failed: {e}")
                    rec["mldsa_sig"] = ""
            else:
                rec["mldsa_sig"] = ""
        except Exception:
            rec["mldsa_sig"] = ""

        try:
            if getattr(self.node, "ed25519_sk", None):
                try:
                    edsig = self.node.ed25519_sk.sign(payload_bytes)
                    rec["ed25519_sig"] = edsig.hex()
                except Exception as e:
                    logger.debug(f"Discovery: Ed25519 signing failed: {e}")
                    rec["ed25519_sig"] = ""
            else:
                rec["ed25519_sig"] = ""
        except Exception:
            rec["ed25519_sig"] = ""

        # store JSON string as DHT value
        try:
            val = json.dumps(rec, separators=(',', ':'), sort_keys=True)
            # Use DHTClient.set which rate-limits and serializes. Ensure record includes ttl and ts
            if 'ts' not in rec or not rec['ts']:
                rec['ts'] = int(time.time())
            if 'ttl' not in rec or not rec['ttl']:
                rec['ttl'] = int(self.ttl)
            await self._server.set(key, rec)
            # update cache
            self._cache[key] = rec
            # also update mDNS TXT if enabled
            try:
                if self.mdns_enabled and self._zeroconf and ServiceInfo is not None:
                    self._mdns_publish()
            except Exception:
                pass
            logger.info(f"Discovery: published peer record to DHT key={key}")
            return True
        except Exception as e:
            logger.debug(f"Discovery: DHT set failed: {e}")
            return False

    async def publish_and_verify_self(self) -> bool:
        """Publish our peer record and attempt to read it back via the DHT lookup.

        Useful for quick end-to-end verification (demo mode).
        """
        try:
            ok = await self.publish_peer_record()
            if not ok:
                logger.debug("Discovery: publish failed during demo")
                return False
            # allow short propagation window
            await asyncio.sleep(max(0.1, self.quorum_interval))
            pid_hex = (self.node.my_id.hex() if getattr(self.node, "my_id", None) else "")
            if not pid_hex:
                logger.debug("Discovery: no my_id available for demo lookup")
                return False
            rec = await self.lookup_peer_by_id(pid_hex)
            if rec is None:
                logger.debug("Discovery: demo lookup failed to retrieve our record")
                return False
            logger.info(f"Discovery demo: successfully published and retrieved our record peerid={pid_hex[:8]}")
            return True
        except Exception as e:
            logger.debug(f"Discovery.demo failed: {e}")
            return False

    async def lookup_peer_by_id(self, peerid_hex: str) -> Optional[Dict[str, Any]]:
        """Lookup peer record by peer id hex in the DHT and verify signatures.

        Returns normalized dict on success or None.
        """
        if not self.enabled or self._server is None:
            logger.debug("Discovery.lookup_peer_by_id skipped: disabled or no server")
            return None

        key = f"pqvpn:peer:{peerid_hex}"
        try:
            # Quorum reads: poll the DHT several times and aggregate identical records
            candidates: Dict[str, int] = {}
            records: Dict[str, Dict[str, Any]] = {}
            for attempt in range(max(1, self.quorum_attempts)):
                try:
                    val = await self._server.get(key)
                except Exception as e:
                    logger.debug(f"Discovery.lookup: DHT get attempt failed: {e}")
                    val = None

                if not val:
                    await asyncio.sleep(self.quorum_interval)
                    continue

                # val may be a JSON string
                if isinstance(val, str):
                    try:
                        rec = json.loads(val)
                    except Exception:
                        logger.debug("Discovery.lookup: invalid JSON in DHT value")
                        rec = None
                elif isinstance(val, dict):
                    rec = val
                else:
                    rec = None

                if not rec:
                    await asyncio.sleep(self.quorum_interval)
                    continue

                # compute a stable fingerprint of the important fields
                try:
                    fingerprint_src = (
                        (rec.get('mldsa_pk', ''), rec.get('kyber_pk', ''), rec.get('ed25519_pk', ''), str(rec.get('seq', 0)))
                    )
                    fp = json.dumps(fingerprint_src, separators=(",", ":"), sort_keys=True)
                except Exception:
                    fp = json.dumps(rec, separators=(",", ":"), sort_keys=True)

                candidates[fp] = candidates.get(fp, 0) + 1
                records[fp] = rec
                await asyncio.sleep(self.quorum_interval)

            # pick the fingerprint with most votes
            if not candidates:
                return None
            best_fp = max(candidates.items(), key=lambda kv: kv[1])[0]
            rec = records.get(best_fp)
            # require majority
            needed = (sum(candidates.values()) // 2) + 1
            if candidates.get(best_fp, 0) < needed:
                logger.debug(f"Discovery.lookup: quorum not reached for {peerid_hex} (best={candidates.get(best_fp,0)} needed={needed})")
                return None

            # Verify ML-DSA signature on the selected record (strict hybrid enforcement)
            try:
                # import runtime helpers
                from main import pq_sig_verify as _pq_sig_verify
                from main import canonical_sign_bytes as _canonical_sign_bytes
            except Exception:
                _pq_sig_verify = None
                _canonical_sign_bytes = None

            if _pq_sig_verify is None or _canonical_sign_bytes is None:
                logger.debug("Discovery.lookup: signing helpers unavailable at runtime")
                return None

            try:
                # ensure defined as strings to satisfy static analysis
                mld_pk_hex = rec.get("mldsa_pk", "")
                mld_sig_hex = rec.get("mldsa_sig", "")
                if not mld_pk_hex or not mld_sig_hex:
                    logger.debug(f"Discovery.lookup: missing ML-DSA signature for {peerid_hex}")
                    return None
                payload_bytes = _canonical_sign_bytes(rec)
            except Exception:
                try:
                    payload_bytes = json.dumps(rec, separators=(",", ":"), sort_keys=True).encode()
                except Exception:
                    payload_bytes = b""

            try:
                mld_pk = bytes.fromhex(mld_pk_hex)
                if not _pq_sig_verify(mld_pk, payload_bytes, mld_sig_hex):
                    logger.debug(f"Discovery.lookup: ML-DSA verification failed for {peerid_hex} during quorum validation")
                    return None
            except Exception as e:
                logger.debug(f"Discovery.lookup: ML-DSA verification exception for {peerid_hex}: {e}")
                return None

            # Anti-poison checks: TTL and monotonic sequence numbers
            try:
                now = int(time.time())
                ttl = int(rec.get('ttl', self.ttl))
                ts = int(rec.get('ts', 0))
                if ts and ttl and (now > ts + ttl):
                    logger.debug(f"Discovery.lookup: record for {peerid_hex} expired (ts={ts}, ttl={ttl})")
                    return None
                # monotonic seq check if we have a cached record
                key_cache = f"pqvpn:peer:{peerid_hex}"
                cached = self._cache.get(key_cache)
                if cached and isinstance(cached, dict):
                    try:
                        old_seq = int(cached.get('seq', 0))
                        new_seq = int(rec.get('seq', 0))
                        if new_seq < old_seq:
                            logger.debug(f"Discovery.lookup: record seq decreased for {peerid_hex} ({old_seq} -> {new_seq}) - possible poison")
                            return None
                    except Exception:
                        # if seq values not parseable, err on safe side and reject
                        logger.debug(f"Discovery.lookup: invalid seq values for {peerid_hex}")
                        return None
            except Exception:
                pass

            # Mask addr when present unless config explicitly allows publishing IPs
            if not self.publish_addr and rec.get('addr'):
                # remove addr to avoid leaking IPs in callers
                rec = dict(rec)
                rec.pop('addr', None)

            # cache the validated record
            try:
                self._cache[key] = rec
            except Exception:
                pass

            return rec
        except Exception as e:
            logger.debug(f"Discovery.lookup_peer_by_id exception: {e}")
            return None

    def encrypt_contact_for(self, recipient_brainpool_pub_bytes: bytes) -> str:
        """Produce an encrypted contact blob (base64) that contains this node's listen address.

        The blob can be sent to a specific recipient (out-of-band) and decrypted
        by them using ECDH with their BrainpoolP512R1 private key. This allows
        sharing IP:port without publishing it openly in the DHT.
        """
        try:
            # recipient public key point
            peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP512R1(), recipient_brainpool_pub_bytes)
            # ephemeral key
            eph_sk = ec.generate_private_key(ec.BrainpoolP512R1())
            eph_pub = eph_sk.public_key()
            shared = eph_sk.exchange(ec.ECDH(), peer_pub)
            # derive symmetric key via HKDF-SHA256
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pqvpn-contact")
            key = hkdf.derive(shared)
            aes = AESGCM(key)
            # contact string: prefer configured reachable address if publish_addr True, otherwise try node.transport sockname
            contact = ''
            try:
                if self.publish_addr and self._build_record()[1].get('addr'):
                    contact = self._build_record()[1].get('addr')
                else:
                    # derive from node transport sockname if available
                    t = getattr(self.node, 'transport', None)
                    if t and getattr(t, '_sock', None):
                        sn = t._sock.getsockname()
                        if sn:
                            contact = f"{sn[0]}:{sn[1]}"
            except Exception:
                contact = ''

            if not contact:
                raise RuntimeError('No local contact address available to encrypt')

            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, contact.encode(), None)
            eph_bytes = eph_pub.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
            blob = base64.b64encode(eph_bytes + nonce + ct).decode()
            return blob
        except Exception as e:
            logger.debug(f"encrypt_contact_for failed: {e}")
            raise

    def _mdns_publish(self) -> None:
        """Publish a mDNS service TXT record containing PQ public keys (base64).

        Does NOT include raw 'addr' unless publish_addr is True and token validated.
        """
        if Zeroconf is None or ServiceInfo is None:
            return
        try:
            key, rec = self._build_record()
            txt = {
                "peerid": rec.get("peerid", ""),
                "kyber_pk": base64.b64encode(bytes.fromhex(rec.get("kyber_pk", ""))).decode() if rec.get("kyber_pk") else "",
                "mldsa_pk": base64.b64encode(bytes.fromhex(rec.get("mldsa_pk", ""))).decode() if rec.get("mldsa_pk") else "",
                "brainpool_pk": base64.b64encode(bytes.fromhex(rec.get("brainpoolP512r1_pk", ""))).decode() if rec.get("brainpoolP512r1_pk") else "",
                "ed25519_pk": base64.b64encode(bytes.fromhex(rec.get("ed25519_pk", ""))).decode() if rec.get("ed25519_pk") else "",
                "seq": str(rec.get("seq", 0)),
                "ts": str(rec.get("ts", 0)),
                "relay": str(bool(rec.get("relay", False)))
            }
            # include addr only when explicit permission granted
            if self.publish_addr and rec.get('addr'):
                txt['addr'] = rec.get('addr')

            # Service name using peerid
            name = f"pqvpn-{rec.get('peerid')[:8]}._pqvpn._udp.local."
            # Create ServiceInfo (zeroconf expects bytes for properties)
            props = {k: v.encode() for k, v in txt.items()}
            info = ServiceInfo(
                "_pqvpn._udp.local.",
                name,
                addresses=[b"\x00\x00\x00\x00"],
                port=0,
                properties=props,
            )
            # unregister previous if exists
            if getattr(self, '_mdns_info', None):
                try:
                    self._zeroconf.unregister_service(self._mdns_info)
                except Exception:
                    pass
            self._mdns_info = info
            self._zeroconf.register_service(info)
        except Exception as e:
            logger.debug(f"Discovery: mDNS publish failed: {e}")

    def _derive_cache_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive a key for AES-GCM from the given password and salt using Argon2."""
        if Argon2Type is None or hash_secret_raw is None:
            raise RuntimeError("Argon2 KDF not available")

        # Argon2id: time_cost=2, memory_cost=64MiB, parallelism=1
        hash_len = 32
        argon_type = getattr(Argon2Type, "ARGON2id", None)
        if argon_type is None:
            # best-effort default value if low-level Type not available to static analyzer
            raise RuntimeError("Argon2 KDF type not available")
        secret = hash_secret_raw(
            password,
            salt,
            time_cost=self.cache_argon["time_cost"],
            memory_cost_kib=self.cache_argon["memory_cost_kib"],
            parallelism=self.cache_argon["parallelism"],
            type=argon_type,
        )
        return secret[:hash_len]

# End of discovery.py

