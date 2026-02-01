import random
import hashlib


class PathManager:
    def __init__(self, local_peer_id: bytes):
        self.local_id = local_peer_id
        self.paths = {}  # peer_id -> {'endpoint': tuple, 'rtt': float}
        self.known_peers = set()

    def add_peer(self, peer_id: bytes, endpoint: tuple):
        self.known_peers.add(peer_id)
        self.paths[peer_id] = {"endpoint": endpoint, "rtt": float("inf")}

    def build_pathlet(self, dst_peer_id: bytes, max_hops: int = 2) -> list:
        """Build source-routed pathlet: [self, relay, dst]"""
        if dst_peer_id not in self.paths:
            return None

        path = [self.local_id, dst_peer_id]  # direct path

        # Add relay for 2-hop if possible
        if max_hops > 1 and len(self.known_peers) > 2:
            relays = [
                p for p in self.known_peers if p != self.local_id and p != dst_peer_id
            ]
            if relays:
                relay = random.choice(relays)
                path = [self.local_id, relay, dst_peer_id]
                print(
                    f"🔗 2-hop path: {self.short_id(self.local_id)} -> {self.short_id(relay)} -> {self.short_id(dst_peer_id)}"
                )

        return path

    def get_next_hop(self, path: list, hop_index: int) -> bytes:
        """Get next hop hash for RELAY frame"""
        if hop_index >= len(path):
            return b"\x00" * 8
        return hashlib.sha256(path[hop_index]).digest()[:8]

    def choose_best_path(self, dst_peer_id: bytes) -> list:
        """Select path with lowest RTT"""
        return self.build_pathlet(dst_peer_id)

    @staticmethod
    def short_id(peer_id: bytes) -> str:
        import base64

        return base64.urlsafe_b64encode(hashlib.sha256(peer_id).digest()[:8]).decode()[
            :8
        ]
