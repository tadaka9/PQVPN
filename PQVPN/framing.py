import struct
import hashlib

VERSION = 1
FT_HELLO = 0x01
FT_HS1 = 0x02
FT_HS2 = 0x03
FT_PATH_PROBE = 0x04
FT_PATH_PONG = 0x05
FT_RELAY = 0x06
FT_DATA = 0x07
FT_REKEY = 0x08
FT_CLOSE = 0x09

OUTER_HDR_FMT = "!BB8sIH"  # version1, type1, next_hash8, circuit4, length2
OUTER_HDR_LEN = struct.calcsize(OUTER_HDR_FMT)


def parse_outer_header(data: bytes):
    if len(data) < OUTER_HDR_LEN:
        raise ValueError("short header")
    ver, ftype, next_hash, circuit, length = struct.unpack(
        OUTER_HDR_FMT, data[:OUTER_HDR_LEN]
    )
    payload = data[OUTER_HDR_LEN : OUTER_HDR_LEN + length]
    return ver, ftype, next_hash, circuit, length, payload


def build_outer_header(
    ftype: int, next_hash: bytes, circuit: int, payload: bytes
) -> bytes:
    return (
        struct.pack(OUTER_HDR_FMT, VERSION, ftype, next_hash[:8], circuit, len(payload))
        + payload
    )


def peer_hash8(peer_id: bytes) -> bytes:
    return hashlib.sha256(peer_id).digest()[:8]
