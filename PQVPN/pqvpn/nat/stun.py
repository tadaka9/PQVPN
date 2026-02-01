import socket


def stun_query(
    host: str = "stun.l.google.com", port: int = 19302, timeout: float = 1.0
):
    """Minimal STUN client for public IP discovery"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # Basic binding request
        msg = b"\x00\x01\x00\x00" + b"\x21" * 20  # Simplified
        s.sendto(msg, (host, port))
        data, addr = s.recvfrom(1024)
        if data[1] == 0x01:  # Binding response
            print(f"🌐 STUN public addr: {addr}")
            return addr
    except Exception as e:
        print(f"STUN failed: {e}")
    finally:
        s.close()
    return None
