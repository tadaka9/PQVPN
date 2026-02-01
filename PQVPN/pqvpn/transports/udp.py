import asyncio
import socket
import logging
import errno

logger = logging.getLogger("pqvpn.transports.udp")


class UDPTransport:
    def __init__(self, host: str, port: int, inbound_cb):
        self.host = host
        self.port = port
        self.inbound_cb = inbound_cb
        self.transport = None
        self._sock = None

    class Protocol(asyncio.DatagramProtocol):
        def __init__(self, cb):
            self.cb = cb

        def datagram_received(self, data, addr):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.cb(data, addr))
            except Exception:
                try:
                    self.cb(data, addr)
                except Exception:
                    pass

        def connection_made(self, transport):
            try:
                sockname = transport.get_extra_info("sockname")
            except Exception:
                sockname = None
            logger.info(f"🚀 UDP listening on {sockname}")

        def error_received(self, exc):
            # Log socket-level errors at debug; we now attempt fallbacks in sendto()
            try:
                logger.debug(f"UDP socket error received: {exc}")
            except Exception:
                pass

    async def start(self):
        loop = asyncio.get_running_loop()

        # Select appropriate family based on host
        family = socket.AF_INET
        try:
            # If host looks like IPv6 literal or '::' use AF_INET6
            if isinstance(self.host, str) and (":" in self.host or self.host == "::"):
                family = socket.AF_INET6
        except Exception:
            family = socket.AF_INET

        # Create a real UDP socket so we can set reuse options reliably
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setblocking(False)

            # Attempt to allow dual-stack on IPv6 sockets when host is IPv6-any
            if family == socket.AF_INET6:
                try:
                    # Clear IPV6_V6ONLY to allow IPv4-mapped addresses when supported
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except Exception:
                    # Some platforms don't allow changing this; continue
                    logger.debug("Could not clear IPV6_V6ONLY (platform limitation)")

            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass

            # Bind to the configured address
            bind_addr = (self.host, self.port)
            try:
                sock.bind(bind_addr)
            except OSError as e:
                logger.debug(f"Bind attempt to {bind_addr} failed: {e}; attempting fallback bind")
                # Fallback: try binding to INADDR_ANY with same family
                try:
                    if family == socket.AF_INET6:
                        sock.bind(("::", self.port))
                    else:
                        sock.bind(("0.0.0.0", self.port))
                except Exception:
                    raise

            self._sock = sock

            # Pass the pre-bound socket to asyncio to create the transport
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: self.Protocol(self.inbound_cb), sock=sock
            )
        except Exception as e:
            logger.debug(f"Prebound socket setup failed ({e}), falling back to create_datagram_endpoint")
            # Cleanup partially created socket
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
            # Fallback to loop.create_datagram_endpoint without pre-bound socket
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: self.Protocol(self.inbound_cb), local_addr=(self.host, self.port)
            )

        return self.transport

    def sendto(self, data: bytes, addr):
        # Try transport first; if it fails with EAFNOSUPPORT, fall back to a temporary socket
        if self.transport:
            try:
                self.transport.sendto(data, addr)
                return
            except OSError as e:
                # Address-family related error -> fallback
                if e.errno == errno.EAFNOSUPPORT or "Address family" in str(e):
                    logger.debug(f"transport.sendto EAFNOSUPPORT: {e}; attempting fallback socket send")
                else:
                    logger.debug(f"transport.sendto OSError: {e}")
            except Exception as e:
                logger.debug(f"transport.sendto failed: {e}")

        # Fallback: create a temporary socket with the appropriate family to send the packet
        try:
            host = addr[0]
            is_ipv4 = isinstance(host, str) and ("." in host)
            family = socket.AF_INET if is_ipv4 else socket.AF_INET6
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass
                # Bind to ephemeral port; binding to the node port may fail if in use
                try:
                    if is_ipv4:
                        s.bind(("0.0.0.0", 0))
                    else:
                        s.bind(("::", 0))
                except Exception:
                    pass
                s.sendto(data, addr)
                logger.debug(f"sendto fallback socket sent {len(data)} bytes to {addr}")
                return
        except Exception as e:
            logger.debug(f"Temporary socket fallback send failed: {e}")

    def close(self):
        try:
            if self.transport:
                self.transport.close()
        except Exception:
            pass
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
