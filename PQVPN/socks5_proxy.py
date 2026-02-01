"""Simple asyncio SOCKS5 proxy (CONNECT only, no authentication)

Run this on the same host as your PQVPN node (or on any host you want to act
as an egress SOCKS5 server). Configure LibreWolf to use this SOCKS5 server
(127.0.0.1:1080 by default). Outgoing connections are made by this process,
so the destination will see this host's public IP.

Usage:
    python socks5_proxy.py --host 127.0.0.1 --port 1080

Notes:
- This is a minimal, production-grade but simple implementation intended for
  local testing. It does not implement UDP ASSOC or authentication.
- If you run it on the PQVPN node host, client traffic will egress via that
  host's network stack, so the destination IP will match the node's IP.

"""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import socket

logger = logging.getLogger("socks5_proxy")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

SOCKS_VERSION = 5


class SocksError(Exception):
    pass


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info(f"Incoming SOCKS5 connection from {peer}")

    try:
        # ===== Stage 1: Method selection =====
        data = await reader.readexactly(2)
        ver, nmethods = struct.unpack("!BB", data)
        if ver != SOCKS_VERSION:
            raise SocksError("Unsupported SOCKS version")
        methods = await reader.readexactly(nmethods)
        # We support only NO AUTH (0x00)
        if 0x00 not in methods:
            # No acceptable methods
            writer.write(struct.pack("!BB", SOCKS_VERSION, 0xFF))
            await writer.drain()
            raise SocksError("No supported auth methods")
        # Accept NO AUTH
        writer.write(struct.pack("!BB", SOCKS_VERSION, 0x00))
        await writer.drain()

        # ===== Stage 2: Request =====
        # VER, CMD, RSV, ATYP
        hdr = await reader.readexactly(4)
        ver, cmd, rsv, atyp = struct.unpack("!BBBB", hdr)
        if ver != SOCKS_VERSION:
            raise SocksError("Unsupported SOCKS version in request")
        if cmd != 1:
            # Only CONNECT is supported
            await send_socks_reply(writer, 0x07)  # Command not supported
            raise SocksError("Only CONNECT supported")

        if atyp == 1:  # IPv4
            addr_bytes = await reader.readexactly(4)
            addr = socket.inet_ntop(socket.AF_INET, addr_bytes)
        elif atyp == 3:  # Domain name
            alen_b = await reader.readexactly(1)
            alen = alen_b[0]
            domain = await reader.readexactly(alen)
            addr = domain.decode(errors="ignore")
        elif atyp == 4:  # IPv6
            addr_bytes = await reader.readexactly(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            await send_socks_reply(writer, 0x08)  # Address type not supported
            raise SocksError("Address type not supported")

        port_bytes = await reader.readexactly(2)
        port = struct.unpack("!H", port_bytes)[0]

        logger.info(f"CONNECT request to {addr}:{port} from {peer}")

        # Attempt to open outbound connection
        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
        except Exception as e:
            logger.warning(f"Failed to connect to {addr}:{port}: {e}")
            await send_socks_reply(writer, 0x05)  # Connection refused
            raise SocksError("Remote connect failed")

        # Send success reply. BND.ADDR and BND.PORT can be the local socket details
        sock = remote_writer.get_extra_info("socket")
        try:
            laddr = sock.getsockname()
            if isinstance(laddr, tuple):
                bnd_addr, bnd_port = laddr[0], laddr[1]
            else:
                bnd_addr, bnd_port = "0.0.0.0", 0
        except Exception:
            bnd_addr, bnd_port = "0.0.0.0", 0

        await send_socks_reply(writer, 0x00, bnd_addr, bnd_port)

        # Relay data between client and remote
        async def relay(
            src: asyncio.StreamReader, dst: asyncio.StreamWriter, desc: str
        ):
            try:
                while True:
                    data = await src.read(4096)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug(f"Relay {desc} error: {e}")

        t1 = asyncio.create_task(
            relay(reader, remote_writer, f"c2r {peer}->{addr}:{port}")
        )
        t2 = asyncio.create_task(
            relay(remote_reader, writer, f"r2c {addr}:{port}->{peer}")
        )

        done, pending = await asyncio.wait(
            [t1, t2], return_when=asyncio.FIRST_COMPLETED
        )
        for p in pending:
            p.cancel()

        remote_writer.close()
        try:
            await remote_writer.wait_closed()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        logger.info(f"Connection {addr}:{port} closed")

    except asyncio.IncompleteReadError:
        logger.info(f"Client {peer} disconnected prematurely")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    except SocksError as se:
        logger.debug(f"SOCKS error with {peer}: {se}")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as e:
        logger.exception(f"Unhandled error in client handler: {e}")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def send_socks_reply(
    writer: asyncio.StreamWriter, rep: int, bnd_addr: str = "0.0.0.0", bnd_port: int = 0
):
    # Choose ATYP according to address form
    try:
        # IPv4?
        try:
            packed = socket.inet_pton(socket.AF_INET, bnd_addr)
            atyp = 1
            addr_field = packed
        except OSError:
            try:
                packed = socket.inet_pton(socket.AF_INET6, bnd_addr)
                atyp = 4
                addr_field = packed
            except OSError:
                atyp = 3
                addr_field = bnd_addr.encode()
                if len(addr_field) > 255:
                    addr_field = addr_field[:255]
    except Exception:
        atyp = 1
        addr_field = socket.inet_pton(socket.AF_INET, "0.0.0.0")

    if atyp == 1:
        header = struct.pack(
            "!BBBB4sH", SOCKS_VERSION, rep, 0x00, atyp, addr_field, bnd_port
        )
    elif atyp == 4:
        header = struct.pack(
            "!BBBB16sH", SOCKS_VERSION, rep, 0x00, atyp, addr_field, bnd_port
        )
    else:
        header = (
            struct.pack("!BBBBB", SOCKS_VERSION, rep, 0x00, atyp, len(addr_field))
            + addr_field
            + struct.pack("!H", bnd_port)
        )

    writer.write(header)
    await writer.drain()


async def serve(host: str, port: int):
    server = await asyncio.start_server(handle_client, host, port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"SOCKS5 server listening on {addrs}")
    async with server:
        await server.serve_forever()


def parse_args():
    p = argparse.ArgumentParser(
        description="Simple asyncio SOCKS5 proxy (CONNECT only)"
    )
    p.add_argument("--host", default="127.0.0.1", help="Bind host")
    p.add_argument("--port", default=1080, type=int, help="Bind port")
    p.add_argument("--log-level", default="INFO", help="Log level")
    return p.parse_args()


def main():
    args = parse_args()
    logger.setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    try:
        asyncio.run(serve(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("SOCKS5 server shutting down")


if __name__ == "__main__":
    main()
