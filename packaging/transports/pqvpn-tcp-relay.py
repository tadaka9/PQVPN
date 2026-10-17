#!/usr/bin/env python3
"""Bounded TCP transport for opaque, authenticated PQVPN datagrams.

The relay never decrypts or interprets a PQVPN frame. Each TCP record is a
four-byte big-endian length followed by one complete datagram. Server mode
gives every TCP client a connected UDP socket, preserving the node's endpoint
semantics. Client mode exposes a loopback UDP attachment for one local node.
"""

import argparse
import asyncio
import contextlib
import socket
import struct

MAX_FRAME = 65_507
READ_TIMEOUT = 90.0
QUEUE_LIMIT = 64


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), READ_TIMEOUT)
    size = struct.unpack("!I", header)[0]
    if size < 1 or size > MAX_FRAME:
        raise ValueError("invalid PQVPN TCP frame length")
    return await asyncio.wait_for(reader.readexactly(size), READ_TIMEOUT)


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if not 0 < len(payload) <= MAX_FRAME:
        raise ValueError("invalid PQVPN datagram length")
    writer.write(struct.pack("!I", len(payload)) + payload)
    await writer.drain()


class UdpInbox(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue[tuple[bytes, tuple]] = asyncio.Queue(QUEUE_LIMIT)

    def datagram_received(self, data: bytes, address: tuple) -> None:
        if not 0 < len(data) <= MAX_FRAME or self.queue.full():
            return
        self.queue.put_nowait((data, address))


async def serve_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, udp_host: str, udp_port: int
) -> None:
    loop = asyncio.get_running_loop()
    inbox = UdpInbox()
    family = socket.AF_INET6 if ":" in udp_host else socket.AF_INET
    transport, _ = await loop.create_datagram_endpoint(
        lambda: inbox, remote_addr=(udp_host, udp_port), family=family
    )

    async def tcp_to_udp() -> None:
        while True:
            transport.sendto(await read_frame(reader))

    async def udp_to_tcp() -> None:
        while True:
            payload, _ = await inbox.queue.get()
            await write_frame(writer, payload)

    tasks = {asyncio.create_task(tcp_to_udp()), asyncio.create_task(udp_to_tcp())}
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        for task in pending:
            task.cancel()
    except (asyncio.IncompleteReadError, ConnectionError, TimeoutError, ValueError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        transport.close()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def run_server(args: argparse.Namespace) -> None:
    listen_host = None if args.listen_host == "*" else args.listen_host
    server = await asyncio.start_server(
        lambda r, w: serve_connection(r, w, args.udp_host, args.udp_port),
        listen_host,
        args.listen_port,
        limit=MAX_FRAME + 4,
        backlog=128,
        reuse_port=False,
    )
    async with server:
        await server.serve_forever()


async def run_client(args: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()
    inbox = UdpInbox()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: inbox, local_addr=(args.listen_host, args.listen_port)
    )
    local_peer = None
    delay = 1.0
    try:
        while True:
            try:
                reader, writer = await asyncio.open_connection(args.tcp_host, args.tcp_port)
                delay = 1.0

                async def udp_to_tcp() -> None:
                    nonlocal local_peer
                    while True:
                        payload, local_peer = await inbox.queue.get()
                        await write_frame(writer, payload)

                async def tcp_to_udp() -> None:
                    while True:
                        payload = await read_frame(reader)
                        if local_peer is not None:
                            transport.sendto(payload, local_peer)

                tasks = {asyncio.create_task(udp_to_tcp()), asyncio.create_task(tcp_to_udp())}
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                for task in done:
                    task.result()
            except (OSError, asyncio.IncompleteReadError, ConnectionError, TimeoutError, ValueError):
                await asyncio.sleep(delay)
                delay = min(delay * 2.0, 30.0)
            finally:
                if "writer" in locals():
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
    finally:
        transport.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="PQVPN authenticated datagrams over bounded TCP")
    sub = result.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--listen-host", default="*", help="address or * for IPv4+IPv6")
    server.add_argument("--listen-port", type=int, default=9090)
    server.add_argument("--udp-host", default="::1")
    server.add_argument("--udp-port", type=int, default=9090)
    client = sub.add_parser("client")
    client.add_argument("--listen-host", default="127.0.0.1")
    client.add_argument("--listen-port", type=int, default=9091)
    client.add_argument("--tcp-host", required=True)
    client.add_argument("--tcp-port", type=int, default=9090)
    return result


def main() -> None:
    args = parser().parse_args()
    for value in vars(args).values():
        if isinstance(value, int) and not 0 < value < 65_536:
            raise SystemExit("ports must be between 1 and 65535")
    asyncio.run(run_server(args) if args.mode == "server" else run_client(args))


if __name__ == "__main__":
    main()
