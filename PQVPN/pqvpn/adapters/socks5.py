import asyncio


async def handle_socks5(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, auth_db=None
):
    try:
        # Greeting: VER, NMETHODS
        buf = await reader.readexactly(2)
        if buf[0] != 5:
            writer.close()
            return

        nmethods = buf[1]
        await reader.readexactly(nmethods)  # ignore methods, accept anything
        # Reply: no-auth
        writer.write(b"\x05\x00")
        await writer.drain()

        # Request: VER CMD RSV ATYP
        hdr = await reader.readexactly(4)
        ver, cmd, _rsv, atyp = hdr
        if ver != 5 or cmd != 1:  # CONNECT only
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        # Address
        if atyp == 1:  # IPv4
            addr_bytes = await reader.readexactly(4)
            host = ".".join(map(str, addr_bytes))
        elif atyp == 3:  # DOMAIN
            alen = (await reader.readexactly(1))[0]
            addr_bytes = await reader.readexactly(alen)
            host = addr_bytes.decode(errors="ignore")
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        port_bytes = await reader.readexactly(2)
        port = int.from_bytes(port_bytes, "big")

        print(f"SOCKS5 CONNECT {host}:{port}")

        try:
            r_remote, w_remote = await asyncio.open_connection(host, port)
        except Exception as e:
            print(f"Connect failed: {e}")
            writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        # Success reply
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(4096)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except asyncio.CancelledError:
                pass

        await asyncio.gather(
            pipe(reader, w_remote),
            pipe(r_remote, writer),
        )
    except asyncio.IncompleteReadError:
        pass
    finally:
        writer.close()
