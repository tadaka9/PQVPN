import asyncio


async def attempt_holepunch(transport, remote_addr: tuple, count: int = 5):
    """Send UDP probes to punch NAT hole"""
    for i in range(count):
        transport.sendto(b"PQPUNCH" + struct.pack("!I", i), remote_addr)
        await asyncio.sleep(0.1 * (i + 1))
    print(f"🔨 Holepunch to {remote_addr} ({count} probes)")
