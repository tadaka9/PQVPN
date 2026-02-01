# pqvpn/cli.py - MINIMAL VERSION
import asyncio
from .config import load_config
from .transports.udp import UDPTransport
import pqvpn.adapters.socks5 as socks5


async def run(config_path):
    cfg = load_config(config_path)

    async def udp_cb(data, addr):
        print(f"UDP {len(data)} bytes from {addr}")

    udp = UDPTransport(cfg.listen_host, cfg.listen_port, udp_cb)
    await udp.start()
    print(f"Listening UDP {cfg.listen_host}:{cfg.listen_port}")

    # SOCKS5 server
    server = await asyncio.start_server(
        lambda r, w: socks5.handle_socks5(r, w), "127.0.0.1", 1080
    )
    print("✅ SOCKS5 ready: 127.0.0.1:1080")

    await asyncio.Event().wait()


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    asyncio.run(run(args.config))


if __name__ == "__main__":
    main()
