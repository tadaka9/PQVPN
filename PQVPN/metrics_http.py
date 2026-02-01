"""
Lightweight asyncio HTTP server exposing Prometheus metrics endpoint for PQVPN.
Uses only the standard library to avoid adding heavy dependencies. It's intentionally
minimal: accepts GET /metrics and returns NetworkAnalytics.export_prometheus() output.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


class MetricsHTTPServer:
    def __init__(self, analytics, host="127.0.0.1", port=9100):
        self.analytics = analytics
        self.host = host
        self.port = port
        self._server = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            data = await reader.read(1024)
            # minimal HTTP parse
            req = data.decode(errors="ignore").splitlines()[0] if data else ""
            if req.startswith("GET ") and " /metrics" in req:
                body = self.analytics.export_prometheus() if self.analytics else ""
                resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}".format(
                    len(body.encode()), body
                )
                writer.write(resp.encode())
                await writer.drain()
            else:
                # simple 404
                body = "Not found"
                resp = f"HTTP/1.1 404 Not Found\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                writer.write(resp.encode())
                await writer.drain()
        except Exception as e:
            logger.debug(f"metrics server client handler error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info(f"Metrics HTTP server started on {self.host}:{self.port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Metrics HTTP server stopped")

    def serve_task(self):
        return asyncio.create_task(self.start())


__all__ = ["MetricsHTTPServer"]
