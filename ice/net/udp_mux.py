import asyncio
from typing import override, Any

from .types import InboundHandlerProtocol


class UDPMux(asyncio.DatagramProtocol):
    def __init__(
        self,
        inbound_handler: InboundHandlerProtocol,
    ) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._inbound_handler = inbound_handler

    @override
    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        self._transport = transport

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._inbound_handler.on_inbound_pkt(data, addr)

    @override
    def connection_lost(self, exc: Exception | None) -> None:
        print(f"connection lost {exc}")

    def error_received(self, exc):
        print(f"Error received: {exc}")

