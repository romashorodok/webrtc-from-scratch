import asyncio
from typing import Protocol, Any


class MuxProtocol(Protocol):
    def addr_str(self) -> str: ...
    def get_transport(self) -> asyncio.DatagramTransport: ...


class InboundHandlerProtocol(Protocol):
    def on_inbound_pkt(
        self, origin_muxer: MuxProtocol, data: bytes, addr: tuple[str | Any, int]
    ):
        "On recv queue"
        ...
