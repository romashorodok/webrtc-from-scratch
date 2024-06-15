from typing import Protocol, Any


class InboundHandlerProtocol(Protocol):
    def on_inbound_pkt(self, data: bytes, addr: tuple[str | Any, int]):
        "On recv queue"
        ...
