from typing import Protocol, Any


class InboundHandlerProtocol(Protocol):
    def on_recv(self, data: bytes, addr: tuple[str | Any, int]):
        "On recv queue"
        ...
