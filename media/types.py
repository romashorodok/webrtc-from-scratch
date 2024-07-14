import asyncio
from typing import Protocol


class PayloaderProtocol(Protocol):
    @classmethod
    def packetize(cls, buffer: bytes, picture_id: int) -> list[bytes]: ...


async def ticker(wait_ms: float):
    while True:
        yield
        await asyncio.sleep(wait_ms)
