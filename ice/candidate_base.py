import asyncio

from typing import Any


class CandidateBase:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        # TODO: use not hardcoded
        self._addr: tuple[str, int] | None = None

    def on_inbound_pkt(self, data: bytes, addr: tuple[str | Any, int]):
        self._addr = addr
        print("recv from packet from candidate", addr)
        self._queue.put_nowait(data)
