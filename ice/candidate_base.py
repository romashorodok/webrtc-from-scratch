import asyncio

from . import stun as stun

from typing import Any


class CandidateBase:
    def __init__(self) -> None:
        self._pkt_queue: asyncio.Queue[bytes] = asyncio.Queue()
        # TODO: use not hardcoded
        self._addr: tuple[str, int] | None = None

    def on_inbound_pkt(self, data: bytes, addr: tuple[str | Any, int]):
        self._addr = addr
        print("recv from packet from candidate", addr)

        if stun.is_stun(data):
            stun.Message(data)
            print("Is stun message")
        else:
            self._pkt_queue.put_nowait(data)
