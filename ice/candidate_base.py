import asyncio

from ice.net.types import MuxProtocol

from . import stun as stun

from typing import Any


class CandidateBase:
    def __init__(self) -> None:
        self._pkt_queue: asyncio.Queue[
            tuple[MuxProtocol, tuple[str | Any, int], bytes]
        ] = asyncio.Queue()
        # TODO: use not hardcoded
        self._addr: tuple[str, int] | None = None

    def on_inbound_pkt(
        self, origin_muxer: MuxProtocol, data: bytes, addr: tuple[str | Any, int]
    ):
        self._addr = addr
        print("recv from packet from candidate", addr)

        if stun.is_stun(data):
            stun.Message.parse(data)
            print("Is stun message")
        else:
            self._pkt_queue.put_nowait((origin_muxer, addr, data))

    async def accept(self, ufrag: bytes):
        while True:
            origin_muxer, origin_addr, pkt = await self._pkt_queue.get()

            resp = stun.Message(
                stun.MessageType(stun.Method.Binding, stun.MessageClass.SuccessResponse)
            )
            resp.add_attribute(stun.Username("username", "password"))

            transport = origin_muxer.get_transport()
            transport.sendto(
                resp.encode(ufrag),
                origin_addr,
            )

            print(origin_muxer, pkt)
