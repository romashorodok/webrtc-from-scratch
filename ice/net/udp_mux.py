import asyncio
from typing import override, Any

from .interface import Interface
from .types import InboundHandlerProtocol, MuxProtocol


class UDPMux(asyncio.DatagramProtocol, MuxProtocol):
    def __init__(
        self, interface: Interface, inbound_handler: InboundHandlerProtocol
    ) -> None:
        self._interface = interface
        self._transport: asyncio.DatagramTransport | None = None
        self._inbound_handler = inbound_handler

    def get_transport(self) -> asyncio.DatagramTransport:
        if self._transport is None:
            raise ValueError("transport is None")
        return self._transport

    def addr_str(self) -> str:
        return str(self._interface.address)

    @override
    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        self._transport = transport

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._inbound_handler.on_inbound_pkt(self, data, addr)


class MultiUDPMux:
    def __init__(
        self, interfaces: list[Interface], loop: asyncio.AbstractEventLoop
    ) -> None:
        self._interfaces = interfaces
        self._muxers = dict[str, dict[str, MuxProtocol]]()
        self._loop = loop

    def get_mux_conn(self, ufrag: str, addr: str) -> MuxProtocol:
        muxers = self._muxers.get(ufrag)
        if muxers is None:
            raise ValueError("Not found muxers by ufrag")
        muxer = muxers.get(addr)
        if muxer is None:
            raise ValueError("Not found muxer by addr")
        return muxer

    async def bind(
        self,
        ufrag: str,
        candidate_inbound_handler: InboundHandlerProtocol,
        port: int = 0,
    ) -> dict[str, MuxProtocol]:
        coros: list[asyncio.Future[tuple[asyncio.DatagramTransport, UDPMux]]] = []

        for interface in self._interfaces:
            coros.append(
                asyncio.wrap_future(
                    asyncio.run_coroutine_threadsafe(
                        self._loop.create_datagram_endpoint(
                            lambda iface=interface: UDPMux(
                                iface, candidate_inbound_handler
                            ),
                            local_addr=(interface.address.value, port),
                        ),
                        self._loop,
                    ),
                    loop=self._loop,
                )
            )

        muxers = dict[str, MuxProtocol]()
        for _, mux in await asyncio.gather(*coros):
            muxers[mux.addr_str()] = mux

        self._muxers[ufrag] = muxers
        return muxers
