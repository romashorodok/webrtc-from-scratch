import asyncio
from typing import override, Any

from utils.types import impl_protocol

from .interface import Interface
from .types import (
    CandidateProtocol,
    MuxProtocol,
    MuxConnProtocol,
    NetworkType,
    Address,
    Packet,
)


class Interceptor:
    def __init__(self):
        self._queue = asyncio.Queue[Packet]()

    def put_nowait(self, pkt: Packet):
        self._queue.put_nowait(pkt)

    async def get(self) -> Packet:
        return await self._queue.get()


class InterfaceMuxUDPHandler(asyncio.DatagramProtocol):
    def __init__(self, interface: Interface, port: int) -> None:
        self._interface = interface
        self._port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._interceptors = dict[str, dict[int, Interceptor]]()

    def bind_interceptor(self, address: str, port: int, interceptor: Interceptor):
        interceptors_ports = self._interceptors.get(address, dict[int, Interceptor]())
        interceptors_ports[port] = interceptor

        self._interceptors[address] = interceptors_ports

    def addr_str(self) -> str:
        return str(self._interface.address)

    def port(self) -> int:
        return self._port

    @property
    def transport(self) -> asyncio.DatagramTransport:
        if self._transport is None:
            raise ValueError("Unable get interface transport")
        return self._transport

    @override
    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        self._transport = transport
        # If zero port os will assign it by itself
        _, port = transport.get_extra_info("sockname")
        self._port = port

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if self._transport is None:
            return

        address, port = addr
        address_str = str(address)

        interceptors_ports = self._interceptors.get(address_str)
        if interceptors_ports is None:
            print(f"Unbinded datagram recv not found {address_str} address")
            return

        interceptor = interceptors_ports.get(port)
        if interceptor is None:
            print(f"Unbinded datagram recv not found {address_str} port")
            return

        interceptor.put_nowait(Packet(Address(address, port), memoryview(data)))


@impl_protocol(MuxConnProtocol)
class UDPMuxConn:
    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        address: tuple[str, int],
        interceptor: Interceptor,
    ) -> None:
        self._transport = transport
        self._address = address
        self._interceptor = interceptor

    def sendto(self, data: memoryview | bytearray | bytes):
        return self._transport.sendto(data, self._address)

    async def recvfrom(self) -> Packet:
        return await self._interceptor.get()


@impl_protocol(MuxProtocol)
class UDPMux:
    def __init__(
        self,
        local_ufrag: str,
        local_candidate: CandidateProtocol,
        interface_handler: InterfaceMuxUDPHandler,
    ) -> None:
        self._local_ufrag = local_ufrag
        self._local_candidate = local_candidate
        self._interface_handler = interface_handler

    # TODO: This so bad must looks like that on recv side
    # This approach hold in event loop while True which never end
    """
        await self._loop.run_in_executor(
                self._executor,
                self._candidate.on_inbound_pkt,
                self._local_ufrag,
                transport,
                pkt,
                addr
            )
    """

    def intercept(self, remote: CandidateProtocol) -> MuxConnProtocol:
        interceptor = Interceptor()
        address = (remote.address, remote.port)

        self._interface_handler.bind_interceptor(
            remote.address,
            remote.port,
            interceptor,
        )

        return UDPMuxConn(self._interface_handler.transport, address, interceptor)


"""
TODO: refactor muxer to work with multi peer connection
"""


class MultiUDPMux:
    def __init__(
        self, interfaces: list[Interface], loop: asyncio.AbstractEventLoop
    ) -> None:
        self._interfaces = interfaces
        self._inbound_handlers = dict[str, InterfaceMuxUDPHandler]()
        self._loop = loop

    async def accept(self, port: int = 0):
        coros: list[
            asyncio.Future[tuple[asyncio.DatagramTransport, InterfaceMuxUDPHandler]]
        ] = []

        for interface in self._interfaces:
            coros.append(
                asyncio.ensure_future(
                    self._loop.create_datagram_endpoint(
                        lambda iface=interface: InterfaceMuxUDPHandler(iface, port),
                        local_addr=(interface.address.value, port),
                    ),
                    loop=self._loop,
                )
            )

        for _, handler in await asyncio.gather(*coros):
            self._inbound_handlers[handler.addr_str()] = handler

    def bind(
        self, ufrag: str, handler: InterfaceMuxUDPHandler, candidate: CandidateProtocol
    ) -> UDPMux:
        transport = handler._transport
        if transport is None:
            raise ValueError("Unable bind unactive inbound handler transport")

        mux = UDPMux(ufrag, candidate, handler)

        candidate.set_port(handler.port())
        candidate.set_address(handler.addr_str())
        candidate.set_network_type(NetworkType.UDP)

        return mux

    def inbound_handlers(self) -> dict[str, InterfaceMuxUDPHandler]:
        if len(self._inbound_handlers) <= 0:
            raise RuntimeError("Inbound handlers not found accept connections first")
        return self._inbound_handlers
