import asyncio
import socket
from typing import override, Any

from webrtc.utils.types import impl_protocol
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.performance import ObservedComponent, event_loop
from webrtc.tracing import perf_mark

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
    def __init__(self, maxsize: int = 0, *, drop_oldest: bool = False):
        self._queue = asyncio.Queue[Packet](maxsize=maxsize)
        self._drop_oldest = drop_oldest

    def put_nowait(self, pkt: Packet):
        if self._drop_oldest and self._queue.full():
            # Datagram producers cannot apply backpressure. Keep the freshest
            # traffic (especially RTP/RTCP) instead of retaining packets for
            # the lifetime of a slow or stalled consumer.
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        self._queue.put_nowait(pkt)

    async def put(self, pkt: Packet):
        return await self._queue.put(pkt)

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
        logger = get_logger()
        config = get_config()

        self._transport = transport
        # If zero port os will assign it by itself
        _, port = transport.get_extra_info("sockname")
        self._port = port

        # Increase UDP socket receive buffer to prevent packet loss
        # Default is ~768KB, we increase to 4MB for high-bandwidth RTP
        sock = transport.get_extra_info("socket")
        if sock and config.log_udp_socket_buffers:
            try:
                # Get current buffer size
                current_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                current_sndbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                logger.debug(Component.UDP, "Socket buffer sizes before",
                           RCV=current_rcvbuf, SND=current_sndbuf)

                # Set receive buffer to 4MB (4 * 1024 * 1024)
                # Note: macOS kern.ipc.maxsockbuf limits total buffer space
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4194304)
                # Set send buffer to 1MB (less critical than receive)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)

                # Verify new buffer sizes
                new_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                new_sndbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                logger.info(Component.UDP, "Socket buffer sizes configured",
                          RCV=new_rcvbuf, SND=new_sndbuf)
            except Exception as e:
                logger.error(Component.UDP, "Failed to set socket buffer sizes", error=str(e))

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if self._transport is None:
            return

        logger = get_logger()
        address, port = addr
        address_str = str(address)

        interceptors_ports = self._interceptors.get(address_str)
        if interceptors_ports is None:
            perf_mark(
                "udp", "datagram", "unbound_dropped",
                metadata={
                    "flow_direction": "rx", "remote_address": address_str,
                    "remote_port": port, "size_bytes": len(data),
                    "drop_reason": "unbound", "counter.udp.datagrams_dropped": 1,
                },
            )
            logger.warn(Component.UDP, "Unbound datagram received - address not found",
                       address=address_str)
            return

        interceptor = interceptors_ports.get(port)
        if interceptor is None:
            perf_mark(
                "udp", "datagram", "unbound_dropped",
                metadata={
                    "flow_direction": "rx", "remote_address": address_str,
                    "remote_port": port, "size_bytes": len(data),
                    "drop_reason": "unbound", "counter.udp.datagrams_dropped": 1,
                },
            )
            logger.warn(Component.UDP, "Unbound datagram received - port not found",
                       address=address_str, port=port)
            return

        local_address, local_port = self.transport.get_extra_info("sockname")[:2]
        perf_mark(
            "udp", "datagram", "rx",
            metadata={
                "flow_direction": "rx", "local_address": str(local_address),
                "local_port": local_port, "remote_address": address_str,
                "remote_port": port, "size_bytes": len(data),
                "counter.udp.datagrams_rx": 1,
            },
        )
        interceptor.put_nowait(Packet(Address(address_str, port), data))

    @override
    def error_received(self, exc: Exception) -> None:
        perf_mark(
            "udp", "datagram", "failed",
            metadata={
                "failure_source": "error_received", "error_stage": "udp_transport",
                "exception_class": exc.__class__.__name__,
                "counter.udp.datagrams_failed": 1,
            },
        )


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
        self._pair_id: str | None = None

    def set_trace_pair_id(self, pair_id: str) -> None:
        self._pair_id = pair_id

    def sendto(self, data: bytes | bytearray | bytes):
        local_address, local_port = self._transport.get_extra_info("sockname")[:2]
        metadata: dict[str, object] = {
            "flow_direction": "tx", "local_address": str(local_address),
            "local_port": local_port, "remote_address": self._address[0],
            "remote_port": self._address[1], "packet_kind": _packet_kind(data),
            "size_bytes": len(data),
        }
        if self._pair_id is not None:
            metadata["pair_id"] = self._pair_id
        try:
            result = self._transport.sendto(data, self._address)
        except Exception as exc:
            perf_mark(
                "udp", "datagram", "failed",
                metadata={
                    **metadata, "failure_source": "sendto", "error_stage": "sendto",
                    "exception_class": exc.__class__.__name__,
                    "counter.udp.datagrams_failed": 1,
                },
            )
            raise
        perf_mark(
            "udp", "datagram", "tx",
            metadata={**metadata, "counter.udp.datagrams_tx": 1},
        )
        return result

    async def recvfrom(self) -> Packet:
        return await self._interceptor.get()


def _packet_kind(data: bytes | bytearray) -> str:
    """Classify only from headers; UDP callbacks must never parse payloads."""
    if not data:
        return "unknown"
    first_byte = data[0]
    if 20 <= first_byte < 64:
        return "dtls"
    if len(data) >= 8 and first_byte & 0xC0 == 0 and data[4:8] == b"\x21\x12\xA4\x42":
        return "stun"
    if 128 <= first_byte < 192:
        if len(data) >= 2 and 192 <= data[1] <= 208:
            return "rtcp"
        return "rtp"
    return "unknown"


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


class MultiUDPMux(ObservedComponent):
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
                self._loop.create_datagram_endpoint(
                    lambda iface=interface: InterfaceMuxUDPHandler(iface, port),
                    local_addr=(interface.address.value, port),
                )
            )

        for _, handler in await asyncio.gather(*coros):
            self._inbound_handlers[handler.addr_str()] = handler

    @event_loop
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

    @event_loop
    def inbound_handlers(self) -> dict[str, InterfaceMuxUDPHandler]:
        if len(self._inbound_handlers) <= 0:
            raise RuntimeError("Inbound handlers not found accept connections first")
        return self._inbound_handlers

    async def aclose(self) -> None:
        handlers = tuple(self._inbound_handlers.values())
        self._inbound_handlers.clear()
        for handler in handlers:
            transport = handler._transport
            handler._transport = None
            if transport is not None:
                transport.close()
