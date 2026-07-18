import asyncio
import hashlib
import secrets
import socket
import weakref
from typing import override, Any

from webrtc.utils.types import impl_protocol
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.runtime_services import current_execution_scope
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.state_machine import (
    SynchronousStateReducer,
)
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

_ENDPOINT_OBSERVABILITY_KEY = secrets.token_bytes(16)
_UNBOUND_QUEUE_TELEMETRY: weakref.WeakKeyDictionary[object, dict[str, int]] = (
    weakref.WeakKeyDictionary()
)


def _endpoint_id(address: object, port: object) -> str:
    return "endpoint:" + hashlib.blake2s(
        f"{address}:{port}".encode(), key=_ENDPOINT_OBSERVABILITY_KEY,
        digest_size=8,
    ).hexdigest()


class Interceptor:
    def __init__(
        self, maxsize: int = 256, *, drop_oldest: bool = True,
        queue_id: str = "packet",
    ):
        self._queue = asyncio.Queue[Packet](maxsize=maxsize)
        self._drop_oldest = drop_oldest
        self._queue_id = queue_id
        self._observability_id = f"{queue_id}:{secrets.token_hex(6)}"
        self._fatal_error: BaseException | None = None
        self._runtime = current_execution_scope()
        self.entity_id = (
            self._runtime.allocate_domain_entity_id("queue", hint=self._observability_id)
            if hasattr(self._runtime, "allocate_domain_entity_id")
            else f"queue:{self._observability_id}:{secrets.token_hex(4)}"
        )
        self._runner = SynchronousStateReducer(
            MACHINE_SPECS["queue"], entity_id=self.entity_id,
            transition_sink=None,
        )
        if self._runtime is not None:
            self._runtime.compose_domain_machine(
                self._runner, queue_kind=self._queue_id,
            )
            self._record_packet_activity(exact=True)

    def _record_packet_activity(self, *, admitted: int = 0,
                                dequeued: int = 0, dropped: int = 0,
                                rejected: int = 0, exact: bool = False) -> None:
        if self._runtime is not None:
            self._runtime.record_queue_activity(
                entity_id=self.entity_id, queue_kind=self._queue_id,
                depth=self._queue.qsize(), capacity=self._queue.maxsize,
                deltas={"admitted_packets": admitted,
                        "dequeued_packets": dequeued,
                        "dropped_media_packets": dropped,
                        "rejected_control_packets": rejected},
                failure_diagnostic="udp_queue_facet_publish_failures",
                exact=exact,
            )
        else:
            counters = _UNBOUND_QUEUE_TELEMETRY.setdefault(self, {})
            counters["admitted_packets"] = counters.get("admitted_packets", 0) + admitted
            counters["dequeued_packets"] = counters.get("dequeued_packets", 0) + dequeued
            counters["dropped_media_packets"] = counters.get("dropped_media_packets", 0) + dropped
            counters["rejected_control_packets"] = counters.get("rejected_control_packets", 0) + rejected

    @property
    def observability_id(self) -> str:
        return self._observability_id

    def _counter(self, name: str) -> int:
        if self._runtime is None:
            return _UNBOUND_QUEUE_TELEMETRY.get(self, {}).get(name, 0)
        return self._runtime.queue_telemetry_snapshot(self.entity_id).get(name, 0)

    dropped_media = property(lambda self: self._counter("dropped_media_packets"))
    rejected_control = property(lambda self: self._counter("rejected_control_packets"))

    def put_nowait(self, pkt: Packet):
        kind = _packet_kind(pkt.data)
        if self._queue.full() and kind == "stun":
            self._record_packet_activity(rejected=1)
            error = asyncio.QueueFull("bounded STUN/control ingress overflow")
            self._fatal_error = error
            if self._runner.snapshot().state == "open":
                self._runner.transition("failed", cause=f"{self.entity_id}:fail")
            raise error
        if self._drop_oldest and self._queue.full():
            # Datagram producers cannot apply backpressure. Keep the freshest
            # traffic (especially RTP/RTCP) instead of retaining packets for
            # the lifetime of a slow or stalled consumer.
            try:
                self._queue.get_nowait()
                self._record_packet_activity(dropped=1)
            except asyncio.QueueEmpty:
                pass
        self._queue.put_nowait(pkt)
        self._record_packet_activity(admitted=1)

    async def put(self, pkt: Packet):
        result = await self._queue.put(pkt)
        self._record_packet_activity(admitted=1)
        return result

    async def get(self) -> Packet:
        if self._fatal_error is not None:
            error, self._fatal_error = self._fatal_error, None
            raise error
        result = await self._queue.get()
        if self._fatal_error is not None:
            error, self._fatal_error = self._fatal_error, None
            raise error
        self._record_packet_activity(dequeued=1)
        return result

    async def aclose(self) -> None:
        if self._runner.snapshot().terminal:
            return
        self._runner.transition("closing", cause=f"{self.entity_id}:close")
        while not self._queue.empty():
            self._queue.get_nowait()
        self._runner.transition("drained", cause=f"{self.entity_id}:drain")
        self._runner.transition("closed", cause=f"{self.entity_id}:closed")
        if self._runtime is not None:
            self._record_packet_activity(exact=True)
            await self._runtime.flush_observations()
            self._runtime.retire_domain_machine(
                self.entity_id, self._runner.epoch
            )

class InterfaceMuxUDPHandler(asyncio.DatagramProtocol):
    def __init__(self, interface: Interface, port: int) -> None:
        self._interface = interface
        self._port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._interceptors = dict[str, dict[int, Interceptor]]()
        self._closed: asyncio.Future[None] | None = None
        self._connection_error: Exception | None = None

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
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None and self._closed is None:
            self._closed = loop.create_future()
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
                    "flow_direction": "rx",
                    "remote_endpoint_id": _endpoint_id(address_str, port),
                    "size_bytes": len(data),
                    "drop_reason": "unbound", "counter.udp.datagrams_dropped": 1,
                },
            )
            logger.warn(
                Component.UDP, "Unbound datagram received - address not found",
                remote_endpoint_id=_endpoint_id(address_str, port),
            )
            return

        interceptor = interceptors_ports.get(port)
        if interceptor is None:
            perf_mark(
                "udp", "datagram", "unbound_dropped",
                metadata={
                    "flow_direction": "rx",
                    "remote_endpoint_id": _endpoint_id(address_str, port),
                    "size_bytes": len(data),
                    "drop_reason": "unbound", "counter.udp.datagrams_dropped": 1,
                },
            )
            logger.warn(
                Component.UDP, "Unbound datagram received - port not found",
                remote_endpoint_id=_endpoint_id(address_str, port),
            )
            return

        local_address, local_port = self.transport.get_extra_info("sockname")[:2]
        perf_mark(
            "udp", "datagram", "rx",
            metadata={
                "flow_direction": "rx",
                "local_endpoint_id": _endpoint_id(local_address, local_port),
                "remote_endpoint_id": _endpoint_id(address_str, port),
                "size_bytes": len(data),
                "counter.udp.datagrams_rx": 1,
            },
        )
        try:
            interceptor.put_nowait(Packet(Address(address_str, port), data))
        except asyncio.QueueFull as exc:
            self._connection_error = exc
            perf_mark(
                "udp", "datagram", "control_overflow",
                metadata={"packet_kind": "stun", "counter.udp.control_overflow": 1},
            )

    @override
    def error_received(self, exc: Exception) -> None:
        self._connection_error = exc
        perf_mark(
            "udp", "datagram", "failed",
            metadata={
                "failure_source": "error_received", "error_stage": "udp_transport",
                "exception_class": exc.__class__.__name__,
                "counter.udp.datagrams_failed": 1,
            },
        )

    @override
    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            self._connection_error = exc
        self._transport = None
        if self._closed is not None and not self._closed.done():
            self._closed.set_result(None)

    async def wait_closed(self) -> None:
        if self._closed is None:
            self._closed = asyncio.get_running_loop().create_future()
            if self._transport is None:
                self._closed.set_result(None)
        await asyncio.shield(self._closed)


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
            "flow_direction": "tx",
            "local_endpoint_id": _endpoint_id(local_address, local_port),
            "remote_endpoint_id": _endpoint_id(*self._address),
            "packet_kind": _packet_kind(data),
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

    async def aclose(self) -> None:
        await self._interceptor.aclose()


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


class _UDPCommand(str):
    BIND = "bind"
    ACTIVE = "active"
    DRAIN = "drain"
    CLOSE = "close"
    FAIL = "fail"


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
        self._runtime = current_execution_scope()
        self.entity_id = (
            self._runtime.allocate_domain_entity_id("udp-binding")
            if hasattr(self._runtime, "allocate_domain_entity_id")
            else f"udp-binding:{secrets.token_hex(4)}"
        )
        self._runner = SynchronousStateReducer(
            MACHINE_SPECS["udp-binding"], entity_id=self.entity_id,
            transition_sink=None,
        )
        if self._runtime is not None:
            self._runtime.compose_domain_machine(self._runner)
        self._runner.transition("bound", cause=f"{self.entity_id}:bind")
        self._runner.transition("active", cause=f"{self.entity_id}:active")

    async def aclose(self) -> None:
        if self._runner.snapshot().terminal:
            return
        cause = f"{self.entity_id}:close"
        self._runner.transition("draining", cause=cause)
        self._runner.transition("closed", cause=cause)
        if self._runtime is not None:
            self._runtime.retire_domain_machine(
                self.entity_id, self._runner.epoch
            )

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
        self._bindings: list[UDPMux] = []
        self._socket_resources = {}
        self._runtime = current_execution_scope()
        self.entity_id = (
            self._runtime.allocate_domain_entity_id("udp-mux")
            if hasattr(self._runtime, "allocate_domain_entity_id")
            else f"udp-mux:{secrets.token_hex(4)}"
        )
        self._runner = SynchronousStateReducer(
            MACHINE_SPECS["udp-mux"], entity_id=self.entity_id,
            transition_sink=None,
        )
        if self._runtime is not None:
            self._runtime.compose_domain_machine(self._runner)
        if hasattr(self._runtime, "register_owner"):
            self._runtime.register_owner(self.entity_id, epoch=1, role="udp-mux")
            self._runtime.compose_domain_subject(
                self, entity_id=self.entity_id, role="udp-mux", owner_epoch=1,
            )

    async def accept(self, port: int = 0):
        self._runner.transition("binding", cause=f"{self.entity_id}:bind")
        try:
            for interface in self._interfaces:
                _, handler = await self._loop.create_datagram_endpoint(
                    lambda iface=interface: InterfaceMuxUDPHandler(iface, port),
                    local_addr=(interface.address.value, port),
                )
                self._inbound_handlers[handler.addr_str()] = handler
                if hasattr(self._runtime, "register_owned_resource"):
                    transport = handler._transport
                    assert transport is not None
                    self._socket_resources[handler] = self._runtime.register_owned_resource(
                        close=transport.close, wait_closed=handler.wait_closed,
                        owner_entity_id=self.entity_id,
                        owner_epoch=1,
                        name=f"udp:socket-barrier:{handler.addr_str()}",
                    )
        except BaseException:
            await self._close_socket_handlers()
            self._runner.transition("failed", cause=f"{self.entity_id}:bind-failed")
            await self._runtime.flush_observations()
            raise
        self._runner.transition("active", cause=f"{self.entity_id}:active")
        await self._runtime.flush_observations()

    def bind(
        self, ufrag: str, handler: InterfaceMuxUDPHandler, candidate: CandidateProtocol
    ) -> UDPMux:
        transport = handler._transport
        if transport is None:
            raise ValueError("Unable bind unactive inbound handler transport")

        mux = UDPMux(ufrag, candidate, handler)
        self._bindings.append(mux)

        candidate.set_port(handler.port())
        candidate.set_address(handler.addr_str())
        candidate.set_network_type(NetworkType.UDP)

        return mux

    def inbound_handlers(self) -> dict[str, InterfaceMuxUDPHandler]:
        if len(self._inbound_handlers) <= 0:
            raise RuntimeError("Inbound handlers not found accept connections first")
        return self._inbound_handlers

    async def _close_socket_handlers(self) -> None:
        handlers = tuple(self._inbound_handlers.values())
        self._inbound_handlers.clear()
        for handler in handlers:
            resource = self._socket_resources.pop(handler, None)
            try:
                async with asyncio.timeout(1.0):
                    if resource is not None:
                        await resource.aclose()
                    else:
                        transport = handler._transport
                        if transport is not None:
                            transport.close()
                        await handler.wait_closed()
            finally:
                handler._transport = None

    async def aclose(self) -> None:
        if self._runner.snapshot().terminal:
            return
        cause = f"{self.entity_id}:close"
        if self._runner.snapshot().state != "draining":
            self._runner.transition("draining", cause=cause)
        for binding in self._bindings:
            await binding.aclose()
        self._bindings.clear()
        try:
            await self._close_socket_handlers()
        except TimeoutError as exc:
            self._runner.transition("failed", cause=cause)
            self._runner.transition("closed", cause=cause)
            await self._runtime.flush_observations()
            self._runtime.remove_owner(self.entity_id, 1)
            raise RuntimeError("UDP socket connection_lost barrier timed out") from exc
        self._runner.transition("closed", cause=cause)
        await self._runtime.flush_observations()
        self._runtime.remove_owner(self.entity_id, 1)
