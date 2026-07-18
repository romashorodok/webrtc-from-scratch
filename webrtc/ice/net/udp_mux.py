import asyncio
import hashlib
import secrets
import socket
from typing import override, Any

from webrtc.utils.types import impl_protocol
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.performance import ObservedComponent, event_loop
from webrtc.runtime_services import current_execution_scope
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.observability import MachineTransitionOp
from webrtc.state_machine import (
    AsyncStateMachineRunner, MachineCommand, PreparedTransition, ReplyPort,
    TransitionCommit,
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
        self._high_water = 0
        self.admitted = 0
        self.dropped_media = 0
        self.rejected_control = 0
        self._fatal_error: BaseException | None = None
        self._runtime = current_execution_scope()
        scope_id = getattr(self._runtime, "scope_id", None) or id(self)
        self.entity_id = f"queue:{scope_id}:{self._observability_id}"
        self._command_id = 0
        self._runner = _InterceptorQueueRunner(
            MACHINE_SPECS["queue"], entity_id=self.entity_id,
            mailbox_capacity=8,
            controller=getattr(self._runtime, "transition_controller", None),
            transition_sink=self._project_transition,
        )
        if hasattr(self._runtime, "start_machine"):
            self._runtime.projection.machines.register(
                self.entity_id, MACHINE_SPECS["queue"]
            )
            self._runtime.register_owner(self.entity_id, epoch=self._runner.epoch)
            self._machine_handle = self._runtime.start_machine(
                self._runner, owner_entity_id=self.entity_id,
                owner_epoch=self._runner.epoch,
            )
            self._publish_depth()
        else:
            self._machine_handle = None

    def _project_transition(self, commit: TransitionCommit) -> None:
        if self._runtime is None:
            return
        self._runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state,
            commit.to_state, commit.epoch, commit.revision,
            self._runtime.new_producer_dot(), commit.cause, commit.monotonic_ns,
        ))
        self._publish_depth(commit.revision)

    def _submit(self, kind: str, reply=None) -> None:
        if self._machine_handle is None:
            return
        self._command_id += 1
        self._runner.try_submit(MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            expected_revision=None,
            cause_id=f"{self.entity_id}:{kind}:{self._command_id}",
        ))

    def _publish_depth(self, revision: int | None = None) -> None:
        depth = self._queue.qsize()
        self._high_water = max(self._high_water, depth)
        if self._runtime is not None:
            self._runtime.projection.merge_values(
                self.entity_id, self._runtime.new_producer_dot(), {
                    "depth": depth, "high_water": self._high_water,
                    "queue_kind": self._queue_id,
                },
                observer_meta="exact", source_entity_id=self.entity_id,
                source_epoch=self._runner.epoch,
                source_revision=(self._runner.revision if revision is None else revision),
                source_order=self._runtime.projection.new_facet_source_order(),
            )

    @property
    def observability_id(self) -> str:
        return self._observability_id

    def put_nowait(self, pkt: Packet):
        kind = _packet_kind(pkt.data)
        if self._queue.full() and kind == "stun":
            self.rejected_control += 1
            error = asyncio.QueueFull("bounded STUN/control ingress overflow")
            self._fatal_error = error
            if self._runner.snapshot().state == "open":
                self._submit("fail")
            raise error
        if self._drop_oldest and self._queue.full():
            # Datagram producers cannot apply backpressure. Keep the freshest
            # traffic (especially RTP/RTCP) instead of retaining packets for
            # the lifetime of a slow or stalled consumer.
            try:
                self._queue.get_nowait()
                self.dropped_media += 1
            except asyncio.QueueEmpty:
                pass
        self._queue.put_nowait(pkt)
        self.admitted += 1
        self._publish_depth()

    async def put(self, pkt: Packet):
        result = await self._queue.put(pkt)
        self._publish_depth()
        return result

    async def get(self) -> Packet:
        if self._fatal_error is not None:
            error, self._fatal_error = self._fatal_error, None
            raise error
        result = await self._queue.get()
        if self._fatal_error is not None:
            error, self._fatal_error = self._fatal_error, None
            raise error
        self._publish_depth()
        return result

    async def aclose(self) -> None:
        if self._machine_handle is None or self._runner.snapshot().terminal:
            return
        for kind in ("close", "drain", "closed"):
            reply = ReplyPort[TransitionCommit]()
            self._submit(kind, reply)
            await reply.wait()
        await self._machine_handle.wait()
        self._runtime.remove_owner(self.entity_id, self._runner.epoch)


class _InterceptorQueueRunner(AsyncStateMachineRunner):
    async def step(self, command):
        proposed = {
            "fail": "failed", "close": "closing",
            "drain": "drained", "closed": "closed",
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported queue command: {command.kind}")
        return PreparedTransition(
            self.snapshot().state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
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


class _UDPRunner(AsyncStateMachineRunner):
    async def step(self, command):
        state = self.snapshot().state
        if command.kind == _UDPCommand.BIND:
            proposed = "binding" if self.spec.machine_type == "udp-mux" else "bound"
        elif command.kind == _UDPCommand.ACTIVE:
            proposed = "active"
        elif command.kind == _UDPCommand.DRAIN:
            proposed = "draining"
        elif command.kind == _UDPCommand.CLOSE:
            proposed = "closed"
        elif command.kind == _UDPCommand.FAIL:
            proposed = "failed"
        else:
            raise ValueError(f"unsupported UDP command: {command.kind}")
        return PreparedTransition(
            state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )


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
        scope_id = getattr(self._runtime, "scope_id", None) or id(self)
        self.entity_id = f"udp-binding:{scope_id}:{secrets.token_hex(4)}"
        self._command_id = 0
        self._runner = _UDPRunner(
            MACHINE_SPECS["udp-binding"], entity_id=self.entity_id,
            mailbox_capacity=8,
            controller=getattr(self._runtime, "transition_controller", None),
            transition_sink=self._project,
        )
        projection = getattr(self._runtime, "projection", None)
        if projection is not None:
            projection.machines.register(self.entity_id, MACHINE_SPECS["udp-binding"])
        if hasattr(self._runtime, "start_machine"):
            self._runtime.register_owner(self.entity_id, epoch=self._runner.epoch)
            self._machine_handle = self._runtime.start_machine(
                self._runner, owner_entity_id=self.entity_id,
                owner_epoch=self._runner.epoch,
            )
            self._submit(_UDPCommand.BIND)
            self._submit(_UDPCommand.ACTIVE)
        else:
            self._machine_handle = None

    @event_loop
    def _project(self, commit: TransitionCommit) -> None:
        if self._runtime is None:
            return
        self._runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state, commit.to_state,
            commit.epoch, commit.revision, self._runtime.new_producer_dot(),
            commit.cause, commit.monotonic_ns,
        ))

    def _submit(self, kind, reply=None, cause_id=None):
        self._command_id += 1
        self._runner.try_submit(MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            expected_revision=None,
            cause_id=cause_id or f"{self.entity_id}:{self._command_id}",
        ))

    async def aclose(self) -> None:
        if self._machine_handle is None or self._runner.snapshot().terminal:
            return
        cause = f"{self.entity_id}:close"
        for kind in (_UDPCommand.DRAIN, _UDPCommand.CLOSE):
            reply = ReplyPort[TransitionCommit]()
            self._submit(kind, reply, cause)
            await reply.wait()
        await self._machine_handle.wait()
        self._runtime.remove_owner(self.entity_id, self._runner.epoch)

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
        self._bindings: list[UDPMux] = []
        self._socket_resources = {}
        self._runtime = current_execution_scope()
        scope_id = getattr(self._runtime, "scope_id", None) or id(self)
        self.entity_id = f"udp-mux:{scope_id}:{secrets.token_hex(4)}"
        self._command_id = 0
        self._runner = _UDPRunner(
            MACHINE_SPECS["udp-mux"], entity_id=self.entity_id,
            mailbox_capacity=8,
            controller=getattr(self._runtime, "transition_controller", None),
            transition_sink=self._project,
        )
        projection = getattr(self._runtime, "projection", None)
        if projection is not None:
            projection.machines.register(self.entity_id, MACHINE_SPECS["udp-mux"])
        if hasattr(self._runtime, "start_machine"):
            self._runtime.register_owner(self.entity_id, epoch=self._runner.epoch)
            self._machine_handle = self._runtime.start_machine(
                self._runner, owner_entity_id=self.entity_id,
                owner_epoch=self._runner.epoch,
            )
        else:
            self._machine_handle = None

    @event_loop
    def _project(self, commit: TransitionCommit) -> None:
        if self._runtime is None:
            return
        self._runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state, commit.to_state,
            commit.epoch, commit.revision, self._runtime.new_producer_dot(),
            commit.cause, commit.monotonic_ns,
        ))

    @event_loop
    def _command(self, kind, reply=None, cause_id=None):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            expected_revision=None,
            cause_id=cause_id or f"{self.entity_id}:{self._command_id}",
        )

    async def accept(self, port: int = 0):
        binding = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(_UDPCommand.BIND, binding))
        await binding.wait()
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
                        owner_epoch=self._runner.epoch,
                        name=f"udp:socket-barrier:{handler.addr_str()}",
                    )
        except BaseException:
            await self._close_socket_handlers()
            failed = ReplyPort[TransitionCommit]()
            self._runner.try_submit(self._command(_UDPCommand.FAIL, failed))
            await failed.wait()
            raise
        active = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(_UDPCommand.ACTIVE, active))
        await active.wait()

    @event_loop
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

    @event_loop
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
        if self._machine_handle is None or self._runner.snapshot().terminal:
            return
        cause = f"{self.entity_id}:close"
        if self._runner.snapshot().state != "draining":
            draining = ReplyPort[TransitionCommit]()
            self._runner.try_submit(self._command(_UDPCommand.DRAIN, draining, cause))
            await draining.wait()
        for binding in self._bindings:
            await binding.aclose()
        self._bindings.clear()
        try:
            await self._close_socket_handlers()
        except TimeoutError as exc:
            failed = ReplyPort[TransitionCommit]()
            self._runner.try_submit(self._command(_UDPCommand.FAIL, failed, cause))
            await failed.wait()
            closed = ReplyPort[TransitionCommit]()
            self._runner.try_submit(self._command(_UDPCommand.CLOSE, closed, cause))
            await closed.wait()
            await self._machine_handle.wait()
            self._runtime.remove_owner(self.entity_id, self._runner.epoch)
            raise RuntimeError("UDP socket connection_lost barrier timed out") from exc
        closed = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(_UDPCommand.CLOSE, closed, cause))
        await closed.wait()
        await self._machine_handle.wait()
        self._runtime.remove_owner(self.entity_id, self._runner.epoch)
