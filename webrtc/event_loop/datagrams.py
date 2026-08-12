"""Bounded datagram receive and explicit packet ownership."""

from __future__ import annotations

import socket
import selectors

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Protocol

import pymeta

if TYPE_CHECKING:
    from .loop import LoopConfig, WebRTCSelectorEventLoop


class PacketPoolExhausted(RuntimeError):
    pass


class PacketPool:
    """A checked fixed-capacity pool of reusable receive buffers."""

    __slots__ = ("_available", "_buffer_size", "_capacity", "_in_use")

    def __init__(self, capacity: int, buffer_size: int = 65_535) -> None:
        if capacity <= 0:
            raise ValueError("packet pool capacity must be positive")
        if buffer_size <= 0:
            raise ValueError("packet buffer size must be positive")
        self._capacity = capacity
        self._buffer_size = buffer_size
        self._available = deque(bytearray(buffer_size) for _ in range(capacity))
        self._in_use: set[int] = set()

    def acquire(self) -> bytearray:
        try:
            buffer = self._available.popleft()
        except IndexError as exc:
            raise PacketPoolExhausted("packet pool is exhausted") from exc
        self._in_use.add(id(buffer))
        return buffer

    def release(self, buffer: bytearray) -> None:
        identity = id(buffer)
        if identity not in self._in_use:
            raise ValueError("packet buffer was not acquired or was already released")
        self._in_use.remove(identity)
        self._available.append(buffer)

    @property
    def available(self) -> int:
        return len(self._available)

    @property
    def capacity(self) -> int:
        return self._capacity


class PacketView:
    """A non-escaping view that returns its backing slab exactly once."""

    __slots__ = ("_buffer", "_length", "_pool", "address", "peer_id")

    def __init__(
        self,
        pool: PacketPool,
        buffer: bytearray,
        length: int,
        address: object,
        peer_id: object,
    ) -> None:
        self._pool = pool
        self._buffer: bytearray | None = buffer
        self._length = length
        self.address = address
        self.peer_id = peer_id

    @property
    def payload(self) -> memoryview:
        if self._buffer is None:
            raise RuntimeError("packet view has been released")
        return memoryview(self._buffer)[: self._length].toreadonly()

    def to_bytes(self) -> bytes:
        return bytes(self.payload)

    def release(self) -> None:
        buffer = self._buffer
        if buffer is None:
            return
        self._buffer = None
        self._pool.release(buffer)

    def __enter__(self) -> "PacketView":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


@pymeta.record(abi="webrtc.event_loop.owned_packet.v1")
@dataclass(frozen=True, slots=True)
class OwnedPacket:
    peer_id: Annotated[int, pymeta.uint[64]]
    payload: Annotated[
        bytes,
        pymeta.buffer[pymeta.u8] | pymeta.read | pymeta.lifetime.call,
    ]


class PacketDelivery(Protocol):
    def deliver(self, packet: PacketView) -> None: ...


class DescriptorRegistry:
    """Executable-Python reference for the native generation-tagged registry."""

    __slots__ = ("_capacity", "_next_generation", "_owners", "_tokens")

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("descriptor registry capacity must be positive")
        self._capacity = capacity
        self._next_generation = 1
        self._owners: dict[tuple[int, int], object] = {}
        self._tokens: dict[int, tuple[int, int]] = {}

    def register(self, descriptor: int, events: int, owner: object) -> tuple[int, int]:
        del events
        if descriptor < 0:
            raise ValueError("datagram socket is closed")
        if descriptor in self._tokens:
            raise RuntimeError("datagram descriptor is already registered")
        if len(self._tokens) >= self._capacity:
            raise RuntimeError("descriptor registry is full")
        token = (descriptor, self._next_generation)
        self._next_generation += 1
        self._tokens[descriptor] = token
        self._owners[token] = owner
        return token

    def remove(self, token: tuple[int, int]) -> bool:
        if self._tokens.get(token[0]) != token:
            return False
        del self._tokens[token[0]]
        del self._owners[token]
        return True

    def is_current(self, token: tuple[int, int]) -> bool:
        return self._tokens.get(token[0]) == token

    def owner(self, token: tuple[int, int]) -> object:
        return self._owners[token]


class WebRTCDatagramTransport:
    """Reader callback registered once for a nonblocking UDP socket."""

    __slots__ = (
        "_closed",
        "_descriptor",
        "_generation",
        "_loop",
        "_protocol",
        "_reactor",
        "socket",
    )

    def __init__(
        self,
        loop: "WebRTCSelectorEventLoop",
        sock: socket.socket,
        protocol: object,
        reactor: "DatagramReactor",
    ) -> None:
        self._loop = loop
        self.socket = sock
        self._protocol = protocol
        self._reactor = reactor
        self._closed = False
        self._descriptor = -1
        self._generation = 0
        sock.setblocking(False)

    def start(self) -> None:
        if self._generation != 0:
            raise RuntimeError("datagram transport is already registered")
        descriptor = self.socket.fileno()
        generation = self._reactor._activate(descriptor, self)
        self._descriptor = descriptor
        self._generation = generation
        try:
            self._loop.add_reader(
                descriptor,
                self._reactor.drain_socket,
                self,
                generation,
            )
        except BaseException:
            self._reactor._deactivate(descriptor, generation, self)
            self._descriptor = -1
            self._generation = 0
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptor = self._descriptor
        generation = self._generation
        self._descriptor = -1
        self._generation = 0
        # A stale transport must never remove a newer registration that reused
        # the same numeric descriptor.
        if self._reactor._deactivate(descriptor, generation, self):
            self._loop.remove_reader(descriptor)

    def receive_one(self) -> PacketView | None:
        try:
            buffer = self._reactor.packet_pool.acquire()
        except PacketPoolExhausted:
            return None
        try:
            size, address = self.socket.recvfrom_into(buffer)
        except (BlockingIOError, InterruptedError):
            self._reactor.packet_pool.release(buffer)
            return None
        except BaseException:
            self._reactor.packet_pool.release(buffer)
            raise
        return PacketView(
            self._reactor.packet_pool,
            buffer,
            size,
            address,
            self._reactor.peer_id(address),
        )

    def deliver(self, packet: PacketView) -> None:
        delivery = getattr(self._protocol, "packet_received", None)
        if delivery is not None:
            # The WebRTC-only boundary is an explicit ownership transfer.  Its
            # consumer must release the view when native processing finishes.
            try:
                delivery(packet)
            except BaseException:
                packet.release()
                raise
        else:
            try:
                self._protocol.datagram_received(packet.to_bytes(), packet.address)
            finally:
                packet.release()

    def request_reschedule(self) -> None:
        if self._generation != 0:
            self._loop.call_soon(
                self._reactor.drain_socket,
                self,
                self._generation,
            )


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class DatagramReactor:
    __slots__ = (
        "_config",
        "_native_packets",
        "_native_registry",
        "_next_generation",
        "_registrations",
        "_transports",
        "packet_pool",
    )

    _native_registry: Annotated[
        object,
        pymeta.storage.selector_registry(
            capacity="self._config.packet_queue_capacity"
        )
        | pymeta.owned_by("reactor"),
    ]
    _native_packets: Annotated[
        object,
        pymeta.storage.packet_slab(
            capacity="self._config.packet_queue_capacity",
            buffer_size=65_535,
        )
        | pymeta.owned_by("reactor"),
    ]

    def __init__(self, config: "LoopConfig") -> None:
        self._config = config
        self.packet_pool = PacketPool(config.packet_queue_capacity)
        self._transports: set[WebRTCDatagramTransport] = set()
        self._registrations: dict[
            int, tuple[int, WebRTCDatagramTransport]
        ] = {}
        # Executable-Python aliases. The compiler replaces only these explicitly
        # annotated fields with reactor-owned selector/slab storage.
        self._native_registry = DescriptorRegistry(config.packet_queue_capacity)
        self._native_packets = self.packet_pool
        self._next_generation = 1

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="reactor", suspend=pymeta.never),
    )
    def _activate(
        self,
        descriptor: int,
        transport: WebRTCDatagramTransport,
    ) -> int:
        token = self._native_registry.register(
            descriptor, selectors.EVENT_READ, transport
        )
        self._registrations[descriptor] = (token[1], transport)
        return token[1]

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="reactor", suspend=pymeta.never),
    )
    def _deactivate(
        self,
        descriptor: int,
        generation: int,
        transport: WebRTCDatagramTransport,
    ) -> bool:
        token = (descriptor, generation)
        if not self._native_registry.is_current(token):
            return False
        if self._native_registry.owner(token) is not transport:
            return False
        if not self._native_registry.remove(token):
            return False
        self._registrations.pop(descriptor)
        return True

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="reactor", suspend=pymeta.never),
    )
    def _is_current(
        self,
        transport: WebRTCDatagramTransport,
        generation: int,
    ) -> bool:
        token = (transport._descriptor, generation)
        return self._native_registry.is_current(token) and (
            self._native_registry.owner(token) is transport
        )

    @staticmethod
    def peer_id(address: object) -> object:
        return address

    def register(
        self,
        loop: "WebRTCSelectorEventLoop",
        sock: socket.socket,
        protocol: object,
    ) -> WebRTCDatagramTransport:
        transport = WebRTCDatagramTransport(loop, sock, protocol, self)
        self._transports.add(transport)
        try:
            transport.start()
        except BaseException:
            self._transports.discard(transport)
            raise
        return transport

    def unregister(self, transport: WebRTCDatagramTransport) -> None:
        transport.close()
        self._transports.discard(transport)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"transport.socket", "config.receive_packet_budget"},
            writes={"transport.protocol", "packet_pool"},
            owner="reactor",
            noescape={"packet"},
            allocate=pymeta.never,
            suspend=pymeta.never,
        ),
    )
    def drain_socket(
        self,
        loop: "WebRTCSelectorEventLoop",
        transport: WebRTCDatagramTransport,
        generation: int | None = None,
    ) -> None:
        if generation is not None and not self._is_current(
            transport, generation
        ):
            return
        started = loop.time()
        budget = self._config.receive_packet_budget
        time_budget = self._config.receive_time_budget_us / 1_000_000
        for _ in range(budget):
            if loop.time() - started >= time_budget:
                transport.request_reschedule()
                return
            packet = transport.receive_one()
            if packet is None:
                return
            transport.deliver(packet)

    def close(self) -> None:
        for transport in tuple(self._transports):
            self.unregister(transport)
