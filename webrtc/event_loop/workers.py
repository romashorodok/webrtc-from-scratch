"""Fixed peer-sharded reference packet workers."""

from __future__ import annotations

import threading

from dataclasses import dataclass
from queue import Empty, Full
from typing import TYPE_CHECKING, Annotated, Callable

import pymeta
from pymeta.concurrent import BoundedQueue, bounded_queue, spsc

from .datagrams import OwnedPacket

if TYPE_CHECKING:
    from .loop import LoopConfig, WebRTCSelectorEventLoop


@pymeta.record(abi="webrtc.event_loop.packet_result.v1")
@dataclass(frozen=True, slots=True)
class PacketResult:
    peer_id: object
    value: object


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class PacketWorker:
    _input: Annotated[
        BoundedQueue[OwnedPacket],
        spsc
        | bounded_queue(capacity="self._capacity")
        | pymeta.owned_by("worker"),
    ]
    _output: Annotated[
        BoundedQueue[PacketResult],
        spsc
        | bounded_queue(capacity="self._capacity")
        | pymeta.owned_by("reactor"),
    ]

    __slots__ = (
        "_capacity",
        "_input_ready",
        "_input",
        "_loop",
        "_on_result",
        "_output",
        "_processor",
        "_thread",
        "dropped",
        "index",
    )

    def __init__(
        self,
        index: int,
        capacity: int,
        processor: Callable[[OwnedPacket], PacketResult],
        loop: "WebRTCSelectorEventLoop",
        on_result: Callable[[PacketResult], object],
    ) -> None:
        self.index = index
        self._capacity = capacity
        self._input = BoundedQueue[OwnedPacket](capacity)
        self._output = BoundedQueue[PacketResult](capacity)
        self._input_ready = threading.Event()
        self._processor = processor
        self._loop = loop
        self._on_result = on_result
        self.dropped = 0
        self._thread = threading.Thread(
            target=self._run,
            name=f"webrtc-packet-{index}",
            daemon=False,
        )

    def start(self) -> None:
        self._thread.start()

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"packet"},
            writes={"self._input"},
            owner="reactor",
            suspend=pymeta.never,
        ),
    )
    def submit(self, packet: OwnedPacket) -> bool:
        try:
            self._input.put_nowait(packet)
        except (Full, RuntimeError):
            self.dropped += 1
            return False
        self._input_ready.set()
        return True

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"packet"},
            writes={"self.peer_state"},
            owner="worker",
            noescape={"packet.payload"},
            allocate=pymeta.never,
            suspend=pymeta.never,
        ),
    )
    def process_packet(self, packet: OwnedPacket) -> PacketResult:
        return self._processor(packet)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._input"},
            writes={"self._input"},
            owner="worker",
            suspend=pymeta.never,
        ),
    )
    def receive_packet(self) -> OwnedPacket | None:
        try:
            return self._input.get_nowait()
        except Empty:
            return None

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"result"},
            writes={"self._output"},
            owner="worker",
            suspend=pymeta.never,
        ),
    )
    def publish_result(self, result: PacketResult) -> bool:
        try:
            self._output.put_nowait(result)
        except (Full, RuntimeError):
            self.dropped += 1
            return False
        return True

    def _run(self) -> None:
        while True:
            self._input_ready.wait()
            self._input_ready.clear()
            while True:
                packet = self.receive_packet()
                if packet is None:
                    break
                result = self.process_packet(packet)
                if not self.publish_result(result):
                    continue
                try:
                    self._loop.call_soon_threadsafe(self.drain_results)
                except RuntimeError:
                    return
            if self._input.closed and self._input.empty():
                return

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._output"},
            writes={"self._output"},
            owner="reactor",
            suspend=pymeta.never,
        ),
    )
    def drain_results(self) -> None:
        for _ in range(self._output.qsize()):
            try:
                result = self._output.get_nowait()
            except Empty:
                break
            self._on_result(result)

    def stop(self) -> None:
        self._input.close()
        self._input_ready.set()

    def join(self) -> None:
        self._thread.join()

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._input", "self._output"},
            writes={"self._input", "self._output"},
            owner="reactor",
            suspend=pymeta.never,
        ),
    )
    def close_channels(self) -> None:
        self._input.close()
        while not self._input.empty():
            try:
                self._input.get_nowait()
            except Empty:
                break
        self._output.close()
        while not self._output.empty():
            try:
                result = self._output.get_nowait()
            except Empty:
                break
            self._on_result(result)


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class PacketWorkerPool:
    __slots__ = ("_accepting", "_workers")

    def __init__(
        self,
        config: "LoopConfig",
        loop: "WebRTCSelectorEventLoop",
        processor: Callable[[OwnedPacket], PacketResult] | None = None,
        on_result: Callable[[PacketResult], object] | None = None,
    ) -> None:
        processor = processor or (lambda packet: PacketResult(packet.peer_id, packet))
        on_result = on_result or (lambda result: None)
        self._accepting = True
        self._workers = tuple(
            PacketWorker(
                index,
                config.packet_queue_capacity,
                processor,
                loop,
                on_result,
            )
            for index in range(config.packet_workers)
        )
        for worker in self._workers:
            worker.start()

    @property
    def workers(self) -> tuple[PacketWorker, ...]:
        return self._workers

    def submit(self, packet: OwnedPacket) -> bool:
        if not self._accepting or not self._workers:
            return False
        index = hash(packet.peer_id) % len(self._workers)
        return self._workers[index].submit(packet)

    def stop_admission(self) -> None:
        self._accepting = False

    def close(self) -> None:
        if not self._accepting and not any(
            worker._thread.is_alive() for worker in self._workers
        ):
            return
        self.stop_admission()
        for worker in self._workers:
            worker.stop()
        for worker in self._workers:
            worker.join()
        for worker in self._workers:
            worker.close_channels()
