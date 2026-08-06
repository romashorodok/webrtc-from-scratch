"""Bounded Go-style SPSC behavior for the reference packet workers."""

from __future__ import annotations

import threading
import time

from queue import Empty, Full
from typing import get_type_hints

import pymeta
from pymeta.concurrent import BoundedQueue

from webrtc.event_loop.datagrams import OwnedPacket
from webrtc.event_loop.workers import PacketResult, PacketWorker


def test_worker_channel_metadata_is_bounded_spsc() -> None:
    hints = get_type_hints(PacketWorker, include_extras=True)
    for name in ("_input", "_output"):
        text = repr(hints[name])
        assert "spsc" in text
        assert "bounded_queue" in text
    assert pymeta.metadata(PacketWorker.submit).required
    assert pymeta.metadata(PacketWorker.receive_packet).required
    assert pymeta.metadata(PacketWorker.publish_result).required
    assert pymeta.metadata(PacketWorker.drain_results).required
    assert pymeta.metadata(PacketWorker.close_channels).required
    packet_hints = get_type_hints(OwnedPacket, include_extras=True)
    payload = repr(packet_hints["payload"]).lower()
    assert "buffer" in payload
    assert "read" in payload
    assert "lifetime.call" in payload


def test_reference_bounded_queue_capacity_one_close_and_drain() -> None:
    channel = BoundedQueue[object](1)
    first = object()
    channel.put_nowait(first)
    try:
        channel.put_nowait(object())
    except Full:
        pass
    else:
        raise AssertionError("capacity-one channel accepted an extra item")
    channel.close()
    try:
        channel.put_nowait(object())
    except RuntimeError:
        pass
    else:
        raise AssertionError("closed channel accepted a send")
    assert channel.get_nowait() is first
    try:
        channel.get_nowait()
    except Empty:
        pass
    else:
        raise AssertionError("drained channel did not report empty")


def test_worker_close_processes_accepted_inputs_and_drains_outputs() -> None:
    callbacks: list[object] = []
    results: list[int] = []
    lock = threading.Lock()

    class FakeLoop:
        def call_soon_threadsafe(self, callback: object) -> None:
            with lock:
                callbacks.append(callback)

    worker = PacketWorker(
        0,
        2,
        lambda packet: PacketResult(packet.peer_id, int(packet.payload[0])),
        FakeLoop(),  # type: ignore[arg-type]
        lambda result: results.append(result.value),  # type: ignore[arg-type]
    )
    worker.start()
    assert worker.submit(OwnedPacket("peer", b"\x01"))
    assert worker.submit(OwnedPacket("peer", b"\x02"))
    worker.stop()
    worker.join()
    worker.close_channels()
    assert results == [1, 2]
    assert worker._input.closed
    assert worker._output.closed
    assert worker._input.empty()
    assert worker._output.empty()


def test_worker_full_is_nonblocking() -> None:
    gate = threading.Event()

    class FakeLoop:
        def call_soon_threadsafe(self, callback: object) -> None:
            del callback

    worker = PacketWorker(
        0,
        1,
        lambda packet: (
            gate.wait(),
            PacketResult(packet.peer_id, packet.payload),
        )[1],
        FakeLoop(),  # type: ignore[arg-type]
        lambda result: None,
    )
    worker.start()
    assert worker.submit(OwnedPacket("peer", b"a"))
    deadline = time.monotonic() + 1.0
    while worker._input.qsize() and time.monotonic() < deadline:
        time.sleep(0.001)
    assert worker.submit(OwnedPacket("peer", b"b"))
    started = time.monotonic()
    assert not worker.submit(OwnedPacket("peer", b"c"))
    assert time.monotonic() - started < 0.1
    gate.set()
    worker.stop()
    worker.join()
    worker.close_channels()
