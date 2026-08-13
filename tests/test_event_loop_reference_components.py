"""Focused Stage M1 tests for the executable custom-loop components."""

from __future__ import annotations

import asyncio
import contextvars
import socket
import threading
from typing import get_type_hints

import pymeta

from webrtc.event_loop.commands import CommandInbox, PublishedHandle, PublishedState
from webrtc.event_loop.datagrams import DatagramReactor, PacketPool
from webrtc.event_loop.loop import (
    ClockValue,
    LoopConfig,
    LoopLifecycle,
    LoopState,
    ReadyQueue,
    TimerCount,
    TimerQueue,
    WebRTCSelectorEventLoop,
)
from webrtc.event_loop.scheduler import ReactorScheduler
from webrtc.event_loop.workers import PacketWorkerPool


def test_loop_native_fields_keep_alias_metadata_at_the_declaration() -> None:
    hints = get_type_hints(WebRTCSelectorEventLoop, include_extras=True)
    source_hints = WebRTCSelectorEventLoop.__annotations__

    assert hints["_ready"] == ReadyQueue
    assert hints["_scheduled"] == TimerQueue
    assert hints["_timer_cancelled_count"] == TimerCount
    assert hints["_clock_resolution"] == ClockValue
    assert "storage.fifo" in source_hints["_ready"]
    assert "storage.min_heap" in source_hints["_scheduled"]
    assert "storage.native_field" in source_hints["_timer_cancelled_count"]
    assert "storage.native_field" in source_hints["_clock_resolution"]
    assert all(
        "owned_by(" in source_hints[name] and "reactor" in source_hints[name]
        for name in (
            "_ready",
            "_scheduled",
            "_timer_cancelled_count",
            "_clock_resolution",
        )
    )


def test_exact_loop_components_are_native_class_candidates() -> None:
    components = (
        ReactorScheduler,
        CommandInbox,
        DatagramReactor,
        PacketWorkerPool,
        LoopLifecycle,
    )

    assert all(
        pymeta.metadata(component).native_layout is pymeta.compact_object
        for component in components
    )


def test_scheduler_regions_are_required_and_facade_is_thin() -> None:
    required_methods = (
        "remove_cancelled_timers",
        "compute_timeout",
        "process_selector_events",
        "promote_due_timers",
        "run_ready_snapshot",
        "run_once",
    )
    assert all(pymeta.metadata(getattr(ReactorScheduler, name)).required for name in required_methods)
    assert all(
        pymeta.metadata(getattr(WebRTCSelectorEventLoop, name)).required
        for name in (
            "_run_once",
            "call_soon",
            "_call_soon",
            "call_at",
            "call_later",
            "call_soon_threadsafe",
        )
    )

    loop = WebRTCSelectorEventLoop()
    seen: list[str] = []
    try:
        loop.call_soon(seen.append, "ready")
        loop._run_once()
        assert seen == ["ready"]
    finally:
        loop.close()


def test_published_handle_cancel_wins_only_before_claim() -> None:
    loop = asyncio.new_event_loop()
    called: list[str] = []
    try:
        cancelled = PublishedHandle(called.append, ("cancelled",), loop, None)
        cancelled.cancel()
        cancelled._run()
        assert cancelled.cancelled()
        assert called == []

        context_value = contextvars.ContextVar("published", default="outer")
        context = contextvars.copy_context()
        context.run(context_value.set, "captured")
        claimed = PublishedHandle(
            lambda: called.append(context_value.get()), (), loop, context
        )
        assert claimed.claim()
        claimed.cancel()
        claimed._handle._run()
        claimed._state.store(PublishedState.DONE)
        assert not claimed.cancelled()
        assert called == ["captured"]
    finally:
        loop.close()


def test_threadsafe_publications_merge_before_ready_snapshot() -> None:
    loop = WebRTCSelectorEventLoop()
    trace: list[str] = []
    try:
        thread = threading.Thread(
            target=lambda: loop.call_soon_threadsafe(trace.append, "published")
        )
        thread.start()
        thread.join()
        loop.call_soon(trace.append, "local")
        loop._run_once()
        assert trace == ["local", "published"]
    finally:
        loop.close()


def test_packet_pool_enforces_capacity_and_release_once() -> None:
    pool = PacketPool(1, buffer_size=32)
    buffer = pool.acquire()
    assert pool.available == 0
    pool.release(buffer)
    assert pool.available == 1
    try:
        pool.release(buffer)
    except ValueError as exc:
        assert "already released" in str(exc)
    else:
        raise AssertionError("duplicate packet release was accepted")


def test_datagram_drain_is_packet_budget_bounded_and_reschedules() -> None:
    config = LoopConfig(receive_packet_budget=2, receive_time_budget_us=10_000)
    loop = WebRTCSelectorEventLoop(config)

    class FakeTransport:
        remaining = 5
        delivered = 0
        rescheduled = 0

        def receive_one(self) -> object | None:
            if self.remaining == 0:
                return None
            self.remaining -= 1
            return object()

        def deliver(self, packet: object) -> None:
            del packet
            self.delivered += 1

        def request_reschedule(self) -> None:
            self.rescheduled += 1

    transport = FakeTransport()
    try:
        loop._datagrams.drain_socket(loop, transport)  # type: ignore[arg-type]
        assert transport.delivered == 2
        assert transport.remaining == 3
        # Exhausting the packet budget yields naturally; selector readiness
        # schedules the next bounded activation.
        assert transport.rescheduled == 0
    finally:
        loop.close()


def test_datagram_registration_generation_rejects_stale_ready_callback() -> None:
    loop = WebRTCSelectorEventLoop()

    class Protocol:
        def datagram_received(self, data: bytes, address: object) -> None:
            del data, address

    first_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    second_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        first = loop._datagrams.register(loop, first_socket, Protocol())
        descriptor = first._descriptor
        generation = first._generation
        loop._datagrams.unregister(first)
        assert not loop._datagrams._is_current(first, generation)

        # Calling the already-queued callback is harmless after removal.  It
        # cannot receive from or remove a replacement registration.
        loop._datagrams.drain_socket(loop, first, generation)
        assert descriptor not in loop._datagrams._registrations

        second = loop._datagrams.register(loop, second_socket, Protocol())
        second_generation = second._generation
        loop._datagrams.drain_socket(loop, first, generation)
        assert loop._datagrams._is_current(second, second_generation)
        loop._datagrams.unregister(second)
    finally:
        first_socket.close()
        second_socket.close()
        loop.close()


def test_lifecycle_state_machine_is_monotonic() -> None:
    lifecycle = LoopLifecycle()
    assert lifecycle.state is LoopState.OPEN
    assert lifecycle.begin_close()
    assert not lifecycle.begin_close()
    assert lifecycle.begin_draining()
    assert lifecycle.finish_close()
    assert lifecycle.state is LoopState.CLOSED
