"""Differential semantics for the compiled event-loop source contract."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import contextvars
import threading
from typing import Any

import pytest

from webrtc.compiler import event_loop as reference_event_loop


LoopFactory = Callable[[], asyncio.AbstractEventLoop]


def _close(loop: asyncio.AbstractEventLoop) -> None:
    if not loop.is_closed():
        loop.close()


def _scheduling_trace(factory: LoopFactory) -> dict[str, Any]:
    loop = factory()
    trace: list[object] = []
    token = contextvars.ContextVar("event-loop-differential", default="outer")
    contexts: list[str] = []
    errors: list[tuple[str, str]] = []
    try:
        def first() -> None:
            trace.append("first")
            loop.call_soon(trace.append, "next-cycle")

        loop.call_soon(first)
        loop.call_soon(trace.append, "second")
        loop._run_once()  # type: ignore[attr-defined]
        after_first_cycle = tuple(trace)
        loop._run_once()  # type: ignore[attr-defined]

        deadline = loop.time()
        cancelled = loop.call_at(deadline, trace.append, "cancelled")
        cancelled.cancel()
        loop.call_at(deadline, trace.append, "timer-a")
        loop.call_at(deadline, trace.append, "timer-b")
        loop._run_once()  # type: ignore[attr-defined]

        callback_context = contextvars.copy_context()
        callback_context.run(token.set, "captured")
        loop.call_soon(
            lambda: contexts.append(token.get()),
            context=callback_context,
        )
        token.set("mutated-after-schedule")
        loop._run_once()  # type: ignore[attr-defined]

        def exception_handler(
            _loop: asyncio.AbstractEventLoop, context: dict[str, Any]
        ) -> None:
            exception = context.get("exception")
            errors.append(
                (
                    type(exception).__name__,
                    str(exception),
                )
            )

        def fail() -> None:
            raise LookupError("scheduled failure")

        loop.set_exception_handler(exception_handler)
        loop.set_debug(True)
        loop.call_soon(fail)
        loop._run_once()  # type: ignore[attr-defined]
        return {
            "trace": tuple(trace),
            "after_first_cycle": after_first_cycle,
            "contexts": tuple(contexts),
            "errors": tuple(errors),
            "debug": loop.get_debug(),
            "cancelled_count": getattr(loop, "_timer_cancelled_count"),
        }
    finally:
        _close(loop)


def _threadsafe_trace(factory: LoopFactory) -> tuple[str, ...]:
    loop = factory()
    trace: list[str] = []
    scheduled = threading.Event()

    def submit() -> None:
        loop.call_soon_threadsafe(trace.append, "thread")
        loop.call_soon_threadsafe(loop.stop)
        scheduled.set()

    thread = threading.Thread(target=submit, name="event-loop-differential")
    thread.start()
    try:
        assert scheduled.wait(timeout=5)
        loop.run_forever()
        return tuple(trace)
    finally:
        thread.join(timeout=5)
        _close(loop)


def _executor_trace(factory: LoopFactory) -> tuple[int, str]:
    loop = factory()
    try:
        future = loop.run_in_executor(None, lambda: (42, threading.current_thread().name))
        value, thread_name = loop.run_until_complete(future)
        loop.run_until_complete(loop.shutdown_default_executor())
        return value, "thread" if thread_name != threading.current_thread().name else "main"
    finally:
        _close(loop)


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, received: asyncio.Future[bytes]) -> None:
        self.received = received

    def datagram_received(self, data: bytes, addr: object) -> None:
        del addr
        if not self.received.done():
            self.received.set_result(data)


def _udp_trace(factory: LoopFactory) -> bytes:
    loop = factory()

    async def exchange() -> bytes:
        received: asyncio.Future[bytes] = loop.create_future()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramProtocol(received),
            local_addr=("127.0.0.1", 0),
        )
        try:
            address = transport.get_extra_info("sockname")
            transport.sendto(b"compiled-loop-udp", address)
            return await asyncio.wait_for(received, timeout=2)
        finally:
            transport.close()
            await asyncio.sleep(0)

    try:
        return loop.run_until_complete(exchange())
    finally:
        _close(loop)


@pytest.mark.parametrize(
    "exercise",
    (_scheduling_trace, _threadsafe_trace, _executor_trace, _udp_trace),
    ids=("scheduling", "threadsafe", "executor", "udp"),
)
def test_reference_loop_matches_stock_asyncio(
    exercise: Callable[[LoopFactory], object],
) -> None:
    assert exercise(reference_event_loop.new_event_loop) == exercise(
        asyncio.new_event_loop
    )


def test_ready_callbacks_use_a_snapshot() -> None:
    result = _scheduling_trace(reference_event_loop.new_event_loop)
    assert result["after_first_cycle"] == ("first", "second")
    assert result["trace"][:3] == ("first", "second", "next-cycle")
    assert "cancelled" not in result["trace"]
    assert result["contexts"] == ("captured",)
    assert result["errors"] == (("LookupError", "scheduled failure"),)


def test_reference_factory_returns_fresh_selector_loops() -> None:
    first = reference_event_loop.new_event_loop()
    second = reference_event_loop.new_event_loop()
    try:
        assert isinstance(first, reference_event_loop.WebRTCSelectorEventLoop)
        assert isinstance(first, asyncio.SelectorEventLoop)
        assert first is not second
    finally:
        _close(first)
        _close(second)
