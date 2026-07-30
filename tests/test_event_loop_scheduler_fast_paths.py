"""Differential guards for Stage-3 native scheduler paths."""

from __future__ import annotations

import asyncio
import contextvars
import heapq
import math
import threading
import time
from collections import deque
from pathlib import Path

import pytest

from webrtc.compiler import event_loop as reference_event_loop
from webrtc.compiler.module_compiler import compile_module
from webrtc.compiler.native_artifact import (
    NativeClassRequirement,
    NativeModuleRequirements,
    load_native_artifact,
)


@pytest.fixture(scope="module")
def native_module(tmp_path_factory: pytest.TempPathFactory) -> object:
    source = Path(reference_event_loop.__file__)
    artifact = compile_module(
        source, tmp_path_factory.mktemp("event-loop-stage3")
    ).artifact_path
    return load_native_artifact(
        artifact,
        NativeModuleRequirements(
            "event_loop_native",
            source,
            ("new_event_loop",),
            {
                "WebRTCSelectorEventLoop": NativeClassRequirement(
                    asyncio.SelectorEventLoop, ("_run_once",)
                )
            },
        ),
    )


def _factories(native_module: object) -> tuple[object, object]:
    return (
        reference_event_loop.new_event_loop,
        native_module.new_event_loop,  # type: ignore[attr-defined]
    )


def test_list_and_deque_subclasses_use_generic_protocol(
    native_module: object,
) -> None:
    class Scheduled(list[asyncio.TimerHandle]):
        def __init__(self, values: list[asyncio.TimerHandle]) -> None:
            super().__init__(values)
            self.length_calls = 0
            self.item_calls = 0

        def __len__(self) -> int:
            self.length_calls += 1
            return super().__len__()

        def __getitem__(self, key: object) -> object:
            self.item_calls += 1
            return super().__getitem__(key)  # type: ignore[index]

    class Ready(deque[asyncio.Handle]):
        def __init__(self, values: deque[asyncio.Handle]) -> None:
            super().__init__(values)
            self.append_calls = 0
            self.popleft_calls = 0

        def append(self, value: asyncio.Handle) -> None:
            self.append_calls += 1
            super().append(value)

        def popleft(self) -> asyncio.Handle:
            self.popleft_calls += 1
            return super().popleft()

    outcomes: list[tuple[list[str], int, int, int, int]] = []
    for factory in _factories(native_module):
        loop = factory()  # type: ignore[operator]
        trace: list[str] = []
        try:
            loop._scheduled = Scheduled(loop._scheduled)
            loop._ready = Ready(loop._ready)
            loop.call_at(loop.time(), trace.append, "timer")
            loop.call_soon(trace.append, "ready")
            loop._run_once()
            outcomes.append(
                (
                    trace,
                    loop._scheduled.length_calls,
                    loop._scheduled.item_calls,
                    loop._ready.append_calls,
                    loop._ready.popleft_calls,
                )
            )
        finally:
            loop.close()

    assert outcomes[0][0] == outcomes[1][0] == ["ready", "timer"]
    for outcome in outcomes:
        assert outcome[1] > 0
        assert outcome[2] > 0
        assert outcome[3] >= 2
        assert outcome[4] == 2


def test_timer_handle_subclass_and_cancellation_fall_back(
    native_module: object,
) -> None:
    class DerivedTimer(asyncio.TimerHandle):
        reads = 0

        @property
        def _when(self) -> float:
            type(self).reads += 1
            return self._derived_when

        @_when.setter
        def _when(self, value: float) -> None:
            self._derived_when = value

    outcomes: list[tuple[list[str], int]] = []
    for factory in _factories(native_module):
        DerivedTimer.reads = 0
        loop = factory()  # type: ignore[operator]
        trace: list[str] = []
        try:
            when = loop.time()
            cancelled = DerivedTimer(when, trace.append, ("cancelled",), loop)
            active = DerivedTimer(when, trace.append, ("active",), loop)
            for handle in (cancelled, active):
                handle._scheduled = True
                heapq.heappush(loop._scheduled, handle)
            cancelled.cancel()
            loop._run_once()
            outcomes.append((trace, DerivedTimer.reads))
        finally:
            loop.close()

    assert outcomes[0][0] == outcomes[1][0] == ["active"]
    assert outcomes[0][1] > 0
    assert outcomes[1][1] > 0


def test_overridden_time_and_debug_timing_match_reference(
    native_module: object,
) -> None:
    outcomes: list[tuple[list[str], list[float]]] = []
    for factory in _factories(native_module):
        loop = factory()  # type: ignore[operator]
        trace: list[str] = []
        readings = iter((10.0, 20.0, 20.25))
        seen: list[float] = []

        def overridden_time() -> float:
            value = next(readings)
            seen.append(value)
            return value

        try:
            loop.time = overridden_time
            loop.set_debug(True)
            loop.slow_callback_duration = 1.0
            loop.call_soon(trace.append, "ready")
            loop._run_once()
            outcomes.append((trace, seen))
        finally:
            loop.close()

    assert outcomes == [
        (["ready"], [10.0, 20.0, 20.25]),
        (["ready"], [10.0, 20.0, 20.25]),
    ]


def test_module_level_clock_and_ulp_overrides_disable_native_clock(
    native_module: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    loops = [factory() for factory in _factories(native_module)]  # type: ignore[operator]
    monotonic_calls = 0
    ulp_calls = 0

    def monotonic() -> float:
        nonlocal monotonic_calls
        monotonic_calls += 1
        return 50.0

    def ulp(_value: float) -> float:
        nonlocal ulp_calls
        ulp_calls += 1
        return 0.0

    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(math, "ulp", ulp)
    traces: list[list[str]] = []
    try:
        for loop in loops:
            trace: list[str] = []
            loop.call_soon(trace.append, "ready")
            loop._run_once()
            traces.append(trace)
    finally:
        for loop in loops:
            loop.close()

    assert traces == [["ready"], ["ready"]]
    assert monotonic_calls == 2
    assert ulp_calls == 2


def test_equal_deadlines_context_and_threadsafe_wakeup_match(
    native_module: object,
) -> None:
    outcomes: list[tuple[list[str], list[str]]] = []
    marker = contextvars.ContextVar("stage3-marker", default="outer")
    for factory in _factories(native_module):
        loop = factory()  # type: ignore[operator]
        timers: list[str] = []
        ready: list[str] = []
        try:
            deadline = loop.time()
            for label in ("a", "b", "c"):
                loop.call_at(deadline, timers.append, label)
            context = contextvars.copy_context()
            context.run(marker.set, "threadsafe")
            thread = threading.Thread(
                target=lambda: loop.call_soon_threadsafe(
                    lambda: ready.append(marker.get()), context=context
                )
            )
            thread.start()
            thread.join()
            loop._run_once()
            outcomes.append((timers, ready))
        finally:
            loop.close()

    assert outcomes[0] == outcomes[1]
    assert sorted(outcomes[0][0]) == ["a", "b", "c"]
    assert outcomes[0][1] == ["threadsafe"]
