"""Reactor-owned scheduling algorithms for the reference event loop."""

from __future__ import annotations

import asyncio
import heapq
import logging
import math
import selectors

from asyncio.base_events import (
    MAXIMUM_SELECT_TIMEOUT,
    _MIN_CANCELLED_TIMER_HANDLES_FRACTION,
    _MIN_SCHEDULED_TIMER_HANDLES,
    _format_handle,
)
from typing import TYPE_CHECKING

import pymeta
from pymeta.cpython import pinned_semantics

if TYPE_CHECKING:
    from .loop import LoopConfig, WebRTCSelectorEventLoop

logger = logging.getLogger("asyncio")


def _compact_cancelled_timers(scheduled: list[asyncio.TimerHandle]) -> int:
    """Stable Python reference for the native in-place heap compactor."""
    retained = []
    removed = 0
    for handle in scheduled:
        if handle._cancelled:
            handle._scheduled = False
            removed += 1
        else:
            retained.append(handle)
    scheduled[:] = retained
    heapq.heapify(scheduled)
    return removed


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class ReactorScheduler:
    __slots__ = ("_config",)

    def __init__(self, config: "LoopConfig") -> None:
        self._config = config

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor", suspend=pymeta.never))
    def remove_cancelled_timers(self, loop: "WebRTCSelectorEventLoop") -> None:
        if (
            len(loop._scheduled) > _MIN_SCHEDULED_TIMER_HANDLES
            and loop._timer_cancelled_count / len(loop._scheduled)
            > _MIN_CANCELLED_TIMER_HANDLES_FRACTION
        ):
            _compact_cancelled_timers(loop._scheduled)
            loop._timer_cancelled_count = 0
            return
        while loop._scheduled and loop._scheduled[0]._cancelled:
            handle = heapq.heappop(loop._scheduled)
            handle._scheduled = False
            loop._timer_cancelled_count = loop._timer_cancelled_count - 1

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="reactor", suspend=pymeta.never),
        call_returns={
            "loop.time": pinned_semantics("monotonic_clock"),
        },
    )
    def compute_timeout(self, loop: "WebRTCSelectorEventLoop") -> float | None:
        if loop._ready or loop._stopping:
            return 0.0
        if not loop._scheduled:
            return None
        timeout = loop._scheduled[0]._when - loop.time()
        if not timeout > 0.0:
            timeout = 0.0
        if timeout > MAXIMUM_SELECT_TIMEOUT:
            timeout = MAXIMUM_SELECT_TIMEOUT
        return timeout

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor", suspend=pymeta.never))
    def process_selector_events(
        self,
        loop: "WebRTCSelectorEventLoop",
        events: list[tuple[selectors.SelectorKey, int]],
    ) -> None:
        for key, mask in events:
            reader, writer = key.data
            if mask & selectors.EVENT_READ and reader is not None:
                if reader._cancelled:
                    loop._remove_reader(key.fileobj)
                else:
                    loop._ready.append(reader)
            if mask & selectors.EVENT_WRITE and writer is not None:
                if writer._cancelled:
                    loop._remove_writer(key.fileobj)
                else:
                    loop._ready.append(writer)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="reactor", suspend=pymeta.never),
        call_returns={
            "loop.time": pinned_semantics("monotonic_clock"),
            "math.ulp": pinned_semantics("float_ulp"),
        },
    )
    def promote_due_timers(self, loop: "WebRTCSelectorEventLoop") -> None:
        now = loop.time()
        ulp = math.ulp(now)
        if ulp > loop._clock_resolution:
            deadline = now + ulp
        else:
            deadline = now + loop._clock_resolution
        while loop._scheduled:
            if loop._scheduled[0]._when >= deadline:
                break
            handle = heapq.heappop(loop._scheduled)
            handle._scheduled = False
            loop._ready.append(handle)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="reactor", suspend=pymeta.never),
        call_returns={"loop.time": pinned_semantics("monotonic_clock")},
    )
    def run_ready_snapshot(self, loop: "WebRTCSelectorEventLoop") -> None:
        count = len(loop._ready)
        debug = loop._debug
        for _ in range(count):
            handle = loop._ready.popleft()
            if handle._cancelled:
                continue
            if debug:
                try:
                    loop._current_handle = handle
                    started = loop.time()
                    handle._run()
                    elapsed = loop.time() - started
                    if elapsed >= loop.slow_callback_duration:
                        logger.warning(
                            "Executing %s took %.3f seconds",
                            _format_handle(handle),
                            elapsed,
                        )
                finally:
                    loop._current_handle = None
            else:
                handle._run()

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="reactor", suspend=pymeta.never),
        call_returns={
            "loop.time": pinned_semantics("monotonic_clock"),
            "math.ulp": pinned_semantics("float_ulp"),
        },
    )
    def run_once(self, loop: "WebRTCSelectorEventLoop") -> None:
        # Keep the per-iteration scheduler graph in one required region.  The
        # component methods above remain independently callable reference
        # operations, but calling each one here would create a separate AOT
        # frame and sever scalar propagation around the selector boundary.
        if (
            len(loop._scheduled) > _MIN_SCHEDULED_TIMER_HANDLES
            and loop._timer_cancelled_count / len(loop._scheduled)
            > _MIN_CANCELLED_TIMER_HANDLES_FRACTION
        ):
            _compact_cancelled_timers(loop._scheduled)
            loop._timer_cancelled_count = 0
        else:
            while loop._scheduled and loop._scheduled[0]._cancelled:
                cancelled = heapq.heappop(loop._scheduled)
                cancelled._scheduled = False
                loop._timer_cancelled_count = loop._timer_cancelled_count - 1

        loop._command_inbox.merge_into(loop)

        if loop._ready or loop._stopping:
            timeout = 0.0
        elif not loop._scheduled:
            timeout = None
        else:
            timeout = loop._scheduled[0]._when - loop.time()
            if not timeout > 0.0:
                timeout = 0.0
            if timeout > MAXIMUM_SELECT_TIMEOUT:
                timeout = MAXIMUM_SELECT_TIMEOUT

        events = loop._selector.select(timeout)
        for key, mask in events:
            reader, writer = key.data
            if mask & selectors.EVENT_READ and reader is not None:
                if reader._cancelled:
                    loop._remove_reader(key.fileobj)
                else:
                    loop._ready.append(reader)
            if mask & selectors.EVENT_WRITE and writer is not None:
                if writer._cancelled:
                    loop._remove_writer(key.fileobj)
                else:
                    loop._ready.append(writer)

        # The common loop configuration has no packet workers.  Avoid entering
        # an otherwise empty required region on every selector iteration; the
        # immutable scheduler configuration keeps this branch stable.
        if self._config.packet_workers:
            loop._packet_workers.drain_results()

        now = loop.time()
        ulp = math.ulp(now)
        if ulp > loop._clock_resolution:
            deadline = now + ulp
        else:
            deadline = now + loop._clock_resolution
        while loop._scheduled:
            if loop._scheduled[0]._when >= deadline:
                break
            handle = heapq.heappop(loop._scheduled)
            handle._scheduled = False
            loop._ready.append(handle)

        self.run_ready_snapshot(loop)
