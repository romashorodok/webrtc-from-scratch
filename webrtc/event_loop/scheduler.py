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

if TYPE_CHECKING:
    from .loop import LoopConfig, WebRTCSelectorEventLoop

logger = logging.getLogger("asyncio")


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class ReactorScheduler:
    __slots__ = ("_config",)

    def __init__(self, config: "LoopConfig") -> None:
        self._config = config

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor", suspend=pymeta.never))
    def remove_cancelled_timers(self, loop: "WebRTCSelectorEventLoop") -> None:
        scheduled = loop._scheduled
        if (
            len(scheduled) > _MIN_SCHEDULED_TIMER_HANDLES
            and loop._timer_cancelled_count / len(scheduled)
            > _MIN_CANCELLED_TIMER_HANDLES_FRACTION
        ):
            retained = []
            for handle in scheduled:
                if handle._cancelled:
                    handle._scheduled = False
                else:
                    retained.append(handle)
            scheduled[:] = retained
            heapq.heapify(scheduled)
            loop._timer_cancelled_count = 0
            return
        while scheduled and scheduled[0]._cancelled:
            handle = heapq.heappop(scheduled)
            handle._scheduled = False
            loop._timer_cancelled_count -= 1

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor", suspend=pymeta.never))
    def compute_timeout(self, loop: "WebRTCSelectorEventLoop") -> float | None:
        if loop._ready or loop._stopping:
            return 0.0
        if not loop._scheduled:
            return None
        return min(
            max(0.0, loop._scheduled[0]._when - loop.time()),
            MAXIMUM_SELECT_TIMEOUT,
        )

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

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor", suspend=pymeta.never))
    def promote_due_timers(self, loop: "WebRTCSelectorEventLoop") -> None:
        now = loop.time()
        deadline = now + max(loop._clock_resolution, math.ulp(now))
        while loop._scheduled:
            handle = loop._scheduled[0]
            if handle._when >= deadline:
                break
            handle = heapq.heappop(loop._scheduled)
            handle._scheduled = False
            loop._ready.append(handle)

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor", suspend=pymeta.never))
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

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor", suspend=pymeta.never))
    def run_once(self, loop: "WebRTCSelectorEventLoop") -> None:
        self.remove_cancelled_timers(loop)
        loop._command_inbox.merge_into(loop)
        timeout = self.compute_timeout(loop)
        events = loop._selector.select(timeout)
        self.process_selector_events(loop, events)
        self.promote_due_timers(loop)
        self.run_ready_snapshot(loop)
