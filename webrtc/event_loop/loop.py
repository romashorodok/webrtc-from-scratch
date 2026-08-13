"""Complete executable Python specification of the custom selector loop."""

from __future__ import annotations

import asyncio
import contextvars
import heapq

from enum import IntEnum
from typing import Annotated, Callable

import pymeta
from pymeta import bounded, exact_type, float_, owned_by, sint, storage
from pymeta.concurrent import atomic
from pymeta.cpython import pinned_semantics

from .atomic import LockedAtomic
from .config import LoopConfig
from .commands import (
    Command,
    CommandInbox,
    CommandKind,
    PublishedHandle,
    dispatch_command,
)
from .datagrams import DatagramReactor
from .scheduler import ReactorScheduler
from .workers import PacketWorkerPool


class LoopState(IntEnum):
    OPEN = 0
    CLOSING = 1
    DRAINING = 2
    CLOSED = 3


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class LoopLifecycle:
    __slots__ = ("_state",)

    _state: Annotated[
        LockedAtomic[LoopState],
        atomic[pymeta.uint[32]] | owned_by("shared"),
    ]

    def __init__(self) -> None:
        self._state = LockedAtomic(LoopState.OPEN)

    @pymeta.region(pymeta.required, effects=pymeta.effects(writes={"self._state"}))
    def begin_close(self) -> bool:
        _, changed = self._state.compare_exchange(
            LoopState.OPEN, LoopState.CLOSING
        )
        return changed

    @pymeta.region(pymeta.required, effects=pymeta.effects(writes={"self._state"}))
    def begin_draining(self) -> bool:
        _, changed = self._state.compare_exchange(
            LoopState.CLOSING, LoopState.DRAINING
        )
        return changed

    @pymeta.region(pymeta.required, effects=pymeta.effects(writes={"self._state"}))
    def finish_close(self) -> bool:
        _, changed = self._state.compare_exchange(
            LoopState.DRAINING, LoopState.CLOSED
        )
        return changed

    def is_open(self) -> bool:
        # Native atomic storage materializes the enum's integer value.  Value
        # comparison preserves the IntEnum contract in both the Python and
        # compiled representations; identity is not part of IntEnum semantics.
        return self._state.load() == LoopState.OPEN

    @property
    def state(self) -> LoopState:
        return self._state.load()


ReadyQueue = Annotated[
    object,
    storage.fifo | owned_by("reactor") | bounded(min=0),
]
TimerQueue = Annotated[
    object,
    storage.min_heap(
        key="_when",
        ordering=pinned_semantics("heapq"),
    )
    | owned_by("reactor"),
]
TimerCount = Annotated[
    int,
    sint[64] | storage.native_field | owned_by("reactor"),
]
ClockValue = Annotated[
    float,
    float_[64] | storage.native_field | owned_by("reactor"),
]


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class WebRTCSelectorEventLoop(asyncio.SelectorEventLoop):
    """Composition-oriented selector loop written entirely in Python."""

    # Keep the complete representation facts at the field declaration.  The
    # aliases above remain useful to ordinary Python type consumers, while an
    # ahead-of-time frontend can discover the facts without executing imports
    # or having to treat a module-level alias as layout authority.
    _ready: Annotated[
        object,
        storage.fifo | owned_by("reactor") | bounded(min=0),
    ]
    _scheduled: Annotated[
        object,
        storage.min_heap(
            key="_when",
            ordering=pinned_semantics("heapq"),
        )
        | owned_by("reactor"),
    ]
    _timer_cancelled_count: Annotated[
        int,
        sint[64] | storage.native_field | owned_by("reactor"),
    ]
    _clock_resolution: Annotated[
        float,
        float_[64] | storage.native_field | owned_by("reactor"),
    ]
    # ``SelectorEventLoop.__init__`` creates these attributes on the base
    # instance.  Declare them here as boxed native fields so a generated
    # subtype can install its own data descriptors before delegating to that
    # initializer.  Boxed storage is intentional: CPython permits callers to
    # replace each value with an arbitrary object.
    _selector: Annotated[
        object,
        owned_by("reactor"),
    ]
    _debug: Annotated[
        object,
        owned_by("reactor"),
    ]
    _stopping: Annotated[
        object,
        owned_by("reactor"),
    ]
    _current_handle: Annotated[
        object,
        owned_by("reactor"),
    ]
    slow_callback_duration: Annotated[
        object,
        owned_by("reactor"),
    ]
    _scheduler: Annotated[
        ReactorScheduler, exact_type(ReactorScheduler) | owned_by("reactor")
    ]
    _command_inbox: Annotated[
        CommandInbox, exact_type(CommandInbox) | owned_by("reactor")
    ]
    _datagrams: Annotated[
        DatagramReactor, exact_type(DatagramReactor) | owned_by("reactor")
    ]
    _packet_workers: Annotated[
        PacketWorkerPool, exact_type(PacketWorkerPool) | owned_by("reactor")
    ]
    _lifecycle: Annotated[LoopLifecycle, exact_type(LoopLifecycle)]

    def __init__(self, config: LoopConfig | None = None) -> None:
        super().__init__()
        self._config = config or LoopConfig()
        self._scheduler = ReactorScheduler(self._config)
        self._command_inbox = CommandInbox(self._config.command_capacity)
        self._datagrams = DatagramReactor(self._config)
        self._lifecycle = LoopLifecycle()
        self._packet_workers = PacketWorkerPool(self._config, self)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._scheduler"},
            writes={
                "self._ready",
                "self._scheduled",
                "self._timer_cancelled_count",
            },
            owner="reactor",
            suspend=pymeta.never,
        ),
    )
    def _run_once(self) -> None:
        self._scheduler.run_once(self)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(writes={"self._ready"}, owner="reactor"),
    )
    def call_soon(
        self,
        callback: Callable[..., object],
        *args: object,
        context: contextvars.Context | None = None,
    ) -> asyncio.Handle:
        self._check_closed()
        if self._debug:
            self._check_thread()
            self._check_callback(callback, "call_soon")
        handle = self._call_soon(callback, args, context)
        if handle._source_traceback:
            handle._source_traceback.pop()
        return handle

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(writes={"self._ready"}, owner="reactor"),
    )
    def _call_soon(
        self,
        callback: Callable[..., object],
        args: tuple[object, ...],
        context: contextvars.Context | None,
    ) -> asyncio.Handle:
        handle = asyncio.Handle(callback, args, self, context=context)
        if handle._source_traceback:
            handle._source_traceback.pop()
        self._ready.append(handle)
        return handle

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(writes={"self._scheduled"}, owner="reactor"),
    )
    def call_at(
        self,
        when: float,
        callback: Callable[..., object],
        *args: object,
        context: contextvars.Context | None = None,
    ) -> asyncio.TimerHandle:
        if when is None:
            raise TypeError("when cannot be None")
        self._check_closed()
        if self._debug:
            self._check_thread()
            self._check_callback(callback, "call_at")
        timer = self._call_at(when, callback, args, context)
        if timer._source_traceback:
            timer._source_traceback.pop()
        return timer

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(writes={"self._scheduled"}, owner="reactor"),
    )
    def _call_at(
        self,
        when: float,
        callback: Callable[..., object],
        args: tuple[object, ...],
        context: contextvars.Context | None,
    ) -> asyncio.TimerHandle:
        timer = asyncio.TimerHandle(when, callback, args, self, context=context)
        if timer._source_traceback:
            timer._source_traceback.pop()
        heapq.heappush(self._scheduled, timer)
        timer._scheduled = True
        return timer

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(writes={"self._scheduled"}, owner="reactor"),
    )
    def call_later(
        self,
        delay: float,
        callback: Callable[..., object],
        *args: object,
        context: contextvars.Context | None = None,
    ) -> asyncio.TimerHandle:
        if delay is None:
            raise TypeError("delay must not be None")
        self._check_closed()
        if self._debug:
            self._check_thread()
            self._check_callback(callback, "call_at")
        timer = self._call_at(self.time() + delay, callback, args, context)
        if timer._source_traceback:
            timer._source_traceback.pop()
        return timer

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(owner="shared", synchronize=pymeta.synchronize),
    )
    def call_soon_threadsafe(
        self,
        callback: Callable[..., object],
        *args: object,
        context: contextvars.Context | None = None,
    ) -> PublishedHandle:
        self._check_closed()
        self._check_callback(callback, "call_soon_threadsafe")
        if not self._lifecycle.is_open():
            raise RuntimeError("event loop is closing")
        handle = PublishedHandle(callback, args, self, context)
        self._command_inbox.publish(
            self, Command(CommandKind.CALLBACK, handle)
        )
        return handle

    def close(self) -> None:
        if self.is_running():
            raise RuntimeError("Cannot close a running event loop")
        if self.is_closed():
            return
        if not self._lifecycle.begin_close():
            return
        accepted = self._command_inbox.close_and_drain()
        self._lifecycle.begin_draining()
        # Closing an asyncio loop never runs pending callbacks.  Dispatching
        # the accepted snapshot transfers every command to its normal
        # reactor-owned destination; ``super().close()`` then performs the
        # standard cancellation/reference release for ready callbacks.
        for command in accepted:
            dispatch_command(self, command)
        self._packet_workers.close()
        self._datagrams.close()
        asyncio.SelectorEventLoop.close(self)
        self._lifecycle.finish_close()


def new_event_loop(
    *,
    packet_workers: int = 0,
    packet_queue_capacity: int = 2048,
    receive_packet_budget: int = 32,
    receive_time_budget_us: int = 100,
) -> asyncio.AbstractEventLoop:
    return WebRTCSelectorEventLoop(
        LoopConfig(
            packet_workers=packet_workers,
            packet_queue_capacity=packet_queue_capacity,
            receive_packet_budget=receive_packet_budget,
            receive_time_budget_us=receive_time_budget_us,
        )
    )
