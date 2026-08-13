"""Typed cross-thread publication for the reference event loop."""

from __future__ import annotations

import asyncio
import contextvars
import queue

from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Annotated, TYPE_CHECKING, Any, Callable

import pymeta
from pymeta.concurrent import BoundedQueue, atomic

from .atomic import LockedAtomic

if TYPE_CHECKING:
    from .loop import WebRTCSelectorEventLoop


class CommandKind(Enum):
    CALLBACK = auto()
    WORKER_RESULT = auto()
    REGISTER_FD = auto()
    REMOVE_FD = auto()
    STOP = auto()


@pymeta.record(abi="webrtc.event_loop.command.v1")
@dataclass(frozen=True, slots=True)
class Command:
    kind: CommandKind
    payload: object


class PublishedState(IntEnum):
    PENDING = 0
    CANCELLED = 1
    CLAIMED = 2
    DONE = 3


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class PublishedHandle:
    """Cancellation/claim boundary returned by ``call_soon_threadsafe``."""

    __slots__ = ("_handle", "_state")

    _state: Annotated[
        LockedAtomic[PublishedState],
        atomic[pymeta.uint[32]] | pymeta.owned_by("shared"),
    ]

    def __init__(
        self,
        callback: Callable[..., object],
        args: tuple[object, ...],
        loop: asyncio.AbstractEventLoop,
        context: contextvars.Context | None,
    ) -> None:
        self._state = LockedAtomic(PublishedState.PENDING)
        self._handle = asyncio.Handle(callback, args, loop, context=context)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            writes={"self._state"}, synchronize=pymeta.synchronize
        ),
    )
    def cancel(self) -> None:
        _, changed = self._state.compare_exchange(
            PublishedState.PENDING, PublishedState.CANCELLED
        )
        if changed:
            self._handle.cancel()

    def cancelled(self) -> bool:
        return self._state.load() is PublishedState.CANCELLED

    @property
    def _cancelled(self) -> bool:
        # asyncio's ready FIFO reads this private exact-handle field.  Exposing
        # the same shape keeps the wrapper compatible with the scheduler.
        return self.cancelled()

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            writes={"self._state"}, synchronize=pymeta.synchronize
        ),
    )
    def claim(self) -> bool:
        _, claimed = self._state.compare_exchange(
            PublishedState.PENDING, PublishedState.CLAIMED
        )
        return claimed

    def _run(self) -> None:
        if not self.claim():
            return
        try:
            self._handle._run()
        finally:
            self._state.store(PublishedState.DONE)

    def __repr__(self) -> str:
        return repr(self._handle)


@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class CommandInbox:
    """A Go-channel-style bounded MPSC inbox.

    Publication is nonblocking: a full inbox raises ``RuntimeError`` and a
    closed inbox rejects every new command.  ``close_and_drain`` first closes
    producer admission, waits for any publication already inside the
    reference queue's admission critical section, and then returns every
    accepted command as one stable reactor-owned snapshot.
    """

    __slots__ = ("_capacity", "_closed", "_notified", "_queue")

    _queue: Annotated[
        BoundedQueue[Command],
        pymeta.mpsc
        | pymeta.bounded_queue(capacity="self._capacity")
        | pymeta.owned_by("reactor"),
    ]
    _notified: Annotated[
        LockedAtomic[bool],
        atomic[pymeta.uint[32]]
        | pymeta.coalesced_notification
        | pymeta.owned_by("shared"),
    ]
    _closed: Annotated[
        LockedAtomic[bool],
        atomic[pymeta.uint[32]] | pymeta.owned_by("shared"),
    ]

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("command capacity must be positive")
        self._capacity = capacity
        self._queue: BoundedQueue[Command] = BoundedQueue(capacity)
        self._closed = LockedAtomic(False)
        self._notified = LockedAtomic(False)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._queue", "self._notified"},
            writes={"self._queue", "self._notified"},
            owner="shared",
            suspend=pymeta.never,
            synchronize=pymeta.synchronize,
        ),
    )
    def publish(self, loop: "WebRTCSelectorEventLoop", command: Command) -> None:
        try:
            self._queue.put_nowait(command)
        except queue.Full as exc:
            raise RuntimeError("event-loop command inbox is full") from exc
        except RuntimeError as exc:
            # Exact BoundedQueue publication raises RuntimeError only after
            # close has linearized under its admission lock.
            raise RuntimeError("event loop is closing") from exc
        _, should_wake = self._notified.compare_exchange(False, True)
        if should_wake:
            loop._write_to_self()

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._queue"},
            writes={"self._queue"},
            owner="reactor",
            suspend=pymeta.never,
        ),
    )
    def drain_snapshot(self) -> tuple[Command, ...]:
        commands: list[Command] = []
        for _ in range(self._queue.qsize()):
            try:
                commands.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return tuple(commands)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._queue", "self._notified"},
            writes={"self._queue", "self._notified"},
            owner="reactor",
            suspend=pymeta.never,
            synchronize=pymeta.synchronize,
        ),
    )
    def close_and_drain(self) -> tuple[Command, ...]:
        """Reject new publications and transfer all accepted commands."""
        self._closed.compare_exchange(False, True)
        self._queue.close()
        commands = []
        while not self._queue.empty():
            commands.append(self._queue.get_nowait())
        self._notified.store(False)
        return tuple(commands)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._queue"},
            writes={"self._queue", "loop._ready"},
            owner="reactor",
            suspend=pymeta.never,
        ),
    )
    def merge_into(self, loop: "WebRTCSelectorEventLoop") -> None:
        # Drain the fixed native MPSC snapshot directly into the loop FIFO.
        # Keeping this spelling in ordinary Python preserves the reference
        # implementation while allowing the direct graph to fuse the queue
        # transfer without constructing the public drain_snapshot tuple.
        for _ in range(self._queue.qsize()):
            command = self._queue.get_nowait()
            self.dispatch(loop, command)
        self._notified.store(False)
        # Close the enqueue/reset race: a producer that observed the old true
        # pending bit did not write the self-pipe.
        if not self._queue.empty():
            _, should_wake = self._notified.compare_exchange(False, True)
            if should_wake:
                loop._write_to_self()

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            writes={"loop._ready"}, owner="reactor", suspend=pymeta.never
        ),
    )
    def dispatch(
        self, loop: "WebRTCSelectorEventLoop", command: Command
    ) -> None:
        if command.kind in (CommandKind.CALLBACK, CommandKind.WORKER_RESULT):
            loop._ready.append(command.payload)
        else:
            dispatch_control_command(loop, command)

    @pymeta.region(
        pymeta.required,
        effects=pymeta.effects(
            reads={"self._queue"},
            owner="reactor",
            suspend=pymeta.never,
        ),
    )
    def empty(self) -> bool:
        return self._queue.empty()

    @property
    def closed(self) -> bool:
        return self._queue.closed


def dispatch_command(loop: "WebRTCSelectorEventLoop", command: Command) -> None:
    """Compatibility entry point for callers outside the compiled graph."""
    loop._command_inbox.dispatch(loop, command)


def dispatch_control_command(
    loop: "WebRTCSelectorEventLoop", command: Command
) -> None:
    """Generic boundary for the uncommon descriptor-control commands."""
    if command.kind is CommandKind.REGISTER_FD:
        fd, callback, args = command.payload  # type: ignore[misc]
        loop.add_reader(fd, callback, *args)
    elif command.kind is CommandKind.REMOVE_FD:
        loop.remove_reader(command.payload)
    elif command.kind is CommandKind.STOP:
        loop.stop()
    else:
        raise ValueError(f"unsupported event-loop command: {command.kind!r}")
