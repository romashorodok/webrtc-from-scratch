"""Concurrency descriptors and their real, lock-backed Python behavior."""

from __future__ import annotations

from queue import Empty, Full, Queue
from threading import Lock, get_ident
from typing import Callable, Generic, TypeVar

from . import Descriptor

__all__ = [
    "AtomicValue", "BoundedQueue", "CoalescedNotification", "LockedAtomic",
    "OwnedResource", "atomic", "bounded_queue", "coalesced_notification",
    "mpsc", "owned_shard", "parallel_for", "pipeline", "sequential", "simd",
    "spmd", "spsc",
]

T = TypeVar("T")


class _AtomicFactory:
    def __getitem__(self, representation: object) -> Descriptor:
        return Descriptor(
            "atomic",
            (
                ("linearization", "compare_exchange"),
                ("memory_order", "seq_cst"),
                ("operation", "compare_exchange"),
                ("representation", representation),
                ("scope", "process"),
            ),
            "atomic",
        )


atomic = _AtomicFactory()


class _BoundedQueueFactory:
    def __call__(self, *, capacity: int | str) -> Descriptor:
        if isinstance(capacity, int):
            if isinstance(capacity, bool) or capacity <= 0:
                raise ValueError("queue capacity must be positive")
        elif not isinstance(capacity, str) or not capacity:
            raise TypeError("queue capacity must be a positive integer or source expression")
        return Descriptor(
            "bounded_queue", (("capacity", capacity),), "queue_bounds"
        )

    def __repr__(self) -> str:
        return "bounded_queue"


bounded_queue = _BoundedQueueFactory()
mpsc = Descriptor("mpsc", category="queue_topology")
spsc = Descriptor("spsc", category="queue_topology")
coalesced_notification = Descriptor(
    "coalesced_notification", category="notification"
)
sequential = Descriptor("sequential", category="execution")
simd = Descriptor("simd", category="execution")
spmd = Descriptor("spmd", category="execution")
pipeline = Descriptor("pipeline", category="execution")


def parallel_for(
    index: str,
    *,
    schedule: object,
    minimum_grain: int,
    maximum_workers: int,
    errors: object,
    nested: object,
) -> Descriptor:
    if not index:
        raise ValueError("parallel-for index must not be empty")
    if minimum_grain <= 0 or maximum_workers <= 0:
        raise ValueError("parallel-for bounds must be positive")
    return Descriptor(
        "parallel_for",
        (
            ("index", index),
            ("schedule", schedule),
            ("minimum_grain", minimum_grain),
            ("maximum_workers", maximum_workers),
            ("errors", errors),
            ("nested", nested),
        ),
        "execution",
    )


def owned_shard(
    *,
    key: str,
    workers: str | int,
    input: object | None = None,
    output: object | None = None,
    ordered: bool = True,
) -> Descriptor:
    if not key:
        raise ValueError("owned shard key must not be empty")
    return Descriptor(
        "owned_shard",
        (
            ("key", key),
            ("workers", workers),
            ("input", input),
            ("output", output),
            ("ordered", ordered),
        ),
        "execution",
    )


class AtomicValue(Generic[T]):
    """Structural base for Python atomic implementations."""

    def load(self) -> T:
        raise NotImplementedError

    def store(self, value: T) -> None:
        raise NotImplementedError

    def exchange(self, value: T) -> T:
        raise NotImplementedError

    def compare_exchange(self, expected: T, desired: T) -> tuple[T, bool]:
        raise NotImplementedError


class LockedAtomic(AtomicValue[T]):
    """Linearizable reference atomic using one ordinary Python lock."""

    def __init__(self, value: T) -> None:
        self._value = value
        self._lock = Lock()

    def load(self) -> T:
        with self._lock:
            return self._value

    def store(self, value: T) -> None:
        with self._lock:
            self._value = value

    def exchange(self, value: T) -> T:
        with self._lock:
            previous = self._value
            self._value = value
            return previous

    def fetch_add(self, value: T) -> T:
        with self._lock:
            previous = self._value
            self._value = previous + value  # type: ignore[operator]
            return previous

    def compare_exchange(self, expected: T, desired: T) -> tuple[T, bool]:
        with self._lock:
            previous = self._value
            if previous == expected:
                self._value = desired
                return previous, True
            return previous, False


class BoundedQueue(Generic[T]):
    """A checked finite FIFO with standard nonblocking queue exceptions."""

    def __init__(self, capacity: int) -> None:
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity <= 0:
            raise ValueError("queue capacity must be a positive integer")
        self.capacity = capacity
        self._queue: Queue[T] = Queue(maxsize=capacity)
        self._closed = False
        self._admission_lock = Lock()

    def put_nowait(self, value: T) -> None:
        with self._admission_lock:
            if self._closed:
                raise RuntimeError("queue is closed")
            self._queue.put_nowait(value)

    def get_nowait(self) -> T:
        return self._queue.get_nowait()

    def drain_snapshot(self) -> tuple[T, ...]:
        count = self._queue.qsize()
        drained: list[T] = []
        for _ in range(count):
            try:
                drained.append(self._queue.get_nowait())
            except Empty:
                break
        return tuple(drained)

    def qsize(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()

    def full(self) -> bool:
        return self._queue.full()

    def close(self) -> None:
        """Reject future sends while preserving already accepted items."""
        with self._admission_lock:
            self._closed = True

    @property
    def closed(self) -> bool:
        with self._admission_lock:
            return self._closed


class OwnedResource(Generic[T]):
    """A value whose mutations are checked against one owning thread."""

    def __init__(self, value: T) -> None:
        self._value = value
        self._owner = get_ident()
        self._lock = Lock()

    @property
    def owner(self) -> int:
        with self._lock:
            return self._owner

    def get(self) -> T:
        if get_ident() != self.owner:
            raise RuntimeError("resource accessed by a non-owner thread")
        return self._value

    def transfer(self, owner: int) -> None:
        if not isinstance(owner, int):
            raise TypeError("owner must be a thread identifier")
        with self._lock:
            if get_ident() != self._owner:
                raise RuntimeError("only the current owner may transfer a resource")
            self._owner = owner


class CoalescedNotification:
    """Execute at most one wakeup until the reactor consumes the pending bit."""

    def __init__(self, wakeup: Callable[[], None]) -> None:
        if not callable(wakeup):
            raise TypeError("wakeup must be callable")
        self._wakeup = wakeup
        self._pending = LockedAtomic(False)

    def notify(self) -> bool:
        _, changed = self._pending.compare_exchange(False, True)
        if changed:
            try:
                self._wakeup()
            except BaseException:
                self._pending.store(False)
                raise
        return changed

    def consume(self) -> bool:
        return self._pending.exchange(False)
