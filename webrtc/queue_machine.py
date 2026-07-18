"""Typed bounded queues with Runtime-owned lifecycle and coalesced load facets."""

from __future__ import annotations

import asyncio
from typing import Generic, TypeVar

from .runtime_services import current_execution_scope

T = TypeVar("T")


class RuntimeOwnedQueue(Generic[T]):
    """A bounded Runtime-owned queue with direct admission and close state."""

    def __init__(self, maxsize: int, *, entity_id: str, queue_kind: str) -> None:
        if maxsize < 1:
            raise ValueError("Runtime-owned queue capacity must be positive")
        self._queue: asyncio.Queue[T] = asyncio.Queue(maxsize=maxsize)
        self.entity_id = entity_id
        self.queue_kind = queue_kind
        self._runtime = current_execution_scope()
        self._state = "open"
        self._revision = 0
        self._pending_puts: set[asyncio.Task[object]] = set()
        self._pending_gets: set[asyncio.Task[object]] = set()
        if self._runtime is not None:
            self._record_packet_activity(exact=True)

    @property
    def maxsize(self) -> int:
        return self._queue.maxsize

    def qsize(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()

    async def put(self, item: T) -> None:
        if self._state != "open":
            raise RuntimeError("queue is closing")
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull:
            pass
        else:
            self._record_packet_activity(enqueued=1)
            return
        pending = asyncio.current_task()
        assert pending is not None
        self._pending_puts.add(pending)
        try:
            await self._queue.put(item)
        except asyncio.CancelledError:
            if self._state != "open":
                raise RuntimeError("queue is closing") from None
            raise
        finally:
            self._pending_puts.discard(pending)
        if self._state != "open":
            raise RuntimeError("queue is closing")
        self._record_packet_activity(enqueued=1)

    def put_nowait(self, item: T) -> None:
        if self._state != "open":
            raise RuntimeError("queue is closing")
        self._queue.put_nowait(item)
        self._record_packet_activity(enqueued=1)

    async def get(self) -> T:
        if self._state == "closed" and self._queue.empty():
            raise RuntimeError("queue is closed")
        try:
            item = self._queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        else:
            self._record_packet_activity(dequeued=1)
            return item
        pending = asyncio.current_task()
        assert pending is not None
        self._pending_gets.add(pending)
        try:
            item = await self._queue.get()
        except asyncio.CancelledError:
            if self._state != "open":
                raise RuntimeError("queue is closed") from None
            raise
        finally:
            self._pending_gets.discard(pending)
        self._record_packet_activity(dequeued=1)
        return item

    def get_nowait(self) -> T:
        item = self._queue.get_nowait()
        self._record_packet_activity(dequeued=1)
        return item

    def _record_packet_activity(self, *, enqueued: int = 0,
                                dequeued: int = 0,
                                exact: bool = False) -> None:
        """Send a value sample to the Runtime telemetry reducer."""
        if self._runtime is None:
            return
        self._runtime.record_queue_activity(
            entity_id=self.entity_id, queue_kind=self.queue_kind,
            depth=self._queue.qsize(), capacity=self.maxsize,
            deltas={
                "enqueued_packets": enqueued,
                "dequeued_packets": dequeued,
            }, exact=exact,
        )

    async def close(self) -> None:
        if self._state == "closed":
            return
        self._state = "closing"
        self._revision += 1
        pending = tuple(self._pending_puts | self._pending_gets)
        for operation in pending:
            operation.cancel()
        while not self._queue.empty():
            self._queue.get_nowait()
        self._state = "closed"
        self._revision += 1
        self._record_packet_activity(exact=True)
