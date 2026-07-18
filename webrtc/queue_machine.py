"""Typed bounded queues with Runtime-owned lifecycle and coalesced load facets."""

from __future__ import annotations

import asyncio
from typing import Generic, TypeVar

from .runtime_services import current_execution_scope
from .state_machine import MachineSnapshot

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
        self._high_water = 0
        self._enqueued = 0
        self._dequeued = 0
        self._facets_pending = False
        if self._runtime is not None:
            self._publish()

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
                                dequeued: int = 0) -> None:
        """Record hot-path metrics without doing projection work inline."""
        self._enqueued += enqueued
        self._dequeued += dequeued
        self._high_water = max(self._high_water, self._queue.qsize())
        if self._runtime is None or self._facets_pending:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if loop.is_closed():
            return
        self._facets_pending = True
        loop.call_soon(self._flush_facets)

    def _flush_facets(self) -> None:
        self._facets_pending = False
        try:
            self._publish()
        except Exception:
            # Queue operation success must never depend on observability.
            diagnostics = getattr(self._runtime, "diagnostics", None)
            if diagnostics is not None:
                with diagnostics.suspend_notifications():
                    diagnostics["queue_facet_publish_failures"] += 1

    def _publish(self, revision: int | None = None) -> None:
        if self._runtime is None:
            return
        depth = self._queue.qsize()
        self._high_water = max(self._high_water, depth)
        source_revision = self._revision if revision is None else revision
        source = MachineSnapshot(
            self.entity_id, "queue", 1, source_revision,
            self._state, self._state == "closed",
        )
        self._runtime.observe_facets(
            source, {
                "depth": depth, "capacity": self.maxsize,
                "high_water": self._high_water, "queue_kind": self.queue_kind,
                "enqueued_packets": self._enqueued,
                "dequeued_packets": self._dequeued,
            },
            observer_meta="aggregate",
            failure_diagnostic="queue_facet_publish_failures",
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
        self._flush_facets()
