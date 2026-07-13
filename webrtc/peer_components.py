from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import AsyncIterator
from typing import Any

from .config import DebugConfig
from .logger import get_logger
from .performance import ObservedComponent, event_loop, performance, task, worker
from .runtime_services import FailurePolicy


class NeedMoreData:
    pass


class PeerEventInboxClosed:
    pass


class PeerEventInbox:
    """A bounded, single-terminal peer-domain event inbox."""

    def __init__(self, maxsize: int = 1024) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self._ready = asyncio.Event()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def offer_nowait(self, event: Any) -> bool:
        if self._closed:
            return False
        self._queue.put_nowait(event)
        self._ready.set()
        return True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._ready.set()

    def receive_nowait(self) -> Any | NeedMoreData | PeerEventInboxClosed:
        try:
            event = self._queue.get_nowait()
        except asyncio.QueueEmpty:
            if self._closed:
                return PeerEventInboxClosed()
            self._ready.clear()
            return NeedMoreData()
        if not self._queue.empty() or self._closed:
            self._ready.set()
        else:
            self._ready.clear()
        return event

    async def wait_ready(self) -> None:
        await self._ready.wait()

    def __aiter__(self) -> AsyncIterator[Any]:
        async def iterator() -> AsyncIterator[Any]:
            while True:
                item = self.receive_nowait()
                if isinstance(item, NeedMoreData):
                    await self.wait_ready()
                    continue
                if isinstance(item, PeerEventInboxClosed):
                    return
                yield item

        return iterator()


class PeerConnectionLogInbox:
    def __init__(self, maxsize: int = 4096) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self.accepting = True
        self.dropped_debug = 0
        self.dropped = 0

    def stop_intake(self) -> None:
        self.accepting = False

    def put_nowait(self, event: Any) -> bool:
        if not self.accepting:
            return False
        if not self._queue.full():
            self._queue.put_nowait(event)
            return True
        level = getattr(getattr(event, "level", None), "value", 0)
        if level >= 4:
            self.dropped_debug += 1
            return False
        self.dropped += 1
        try:
            self._queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            return False

    async def get(self) -> Any:
        return await self._queue.get()

    def drain_batch(self, maximum: int) -> list[Any]:
        batch: list[Any] = []
        for _ in range(maximum):
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch


class AsyncLogDrain(ObservedComponent):
    """Peer-owned log intake and final-flush component."""

    def __init__(self, inbox: PeerConnectionLogInbox | None = None) -> None:
        self.inbox = inbox or PeerConnectionLogInbox(DebugConfig.get().log_max)
        self._stopping = asyncio.Event()
        self._wake = asyncio.Event()
        self._task: asyncio.Task[Any] | None = None

    @event_loop
    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = self.run()

    @event_loop
    def stop_intake(self) -> None:
        self.inbox.stop_intake()
        self._stopping.set()
        self._wake.set()

    @task(name="logger.drain", kind="log", failure=FailurePolicy.REPORT)
    async def run(self) -> None:
        config = DebugConfig.get()
        last_flush = time.monotonic()
        while not self._stopping.is_set():
            timeout = max(0.0, config.log_flush_interval - (time.monotonic() - last_flush))
            get_task = asyncio.create_task(self.inbox.get())
            stop_task = asyncio.create_task(self._wake.wait())
            done, pending = await asyncio.wait(
                (get_task, stop_task), timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
            for pending_task in pending:
                pending_task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            batch = [get_task.result()] if get_task in done and not get_task.cancelled() else []
            batch.extend(self.inbox.drain_batch(max(0, config.log_flush_max_batch - len(batch))))
            if batch:
                await self.write_batch(batch)
            # Advance the flush deadline even when the periodic wake found an
            # empty inbox.  Otherwise every subsequent timeout is zero and the
            # drain spins creating and cancelling waiter tasks, starving the
            # rest of the peer's event loop.
            last_flush = time.monotonic()
        await self.flush()

    async def flush(self) -> None:
        maximum = max(1, DebugConfig.get().log_flush_max_batch)
        while batch := self.inbox.drain_batch(maximum):
            await self.write_batch(batch)

    @worker
    @performance(name="logger.write", group="logger")
    def write_batch(self, batch: list[Any]) -> None:
        get_logger().write_events_sync(batch)

    async def aclose(self) -> None:
        self.stop_intake()
        task_handle = self._task
        if task_handle is not None and task_handle is not asyncio.current_task():
            await asyncio.gather(task_handle, return_exceptions=True)
        else:
            await self.flush()


async def _call_optional(target: Any, name: str) -> bool:
    method = getattr(target, name, None)
    if method is None:
        return False
    result = method()
    if inspect.isawaitable(result):
        await result
    return True


class AttachmentController(ObservedComponent):
    """Owns start tasks and ordered shutdown for attached domain producers."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._attachments: list[Any] = []
        self._tasks: dict[int, asyncio.Task[Any]] = {}
        self._closing = False

    @event_loop
    def attach(self, attachment: Any) -> Any:
        if self._closing:
            raise RuntimeError(f"{self.kind} attachments are closing")
        self._attachments.append(attachment)
        return attachment

    @event_loop
    def start(self) -> None:
        for attachment in self._attachments:
            key = id(attachment)
            if key not in self._tasks or self._tasks[key].done():
                self._tasks[key] = self._run_attachment(attachment)

    @task(name="attachment.run", kind="application", failure=FailurePolicy.REPORT)
    async def _run_attachment(self, attachment: Any) -> None:
        await _call_optional(attachment, "start")

    async def aclose(self) -> None:
        if self._closing:
            tasks = tuple(self._tasks.values())
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            return
        self._closing = True
        for attachment in reversed(self._attachments):
            await _call_optional(attachment, "stop")
        for running in tuple(self._tasks.values()):
            if not running.done():
                running.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        for attachment in reversed(self._attachments):
            if not await _call_optional(attachment, "aclose"):
                await _call_optional(attachment, "close")


class SignalingController(AttachmentController):
    def __init__(self) -> None:
        super().__init__("signaling")


class MediaSourceController(AttachmentController):
    def __init__(self) -> None:
        super().__init__("media")
