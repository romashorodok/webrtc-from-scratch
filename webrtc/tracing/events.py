from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from threading import RLock
from typing import Any
import weakref


@dataclass(eq=False)
class TraceSubscriber:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop
    peer_id: str | None = None
    pending_events: list[dict[str, Any]] = field(default_factory=list)
    pending_update_positions: dict[str, int] = field(default_factory=dict)
    flush_handle: asyncio.TimerHandle | None = None


class TraceEventBus:
    def __init__(self, *, batch_interval: float = 0.25, max_pending_events: int = 2048) -> None:
        self._lock = RLock()
        self._subscribers: set[TraceSubscriber] = weakref.WeakSet()
        self._sequence = 0
        self._batch_interval = batch_interval
        self._max_pending_events = max_pending_events

    def publish(self, event_name: str, data: dict[str, Any]) -> None:
        event = {"event": event_name, "data": {"sequence": 0, **data}}
        with self._lock:
            self._sequence += 1
            event["data"]["sequence"] = self._sequence
            subs = list(self._subscribers)
        for sub in subs:
            self._deliver(sub, event)

    def subscribe(
        self,
        *,
        maxsize: int = 1024,
        peer_id: str | None = None,
    ) -> TraceSubscriber:
        loop = asyncio.get_running_loop()
        sub = TraceSubscriber(asyncio.Queue(maxsize=maxsize), loop, peer_id=peer_id)
        with self._lock:
            self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: TraceSubscriber) -> None:
        with self._lock:
            self._subscribers.discard(sub)
            handle = sub.flush_handle
            sub.flush_handle = None
            sub.pending_events.clear()
            sub.pending_update_positions.clear()
        if handle is not None:
            handle.cancel()

    def batch_event(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return {"event": "trace:batch", "data": {"events": events}}

    def _deliver(self, sub: TraceSubscriber, event: dict[str, Any]) -> None:
        if sub.peer_id is not None and self._event_peer_id(event) != sub.peer_id:
            return

        def offer() -> None:
            self._append_pending(sub, event)
            if sub.flush_handle is None:
                sub.flush_handle = sub.loop.call_later(self._batch_interval, self._flush, sub)

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is sub.loop:
            offer()
        elif not sub.loop.is_closed():
            sub.loop.call_soon_threadsafe(offer)

    def _flush(self, sub: TraceSubscriber) -> None:
        events = sub.pending_events
        sub.pending_events = []
        sub.pending_update_positions = {}
        sub.flush_handle = None
        if not events:
            return
        self._offer(sub.queue, self.batch_event(events))

    def _append_pending(self, sub: TraceSubscriber, event: dict[str, Any]) -> None:
        trace_id = self._trace_update_id(event)
        if trace_id is not None:
            position = sub.pending_update_positions.get(trace_id)
            if position is None:
                sub.pending_update_positions[trace_id] = len(sub.pending_events)
                sub.pending_events.append(event)
            else:
                sub.pending_events[position] = event
        else:
            sub.pending_events.append(event)
        self._trim_pending_events(sub)

    def _trim_pending_events(self, sub: TraceSubscriber) -> None:
        overflow = len(sub.pending_events) - self._max_pending_events
        if overflow <= 0:
            return

        del sub.pending_events[:overflow]
        if not sub.pending_update_positions:
            return

        trimmed_positions: dict[str, int] = {}
        for trace_id, position in sub.pending_update_positions.items():
            if position >= overflow:
                trimmed_positions[trace_id] = position - overflow
        sub.pending_update_positions = trimmed_positions

    @staticmethod
    def _trace_update_id(event: dict[str, Any]) -> str | None:
        if event.get("event") != "trace:update":
            return None
        data = event.get("data")
        trace = data.get("trace") if isinstance(data, dict) else None
        trace_id = trace.get("trace_id") if isinstance(trace, dict) else None
        return trace_id if isinstance(trace_id, str) else None

    @staticmethod
    def _event_peer_id(event: dict[str, Any]) -> str | None:
        data = event.get("data")
        if not isinstance(data, dict):
            return None

        peer_id = data.get("peer_id")
        if isinstance(peer_id, str):
            return peer_id

        if event.get("event") not in {"trace:init", "trace:update", "trace:complete"}:
            return None

        for trace in TraceEventBus._event_traces(event):
            metadata = trace.get("metadata")
            if isinstance(metadata, dict):
                trace_peer_id = metadata.get("peer_id")
                if isinstance(trace_peer_id, str):
                    return trace_peer_id

        return None

    @staticmethod
    def _event_traces(event: dict[str, Any]) -> list[dict[str, Any]]:
        data = event.get("data")
        if not isinstance(data, dict):
            return []

        traces: list[dict[str, Any]] = []
        trace = data.get("trace")
        if isinstance(trace, dict):
            traces.append(trace)
        trace_list = data.get("traces")
        if isinstance(trace_list, list):
            traces.extend(item for item in trace_list if isinstance(item, dict))
        return traces

    @staticmethod
    def _offer(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        try:
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)
        except Exception:
            return
