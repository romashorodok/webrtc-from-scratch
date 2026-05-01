from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from threading import RLock
from typing import Any


@dataclass(eq=False)
class TraceSubscriber:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop
    peer_id: str | None
    pending_events: list[dict[str, Any]] = field(default_factory=list)
    flush_handle: asyncio.TimerHandle | None = None


class TraceEventBus:
    def __init__(self, *, batch_interval: float = 0.25) -> None:
        self._lock = RLock()
        self._subscribers: set[TraceSubscriber] = set()
        self._sequence = 0
        self._batch_interval = batch_interval

    def publish(self, event_name: str, data: dict[str, Any]) -> None:
        event = {"event": event_name, "data": {"sequence": 0, **data}}
        with self._lock:
            self._sequence += 1
            event["data"]["sequence"] = self._sequence
            subs = list(self._subscribers)
        for sub in subs:
            if self._event_matches_peer(event, sub.peer_id):
                self._deliver(sub, event)

    def subscribe(
        self,
        *,
        maxsize: int = 1024,
        peer_id: str | None = None,
    ) -> TraceSubscriber:
        loop = asyncio.get_running_loop()
        sub = TraceSubscriber(asyncio.Queue(maxsize=maxsize), loop, peer_id)
        with self._lock:
            self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: TraceSubscriber) -> None:
        with self._lock:
            self._subscribers.discard(sub)
            handle = sub.flush_handle
            sub.flush_handle = None
            sub.pending_events.clear()
        if handle is not None:
            handle.cancel()

    def batch_event(self, events: list[dict[str, Any]], *, peer_id: str | None) -> dict[str, Any]:
        data: dict[str, Any] = {"events": events}
        if peer_id is not None:
            data["peer_id"] = peer_id
        return {"event": "trace:batch", "data": data}

    def _deliver(self, sub: TraceSubscriber, event: dict[str, Any]) -> None:
        def offer() -> None:
            sub.pending_events.append(event)
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
        sub.flush_handle = None
        if not events:
            return
        self._offer(sub.queue, self.batch_event(events, peer_id=sub.peer_id))

    @staticmethod
    def _offer(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        try:
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)
        except Exception:
            return

    @staticmethod
    def _event_matches_peer(event: dict[str, Any], peer_id: str | None) -> bool:
        if peer_id is None:
            return True
        data = event.get("data")
        if not isinstance(data, dict):
            return False
        if data.get("peer_id") == peer_id:
            return True
        trace = data.get("trace")
        if isinstance(trace, dict) and trace.get("peer_id") == peer_id:
            return True
        traces = data.get("traces")
        if isinstance(traces, list):
            return any(isinstance(t, dict) and t.get("peer_id") == peer_id for t in traces)
        summaries = data.get("summaries")
        return isinstance(summaries, list) and any(
            isinstance(s, dict) and s.get("peer_id") == peer_id for s in summaries
        )
