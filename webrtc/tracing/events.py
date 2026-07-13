from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from threading import RLock
from typing import Any
import json
import weakref


@dataclass(eq=False)
class TraceSubscriber:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop
    peer_id: str | None = None
    pending_events: list[dict[str, Any]] = field(default_factory=list)
    flush_handle: asyncio.TimerHandle | None = None


class TraceEventBus:
    def __init__(self, *, batch_interval: float = 1.0, max_pending_events: int = 2048) -> None:
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
        if handle is not None:
            handle.cancel()

    def close(self) -> None:
        """Detach subscribers and cancel all owned batching timers."""
        with self._lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            self.unsubscribe(subscriber)

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
        events = self._coalesce(sub.pending_events)
        sub.pending_events = []
        sub.flush_handle = None
        if not events:
            return
        self._offer(sub.queue, self.batch_event(events))

    def _append_pending(self, sub: TraceSubscriber, event: dict[str, Any]) -> None:
        sub.pending_events.append(event)
        self._trim_pending_events(sub)

    def _trim_pending_events(self, sub: TraceSubscriber) -> None:
        overflow = len(sub.pending_events) - self._max_pending_events
        if overflow <= 0:
            return

        del sub.pending_events[:overflow]
    @classmethod
    def _coalesce(cls, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Coalesce updates without crossing task lifecycle boundaries."""
        output: list[dict[str, Any]] = []
        segment: list[dict[str, Any]] = []

        def flush_segment() -> None:
            if not segment:
                return
            output.extend(cls._coalesce_segment(segment))
            segment.clear()

        for event in events:
            if event.get("event") in {"trace:init", "trace:complete", "trace:delete"}:
                flush_segment()
                if output and cls._event_signature(output[-1]) == cls._event_signature(event):
                    cls._retain_highest_sequence(output[-1], event)
                else:
                    output.append(event)
            else:
                segment.append(event)
        flush_segment()
        return output

    @classmethod
    def _coalesce_segment(cls, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        update_position: int | None = None
        update_tasks: dict[str, dict[str, Any]] = {}
        update_data: dict[str, Any] = {}

        for event in events:
            if event.get("event") != "trace:update":
                cls._append_distinct(output, event)
                continue
            data = event.get("data")
            if not isinstance(data, dict):
                cls._append_distinct(output, event)
                continue
            if update_position is None:
                update_position = len(output)
                output.append({"event": "trace:update", "data": {}})
            sequence = data.get("sequence")
            previous_sequence = update_data.get("sequence")
            if isinstance(sequence, int) and (
                not isinstance(previous_sequence, int) or sequence > previous_sequence
            ):
                update_data["sequence"] = sequence
            for key, value in data.items():
                if key not in {"tasks", "sequence", "groups"}:
                    update_data[key] = value
            if "groups" in data:
                update_data["groups"] = data["groups"]
            tasks = data.get("tasks")
            if isinstance(tasks, list):
                for task in tasks:
                    task_id = task.get("task_id") if isinstance(task, dict) else None
                    if isinstance(task_id, str):
                        update_tasks[task_id] = task

        if update_position is not None:
            output[update_position] = {
                "event": "trace:update",
                "data": {**update_data, "tasks": list(update_tasks.values())},
            }
        return output

    @staticmethod
    def _append_distinct(output: list[dict[str, Any]], event: dict[str, Any]) -> None:
        signature = TraceEventBus._event_signature(event)
        for existing in reversed(output):
            if existing.get("event") in {"trace:init", "trace:complete", "trace:delete"}:
                break
            if TraceEventBus._event_signature(existing) == signature:
                TraceEventBus._retain_highest_sequence(existing, event)
                return
        output.append(event)

    @staticmethod
    def _event_signature(event: dict[str, Any]) -> str:
        data = event.get("data")
        normalized = {key: value for key, value in data.items() if key != "sequence"} if isinstance(data, dict) else data
        return json.dumps({"event": event.get("event"), "data": normalized}, sort_keys=True, default=str)

    @staticmethod
    def _retain_highest_sequence(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
        existing_data = existing.get("data")
        incoming_data = incoming.get("data")
        if not isinstance(existing_data, dict) or not isinstance(incoming_data, dict):
            return
        current = existing_data.get("sequence")
        candidate = incoming_data.get("sequence")
        if isinstance(candidate, int) and (not isinstance(current, int) or candidate > current):
            existing_data["sequence"] = candidate

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

        tasks = data.get("tasks")
        return [item for item in tasks if isinstance(item, dict)] if isinstance(tasks, list) else []

    @staticmethod
    def _offer(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        try:
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)
        except Exception:
            return
