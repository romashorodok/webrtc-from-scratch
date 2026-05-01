from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .events import TraceEventBus, TraceSubscriber
from .metrics import MetricDelta, TraceMetricsAggregator
from .models import TaskContext
from .store import TraceStore


@dataclass
class TraceSubscription:
    service: "TraceService"
    subscriber: TraceSubscriber
    _closed: bool = False

    async def get(self) -> dict[str, Any]:
        return await self.subscriber.queue.get()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.service.unsubscribe(self)

    async def __aenter__(self) -> "TraceSubscription":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __aiter__(self):
        async def iterator():
            while not self._closed:
                yield await self.get()

        return iterator()


class TraceService:
    def __init__(
        self,
        *,
        trace_context_limit: int = 4096,
        trace_subscriber_batch_interval: float = 0.25,
        executor=None,
    ) -> None:
        self.store = TraceStore(context_limit=trace_context_limit)
        self.events = TraceEventBus(batch_interval=trace_subscriber_batch_interval)
        self.metrics = TraceMetricsAggregator(executor=executor)

    def create_context(
        self,
        *,
        name: str,
        kind: str,
        peer_id: str | None,
        parent: TaskContext | None,
        parent_id: str | None,
        metadata: Mapping[str, Any] | None,
    ) -> TaskContext:
        resolved_parent_id = parent_id if parent_id is not None else (parent.trace_id if parent else None)
        root_trace_id = parent.root_trace_id if parent else ""
        trace_id = uuid.uuid4().hex
        if not root_trace_id:
            root_trace_id = trace_id
        context = TaskContext(
            trace_id=trace_id,
            parent_id=resolved_parent_id,
            root_trace_id=root_trace_id,
            name=name,
            kind=kind,
            peer_id=peer_id or (parent.peer_id if parent else None),
            metadata=self.store.normalize_metadata(metadata),
        )
        context.transitions.append(
            {"at": context.created_at, "event": "created", "status": "created", "duration_ms": 0.0}
        )
        self.store.create(context)
        self.events.publish("trace:init", {"trace": context.to_dict()})
        return context

    def start_context(self, context: TaskContext) -> None:
        if context.started_at is None:
            context.started_at = time.time()
            context.started_monotonic_ns = time.monotonic_ns()
            context.transitions.append(
                {"at": context.started_at, "event": "started", "status": "running", "duration_ms": 0.0}
            )
        context.status = "running"
        self.store.start(context)
        updates = self.store.live_running(peer_id=context.peer_id, include_duration=True)
        trace = next((item for item in updates if item.get("trace_id") == context.trace_id), context.to_dict())
        self.events.publish("trace:update", {"trace": trace})

    def complete_context(self, context: TaskContext, *, status: str, error: str | None) -> None:
        if context.ended_at is not None:
            return
        context.ended_at = time.time()
        context.ended_monotonic_ns = time.monotonic_ns()
        start_ns = context.started_monotonic_ns or context.created_monotonic_ns
        context.duration_ms = max(0.0, (context.ended_monotonic_ns - start_ns) / 1_000_000)
        context.status = status
        context.error = error
        context.transitions.append(
            {
                "at": context.ended_at,
                "event": status,
                "status": status,
                "duration_ms": context.duration_ms,
                **({"error": error} if error else {}),
            }
        )
        if not self.store.complete(context):
            return
        self.events.publish("trace:complete", {"trace": context.to_dict()})
        self.metrics.enqueue(
            MetricDelta(
                key=(context.peer_id, str(context.metadata.get("group_key") or context.name), context.name, context.kind),
                duration_ms=float(context.duration_ms or 0.0),
                status=status,
            )
        )
        self._prune_terminal_trace(context.trace_id)

    def _prune_terminal_trace(self, trace_id: str) -> None:
        ok, promoted_ids, peer_id = self.store.remove_trace_only(trace_id)
        if not ok:
            return
        self.events.publish("trace:delete", {"trace_ids": [trace_id], "peer_id": peer_id, "auto_prune": True})
        for promoted_id in promoted_ids:
            promoted = self.store.context_by_id(promoted_id)
            if promoted is None:
                continue
            self.events.publish("trace:update", {"trace": promoted.to_dict(), "peer_id": peer_id})

    def trace_live_tree(self, *, peer_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.live_tree(peer_id=peer_id)

    def trace_live_running(
        self,
        *,
        peer_id: str | None = None,
        include_duration: bool = False,
    ) -> list[dict[str, Any]]:
        return self.store.live_running(peer_id=peer_id, include_duration=include_duration)

    def trace_subscribe(
        self,
        *,
        maxsize: int = 1024,
        peer_id: str | None = None,
    ) -> TraceSubscription:
        return TraceSubscription(
            service=self,
            subscriber=self.events.subscribe(maxsize=maxsize, peer_id=peer_id),
        )

    def unsubscribe(self, subscription: TraceSubscription) -> None:
        self.events.unsubscribe(subscription.subscriber)

    def remove_trace_subtree(self, trace_id: str) -> tuple[bool, list[str], str | None]:
        ok, ids, peer_id = self.store.remove_trace_subtree(trace_id)
        if ok and ids:
            self.events.publish("trace:delete", {"trace_ids": ids, "peer_id": peer_id})
        return ok, ids, peer_id

    def delete_traces(
        self,
        *,
        peer_id: str | None = None,
        statuses: set[str] | None = None,
        include_running: bool = False,
    ) -> int:
        count, ids, event_peer = self.store.delete_traces(
            peer_id=peer_id,
            statuses=statuses,
            include_running=include_running,
        )
        if ids:
            self.events.publish("trace:delete", {"trace_ids": ids, "peer_id": event_peer})
        return count

    async def flush_metrics(self) -> dict[tuple[str | None, str, str, str], dict[str, Any]]:
        return await self.metrics.flush()
