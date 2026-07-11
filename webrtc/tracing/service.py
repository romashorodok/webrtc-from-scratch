from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .events import TraceEventBus, TraceSubscriber
from .metrics import MetricDelta, TraceMetricsAggregator
from .models import TaskContext
from .performance import PerfEvent, PerformanceRecorder
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
        self.performance_recorder = PerformanceRecorder(event_sink=self.record_performance_event)

    def record_performance_event(self, event: PerfEvent) -> None:
        """Aggregate a packet-path measurement onto its owning live trace."""
        trace_id = event.metadata.get("trace_id")
        if isinstance(trace_id, str):
            self.store.aggregate_performance_event(
                trace_id, event.name, event.duration_ms, event.metadata
            )

    def create_context(
        self,
        *,
        name: str,
        kind: str,
        parent: TaskContext | None,
        parent_id: str | None,
        metadata: Mapping[str, Any] | None,
    ) -> TaskContext:
        resolved_parent_id = parent_id if parent_id is not None else (parent.trace_id if parent else None)
        trace_id = uuid.uuid4().hex
        context = TaskContext(
            trace_id=trace_id,
            parent_id=resolved_parent_id,
            name=name,
            kind=kind,
            metadata=self.store.normalize_metadata(metadata),
        )
        if parent is not None:
            parent_peer_id = self._context_peer_id(parent)
            if parent_peer_id is not None and "peer_id" not in context.metadata:
                context.metadata["peer_id"] = parent_peer_id
        context.transitions.append(
            {"at": context.created_at, "event": "created", "status": "created", "duration_ms": 0.0}
        )
        self.store.create(context)
        self.events.publish(
            "trace:init",
            {"trace": context.to_dict(), **self._peer_event_data(context)},
        )
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
        updates = self.store.live_running(include_duration=True)
        trace = next((item for item in updates if item.get("trace_id") == context.trace_id), context.to_dict())
        self.events.publish("trace:update", {"trace": trace, **self._peer_event_data(context)})

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
        self.events.publish("trace:complete", {"trace": context.to_dict(), **self._peer_event_data(context)})
        self.metrics.enqueue(
            MetricDelta(
                key=(self.store.root_trace_id(context.trace_id), str(context.metadata.get("group_key") or context.name), context.name, context.kind),
                duration_ms=float(context.duration_ms or 0.0),
                status=status,
            )
        )
        self._prune_terminal_trace(context.trace_id, peer_id=self._context_peer_id(context))

    def _prune_terminal_trace(self, trace_id: str, *, peer_id: str | None = None) -> None:
        ok, promoted_contexts = self.store.remove_trace_only(trace_id)
        if not ok:
            return
        data = {"trace_ids": [trace_id], "auto_prune": True}
        if peer_id is not None:
            data["peer_id"] = peer_id
        self.events.publish("trace:delete", data)
        for promoted in promoted_contexts:
            self.events.publish("trace:update", {"trace": promoted.to_dict(), **self._peer_event_data(promoted)})

    def trace_live_tree(self) -> list[dict[str, Any]]:
        return self.store.live_tree()

    def trace_live_running(
        self,
        *,
        include_duration: bool = False,
        scope_trace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.store.live_running(include_duration=include_duration, scope_trace_id=scope_trace_id)

    def trace_running_signature(
        self,
        *,
        scope_trace_id: str | None = None,
    ) -> tuple[tuple[str, str | None, str], ...]:
        return self.store.running_signature(scope_trace_id=scope_trace_id)

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

    def delete_trace(
        self,
        trace_id: str,
        *,
        is_cancelable: Callable[[TaskContext], bool] | None = None,
        cancel_trace: Callable[[str], None] | None = None,
        mark_inactive: Callable[[str], None] | None = None,
        peer_id: str | None = None,
    ) -> bool:
        contexts = self.store.subtree_contexts(trace_id)
        if not contexts:
            self.events.publish(
                "trace:delete_result",
                {
                    "success": False,
                    "trace_id": trace_id,
                    "reason": "trace_not_found",
                    "failed_trace_ids": [],
                    **({"peer_id": peer_id} if peer_id is not None else {}),
                },
            )
            return False

        subtree_ids = [context.trace_id for context in contexts]
        running = [context for context in contexts if context.status in {"created", "running"}]
        failed_ids = [
            context.trace_id
            for context in running
            if is_cancelable is not None and not is_cancelable(context)
        ]
        if failed_ids:
            self.events.publish(
                "trace:delete_result",
                {
                    "success": False,
                    "trace_id": trace_id,
                    "trace_ids": subtree_ids,
                    "reason": "non_cancelable_path",
                    "failed_trace_ids": failed_ids,
                    **self._peer_event_data(contexts[0]),
                },
            )
            return False

        if cancel_trace is not None:
            for context in running:
                cancel_trace(context.trace_id)

        ok, ids = self.store.remove_trace_subtree(trace_id)
        if ok and ids:
            self.events.publish("trace:delete", {"trace_ids": ids, **self._peer_event_data(contexts[0])})
        self.events.publish(
            "trace:delete_result",
            {
                "success": bool(ok),
                "trace_id": trace_id,
                "trace_ids": ids if ok else subtree_ids,
                "reason": None if ok else "delete_failed",
                "failed_trace_ids": [],
                **({"peer_id": peer_id} if peer_id is not None else self._peer_event_data(contexts[0])),
            },
        )
        if ok and mark_inactive is not None:
            for tid in ids:
                mark_inactive(tid)
        return ok

    def delete_traces(
        self,
        *,
        statuses: set[str] | None = None,
        include_running: bool = False,
        peer_id: str | None = None,
    ) -> tuple[int, list[str]]:
        with self.store.lock:
            selected = [
                node
                for node in self.store._iter_nodes_locked()
                if (statuses is None or node.context.status in statuses)
                and (include_running or node.context.status not in {"created", "running"})
                and (peer_id is None or self._context_peer_id(node.context) == peer_id)
            ]

        removed_ids: list[str] = []
        for node in selected:
            ok, ids = self.store.remove_trace_subtree(node.trace_id)
            if ok:
                removed_ids.extend(ids)

        if removed_ids:
            event_data: dict[str, Any] = {"trace_ids": removed_ids}
            resolved_peer_id = peer_id or self._peer_id_for_contexts((node.context for node in selected))
            if resolved_peer_id is not None:
                event_data["peer_id"] = resolved_peer_id
            self.events.publish("trace:delete", event_data)
        return len(selected), removed_ids

    @staticmethod
    def _context_peer_id(context: TaskContext) -> str | None:
        peer_id = context.metadata.get("peer_id")
        return peer_id if isinstance(peer_id, str) else None

    def _peer_id_for_contexts(self, contexts: Iterable[TaskContext]) -> str | None:
        peer_ids = {
            self._context_peer_id(context)
            for context in contexts
            if self._context_peer_id(context) is not None
        }
        if len(peer_ids) == 1:
            return next(iter(peer_ids))
        return None

    def _peer_event_data(self, context: TaskContext) -> dict[str, Any]:
        peer_id = self._context_peer_id(context)
        return {"peer_id": peer_id} if peer_id is not None else {}

    async def flush_metrics(self) -> dict[tuple[str | None, str, str, str], dict[str, Any]]:
        return await self.metrics.flush()
