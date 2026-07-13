from __future__ import annotations

import asyncio
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any

from webrtc.runtime_services import (
    TaskCancelled,
    TaskCompleted,
    TaskFailed,
    TaskObserver,
    TaskRegistry,
    TaskStarted,
    TraceNodeCompleted,
    TraceNodeCancelabilityChanged,
    TraceNodeStarted,
)

from .events import TraceEventBus, TraceSubscriber
from .models import TaskTrace
from .store import TraceStore


@dataclass
class TraceSubscription:
    service: "TraceService"
    subscriber: TraceSubscriber
    _closed: bool = False

    async def get(self) -> dict[str, Any]:
        return await self.subscriber.queue.get()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.service.unsubscribe(self)

    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc, tb): self.close()


class TraceService(TaskObserver):
    """Projects neutral runtime lifecycle events into a live-only task tree."""

    def __init__(self, registry: TaskRegistry, *, trace_context_limit: int = 4096,
                 trace_subscriber_batch_interval: float = 1.0,
                 diagnostics: Counter[str] | None = None) -> None:
        self.registry = registry
        self.store = TraceStore(
            context_limit=trace_context_limit, diagnostics=diagnostics
        )
        self.diagnostics = self.store.diagnostics
        self.events = TraceEventBus(batch_interval=trace_subscriber_batch_interval)

    def task_started(self, event: TaskStarted) -> None:
        now = time.time(); monotonic = time.monotonic_ns(); context = event.context
        task = TaskTrace(context.trace_id, context.task_id, context.parent_task_id, event.name, event.kind,
                         created_at=now, created_monotonic_ns=monotonic, started_at=now,
                         started_monotonic_ns=monotonic, status="running",
                         metadata=self.store.normalize_metadata({
                             "peer_id": context.scope_id,
                             "node_type": "task",
                             "owner_task_id": context.task_id,
                             "cancelable": event.cancelable,
                             **event.metadata,
                         }),
                         transitions=[{"at": now, "event": "started", "status": "running", "duration_ms": 0.0}])
        if not self.store.create(task):
            return
        self.events.publish("trace:init", self._payload(context.trace_id, tasks=[task.to_dict()]))

    def task_completed(self, event: TaskCompleted) -> None: self._complete(event.context.task_id, "completed")
    def task_cancelled(self, event: TaskCancelled) -> None: self._complete(event.context.task_id, "cancelled")
    def task_failed(self, event: TaskFailed) -> None:
        self._complete(event.context.task_id, "failed", f"{type(event.exception).__name__}: {event.exception}")

    def node_started(self, event: TraceNodeStarted) -> None:
        descriptor = event.descriptor
        now = time.time(); monotonic = time.monotonic_ns()
        task = TaskTrace(
            descriptor.trace_id,
            descriptor.node_id,
            descriptor.parent_node_id,
            descriptor.name,
            descriptor.node_type.value,
            created_at=now,
            created_monotonic_ns=monotonic,
            started_at=now,
            started_monotonic_ns=monotonic,
            status="running",
            metadata=self.store.normalize_metadata({
                "node_type": descriptor.node_type.value,
                "owner_task_id": descriptor.owner_task_id,
                "cancelable": descriptor.cancelable,
                **descriptor.metadata,
            }),
            transitions=[{"at": now, "event": "started", "status": "running", "duration_ms": 0.0}],
        )
        if not self.store.create(task):
            return
        self.events.publish("trace:init", self._payload(descriptor.trace_id, tasks=[task.to_dict()]))

    def node_completed(self, event: TraceNodeCompleted) -> None:
        error = None
        if event.exception is not None:
            error = f"{type(event.exception).__name__}: {event.exception}"
        self._complete(event.descriptor.node_id, event.outcome, error)

    def node_cancelability_changed(self, event: TraceNodeCancelabilityChanged) -> None:
        tasks = self.store.subtree(event.node_id)
        if not tasks:
            return
        task = tasks[0]
        task.metadata["cancelable"] = event.cancelable
        if self.store.update(task):
            self.events.publish("trace:update", self._payload(
                task.trace_id, tasks=[task.to_dict()]
            ))

    def _complete(self, task_id: str, status: str, error: str | None = None) -> None:
        tasks = self.store.subtree(task_id)
        if not tasks: return
        task = tasks[0]; task.ended_at = time.time(); task.ended_monotonic_ns = time.monotonic_ns()
        start = task.started_monotonic_ns or task.created_monotonic_ns
        task.duration_ms = max(0.0, (task.ended_monotonic_ns - start) / 1_000_000)
        task.status = status; task.error = error
        task.transitions.append({"at": task.ended_at, "event": status, "status": status,
                                 "duration_ms": task.duration_ms, **({"error": error} if error else {})})
        if not self.store.update(task): return
        peer_id = task.metadata.get("peer_id") if isinstance(task.metadata.get("peer_id"), str) else None
        self.events.publish("trace:complete", self._payload(task.trace_id, tasks=[task.to_dict()]))
        ok, promoted = self.store.remove_only(task_id)
        if ok:
            self.events.publish("trace:delete", {"trace_id": task.trace_id, "task_ids": [task_id],
                "auto_prune": True, **self._peer(peer_id)})
            if promoted:
                self.events.publish("trace:update", self._payload(task.trace_id, tasks=[item.to_dict() for item in promoted]))

    def live_tree(self, trace_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.live_tree(trace_id=trace_id)

    def live_running(self, *, include_duration=False, trace_id=None):
        return self.store.live_running(include_duration=include_duration, trace_id=trace_id)

    def running_signature(self, *, trace_id=None):
        return self.store.running_signature(trace_id=trace_id)

    def trace_subscribe(self, *, maxsize=1024, peer_id=None) -> TraceSubscription:
        return TraceSubscription(self, self.events.subscribe(maxsize=maxsize, peer_id=peer_id))

    def unsubscribe(self, subscription: TraceSubscription) -> None:
        self.events.unsubscribe(subscription.subscriber)

    def close(self) -> None:
        self.events.close()

    def cancel(self, task_id: str, *, peer_id: str | None = None) -> bool:
        tasks = self.store.subtree(task_id)
        if not tasks:
            self.events.publish("trace:delete_result", {"success": False, "task_id": task_id,
                "reason": "task_not_found", "failed_task_ids": [], **self._peer(peer_id)})
            return False
        requested = tasks[0]
        failed: list[str] = []
        node_type = requested.metadata.get("node_type")
        target_id = requested.task_id if node_type == "task" else None
        if (
            not requested.metadata.get("cancelable", False)
            or (node_type == "task" and (
                not isinstance(target_id, str)
                or not self.registry.can_cancel([target_id])
            ))
        ):
            failed.append(requested.task_id)
        if failed:
            self.events.publish("trace:delete_result", self._payload(tasks[0].trace_id,
                success=False, task_id=task_id, task_ids=[t.task_id for t in tasks],
                reason="non_cancelable_path", failed_task_ids=failed))
            return False
        # Eligibility is checked for the entire subtree before cancellation.
        # Completion observers own pruning so live nodes are never presented as
        # deleted while their work is still running.
        ok = (
            self.registry.cancel(target_id)
            if isinstance(target_id, str)
            else self.registry.cancel_node(requested.task_id)
        )
        if not ok:
            self.events.publish("trace:delete_result", self._payload(tasks[0].trace_id,
                success=False, task_id=task_id, task_ids=[t.task_id for t in tasks],
                reason="cancellation_rejected", failed_task_ids=[requested.task_id]))
            return False
        ids = [task.task_id for task in tasks]
        self.events.publish("trace:delete_result", self._payload(tasks[0].trace_id,
            success=ok, task_id=task_id, task_ids=ids, reason=None, failed_task_ids=[]))
        return ok

    def _payload(self, trace_id: str, **values: Any) -> dict[str, Any]:
        peer_id = next((task.metadata.get("peer_id") for task in self.store.all_tasks()
                        if task.trace_id == trace_id and isinstance(task.metadata.get("peer_id"), str)), None)
        return {"trace_id": trace_id, **values, **self._peer(peer_id)}

    @staticmethod
    def _peer(peer_id: str | None) -> dict[str, str]:
        return {"peer_id": peer_id} if peer_id else {}
