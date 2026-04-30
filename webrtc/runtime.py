import asyncio
import atexit
import contextvars
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, TypeVar


T = TypeVar("T")


@dataclass
class TaskContext:
    trace_id: str
    parent_id: str | None
    name: str
    kind: str
    peer_id: str | None = None
    created_at: float = field(default_factory=time.time)
    created_monotonic_ns: int = field(default_factory=time.monotonic_ns)
    started_at: float | None = None
    started_monotonic_ns: int | None = None
    ended_at: float | None = None
    ended_monotonic_ns: int | None = None
    duration_ms: float | None = None
    status: str = "created"
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    transitions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "kind": self.kind,
            "peer_id": self.peer_id,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error": self.error,
            "metadata": dict(self.metadata),
            "transitions": [dict(transition) for transition in self.transitions],
        }


_current_task_context: contextvars.ContextVar[TaskContext | None] = contextvars.ContextVar(
    "webrtc_current_task_context",
    default=None,
)


def get_current_task_context() -> TaskContext | None:
    return _current_task_context.get()


def set_current_task_context(
    context: TaskContext | None,
) -> contextvars.Token[TaskContext | None]:
    return _current_task_context.set(context)


def reset_current_task_context(token: contextvars.Token[TaskContext | None]) -> None:
    _current_task_context.reset(token)


@dataclass(frozen=True)
class _TraceSubscriber:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop
    peer_id: str | None


class TraceSubscription:
    def __init__(
        self,
        runtime: "WebRTCRuntimeResources",
        subscriber: _TraceSubscriber,
    ) -> None:
        self._runtime = runtime
        self._subscriber = subscriber
        self._closed = False

    async def get(self) -> dict[str, Any]:
        return await self._subscriber.queue.get()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._runtime.unsubscribe_traces(self)

    async def __aenter__(self) -> "TraceSubscription":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __aiter__(self):
        async def iterator():
            while not self._closed:
                yield await self.get()

        return iterator()

    @property
    def subscriber(self) -> _TraceSubscriber:
        return self._subscriber


class WebRTCRuntimeResources:
    def __init__(
        self,
        *,
        executor: ThreadPoolExecutor | None = None,
        offload_capacity: int = 32,
        owns_executor: bool | None = None,
        max_workers: int = 4,
        max_pending_offloads: int | None = None,
        trace_history_limit: int = 2048,
        trace_context_limit: int = 4096,
        trace_archive_limit: int = 8192,
        trace_group_update_interval: float = 0.25,
        success_trace_retention_seconds: float = 60.0,
    ) -> None:
        if max_pending_offloads is not None:
            offload_capacity = max_pending_offloads

        self._executor = executor or ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="webrtc-offload",
        )
        self._owns_executor = (executor is None) if owns_executor is None else owns_executor
        self._offload_limiter = asyncio.Semaphore(offload_capacity)
        self._shutdown = False

        self._trace_lock = RLock()
        self._trace_sequence = 0
        self._trace_context_limit = trace_context_limit
        self._trace_archive_limit = trace_archive_limit
        self._trace_group_update_interval = trace_group_update_interval
        self._default_success_trace_retention = success_trace_retention_seconds
        self._traces: dict[str, TaskContext] = {}
        self._trace_order: deque[str] = deque()
        self._deleted_trace_archives: dict[str, dict[str, Any]] = {}
        self._deleted_trace_archive_order: deque[str] = deque()
        self._hidden_deleted_trace_ids: set[str] = set()
        self._trace_history: deque[dict[str, Any]] = deque(maxlen=trace_history_limit)
        self._trace_subscribers: set[_TraceSubscriber] = set()
        self._trace_groups: dict[tuple[str | None, str | None, str, str, str], TaskContext] = {}
        self._trace_group_keys_by_id: dict[str, tuple[str | None, str | None, str, str, str]] = {}
        self._trace_group_last_emit: dict[str, float] = {}
        self._success_trace_retention_by_peer: dict[str | None, float] = {}
        self._success_trace_delete_handles: dict[str, asyncio.TimerHandle] = {}
        self._trace_summaries: dict[str, dict[str, Any]] = {}
        self._trace_summary_aggregate_keys: dict[str, tuple[str | None, str, str, str]] = {}
        self._trace_summary_averages: dict[
            tuple[str | None, str, str, str],
            dict[str, float | int],
        ] = {}

    @property
    def shutdown_started(self) -> bool:
        return self._shutdown

    def create_task(
        self,
        awaitable: Awaitable[T],
        *,
        name: str | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> asyncio.Task[T]:
        loop = loop or asyncio.get_running_loop()
        return loop.create_task(awaitable, name=name)

    def create_task_context(
        self,
        *,
        name: str,
        kind: str = "task",
        peer_id: str | None = None,
        parent: TaskContext | None | object = None,
        parent_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> TaskContext:
        parent_context: TaskContext | None
        if parent is None:
            parent_context = get_current_task_context()
        elif isinstance(parent, TaskContext):
            parent_context = parent
        else:
            parent_context = None

        context = TaskContext(
            trace_id=uuid.uuid4().hex,
            parent_id=parent_id
            if parent_id is not None
            else (parent_context.trace_id if parent_context else None),
            name=name,
            kind=kind,
            peer_id=peer_id or (parent_context.peer_id if parent_context else None),
            metadata=dict(metadata or {}),
        )
        with self._trace_lock:
            self._append_trace_transition_locked(
                context,
                event="created",
                at=context.created_at,
            )
            self._traces[context.trace_id] = context
            self._trace_order.append(context.trace_id)
            self._trim_traces_locked()
        self._record_trace_event("trace:init", context)
        return context

    def start_task_context(self, context: TaskContext) -> None:
        was_started = context.started_at is not None
        if context.started_at is None:
            context.started_at = time.time()
            context.started_monotonic_ns = time.monotonic_ns()
        context.status = "running"
        if not was_started:
            with self._trace_lock:
                self._append_trace_transition_locked(
                    context,
                    event="started",
                    at=context.started_at,
                )
        if self._update_deleted_trace_archive(context):
            return
        self._record_trace_event("trace:update", context)

    def complete_task_context(
        self,
        context: TaskContext,
        *,
        status: str = "completed",
        error: BaseException | str | None = None,
    ) -> None:
        if context.ended_at is not None:
            return

        context.ended_at = time.time()
        context.ended_monotonic_ns = time.monotonic_ns()
        context.duration_ms = self._elapsed_duration_ms(context, now_ns=context.ended_monotonic_ns)
        context.status = status
        if error is not None:
            context.error = self._format_error(error)
        with self._trace_lock:
            self._append_trace_transition_locked(
                context,
                event=status,
                at=context.ended_at,
            )
        if self._update_deleted_trace_archive(context):
            return
        self._record_trace_event("trace:complete", context)
        if status in {"completed", "cancelled"}:
            self._schedule_success_trace_delete(context)

    def get_or_create_trace_group(
        self,
        *,
        name: str,
        kind: str,
        peer_id: str | None = None,
        parent: TaskContext | None = None,
        group_key: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> TaskContext:
        parent_context = parent or get_current_task_context()
        key = (
            peer_id or (parent_context.peer_id if parent_context else None),
            parent_context.trace_id if parent_context else None,
            group_key or name,
            name,
            kind,
        )

        with self._trace_lock:
            existing = self._trace_groups.get(key)
            if existing is not None and existing.status != "failed":
                return existing

        group = self.create_task_context(
            name=name,
            kind=kind,
            peer_id=key[0],
            parent=parent_context,
            metadata={
                "trace_group": True,
                "group_key": key[2],
                "call_count": 0,
                "success_count": 0,
                "cancelled_count": 0,
                "error_count": 0,
                "total_duration_ms": 0.0,
                "avg_duration_ms": 0.0,
                "last_duration_ms": None,
                **(metadata or {}),
            },
        )
        self.start_task_context(group)
        with self._trace_lock:
            self._trace_groups[key] = group
            self._trace_group_keys_by_id[group.trace_id] = key
            self._trace_group_last_emit[group.trace_id] = 0.0
        return group

    def record_trace_group_call(
        self,
        group: TaskContext,
        *,
        duration_ms: float,
        status: str = "completed",
        error: BaseException | str | None = None,
        force: bool = False,
    ) -> None:
        now = time.time()
        metadata = group.metadata
        metadata["call_count"] = int(metadata.get("call_count", 0)) + 1
        metadata["last_duration_ms"] = duration_ms
        metadata["last_status"] = status
        metadata["updated_at"] = now

        if status == "completed":
            metadata["success_count"] = int(metadata.get("success_count", 0)) + 1
            total = float(metadata.get("total_duration_ms", 0.0)) + duration_ms
            metadata["total_duration_ms"] = total
            metadata["avg_duration_ms"] = total / max(1, int(metadata["success_count"]))
            group.duration_ms = self._elapsed_duration_ms(group, now_ns=time.monotonic_ns())
        elif status == "cancelled":
            metadata["cancelled_count"] = int(metadata.get("cancelled_count", 0)) + 1
            group.duration_ms = self._elapsed_duration_ms(group, now_ns=time.monotonic_ns())
        else:
            metadata["error_count"] = int(metadata.get("error_count", 0)) + 1
            self.complete_task_context(group, status="failed", error=error)
            return

        with self._trace_lock:
            self._append_trace_transition_locked(
                group,
                event="grouped-call-updated",
                at=now,
            )

        if self._update_deleted_trace_archive(group):
            return

        should_emit = force
        with self._trace_lock:
            last_emit = self._trace_group_last_emit.get(group.trace_id, 0.0)
            if now - last_emit >= self._trace_group_update_interval:
                should_emit = True
            if should_emit:
                self._trace_group_last_emit[group.trace_id] = now

        if should_emit:
            self._record_trace_event("trace:update", group)

    def close_trace_groups(self, *, peer_id: str | None = None) -> None:
        with self._trace_lock:
            groups = list(self._trace_groups.values())

        for group in groups:
            if peer_id is not None and group.peer_id != peer_id:
                continue
            if group.status == "failed":
                continue
            self.complete_task_context(group, status="completed")

    def set_success_trace_retention(
        self,
        seconds: float,
        *,
        peer_id: str | None = None,
    ) -> None:
        retention = max(0.0, seconds)
        with self._trace_lock:
            self._success_trace_retention_by_peer[peer_id] = retention
            contexts = [
                context
                for context in self._traces.values()
                if context.status in {"completed", "cancelled"}
                and (peer_id is None or context.peer_id == peer_id)
            ]

        for context in contexts:
            self._schedule_success_trace_delete(context)

    def get_success_trace_retention(self, *, peer_id: str | None = None) -> float:
        return self._success_trace_retention_by_peer.get(
            peer_id,
            self._default_success_trace_retention,
        )

    async def trace_awaitable(
        self,
        awaitable: Awaitable[T],
        *,
        name: str | None = None,
        kind: str = "task",
        peer_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        context: TaskContext | None = None,
    ) -> T:
        task_context = context or self.create_task_context(
            name=name or self._awaitable_name(awaitable),
            kind=kind,
            peer_id=peer_id,
            metadata=metadata,
        )
        self.start_task_context(task_context)
        token = set_current_task_context(task_context)
        try:
            result = await awaitable
        except asyncio.CancelledError:
            self.complete_task_context(task_context, status="cancelled")
            raise
        except BaseException as exc:
            self.complete_task_context(task_context, status="failed", error=exc)
            raise
        else:
            self.complete_task_context(task_context, status="completed")
            return result
        finally:
            reset_current_task_context(token)

    def spawn_task(
        self,
        awaitable: Awaitable[T],
        *,
        name: str | None = None,
        kind: str = "task",
        peer_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
        context: TaskContext | None = None,
    ) -> asyncio.Task[T]:
        trace_context = context or self.create_task_context(
            name=name or self._awaitable_name(awaitable),
            kind=kind,
            peer_id=peer_id,
            metadata=metadata,
        )
        return self.create_task(
            self.trace_awaitable(awaitable, context=trace_context),
            name=name or trace_context.name,
            loop=loop,
        )

    async def offload_sync(
        self,
        *args: Any,
        name: str | None = None,
        kind: str = "thread",
        peer_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        aggregate: bool = False,
        group_name: str | None = None,
        group_key: str | None = None,
        **kwargs: Any,
    ) -> T:
        if not args:
            raise TypeError("offload_sync requires a callable")

        if self._looks_like_loop(args[0]):
            if len(args) < 2:
                raise TypeError("offload_sync requires a callable after the loop")
            loop = args[0]
            fn = args[1]
            fn_args = args[2:]
        else:
            loop = asyncio.get_running_loop()
            fn = args[0]
            fn_args = args[1:]

        if not callable(fn):
            raise TypeError("offload_sync expected a callable")

        if aggregate:
            return await self._offload_sync_aggregate(
                loop,
                fn,
                *fn_args,
                name=name,
                kind=kind,
                peer_id=peer_id,
                metadata=metadata,
                group_name=group_name,
                group_key=group_key,
                **kwargs,
            )

        trace_context = self.create_task_context(
            name=name or getattr(fn, "__qualname__", getattr(fn, "__name__", "offload")),
            kind=kind,
            peer_id=peer_id,
            metadata=metadata,
        )
        self.start_task_context(trace_context)
        token = set_current_task_context(trace_context)

        def call_in_thread() -> T:
            thread_token = set_current_task_context(trace_context)
            try:
                return fn(*fn_args, **kwargs)
            finally:
                reset_current_task_context(thread_token)

        try:
            if self._shutdown:
                raise RuntimeError("WebRTC runtime is shutting down")

            async with self._offload_limiter:
                if self._shutdown:
                    raise RuntimeError("WebRTC runtime is shutting down")
                result = await loop.run_in_executor(self._executor, call_in_thread)
        except asyncio.CancelledError:
            self.complete_task_context(trace_context, status="cancelled")
            raise
        except BaseException as exc:
            self.complete_task_context(trace_context, status="failed", error=exc)
            raise
        else:
            self.complete_task_context(trace_context, status="completed")
            return result
        finally:
            reset_current_task_context(token)

    async def to_thread(
        self,
        fn: Callable[..., T],
        *args: Any,
        name: str | None = None,
        peer_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        aggregate: bool = False,
        group_name: str | None = None,
        group_key: str | None = None,
        **kwargs: Any,
    ) -> T:
        return await self.offload_sync(
            fn,
            *args,
            name=name,
            kind="thread",
            peer_id=peer_id,
            metadata=metadata,
            aggregate=aggregate,
            group_name=group_name,
            group_key=group_key,
            **kwargs,
        )

    async def _offload_sync_aggregate(
        self,
        loop: asyncio.AbstractEventLoop,
        fn: Callable[..., T],
        *args: Any,
        name: str | None,
        kind: str,
        peer_id: str | None,
        metadata: Mapping[str, Any] | None,
        group_name: str | None,
        group_key: str | None,
        **kwargs: Any,
    ) -> T:
        if self._shutdown:
            raise RuntimeError("WebRTC runtime is shutting down")

        parent = get_current_task_context()
        call_name = name or getattr(fn, "__qualname__", getattr(fn, "__name__", "offload"))
        group = self.get_or_create_trace_group(
            name=group_name or call_name,
            kind=kind,
            peer_id=peer_id,
            parent=parent,
            group_key=group_key or call_name,
            metadata=metadata,
        )
        token = set_current_task_context(group)
        started = time.perf_counter()

        def call_in_thread() -> T:
            thread_token = set_current_task_context(group)
            try:
                return fn(*args, **kwargs)
            finally:
                reset_current_task_context(thread_token)

        try:
            async with self._offload_limiter:
                if self._shutdown:
                    raise RuntimeError("WebRTC runtime is shutting down")
                result = await loop.run_in_executor(self._executor, call_in_thread)
        except asyncio.CancelledError:
            self.record_trace_group_call(
                group,
                duration_ms=(time.perf_counter() - started) * 1000,
                status="cancelled",
                force=True,
            )
            raise
        except BaseException as exc:
            self.record_trace_group_call(
                group,
                duration_ms=(time.perf_counter() - started) * 1000,
                status="failed",
                error=exc,
                force=True,
            )
            raise
        else:
            self.record_trace_group_call(
                group,
                duration_ms=(time.perf_counter() - started) * 1000,
                status="completed",
            )
            return result
        finally:
            reset_current_task_context(token)

    def trace_snapshot(self, *, peer_id: str | None = None) -> list[dict[str, Any]]:
        with self._trace_lock:
            contexts = [
                context
                for trace_id, context in self._traces.items()
                if trace_id not in self._hidden_deleted_trace_ids
            ]
        if peer_id is not None:
            contexts = [context for context in contexts if context.peer_id == peer_id]
        contexts.sort(key=lambda context: context.created_at)
        now_ns = time.monotonic_ns()
        return [self._trace_record_for_emit(context, now_ns=now_ns) for context in contexts]

    def running_trace_snapshot(self, *, peer_id: str | None = None) -> list[dict[str, Any]]:
        with self._trace_lock:
            contexts = [
                context
                for context in self._traces.values()
                if context.status in {"created", "running"}
                and (peer_id is None or context.peer_id == peer_id)
            ]
        contexts.sort(key=lambda context: context.created_at)
        now_ns = time.monotonic_ns()
        return [self._trace_record_for_emit(context, now_ns=now_ns) for context in contexts]

    def trace_summaries(self, *, peer_id: str | None = None) -> list[dict[str, Any]]:
        with self._trace_lock:
            summaries = list(self._trace_summaries.values())
        if peer_id is not None:
            summaries = [summary for summary in summaries if summary.get("peer_id") == peer_id]
        summaries.sort(key=lambda summary: float(summary.get("deleted_at", 0.0)), reverse=True)
        return [self._copy_trace_summary(summary) for summary in summaries]

    def subscribe_traces(
        self,
        *,
        maxsize: int = 1024,
        include_history: bool = False,
        peer_id: str | None = None,
    ) -> TraceSubscription:
        loop = asyncio.get_running_loop()
        subscriber = _TraceSubscriber(asyncio.Queue(maxsize=maxsize), loop, peer_id)
        subscription = TraceSubscription(self, subscriber)

        with self._trace_lock:
            self._trace_subscribers.add(subscriber)
            history = list(self._trace_history) if include_history else []

        for event in history:
            if self._event_matches_peer(event, peer_id):
                self._offer_queue(subscriber.queue, event)

        return subscription

    def unsubscribe_traces(self, subscription: TraceSubscription) -> None:
        with self._trace_lock:
            self._trace_subscribers.discard(subscription.subscriber)

    def delete_trace(self, trace_id: str) -> bool:
        archived_traces: list[dict[str, Any]] = []
        deleted_at = time.time()
        deleted_at_ns = time.monotonic_ns()
        with self._trace_lock:
            context = self._traces.get(trace_id)
            if context is not None:
                trace_ids = self._collect_trace_subtree_ids_locked(trace_id)
                removed = set(trace_ids)
                self._mark_deleted_traces_locked(trace_ids, deleted_at=deleted_at)
                archived_traces = self._archive_trace_tree_locked(
                    context,
                    deleted_at=deleted_at,
                    deleted_at_ns=deleted_at_ns,
                    deleted_trace_ids=removed,
                    descendant_trace_ids=removed,
                )
                self._store_deleted_trace_archives_locked(archived_traces)

                for removed_trace_id in trace_ids:
                    removed_context = self._traces.get(removed_trace_id)
                    if removed_context is not None and removed_context.status in {"created", "running"}:
                        self._hidden_deleted_trace_ids.add(removed_trace_id)
                    else:
                        self._delete_trace_record_locked(removed_trace_id)
            elif self._is_archived_trace_locked(trace_id):
                return True
            else:
                return False

        summary = self._remember_deleted_summary(
            context,
            archived_traces=archived_traces,
            deleted_at=deleted_at,
            deleted_at_ns=deleted_at_ns,
        )
        if summary is not None:
            self._record_summary_event([summary], peer_id=context.peer_id)
        self._record_delete_event(trace_ids, peer_id=context.peer_id)
        return True

    def delete_traces(
        self,
        *,
        peer_id: str | None = None,
        statuses: set[str] | None = None,
        include_running: bool = False,
    ) -> int:
        contexts: list[TaskContext] = []
        archived_by_trace_id: dict[str, list[dict[str, Any]]] = {}
        deleted_at = time.time()
        deleted_at_ns = time.monotonic_ns()
        with self._trace_lock:
            trace_ids: list[str] = []
            for context in list(self._traces.values()):
                if peer_id is not None and context.peer_id != peer_id:
                    continue
                if statuses is not None and context.status not in statuses:
                    continue
                if not include_running and context.status in {"created", "running"}:
                    continue
                trace_ids.append(context.trace_id)

            removed = set(trace_ids)
            self._mark_deleted_traces_locked(trace_ids, deleted_at=deleted_at)
            for trace_id in trace_ids:
                context = self._traces.get(trace_id)
                if context is not None:
                    archived_traces = self._archive_trace_tree_locked(
                        context,
                        deleted_at=deleted_at,
                        deleted_at_ns=deleted_at_ns,
                        deleted_trace_ids=removed,
                        descendant_trace_ids=removed,
                    )
                    archived_by_trace_id[trace_id] = archived_traces
                    self._store_deleted_trace_archives_locked(archived_traces)
                    contexts.append(context)

            for trace_id in trace_ids:
                context = self._traces.get(trace_id)
                if context is not None and context.status in {"created", "running"}:
                    self._hidden_deleted_trace_ids.add(trace_id)
                else:
                    self._delete_trace_record_locked(trace_id)

            if trace_ids:
                self._trace_order = deque(
                    trace_id for trace_id in self._trace_order if trace_id not in removed
                )

        if trace_ids:
            summaries = [
                summary
                for context in contexts
                if (
                    summary := self._remember_deleted_summary(
                        context,
                        archived_traces=archived_by_trace_id.get(context.trace_id, []),
                        deleted_at=deleted_at,
                        deleted_at_ns=deleted_at_ns,
                    )
                )
                is not None
            ]
            if summaries:
                self._record_summary_event(summaries, peer_id=peer_id)
            self._record_delete_event(trace_ids, peer_id=peer_id)
        return len(trace_ids)

    def shutdown(self, *, wait: bool = False, cancel_futures: bool = True) -> None:
        self._shutdown = True
        if self._owns_executor:
            self._executor.shutdown(wait=wait, cancel_futures=cancel_futures)

    async def aclose(self) -> None:
        self.shutdown(wait=False, cancel_futures=True)

    def _record_trace_event(self, event_name: str, context: TaskContext) -> None:
        now_ns = time.monotonic_ns()
        event = {
            "event": event_name,
            "data": {
                "sequence": 0,
                "trace": self._trace_record_for_emit(context, now_ns=now_ns),
            },
        }
        with self._trace_lock:
            self._trace_sequence += 1
            event["data"]["sequence"] = self._trace_sequence
            self._trace_history.append(event)
            subscribers = list(self._trace_subscribers)

        for subscriber in subscribers:
            if not self._event_matches_peer(event, subscriber.peer_id):
                continue
            self._deliver_event(subscriber, event)

    @staticmethod
    def _trace_record_for_emit(context: TaskContext, *, now_ns: int) -> dict[str, Any]:
        record = context.to_dict()
        if context.status in {"created", "running"}:
            record["duration_ms"] = WebRTCRuntimeResources._elapsed_duration_ms(
                context,
                now_ns=now_ns,
            )
        return record

    @staticmethod
    def _elapsed_duration_ms(context: TaskContext, *, now_ns: int) -> float:
        start_ns = (
            context.started_monotonic_ns
            if context.started_monotonic_ns is not None
            else context.created_monotonic_ns
        )
        return max(0.0, (now_ns - start_ns) / 1_000_000)

    def _record_delete_event(self, trace_ids: list[str], *, peer_id: str | None) -> None:
        event = {
            "event": "trace:delete",
            "data": {
                "sequence": 0,
                "trace_ids": trace_ids,
                "peer_id": peer_id,
            },
        }
        with self._trace_lock:
            self._trace_sequence += 1
            event["data"]["sequence"] = self._trace_sequence
            self._trace_history.append(event)
            subscribers = list(self._trace_subscribers)

        for subscriber in subscribers:
            if peer_id is not None and subscriber.peer_id not in {None, peer_id}:
                continue
            self._deliver_event(subscriber, event)

    def _record_summary_event(
        self,
        summaries: list[dict[str, Any]],
        *,
        peer_id: str | None,
    ) -> None:
        event_summaries = [self._copy_trace_summary(summary) for summary in summaries]
        event = {
            "event": "trace:summary",
            "data": {
                "sequence": 0,
                "summaries": event_summaries,
                "peer_id": peer_id,
            },
        }
        with self._trace_lock:
            self._trace_sequence += 1
            event["data"]["sequence"] = self._trace_sequence
            self._trace_history.append(event)
            subscribers = list(self._trace_subscribers)

        for subscriber in subscribers:
            if peer_id is not None and subscriber.peer_id not in {None, peer_id}:
                continue
            self._deliver_event(subscriber, event)

    def _schedule_success_trace_delete(self, context: TaskContext) -> None:
        retention = self.get_success_trace_retention(peer_id=context.peer_id)
        if retention <= 0:
            self.delete_trace(context.trace_id)
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        with self._trace_lock:
            existing = self._success_trace_delete_handles.pop(context.trace_id, None)
            if existing is not None:
                existing.cancel()
            self._success_trace_delete_handles[context.trace_id] = loop.call_later(
                retention,
                self.delete_trace,
                context.trace_id,
            )

    def _remember_deleted_summary(
        self,
        context: TaskContext,
        *,
        archived_traces: list[dict[str, Any]] | None = None,
        deleted_at: float | None = None,
        deleted_at_ns: int | None = None,
    ) -> dict[str, Any] | None:
        if context.status not in {"created", "running", "completed", "cancelled", "failed"}:
            return None

        metadata = context.metadata
        group_key = str(metadata.get("group_key") or context.name)
        sample_count = int(
            metadata.get("success_count")
            or metadata.get("call_count")
            or metadata.get("error_count")
            or metadata.get("cancelled_count")
            or 1
        )
        avg_duration = self._duration_for_deleted_summary(
            context,
            deleted_at=deleted_at,
            deleted_at_ns=deleted_at_ns,
        )

        key = (context.peer_id, group_key, context.name, context.kind)
        aggregate_key = self._trace_summary_aggregate_key(key)
        summary_id = context.trace_id
        with self._trace_lock:
            previous_average = self._trace_summary_averages.get(key)
            previous_avg = (
                previous_average.get("avg_duration_ms")
                if previous_average is not None
                else None
            )
            summary_archived_traces = self._merge_archived_trace_records(
                [],
                archived_traces or [],
            )
            deleted_trace = next(
                (
                    trace
                    for trace in summary_archived_traces
                    if trace.get("trace_id") == context.trace_id
                ),
                self._copy_trace_record(context.to_dict()),
            )
            deleted_trace_ids = [
                trace["trace_id"]
                for trace in summary_archived_traces
                if trace.get("metadata", {}).get("deleted_target") is True
            ]
            delta = (
                float(avg_duration) - float(previous_avg)
                if isinstance(previous_avg, (int, float))
                else None
            )
            summary = {
                "summary_id": summary_id,
                "peer_id": context.peer_id,
                "aggregate_key": aggregate_key,
                "group_key": group_key,
                "name": context.name,
                "kind": context.kind,
                "status": context.status,
                "error": context.error,
                "avg_duration_ms": float(avg_duration),
                "previous_avg_duration_ms": previous_avg,
                "delta_avg_duration_ms": delta,
                "sample_count": sample_count,
                "deleted_trace_id": context.trace_id,
                "deleted_trace_ids": deleted_trace_ids,
                "deleted_trace": deleted_trace,
                "archived_traces": summary_archived_traces,
                "deleted_at": deleted_at or time.time(),
            }
            self._trace_summaries[summary_id] = summary
            self._trace_summary_aggregate_keys[summary_id] = key
            self._add_trace_summary_average_sample_locked(
                key,
                avg_duration=float(avg_duration),
                sample_count=sample_count,
            )
        return self._copy_trace_summary(summary)

    def _duration_for_deleted_summary(
        self,
        context: TaskContext,
        *,
        deleted_at: float | None = None,
        deleted_at_ns: int | None = None,
    ) -> float:
        metadata = context.metadata
        avg_duration = metadata.get("avg_duration_ms")
        if context.status == "failed" and not metadata.get("success_count"):
            avg_duration = metadata.get("last_duration_ms") or context.duration_ms
        if not isinstance(avg_duration, (int, float)):
            avg_duration = context.duration_ms
        if isinstance(avg_duration, (int, float)):
            return max(0.0, float(avg_duration))

        return self._elapsed_duration_ms(
            context,
            now_ns=deleted_at_ns if deleted_at_ns is not None else time.monotonic_ns(),
        )

    def _archive_trace_tree_locked(
        self,
        context: TaskContext,
        *,
        deleted_at: float,
        deleted_at_ns: int,
        deleted_trace_ids: set[str] | None = None,
        descendant_trace_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        records_by_id: dict[str, dict[str, Any]] = {}
        deleted_trace_ids = deleted_trace_ids or {context.trace_id}

        def add_record(trace_id: str) -> dict[str, Any] | None:
            if trace_id in records_by_id:
                return records_by_id[trace_id]

            active_context = self._traces.get(trace_id)
            if active_context is not None:
                record = self._trace_record_for_emit(
                    active_context,
                    now_ns=deleted_at_ns,
                )
            else:
                archived_record = self._deleted_trace_archives.get(trace_id)
                if archived_record is None:
                    return None
                record = self._copy_trace_record(archived_record)

            metadata = dict(record.get("metadata") or {})
            metadata["archived_trace"] = True
            if trace_id in deleted_trace_ids:
                metadata["deleted_target"] = True
                metadata["deleted_at"] = deleted_at
            else:
                metadata.setdefault("deleted_target", False)
            record["metadata"] = metadata
            if record.get("duration_ms") is None:
                start = record.get("started_at") or record.get("created_at")
                if isinstance(start, (int, float)):
                    record["duration_ms"] = max(0.0, (deleted_at - float(start)) * 1000)
            if trace_id not in deleted_trace_ids:
                self._append_trace_record_transition_locked(
                    record,
                    event="archived",
                    at=deleted_at,
                )

            records_by_id[trace_id] = record
            return record

        seen_ancestors: set[str] = set()
        trace_id: str | None = context.trace_id

        while trace_id and trace_id not in seen_ancestors:
            seen_ancestors.add(trace_id)
            record = add_record(trace_id)
            if record is None:
                break

            parent_id = record.get("parent_id")
            trace_id = parent_id if isinstance(parent_id, str) else None

        for descendant_id in self._collect_trace_descendant_ids_locked(
            context.trace_id,
            candidate_ids=descendant_trace_ids,
        ):
            add_record(descendant_id)

        return sorted(
            records_by_id.values(),
            key=lambda trace: float(trace.get("created_at") or 0.0),
        )

    def _collect_trace_subtree_ids_locked(self, trace_id: str) -> list[str]:
        return [
            trace_id,
            *self._collect_trace_descendant_ids_locked(trace_id),
        ]

    def _collect_trace_descendant_ids_locked(
        self,
        trace_id: str,
        *,
        candidate_ids: set[str] | None = None,
    ) -> list[str]:
        children_by_parent: dict[str, list[str]] = {}
        for child_id, child in self._traces.items():
            if candidate_ids is not None and child_id not in candidate_ids:
                continue
            if child.parent_id is None:
                continue
            children_by_parent.setdefault(child.parent_id, []).append(child_id)

        for child_id, child in self._deleted_trace_archives.items():
            if candidate_ids is not None and child_id not in candidate_ids:
                continue
            parent_id = child.get("parent_id")
            if not isinstance(parent_id, str):
                continue
            children_by_parent.setdefault(parent_id, []).append(child_id)

        descendants: list[str] = []
        seen = {trace_id}
        pending = list(children_by_parent.get(trace_id, []))

        while pending:
            child_id = pending.pop(0)
            if child_id in seen:
                continue
            seen.add(child_id)
            descendants.append(child_id)
            pending.extend(children_by_parent.get(child_id, []))

        return descendants

    def _delete_trace_record_locked(self, trace_id: str) -> None:
        self._traces.pop(trace_id, None)
        self._hidden_deleted_trace_ids.discard(trace_id)
        handle = self._success_trace_delete_handles.pop(trace_id, None)
        if handle is not None:
            handle.cancel()
        group_key = self._trace_group_keys_by_id.pop(trace_id, None)
        if group_key is not None:
            self._trace_groups.pop(group_key, None)
            self._trace_group_last_emit.pop(trace_id, None)
        try:
            self._trace_order.remove(trace_id)
        except ValueError:
            pass

    def _mark_deleted_traces_locked(
        self,
        trace_ids: list[str],
        *,
        deleted_at: float,
    ) -> None:
        for trace_id in trace_ids:
            context = self._traces.get(trace_id)
            if context is None:
                continue
            self._append_trace_transition_locked(
                context,
                event="deleted",
                at=deleted_at,
            )

    def _append_trace_transition_locked(
        self,
        context: TaskContext,
        *,
        event: str,
        at: float | None = None,
    ) -> None:
        transition = self._make_trace_transition(
            at=context.created_at if at is None else at,
            event=event,
            status=context.status,
            duration_ms=self._transition_duration_ms(
                started_at=context.started_at,
                created_at=context.created_at,
                duration_ms=context.duration_ms,
                at=at,
            ),
            error=context.error,
        )
        context.transitions = self._merge_trace_transitions(
            context.transitions,
            [transition],
        )

    def _append_trace_record_transition_locked(
        self,
        record: dict[str, Any],
        *,
        event: str,
        at: float | None = None,
    ) -> None:
        transition_at = float(at if at is not None else record.get("created_at") or time.time())
        transition = self._make_trace_transition(
            at=transition_at,
            event=event,
            status=str(record.get("status") or "unknown"),
            duration_ms=self._transition_duration_ms(
                started_at=record.get("started_at"),
                created_at=record.get("created_at"),
                duration_ms=record.get("duration_ms"),
                at=transition_at,
            ),
            error=record.get("error") if isinstance(record.get("error"), str) else None,
        )
        record["transitions"] = self._merge_trace_transitions(
            record.get("transitions"),
            [transition],
        )

    @staticmethod
    def _make_trace_transition(
        *,
        at: float,
        event: str,
        status: str,
        duration_ms: float | int | None,
        error: str | None,
    ) -> dict[str, Any]:
        transition: dict[str, Any] = {
            "at": float(at),
            "event": event,
            "status": status,
            "duration_ms": float(duration_ms) if isinstance(duration_ms, (int, float)) else None,
        }
        if error:
            transition["error"] = error
        return transition

    @staticmethod
    def _transition_duration_ms(
        *,
        started_at: Any,
        created_at: Any,
        duration_ms: Any,
        at: float | None,
    ) -> float | None:
        if isinstance(duration_ms, (int, float)):
            return max(0.0, float(duration_ms))
        if at is None:
            return None
        start = started_at if isinstance(started_at, (int, float)) else created_at
        if not isinstance(start, (int, float)):
            return None
        return max(0.0, (float(at) - float(start)) * 1000)

    @classmethod
    def _merge_trace_transitions(
        cls,
        previous: Any,
        incoming: Any,
    ) -> list[dict[str, Any]]:
        merged: list[tuple[int, dict[str, Any]]] = []
        seen: set[tuple[Any, ...]] = set()

        def add(raw: Any) -> None:
            transition = cls._copy_trace_transition(raw)
            if transition is None:
                return
            key = (
                transition.get("at"),
                transition.get("event"),
                transition.get("status"),
                transition.get("duration_ms"),
                transition.get("error"),
            )
            if key in seen:
                return
            seen.add(key)
            merged.append((len(merged), transition))

        if isinstance(previous, list):
            for transition in previous:
                add(transition)
        if isinstance(incoming, list):
            for transition in incoming:
                add(transition)

        return [
            transition
            for _, transition in sorted(
                merged,
                key=lambda item: (float(item[1].get("at") or 0.0), item[0]),
            )
        ]

    @staticmethod
    def _copy_trace_transition(raw: Any) -> dict[str, Any] | None:
        if not isinstance(raw, dict):
            return None
        at = raw.get("at")
        event = raw.get("event")
        status = raw.get("status")
        if not isinstance(at, (int, float)) or not isinstance(event, str):
            return None
        transition: dict[str, Any] = {
            "at": float(at),
            "event": event,
            "status": str(status) if status is not None else "unknown",
            "duration_ms": None,
        }
        duration_ms = raw.get("duration_ms")
        if isinstance(duration_ms, (int, float)):
            transition["duration_ms"] = float(duration_ms)
        error = raw.get("error")
        if isinstance(error, str) and error:
            transition["error"] = error
        return transition

    def _store_deleted_trace_archives_locked(self, traces: list[dict[str, Any]]) -> None:
        for trace in traces:
            trace_id = trace.get("trace_id")
            if not isinstance(trace_id, str):
                continue
            if trace_id not in self._deleted_trace_archives:
                self._deleted_trace_archive_order.append(trace_id)
            self._deleted_trace_archives[trace_id] = self._copy_trace_record(trace)

        while (
            len(self._deleted_trace_archives) > self._trace_archive_limit
            and self._deleted_trace_archive_order
        ):
            trace_id = self._deleted_trace_archive_order.popleft()
            if trace_id in self._deleted_trace_archives:
                self._deleted_trace_archives.pop(trace_id, None)

    def _is_archived_trace_locked(self, trace_id: str) -> bool:
        if trace_id in self._deleted_trace_archives:
            return True
        if trace_id in self._trace_summaries:
            return True
        return any(
            isinstance(summary.get("deleted_trace_ids"), list)
            and trace_id in summary["deleted_trace_ids"]
            for summary in self._trace_summaries.values()
        )

    def _merge_archived_trace_records(
        self,
        previous: Any,
        incoming: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        records_by_id: dict[str, dict[str, Any]] = {}
        if isinstance(previous, list):
            for trace in previous:
                if not isinstance(trace, dict):
                    continue
                trace_id = trace.get("trace_id")
                if isinstance(trace_id, str):
                    records_by_id[trace_id] = self._copy_trace_record(trace)

        for trace in incoming:
            trace_id = trace.get("trace_id")
            if isinstance(trace_id, str):
                records_by_id[trace_id] = self._copy_trace_record(trace)

        return sorted(
            records_by_id.values(),
            key=lambda trace: float(trace.get("created_at") or 0.0),
        )

    @staticmethod
    def _copy_trace_record(trace: dict[str, Any]) -> dict[str, Any]:
        copied = dict(trace)
        copied["metadata"] = dict(trace.get("metadata") or {})
        transitions = trace.get("transitions")
        if isinstance(transitions, list):
            copied["transitions"] = [
                transition
                for transition in (
                    WebRTCRuntimeResources._copy_trace_transition(item)
                    for item in transitions
                )
                if transition is not None
            ]
        return copied

    @staticmethod
    def _copy_trace_summary(summary: dict[str, Any]) -> dict[str, Any]:
        copied = dict(summary)
        deleted_trace = copied.get("deleted_trace")
        if isinstance(deleted_trace, dict):
            copied["deleted_trace"] = WebRTCRuntimeResources._copy_trace_record(deleted_trace)

        archived_traces = copied.get("archived_traces")
        if isinstance(archived_traces, list):
            copied["archived_traces"] = [
                WebRTCRuntimeResources._copy_trace_record(trace)
                for trace in archived_traces
                if isinstance(trace, dict)
            ]

        deleted_trace_ids = copied.get("deleted_trace_ids")
        if isinstance(deleted_trace_ids, list):
            copied["deleted_trace_ids"] = list(deleted_trace_ids)

        return copied

    @staticmethod
    def _trace_summary_aggregate_key(
        key: tuple[str | None, str, str, str],
    ) -> str:
        return "|".join("" if part is None else str(part) for part in key)

    def _add_trace_summary_average_sample_locked(
        self,
        key: tuple[str | None, str, str, str],
        *,
        avg_duration: float,
        sample_count: int,
    ) -> None:
        sample_count = max(1, sample_count)
        previous = self._trace_summary_averages.get(key)
        if previous is None:
            self._trace_summary_averages[key] = {
                "avg_duration_ms": float(avg_duration),
                "sample_count": sample_count,
            }
            return

        previous_count = max(0, int(previous.get("sample_count", 0)))
        previous_avg = float(previous.get("avg_duration_ms", 0.0))
        next_count = previous_count + sample_count
        next_avg = (
            (previous_avg * previous_count) + (float(avg_duration) * sample_count)
        ) / max(1, next_count)
        self._trace_summary_averages[key] = {
            "avg_duration_ms": next_avg,
            "sample_count": next_count,
        }

    def _recompute_trace_summary_average_locked(
        self,
        key: tuple[str | None, str, str, str],
    ) -> None:
        total_count = 0
        weighted_total = 0.0
        for summary_id, summary in self._trace_summaries.items():
            if self._trace_summary_aggregate_keys.get(summary_id) != key:
                continue
            avg_duration = summary.get("avg_duration_ms")
            if not isinstance(avg_duration, (int, float)):
                continue
            sample_count = max(1, int(summary.get("sample_count") or 1))
            total_count += sample_count
            weighted_total += float(avg_duration) * sample_count

        if total_count <= 0:
            self._trace_summary_averages.pop(key, None)
            return

        self._trace_summary_averages[key] = {
            "avg_duration_ms": weighted_total / total_count,
            "sample_count": total_count,
        }

    def _update_deleted_trace_archive(self, context: TaskContext) -> bool:
        updated_summaries: list[dict[str, Any]] = []
        with self._trace_lock:
            existing = self._deleted_trace_archives.get(context.trace_id)
            if existing is None:
                return False
            suppress_live_event = (
                context.trace_id not in self._traces
                or context.trace_id in self._hidden_deleted_trace_ids
            )

            updated_trace = self._trace_record_for_emit(
                context,
                now_ns=time.monotonic_ns(),
            )
            metadata = dict(updated_trace.get("metadata") or {})
            existing_metadata = existing.get("metadata", {})
            if isinstance(existing_metadata, dict):
                for key in ("archived_trace", "deleted_target", "deleted_at"):
                    if key in existing_metadata:
                        metadata.setdefault(key, existing_metadata[key])
            metadata["archived_trace"] = True
            updated_trace["metadata"] = metadata
            updated_trace["transitions"] = self._merge_trace_transitions(
                existing.get("transitions"),
                updated_trace.get("transitions"),
            )
            self._deleted_trace_archives[context.trace_id] = self._copy_trace_record(
                updated_trace
            )

            for summary_id, summary in list(self._trace_summaries.items()):
                archived_traces = summary.get("archived_traces")
                if not isinstance(archived_traces, list):
                    continue

                found = False
                next_archived_traces: list[dict[str, Any]] = []
                for trace in archived_traces:
                    if (
                        isinstance(trace, dict)
                        and trace.get("trace_id") == context.trace_id
                    ):
                        next_archived_traces.append(self._copy_trace_record(updated_trace))
                        found = True
                    elif isinstance(trace, dict):
                        next_archived_traces.append(self._copy_trace_record(trace))

                if not found:
                    continue

                next_summary = dict(summary)
                next_summary["archived_traces"] = next_archived_traces
                deleted_trace = next_summary.get("deleted_trace")
                if (
                    isinstance(deleted_trace, dict)
                    and deleted_trace.get("trace_id") == context.trace_id
                ):
                    next_summary["deleted_trace"] = self._copy_trace_record(updated_trace)

                if next_summary.get("deleted_trace_id") == context.trace_id:
                    next_summary["status"] = context.status
                    next_summary["error"] = context.error
                    next_summary["avg_duration_ms"] = self._duration_for_deleted_summary(
                        context
                    )
                    self._trace_summaries[summary_id] = next_summary
                    aggregate_key = self._trace_summary_aggregate_keys.get(summary_id)
                    if aggregate_key is not None:
                        self._recompute_trace_summary_average_locked(aggregate_key)
                else:
                    self._trace_summaries[summary_id] = next_summary
                updated_summaries.append(self._copy_trace_summary(next_summary))

            if context.ended_at is not None and context.trace_id in self._hidden_deleted_trace_ids:
                self._delete_trace_record_locked(context.trace_id)

        if updated_summaries:
            self._record_summary_event(updated_summaries, peer_id=context.peer_id)
        return suppress_live_event

    def _deliver_event(
        self,
        subscriber: _TraceSubscriber,
        event: dict[str, Any],
    ) -> None:
        def offer() -> None:
            self._offer_queue(subscriber.queue, event)

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop is subscriber.loop:
            offer()
            return

        if not subscriber.loop.is_closed():
            subscriber.loop.call_soon_threadsafe(offer)

    @staticmethod
    def _offer_queue(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

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
        summaries = data.get("summaries")
        return isinstance(summaries, list) and any(
            isinstance(summary, dict) and summary.get("peer_id") == peer_id
            for summary in summaries
        )

    def _trim_traces_locked(self) -> None:
        while len(self._traces) > self._trace_context_limit and self._trace_order:
            trace_id = self._trace_order.popleft()
            context = self._traces.get(trace_id)
            if context is None:
                continue
            if context.ended_at is None:
                self._trace_order.append(trace_id)
                break
            self._traces.pop(trace_id, None)
            self._hidden_deleted_trace_ids.discard(trace_id)

    @staticmethod
    def _format_error(error: BaseException | str) -> str:
        if isinstance(error, BaseException):
            return f"{error.__class__.__name__}: {error}"
        return error

    @staticmethod
    def _awaitable_name(awaitable: Awaitable[Any]) -> str:
        name = getattr(awaitable, "__qualname__", None) or getattr(awaitable, "__name__", None)
        if name:
            return str(name)

        coro = getattr(awaitable, "cr_code", None)
        if coro is not None:
            return str(getattr(coro, "co_name", "task"))

        return awaitable.__class__.__name__

    @staticmethod
    def _looks_like_loop(value: Any) -> bool:
        return hasattr(value, "run_in_executor") and hasattr(value, "call_soon")


_default_runtime: WebRTCRuntimeResources | None = None


def get_default_runtime() -> WebRTCRuntimeResources:
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = WebRTCRuntimeResources()
    return _default_runtime


def _shutdown_default_runtime() -> None:
    if _default_runtime is not None:
        _default_runtime.shutdown(wait=False, cancel_futures=True)


atexit.register(_shutdown_default_runtime)
