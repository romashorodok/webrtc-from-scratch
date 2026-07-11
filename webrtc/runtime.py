import asyncio
import atexit
import contextvars
from collections.abc import Awaitable, Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import RLock
from typing import Any, TypeVar

from .tracing import (
    TaskContext,
    TraceService,
    TraceSubscription,
    get_current_performance_recorder,
    use_performance_recorder,
)

T = TypeVar("T")

_current_task_context: contextvars.ContextVar[TaskContext | None] = contextvars.ContextVar(
    "webrtc_current_task_context",
    default=None,
)


@dataclass
class RuntimeTaskEntry:
    trace_id: str
    parent_id: str | None
    cancelable: bool
    active: bool
    task: asyncio.Task[Any] | None = None


def get_current_task_context() -> TaskContext | None:
    return _current_task_context.get()


def set_current_task_context(
    context: TaskContext | None,
) -> contextvars.Token[TaskContext | None]:
    return _current_task_context.set(context)


def reset_current_task_context(token: contextvars.Token[TaskContext | None]) -> None:
    _current_task_context.reset(token)


class WebRTCRuntimeResources:
    def __init__(
        self,
        *,
        executor: ThreadPoolExecutor | None = None,
        offload_capacity: int = 32,
        owns_executor: bool | None = None,
        max_workers: int = 4,
        max_pending_offloads: int | None = None,
        trace_context_limit: int = 4096,
        trace_group_update_interval: float = 0.5,
        trace_subscriber_batch_interval: float = 0.5,
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
        self._trace_group_update_interval = trace_group_update_interval

        self._tracing = TraceService(
            trace_context_limit=trace_context_limit,
            trace_subscriber_batch_interval=trace_subscriber_batch_interval,
            executor=self._executor,
        )
        self._trace_groups: dict[tuple[str | None, str, str, str], TaskContext] = {}
        self._trace_group_last_emit: dict[str, float] = {}
        self._trace_group_emit_handles: dict[str, asyncio.TimerHandle] = {}
        self._task_registry_lock = RLock()
        self._task_registry: dict[str, RuntimeTaskEntry] = {}

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
        return self._tracing.create_context(
            name=name,
            kind=kind,
            parent=parent_context,
            parent_id=parent_id,
            metadata=metadata,
        )

    def start_task_context(self, context: TaskContext) -> None:
        self._tracing.start_context(context)
        if context.status in {"created", "running"}:
            existing = self._task_entry(context.trace_id)
            if existing is None:
                self._register_task_entry(
                    trace_id=context.trace_id,
                    parent_id=context.parent_id,
                    cancelable=self._default_cancelable_for_context(context),
                    active=True,
                    task=None,
                )

    def complete_task_context(
        self,
        context: TaskContext,
        *,
        status: str = "completed",
        error: BaseException | str | None = None,
    ) -> None:
        self._tracing.complete_context(
            context,
            status=status,
            error=self._format_error(error) if error is not None else None,
        )

    def get_or_create_trace_group(
        self,
        *,
        name: str,
        kind: str,
        parent: TaskContext | None = None,
        group_key: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> TaskContext:
        parent_context = parent or get_current_task_context()
        key = (
            parent_context.trace_id if parent_context else None,
            group_key or name,
            name,
            kind,
        )
        existing = self._trace_groups.get(key)
        if existing is not None and existing.status in {"created", "running"}:
            return existing
        if existing is not None:
            self._forget_trace_group(key, existing.trace_id)

        group = self.create_task_context(
            name=name,
            kind=kind,
            parent=parent_context,
            metadata={
                "trace_group": True,
                "group_key": key[1],
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
        self._trace_groups[key] = group
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
        now = asyncio.get_running_loop().time()
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
        elif status == "cancelled":
            metadata["cancelled_count"] = int(metadata.get("cancelled_count", 0)) + 1
        else:
            metadata["error_count"] = int(metadata.get("error_count", 0)) + 1
            self.complete_task_context(group, status="failed", error=error)
            self._forget_trace_group_by_id(group.trace_id)
            return

        should_emit = force or (
            now - self._trace_group_last_emit.get(group.trace_id, 0.0) >= self._trace_group_update_interval
        )
        if should_emit:
            self._trace_group_last_emit[group.trace_id] = now
            self._cancel_trace_group_emit(group.trace_id)
            self._tracing.start_context(group)
            return

        if group.trace_id not in self._trace_group_emit_handles:
            remaining = max(
                0.0,
                self._trace_group_update_interval - (now - self._trace_group_last_emit.get(group.trace_id, 0.0)),
            )
            loop = asyncio.get_running_loop()
            self._trace_group_emit_handles[group.trace_id] = loop.call_later(
                remaining,
                self._emit_trace_group_update,
                group.trace_id,
            )

    def close_trace_groups(self, trace_ids: set[str] | None = None) -> None:
        for group in list(self._trace_groups.values()):
            if trace_ids is not None and group.trace_id not in trace_ids:
                continue
            if group.status == "failed":
                continue
            self.complete_task_context(group, status="completed")
            self._forget_trace_group_by_id(group.trace_id)

    async def trace_awaitable(
        self,
        awaitable: Awaitable[T],
        *,
        name: str | None = None,
        kind: str = "task",
        metadata: Mapping[str, Any] | None = None,
        context: TaskContext | None = None,
    ) -> T:
        task_context = context or self.create_task_context(
            name=name or self._awaitable_name(awaitable),
            kind=kind,
            metadata=metadata,
        )
        self.start_task_context(task_context)
        task = asyncio.current_task()
        self._register_task_entry(
            trace_id=task_context.trace_id,
            parent_id=task_context.parent_id,
            cancelable=True,
            active=True,
            task=task,
        )
        token = set_current_task_context(task_context)
        try:
            # Preserve an explicitly installed recorder (tests and callers use
            # this for isolated captures); otherwise stream through runtime.
            with use_performance_recorder(
                get_current_performance_recorder() or self._tracing.performance_recorder
            ):
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
            self._set_task_entry_active(task_context.trace_id, False)
            reset_current_task_context(token)

    def spawn_task(
        self,
        awaitable: Awaitable[T],
        *,
        name: str | None = None,
        kind: str = "task",
        metadata: Mapping[str, Any] | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
        context: TaskContext | None = None,
    ) -> asyncio.Task[T]:
        trace_context = context or self.create_task_context(
            name=name or self._awaitable_name(awaitable),
            kind=kind,
            metadata=metadata,
        )
        return self.create_task(
            self.trace_awaitable(awaitable, context=trace_context),
            name=name or trace_context.name,
            loop=loop,
        )

    async def offload_sync(self, *args: Any, name: str | None = None, kind: str = "thread", metadata: Mapping[str, Any] | None = None, aggregate: bool = False, group_name: str | None = None, group_key: str | None = None, **kwargs: Any) -> T:
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
            return await self._offload_sync_aggregate(loop, fn, *fn_args, name=name, kind=kind, metadata=metadata, group_name=group_name, group_key=group_key, **kwargs)

        trace_context = self.create_task_context(name=name or getattr(fn, "__qualname__", getattr(fn, "__name__", "offload")), kind=kind, metadata=metadata)
        self.start_task_context(trace_context)
        self._register_task_entry(
            trace_id=trace_context.trace_id,
            parent_id=trace_context.parent_id,
            cancelable=False,
            active=True,
            task=None,
        )
        token = set_current_task_context(trace_context)

        def call_in_thread() -> T:
            thread_token = set_current_task_context(trace_context)
            try:
                with use_performance_recorder(
                    get_current_performance_recorder() or self._tracing.performance_recorder
                ):
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
            self._set_task_entry_active(trace_context.trace_id, False)
            reset_current_task_context(token)

    async def to_thread(self, fn: Callable[..., T], *args: Any, name: str | None = None, metadata: Mapping[str, Any] | None = None, aggregate: bool = False, group_name: str | None = None, group_key: str | None = None, **kwargs: Any) -> T:
        return await self.offload_sync(fn, *args, name=name, kind="thread", metadata=metadata, aggregate=aggregate, group_name=group_name, group_key=group_key, **kwargs)

    async def _offload_sync_aggregate(self, loop: asyncio.AbstractEventLoop, fn: Callable[..., T], *args: Any, name: str | None, kind: str, metadata: Mapping[str, Any] | None, group_name: str | None, group_key: str | None, **kwargs: Any) -> T:
        if self._shutdown:
            raise RuntimeError("WebRTC runtime is shutting down")
        parent = get_current_task_context()
        call_name = name or getattr(fn, "__qualname__", getattr(fn, "__name__", "offload"))
        group = self.get_or_create_trace_group(name=group_name or call_name, kind=kind, parent=parent, group_key=group_key or call_name, metadata=metadata)
        token = set_current_task_context(group)
        started = asyncio.get_running_loop().time()

        def call_in_thread() -> T:
            thread_token = set_current_task_context(group)
            try:
                with use_performance_recorder(
                    get_current_performance_recorder() or self._tracing.performance_recorder
                ):
                    return fn(*args, **kwargs)
            finally:
                reset_current_task_context(thread_token)

        try:
            async with self._offload_limiter:
                if self._shutdown:
                    raise RuntimeError("WebRTC runtime is shutting down")
                result = await loop.run_in_executor(self._executor, call_in_thread)
        except asyncio.CancelledError:
            self.record_trace_group_call(group, duration_ms=(asyncio.get_running_loop().time() - started) * 1000, status="cancelled", force=True)
            raise
        except BaseException as exc:
            self.record_trace_group_call(group, duration_ms=(asyncio.get_running_loop().time() - started) * 1000, status="failed", error=exc, force=True)
            raise
        else:
            self.record_trace_group_call(group, duration_ms=(asyncio.get_running_loop().time() - started) * 1000, status="completed")
            return result
        finally:
            reset_current_task_context(token)

    def trace_live_tree(self, *, scope_trace_id: str | None = None) -> list[dict[str, Any]]:
        return self._tracing.store.live_tree(scope_trace_id=scope_trace_id)

    def trace_live_running(
        self,
        include_duration: bool = False,
        *,
        scope_trace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._tracing.trace_live_running(
            include_duration=include_duration,
            scope_trace_id=scope_trace_id,
        )

    def trace_running_signature(
        self,
        *,
        scope_trace_id: str | None = None,
    ) -> tuple[tuple[str, str | None, str], ...]:
        return self._tracing.trace_running_signature(scope_trace_id=scope_trace_id)

    def trace_subscribe(
        self,
        *,
        maxsize: int = 1024,
        peer_id: str | None = None,
    ) -> TraceSubscription:
        return self._tracing.trace_subscribe(maxsize=maxsize, peer_id=peer_id)

    def delete_trace(self, trace_id: str, *, peer_id: str | None = None) -> bool:
        deleted_contexts = self._tracing.store.subtree_contexts(trace_id)
        ok = self._tracing.delete_trace(
            trace_id,
            is_cancelable=self._is_running_trace_cancelable,
            cancel_trace=self._cancel_running_trace,
            mark_inactive=lambda tid: self._set_task_entry_active(tid, False),
            peer_id=peer_id,
        )
        if ok:
            for context in deleted_contexts:
                self._forget_trace_group_by_id(context.trace_id)
        return ok

    def delete_traces(
        self,
        *,
        statuses: set[str] | None = None,
        include_running: bool = False,
        peer_id: str | None = None,
    ) -> int:
        count, ids = self._tracing.delete_traces(
            statuses=statuses,
            include_running=include_running,
            peer_id=peer_id,
        )
        for trace_id in ids:
            self._forget_trace_group_by_id(trace_id)
        return count

    def shutdown(self, *, wait: bool = False, cancel_futures: bool = True) -> None:
        self._shutdown = True
        if self._owns_executor:
            self._executor.shutdown(wait=wait, cancel_futures=cancel_futures)

    async def aclose(self) -> None:
        self.shutdown(wait=False, cancel_futures=True)

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

    def _register_task_entry(
        self,
        *,
        trace_id: str,
        parent_id: str | None,
        cancelable: bool,
        active: bool,
        task: asyncio.Task[Any] | None,
    ) -> None:
        with self._task_registry_lock:
            self._task_registry[trace_id] = RuntimeTaskEntry(
                trace_id=trace_id,
                parent_id=parent_id,
                cancelable=cancelable,
                active=active,
                task=task,
            )

    def _set_task_entry_active(self, trace_id: str, active: bool) -> None:
        with self._task_registry_lock:
            entry = self._task_registry.get(trace_id)
            if entry is not None:
                entry.active = active

    def _task_entry(self, trace_id: str) -> RuntimeTaskEntry | None:
        with self._task_registry_lock:
            return self._task_registry.get(trace_id)

    def _cancel_running_trace(self, trace_id: str) -> None:
        entry = self._task_entry(trace_id)
        if entry and entry.task and not entry.task.done():
            entry.task.cancel()

    def _is_running_trace_cancelable(self, context: TaskContext) -> bool:
        entry = self._task_entry(context.trace_id)
        if entry is not None:
            return entry.active and entry.cancelable
        return self._default_cancelable_for_context(context)

    @staticmethod
    def _default_cancelable_for_context(context: TaskContext) -> bool:
        # Aggregate trace-group nodes are runtime counters, not active thread jobs.
        # They should never block deleting their parent coroutine subtree.
        if context.metadata.get("trace_group") is True:
            return True
        return context.kind != "thread"

    def _emit_trace_group_update(self, trace_id: str) -> None:
        self._trace_group_emit_handles.pop(trace_id, None)
        group = self._trace_group_by_id(trace_id)
        if group is None or group.status not in {"created", "running"}:
            return
        self._trace_group_last_emit[trace_id] = asyncio.get_running_loop().time()
        self._tracing.start_context(group)

    def _trace_group_by_id(self, trace_id: str) -> TaskContext | None:
        for group in self._trace_groups.values():
            if group.trace_id == trace_id:
                return group
        return None

    def _cancel_trace_group_emit(self, trace_id: str) -> None:
        handle = self._trace_group_emit_handles.pop(trace_id, None)
        if handle is not None:
            handle.cancel()

    def _forget_trace_group_by_id(self, trace_id: str) -> None:
        self._cancel_trace_group_emit(trace_id)
        self._trace_group_last_emit.pop(trace_id, None)
        keys_to_remove = [key for key, group in self._trace_groups.items() if group.trace_id == trace_id]
        for key in keys_to_remove:
            self._trace_groups.pop(key, None)

    def _forget_trace_group(self, key: tuple[str | None, str, str, str], trace_id: str) -> None:
        self._trace_groups.pop(key, None)
        self._forget_trace_group_by_id(trace_id)


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
