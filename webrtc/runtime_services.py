from __future__ import annotations

import asyncio
import contextvars
import secrets
import inspect
import time
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Any, Generic, Protocol, TypeAlias, TypeVar, cast, runtime_checkable

from .observability import ProducerClock, ProducerDot

T = TypeVar("T")
R = TypeVar("R")

Scalar: TypeAlias = str | int | float | bool | None


@runtime_checkable
class StateFacetSink(Protocol):
    """Observation-neutral sink for bounded semantic component state."""

    def transition(self, operation: Any) -> None: ...
    def merge_values(
        self, entity_id: str, dot: ProducerDot, values: Mapping[str, Scalar]
    ) -> None: ...
    def remove(self, entity_id: str, epoch: int, dot: ProducerDot) -> None: ...


class ScopeState(str, Enum):
    NEW = "new"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"


class FailurePolicy(str, Enum):
    REPORT = "report"
    FAIL_CONNECTION = "fail-connection"
    IGNORE = "ignore"


class ExecutionScopeError(RuntimeError):
    """Base error for generic execution-scope lifecycle failures."""


class MissingExecutionScope(ExecutionScopeError):
    pass


class ScopeNotActive(ExecutionScopeError):
    pass


class ScopeShutdownTimeout(ExecutionScopeError):
    pass


@dataclass(frozen=True, slots=True)
class Owned(Generic[R]):
    resource: R


@dataclass(frozen=True, slots=True)
class Borrowed(Generic[R]):
    resource: R


ResourceDeclaration = Owned[R] | Borrowed[R]


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    trace_id: str
    task_id: str
    parent_task_id: str | None = None
    scope_id: str | None = None
    node_id: str | None = None

@dataclass(frozen=True, slots=True)
class TaskSpec:
    name: str = "task"
    kind: str = "task"
    metadata: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    cancelable: bool = True
    failure: FailurePolicy = FailurePolicy.REPORT

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class TaskFailureEvent:
    spec: TaskSpec
    context: ExecutionContext
    exception: BaseException


class TraceNodeType(str, Enum):
    TASK = "task"
    ASYNC_CALL = "async-call"
    INLINE_SYNC_CALL = "inline-sync-call"
    WORKER_CALL = "worker-call"


@dataclass(frozen=True, slots=True)
class TraceNodeDescriptor:
    node_id: str
    trace_id: str
    name: str
    node_type: TraceNodeType
    owner_task_id: str | None
    parent_node_id: str | None = None
    cancelable: bool = False
    metadata: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class TraceNodeStarted:
    descriptor: TraceNodeDescriptor


@dataclass(frozen=True, slots=True)
class TraceNodeCompleted:
    descriptor: TraceNodeDescriptor
    outcome: str
    duration_ms: float
    exception: BaseException | None = None


@dataclass(frozen=True, slots=True)
class TraceNodeCancelabilityChanged:
    node_id: str
    cancelable: bool


@dataclass(frozen=True, slots=True)
class WorkerCallCompleted:
    outcome: str
    queue_ns: int
    worker_ns: int
    total_ns: int
    exception: BaseException | None = None
    observation_delta: Any | None = None

    @property
    def queue_ms(self) -> float:
        return self.queue_ns / 1_000_000

    @property
    def worker_ms(self) -> float:
        return self.worker_ns / 1_000_000

    @property
    def total_ms(self) -> float:
        return self.total_ns / 1_000_000


@runtime_checkable
class TraceServiceProtocol(Protocol):
    def task_started(self, event: TaskStarted) -> None: ...
    def task_completed(self, event: TaskCompleted) -> None: ...
    def task_failed(self, event: TaskFailed) -> None: ...
    def task_cancelled(self, event: TaskCancelled) -> None: ...
    def node_started(self, event: TraceNodeStarted) -> None: ...
    def node_completed(self, event: TraceNodeCompleted) -> None: ...
    def node_cancelability_changed(self, event: TraceNodeCancelabilityChanged) -> None: ...


@runtime_checkable
class MetricSinkProtocol(Protocol):
    def emit(self, event: Any) -> None: ...


@runtime_checkable
class ExecutionScope(Protocol):
    task_scheduler: TaskScheduler
    task_registry: TaskRegistry
    sync_offloader: SyncOffloader
    worker_lane: SerializedWorkerLane
    trace_service: TraceServiceProtocol
    metric_sink: MetricSinkProtocol
    activity_groups: Any
    capture_manager: Any
    diagnostics: Counter[str]
    transition_controller: Any
    runtime_epoch: int
    observability_epoch: int
    state: ScopeState

    def observe_task_failure(self, event: TaskFailureEvent) -> None: ...
    def new_producer_dot(self) -> ProducerDot: ...


_execution_context: contextvars.ContextVar[ExecutionContext | None] = contextvars.ContextVar(
    "webrtc_execution_context", default=None
)
_current_execution_scope: contextvars.ContextVar[ExecutionScope | None] = contextvars.ContextVar(
    "webrtc_execution_scope", default=None
)


def current_execution_context() -> ExecutionContext | None:
    return _execution_context.get()


def set_execution_context(context: ExecutionContext | None):
    return _execution_context.set(context)


def reset_execution_context(token) -> None:
    _execution_context.reset(token)


def current_execution_scope() -> ExecutionScope | None:
    return _current_execution_scope.get()


def require_execution_scope() -> ExecutionScope:
    scope = current_execution_scope()
    if scope is None:
        raise MissingExecutionScope("operation requires an active execution scope")
    state = getattr(scope, "state", ScopeState.ACTIVE)
    if state in (ScopeState.CLOSING, ScopeState.CLOSED, "closing", "closed"):
        raise ScopeNotActive(f"execution scope is {getattr(state, 'value', state)}")
    return scope


@contextmanager
def use_execution_scope(scope: ExecutionScope):
    token = _current_execution_scope.set(scope)
    try:
        yield scope
    finally:
        _current_execution_scope.reset(token)


@dataclass(frozen=True, slots=True)
class TaskStarted:
    context: ExecutionContext
    name: str
    kind: str
    metadata: dict[str, Any]
    cancelable: bool = True


@dataclass(frozen=True, slots=True)
class TaskCompleted:
    context: ExecutionContext


@dataclass(frozen=True, slots=True)
class TaskFailed:
    context: ExecutionContext
    exception: BaseException


@dataclass(frozen=True, slots=True)
class TaskCancelled:
    context: ExecutionContext


class TaskObserver(Protocol):
    def task_started(self, event: TaskStarted) -> None: ...
    def task_completed(self, event: TaskCompleted) -> None: ...
    def task_failed(self, event: TaskFailed) -> None: ...
    def task_cancelled(self, event: TaskCancelled) -> None: ...


class TaskFailureObserver(Protocol):
    def observe_task_failure(self, event: TaskFailureEvent) -> None: ...


@dataclass(slots=True)
class TaskEntry:
    context: ExecutionContext
    task: asyncio.Task[Any] | None
    cancelable: bool
    spec: TaskSpec = field(default_factory=TaskSpec)
    started_at: float = field(default_factory=time.time)


class TaskRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, TaskEntry] = {}
        self._children: dict[str, set[str]] = {}
        self._barriers: dict[str, set[asyncio.Future[Any]]] = {}
        self._cancel_blocks: dict[str, tuple[bool, int]] = {}
        self._node_cancellers: dict[str, Callable[[], bool]] = {}
        self._lock = RLock()

    def add(self, entry: TaskEntry) -> None:
        with self._lock:
            task_id = entry.context.task_id
            if task_id in self._entries:
                raise ValueError(f"task {task_id} is already registered")
            self._entries[task_id] = entry
            parent_id = entry.context.parent_task_id
            if parent_id is not None:
                self._children.setdefault(parent_id, set()).add(task_id)

    def remove(self, task_id: str) -> None:
        with self._lock:
            entry = self._entries.pop(task_id, None)
            if entry is not None and entry.context.parent_task_id is not None:
                children = self._children.get(entry.context.parent_task_id)
                if children is not None:
                    children.discard(task_id)
                    if not children:
                        self._children.pop(entry.context.parent_task_id, None)
            if not self._children.get(task_id):
                self._children.pop(task_id, None)
            self._cancel_blocks.pop(task_id, None)

    def get(self, task_id: str) -> TaskEntry | None:
        with self._lock:
            return self._entries.get(task_id)

    def task_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._entries)

    def child_entries(self, task_id: str) -> tuple[TaskEntry, ...]:
        with self._lock:
            return tuple(
                self._entries[child_id]
                for child_id in self._children.get(task_id, ())
                if child_id in self._entries
            )

    def descendants(self, task_id: str) -> tuple[TaskEntry, ...]:
        result: list[TaskEntry] = []
        pending = [task_id]
        with self._lock:
            while pending:
                parent_id = pending.pop()
                for child_id in self._children.get(parent_id, ()):
                    entry = self._entries.get(child_id)
                    if entry is not None:
                        result.append(entry)
                        pending.append(child_id)
        return tuple(result)

    def can_cancel(self, task_ids: list[str]) -> bool:
        with self._lock:
            return all(
                (entry := self._entries.get(task_id)) is not None and entry.cancelable
                for task_id in task_ids
            )

    def cancel(self, task_id: str) -> bool:
        entry = self.get(task_id)
        if entry is None or not entry.cancelable:
            return False
        if entry.task is not None and not entry.task.done():
            entry.task.cancel()
        return True

    def set_cancelable(self, task_id: str, cancelable: bool) -> None:
        with self._lock:
            entry = self._entries.get(task_id)
            if entry is not None:
                entry.cancelable = cancelable

    def block_cancel(self, task_id: str) -> None:
        """Temporarily make a task non-cancelable, preserving its exact base state."""
        with self._lock:
            entry = self._entries.get(task_id)
            if entry is None:
                return
            base, count = self._cancel_blocks.get(task_id, (entry.cancelable, 0))
            self._cancel_blocks[task_id] = (base, count + 1)
            entry.cancelable = False

    def unblock_cancel(self, task_id: str) -> None:
        with self._lock:
            state = self._cancel_blocks.get(task_id)
            entry = self._entries.get(task_id)
            if state is None or entry is None:
                return
            base, count = state
            if count <= 1:
                self._cancel_blocks.pop(task_id, None)
                entry.cancelable = base
            else:
                self._cancel_blocks[task_id] = (base, count - 1)

    def add_barrier(self, task_id: str, barrier: asyncio.Future[Any]) -> None:
        with self._lock:
            self._barriers.setdefault(task_id, set()).add(barrier)
        barrier.add_done_callback(lambda done: self.remove_barrier(task_id, done))

    def remove_barrier(self, task_id: str, barrier: asyncio.Future[Any]) -> None:
        with self._lock:
            barriers = self._barriers.get(task_id)
            if barriers is not None:
                barriers.discard(barrier)
                if not barriers:
                    self._barriers.pop(task_id, None)

    def barriers(self, task_id: str) -> tuple[asyncio.Future[Any], ...]:
        with self._lock:
            return tuple(self._barriers.get(task_id, ()))

    def register_node_canceller(self, node_id: str, cancel: Callable[[], bool]) -> None:
        with self._lock:
            self._node_cancellers[node_id] = cancel

    def unregister_node_canceller(self, node_id: str) -> None:
        with self._lock:
            self._node_cancellers.pop(node_id, None)

    def cancel_node(self, node_id: str) -> bool:
        with self._lock:
            cancel = self._node_cancellers.get(node_id)
        return cancel() if cancel is not None else False


class SyncOffloader:
    """Bounded physical-executor dispatch with truthful in-flight tracking."""

    def __init__(
        self,
        executor: Executor | None = None,
        *,
        capacity: int = 32,
        max_workers: int = 4,
        owns_executor: bool | None = None,
    ) -> None:
        self.executor = executor or ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="webrtc-offload"
        )
        self.owns_executor = executor is None if owns_executor is None else owns_executor
        self.capacity = max(1, capacity)
        self._limiter: asyncio.Semaphore | None = None
        self._dispatched: set[asyncio.Future[Any]] = set()
        self.closed = False

    def _semaphore(self) -> asyncio.Semaphore:
        if self._limiter is None:
            self._limiter = asyncio.Semaphore(self.capacity)
        return self._limiter

    @property
    def dispatched_count(self) -> int:
        return len(self._dispatched)

    async def run(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        result, _, _ = await self.run_observed(fn, *args, **kwargs)
        return result

    async def run_observed(
        self,
        fn: Callable[..., T],
        *args: Any,
        on_dispatch: Callable[[], None] | None = None,
        on_future: Callable[[asyncio.Future[Any]], None] | None = None,
        on_complete: Callable[[WorkerCallCompleted], None] | None = None,
        **kwargs: Any,
    ) -> tuple[T, float, float]:
        if self.closed:
            raise ScopeNotActive("execution scope is closing")
        loop = asyncio.get_running_loop()
        copied = contextvars.copy_context()
        queued = time.monotonic_ns()
        limiter = self._semaphore()
        await limiter.acquire()
        future: asyncio.Future[Any] | None = None
        try:
            if self.closed:
                raise ScopeNotActive("execution scope is closing")
            dispatched = time.monotonic_ns()

            worker_timing = [0, 0]

            def invoke() -> tuple[T, int, int]:
                started = time.monotonic_ns()
                worker_timing[0] = started
                try:
                    result = copied.run(fn, *args, **kwargs)
                    finished = time.monotonic_ns()
                    worker_timing[1] = finished
                    return result, started, finished
                except BaseException:
                    worker_timing[1] = time.monotonic_ns()
                    raise

            future = loop.run_in_executor(self.executor, invoke)
            self._dispatched.add(future)
            if on_dispatch is not None:
                on_dispatch()
            if on_future is not None:
                on_future(future)
            future.add_done_callback(self._dispatched.discard)
            if on_complete is not None:
                def completed(done: asyncio.Future[Any]) -> None:
                    try:
                        _, worker_started, worker_finished = done.result()
                    except BaseException as error:
                        event = WorkerCallCompleted(
                            "cancelled" if isinstance(error, asyncio.CancelledError) else "error",
                            dispatched - queued,
                            max(0, worker_timing[1] - worker_timing[0]),
                            max(0, worker_timing[1] - queued),
                            error,
                        )
                    else:
                        event = WorkerCallCompleted(
                            "success",
                            dispatched - queued,
                            worker_finished - worker_started,
                            worker_finished - queued,
                        )
                    try:
                        on_complete(event)
                    except Exception:
                        pass
                future.add_done_callback(completed)
            result, worker_started, worker_finished = await asyncio.shield(future)
            observed = (
                result,
                (dispatched - queued) / 1_000_000,
                (worker_finished - worker_started) / 1_000_000,
            )
        except asyncio.CancelledError:
            if future is None or future.done():
                limiter.release()
            else:
                future.add_done_callback(lambda _future: limiter.release())
            raise
        except BaseException:
            limiter.release()
            raise
        else:
            limiter.release()
            return observed

    async def wait_for_dispatched(self, timeout: float | None = None) -> None:
        pending = tuple(self._dispatched)
        if not pending:
            return
        _, remaining = await asyncio.wait(pending, timeout=timeout)
        if remaining:
            raise ScopeShutdownTimeout(
                f"execution scope shutdown timed out with {len(remaining)} worker call(s) running"
            )

    def shutdown(self, wait: bool = False, cancel_futures: bool = True) -> None:
        self.closed = True
        if self.owns_executor:
            self.executor.shutdown(wait=wait, cancel_futures=cancel_futures)


_worker_lane_context: contextvars.ContextVar[object | None] = contextvars.ContextVar(
    "webrtc_worker_lane", default=None
)


class SerializedWorkerLane:
    """One logical serialized lane layered over a possibly shared executor."""

    def __init__(self, offloader: SyncOffloader) -> None:
        self.offloader = offloader
        self._identity = object()
        self._observability_id = f"serialized:{secrets.token_hex(6)}"
        self._semaphore = asyncio.Semaphore(1)
        self._queued: set[asyncio.Task[Any]] = set()
        self._running = False
        self._high_water = 0
        self.state = ScopeState.ACTIVE

    def _publish_state(self) -> None:
        # Imported lazily because domain_events defines its immutable context
        # contract in terms of this module.
        from .domain_events import WorkerLaneStateChanged, emit_domain_event

        emit_domain_event(
            WorkerLaneStateChanged, lane_id="serialized",
            lane_instance_id=self._observability_id,
            queued=len(self._queued), running=self._running,
        )

    @property
    def observability_id(self) -> str:
        return self._observability_id

    def is_current_worker_context(self) -> bool:
        return _worker_lane_context.get() is self._identity

    async def run(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        result, _, _ = await self.run_observed(fn, *args, **kwargs)
        return result

    async def run_observed(
        self,
        fn: Callable[..., T],
        *args: Any,
        on_dispatch: Callable[[], None] | None = None,
        on_future: Callable[[asyncio.Future[Any]], None] | None = None,
        on_complete: Callable[[WorkerCallCompleted], None] | None = None,
        **kwargs: Any,
    ) -> tuple[T, float, float]:
        if self.is_current_worker_context():
            started = time.monotonic()
            return fn(*args, **kwargs), 0.0, (time.monotonic() - started) * 1000
        if self.state is not ScopeState.ACTIVE:
            raise ScopeNotActive(f"worker lane is {self.state.value}")

        owner = asyncio.current_task()
        if owner is not None:
            self._queued.add(owner)
            self._high_water = max(self._high_water, len(self._queued))
            self._publish_state()
        try:
            await self._semaphore.acquire()
        finally:
            if owner is not None:
                self._queued.discard(owner)
            self._publish_state()
        self._running = True
        self._publish_state()

        if self.state is not ScopeState.ACTIVE:
            self._running = False
            self._publish_state()
            self._semaphore.release()
            raise ScopeNotActive(f"worker lane is {self.state.value}")

        async def dispatch() -> tuple[T, float, float]:
            token = _worker_lane_context.set(self._identity)
            try:
                return await self.offloader.run_observed(
                    fn, *args, on_dispatch=on_dispatch, on_future=on_future,
                    on_complete=on_complete, **kwargs
                )
            finally:
                _worker_lane_context.reset(token)

        dispatched = asyncio.create_task(dispatch())
        try:
            result = await asyncio.shield(dispatched)
        except asyncio.CancelledError:
            async def release_when_finished() -> None:
                try:
                    await dispatched
                except BaseException:
                    pass
                finally:
                    self._running = False
                    self._publish_state()
                    self._semaphore.release()

            asyncio.create_task(release_when_finished())
            raise
        else:
            self._running = False
            self._publish_state()
            self._semaphore.release()
            return result

    async def aclose(self, timeout: float | None = None) -> None:
        if self.state is ScopeState.CLOSED:
            return
        self.state = ScopeState.CLOSING
        for task in tuple(self._queued):
            task.cancel()
        await self.offloader.wait_for_dispatched(timeout)
        self.state = ScopeState.CLOSED
        self._running = False
        self._publish_state()


CoroutineFactory = Callable[[], Awaitable[T]]


async def _invoke_coroutine_factory(factory: CoroutineFactory[T]) -> T:
    awaitable = factory()
    if not inspect.isawaitable(awaitable):
        raise TypeError("coroutine factory must return an awaitable")
    return await awaitable


class TaskScheduler:
    def __init__(
        self,
        registry: TaskRegistry | None = None,
        observers=(),
        failure_observers=(),
        diagnostics: Counter[str] | None = None,
    ) -> None:
        self.registry = registry or TaskRegistry()
        self.observers = list(observers)
        self.failure_observers = list(failure_observers)
        self.closed = False
        self.diagnostics = diagnostics if diagnostics is not None else Counter()

    def _notify(self, method: str, event: Any) -> None:
        for observer in tuple(self.observers):
            try:
                getattr(observer, method)(event)
            except Exception:
                self.diagnostics["observer_failures"] += 1

    def _notify_failure(self, event: TaskFailureEvent) -> None:
        for observer in tuple(self.failure_observers):
            try:
                callback = getattr(observer, "observe_task_failure", observer)
                callback(event)
            except Exception:
                self.diagnostics["failure_observer_failures"] += 1

    @staticmethod
    def _context(
        *,
        parent: ExecutionContext | None,
        trace_id: str | None,
        scope_id: str | None,
        context: ExecutionContext | None,
    ) -> ExecutionContext:
        if context is not None:
            return context
        return ExecutionContext(
            trace_id or (parent.trace_id if parent else uuid.uuid4().hex),
            uuid.uuid4().hex,
            parent.task_id if parent else None,
            scope_id or (parent.scope_id if parent else None),
        )

    def spawn_factory(
        self,
        factory: CoroutineFactory[T],
        *,
        name: str = "task",
        kind: str = "task",
        metadata: Mapping[str, Any] | None = None,
        trace_id: str | None = None,
        scope_id: str | None = None,
        context: ExecutionContext | None = None,
        cancelable: bool = True,
        failure: FailurePolicy = FailurePolicy.REPORT,
    ) -> asyncio.Task[T]:
        if self.closed:
            raise ScopeNotActive("execution scope is closing")
        if not callable(factory):
            raise TypeError("spawn_factory requires a callable coroutine factory")
        loop = asyncio.get_running_loop()
        parent = current_execution_context()
        task_context = self._context(
            parent=parent, trace_id=trace_id, scope_id=scope_id, context=context
        )
        spec = TaskSpec(name, kind, metadata or {}, cancelable, failure)

        async def accepted_runner() -> T:
            return await self._run_accepted(
                _invoke_coroutine_factory(factory), spec, task_context
            )

        task = loop.create_task(accepted_runner(), name=name)
        try:
            self.registry.add(TaskEntry(task_context, task, cancelable, spec))
        except BaseException:
            task.cancel()
            raise
        task.add_done_callback(
            lambda done: self._cleanup_task_cancelled_before_start(done, task_context, spec)
        )
        return task

    def _cleanup_task_cancelled_before_start(
        self,
        task: asyncio.Task[Any],
        context: ExecutionContext,
        spec: TaskSpec,
    ) -> None:
        if self.registry.get(context.task_id) is None:
            return
        if task.cancelled():
            self._notify(
                "task_started",
                TaskStarted(context, spec.name, spec.kind, dict(spec.metadata), spec.cancelable),
            )
            self._notify("task_cancelled", TaskCancelled(context))
        self.registry.remove(context.task_id)

    async def run_factory(
        self,
        factory: CoroutineFactory[T],
        **kwargs: Any,
    ) -> T:
        if self.closed:
            raise ScopeNotActive("execution scope is closing")
        if not callable(factory):
            raise TypeError("run_factory requires a callable coroutine factory")
        parent = current_execution_context()
        spec = TaskSpec(
            kwargs.pop("name", "task"),
            kwargs.pop("kind", "task"),
            kwargs.pop("metadata", None) or {},
            kwargs.pop("cancelable", True),
            kwargs.pop("failure", FailurePolicy.REPORT),
        )
        context = self._context(
            parent=parent,
            trace_id=kwargs.pop("trace_id", None),
            scope_id=kwargs.pop("scope_id", None),
            context=kwargs.pop("context", None),
        )
        if kwargs:
            raise TypeError(f"unexpected scheduler arguments: {', '.join(kwargs)}")
        entry = TaskEntry(context, asyncio.current_task(), spec.cancelable, spec)
        self.registry.add(entry)
        return await self._run_accepted(_invoke_coroutine_factory(factory), spec, context)

    async def _run_accepted(
        self,
        awaitable: Awaitable[T],
        spec: TaskSpec,
        context: ExecutionContext,
    ) -> T:
        token = _execution_context.set(context)
        self._notify(
            "task_started",
            TaskStarted(context, spec.name, spec.kind, dict(spec.metadata), spec.cancelable),
        )
        outcome: str
        result: T | None = None
        error: BaseException | None = None
        try:
            result = await awaitable
        except asyncio.CancelledError as exc:
            outcome = "cancelled"
            error = exc
        except BaseException as exc:
            outcome = "failed"
            error = exc
        else:
            outcome = "completed"

        reconciliation = asyncio.create_task(
            self._reconcile_children(context.task_id, cancel=outcome != "completed"),
            name=f"{spec.name}:reconcile-children",
        )
        try:
            while True:
                try:
                    await asyncio.shield(reconciliation)
                except asyncio.CancelledError as exc:
                    if reconciliation.cancelled():
                        raise
                    # Repeated Task.cancel() calls must retain native caller
                    # cancellation without allowing this parent to disappear
                    # before its children and worker barriers are joined.
                    if outcome != "cancelled":
                        outcome = "cancelled"
                        error = exc
                        self._cancel_descendants(context.task_id)
                    continue
                break
        finally:
            if outcome == "completed":
                self._notify("task_completed", TaskCompleted(context))
            elif outcome == "cancelled":
                self._notify("task_cancelled", TaskCancelled(context))
            else:
                assert error is not None
                self._notify("task_failed", TaskFailed(context, error))
                self._notify_failure(TaskFailureEvent(spec, context, error))
            self.registry.remove(context.task_id)
            _execution_context.reset(token)

        if error is not None:
            raise error
        return cast(T, result)

    def _cancel_descendants(self, task_id: str) -> None:
        for entry in self.registry.descendants(task_id):
            if entry.cancelable and entry.task is not None and not entry.task.done():
                entry.task.cancel()

    async def _reconcile_children(self, task_id: str, *, cancel: bool) -> None:
        while True:
            children = self.registry.child_entries(task_id)
            barriers = self.registry.barriers(task_id)
            if not children and not barriers:
                return
            tasks = [entry.task for entry in children if entry.task is not None and not entry.task.done()]
            if cancel:
                self._cancel_descendants(task_id)
            waits: list[asyncio.Future[Any] | asyncio.Task[Any]] = [*tasks, *barriers]
            if not waits:
                await asyncio.sleep(0)
                continue
            await asyncio.gather(*(asyncio.shield(item) for item in waits), return_exceptions=True)

    async def aclose(
        self, *, exclude_task_ids: tuple[str, ...] = (), timeout: float | None = None
    ) -> None:
        self.closed = True
        entries = [
            entry
            for task_id in self.registry.task_ids()
            if (entry := self.registry.get(task_id)) is not None
            and task_id not in exclude_task_ids
            and entry.task is not asyncio.current_task()
        ]
        for entry in entries:
            if entry.cancelable and entry.task is not None and not entry.task.done():
                entry.task.cancel()
        pending = tuple(entry.task for entry in entries if entry.task is not None)
        if not pending:
            return
        _, remaining = await asyncio.wait(pending, timeout=timeout)
        if remaining:
            raise ScopeShutdownTimeout(
                f"execution scope shutdown timed out with {len(remaining)} managed task(s) active"
            )
