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
        self, entity_id: str, dot: ProducerDot, values: Mapping[str, Scalar], *,
        observer_meta: str, source_entity_id: str, source_epoch: int,
        source_revision: int, source_order: int,
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


class WrongRuntimeLoop(ExecutionScopeError):
    pass


class UntrackedRuntimeTask(AssertionError):
    pass


class StaleOwnerEpoch(ExecutionScopeError):
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
class MetricSinkProtocol(Protocol):
    def emit(self, event: Any) -> None: ...


@runtime_checkable
class ExecutionScope(Protocol):
    task_scheduler: TaskScheduler
    task_registry: TaskRegistry
    sync_offloader: SyncOffloader
    worker_lane: ConcurrentWorkerLane
    metric_sink: MetricSinkProtocol
    activity_groups: Any
    capture_manager: Any
    diagnostics: Counter[str]
    transition_controller: Any
    runtime_epoch: int
    observability_epoch: int
    tracing_enabled: bool
    state: ScopeState

    def observe_task_failure(self, event: TaskFailureEvent) -> None: ...
    def new_producer_dot(self) -> ProducerDot: ...
    def start(self, factory: Callable[[], Awaitable[T]], **kwargs: Any) -> OwnedTaskHandle[T]: ...


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


class OwnedTaskHandle(Generic[T]):
    """Opaque component-facing view of one Runtime-owned task."""

    __slots__ = ("_task", "owner_entity_id", "owner_epoch")

    def __init__(
        self, task: asyncio.Task[T], *, owner_entity_id: str, owner_epoch: int
    ) -> None:
        self._task = task
        self.owner_entity_id = owner_entity_id
        self.owner_epoch = owner_epoch

    def cancel(self) -> bool:
        if self._task.done():
            return False
        return self._task.cancel()

    def done(self) -> bool:
        return self._task.done()

    def cancelled(self) -> bool:
        return self._task.cancelled()

    @property
    def status(self) -> str:
        if not self._task.done():
            return "running"
        if self._task.cancelled():
            return "cancelled"
        return "failed" if self._task.exception() is not None else "completed"

    async def wait(self) -> T:
        return await asyncio.shield(self._task)

    def __await__(self):
        return self.wait().__await__()


class OwnedTimerHandle:
    """Opaque timer handle tied to one entity epoch."""

    __slots__ = ("_handle", "_fired", "owner_entity_id", "owner_epoch")

    def __init__(
        self, handle: asyncio.TimerHandle, fired: asyncio.Future[bool],
        *, owner_entity_id: str, owner_epoch: int,
    ) -> None:
        self._handle = handle
        self._fired = fired
        self.owner_entity_id = owner_entity_id
        self.owner_epoch = owner_epoch

    def cancel(self) -> bool:
        if self._handle.cancelled() or self._fired.done():
            return False
        self._handle.cancel()
        self._fired.set_result(False)
        return True

    def done(self) -> bool:
        return self._fired.done()

    async def wait(self) -> bool:
        return await asyncio.shield(self._fired)


class OwnedResourceHandle:
    """Opaque handle for a Runtime-owned resource and its close barrier."""

    __slots__ = (
        "_close", "_wait_closed", "_closed", "_closing",
        "owner_entity_id", "owner_epoch", "name",
    )

    def __init__(
        self, close: Callable[[], Any], wait_closed: Callable[[], Awaitable[Any]],
        *, owner_entity_id: str, owner_epoch: int, name: str,
    ) -> None:
        self._close = close
        self._wait_closed = wait_closed
        self._closed = asyncio.get_running_loop().create_future()
        self._closing = False
        self.owner_entity_id = owner_entity_id
        self.owner_epoch = owner_epoch
        self.name = name

    def done(self) -> bool:
        return self._closed.done()

    @property
    def status(self) -> str:
        if not self._closing:
            return "open"
        if not self._closed.done():
            return "closing"
        return "failed" if self._closed.exception() is not None else "closed"

    async def aclose(self) -> None:
        if self._closing:
            await asyncio.shield(self._closed)
            return
        self._closing = True
        try:
            self._close()
            await self._wait_closed()
        except BaseException as error:
            if not self._closed.done():
                self._closed.set_exception(error)
                # The active closer raises directly; consume the retained
                # future exception unless another closer is already awaiting it.
                self._closed.exception()
            raise
        else:
            if not self._closed.done():
                self._closed.set_result(None)

    async def wait_closed(self) -> None:
        await asyncio.shield(self._closed)


@dataclass(frozen=True, slots=True)
class ImmutableWorkerResult(Generic[T]):
    submission_id: int
    owner_entity_id: str
    owner_epoch: int
    outcome: str
    value: T | None = None
    exception: BaseException | None = None


@dataclass(frozen=True, slots=True)
class RuntimeExecutionPort:
    """Explicit entity-owned execution capability supplied by ``Runtime``.

    The port deliberately contains no tracing or observation policy.  It is
    therefore safe to use with tracing enabled or disabled without changing
    scheduling, affinity, ownership, or stale-epoch checks.
    """

    runtime: Any
    owner_entity_id: str
    owner_epoch: int

    def assert_event_loop(self) -> asyncio.AbstractEventLoop:
        loop = self.runtime._assert_loop()
        self.runtime.assert_owner_epoch(self.owner_entity_id, self.owner_epoch)
        return loop

    async def run_worker(
        self, fn: Callable[..., T], *args: Any, name: str = "worker", **kwargs: Any,
    ) -> T:
        result = await self.runtime.call_worker(
            fn, *args,
            owner_entity_id=self.owner_entity_id,
            owner_epoch=self.owner_epoch,
            name=name,
            **kwargs,
        ).wait()
        if result.outcome == "success":
            return cast(T, result.value)
        if result.exception is not None:
            raise result.exception
        raise RuntimeError(f"worker submission {result.outcome}")

    def start_task(
        self, factory: Callable[[], Awaitable[T]], *, name: str,
        kind: str = "task", metadata: Mapping[str, Any] | None = None,
        failure: FailurePolicy = FailurePolicy.REPORT,
        cancelable: bool = True,
    ) -> OwnedTaskHandle[T]:
        return self.runtime.start_pump(
            factory,
            owner_entity_id=self.owner_entity_id,
            owner_epoch=self.owner_epoch,
            name=name,
            kind=kind,
            metadata=metadata,
            failure=failure,
            cancelable=cancelable,
        )


class TaskRegistry:
    """Event-loop-owned task and reconciliation index."""

    def __init__(self) -> None:
        self._entries: dict[str, TaskEntry] = {}
        self._children: dict[str, set[str]] = {}
        self._barriers: dict[str, set[asyncio.Future[Any]]] = {}
        self._cancel_blocks: dict[str, tuple[bool, int]] = {}
        self._node_cancellers: dict[str, Callable[[], bool]] = {}
        self._revision = 0
        self._changed: asyncio.Future[None] | None = None

    @property
    def revision(self) -> int:
        return self._revision

    def _signal_change(self) -> None:
        self._revision += 1
        changed, self._changed = self._changed, None
        if changed is not None and not changed.done():
            changed.set_result(None)

    async def wait_for_change(self, after_revision: int) -> int:
        while self._revision <= after_revision:
            if self._changed is None:
                self._changed = asyncio.get_running_loop().create_future()
            await asyncio.shield(self._changed)
        return self._revision

    def add(self, entry: TaskEntry) -> None:
        task_id = entry.context.task_id
        if task_id in self._entries:
            raise ValueError(f"task {task_id} is already registered")
        self._entries[task_id] = entry
        parent_id = entry.context.parent_task_id
        if parent_id is not None:
            self._children.setdefault(parent_id, set()).add(task_id)
        self._signal_change()

    def remove(self, task_id: str) -> None:
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
        if entry is not None:
            self._signal_change()

    def get(self, task_id: str) -> TaskEntry | None:
        return self._entries.get(task_id)

    def task_ids(self) -> tuple[str, ...]:
        return tuple(self._entries)

    def child_entries(self, task_id: str) -> tuple[TaskEntry, ...]:
        return tuple(
            self._entries[child_id]
            for child_id in self._children.get(task_id, ())
            if child_id in self._entries
        )

    def descendants(self, task_id: str) -> tuple[TaskEntry, ...]:
        result: list[TaskEntry] = []
        pending = [task_id]
        while pending:
            parent_id = pending.pop()
            for child_id in self._children.get(parent_id, ()):
                entry = self._entries.get(child_id)
                if entry is not None:
                    result.append(entry)
                    pending.append(child_id)
        return tuple(result)

    def can_cancel(self, task_ids: list[str]) -> bool:
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
        entry = self._entries.get(task_id)
        if entry is not None:
            entry.cancelable = cancelable

    def block_cancel(self, task_id: str) -> None:
        """Temporarily make a task non-cancelable, preserving its exact base state."""
        entry = self._entries.get(task_id)
        if entry is None:
            return
        base, count = self._cancel_blocks.get(task_id, (entry.cancelable, 0))
        self._cancel_blocks[task_id] = (base, count + 1)
        entry.cancelable = False

    def unblock_cancel(self, task_id: str) -> None:
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
        self._barriers.setdefault(task_id, set()).add(barrier)
        barrier.add_done_callback(lambda done: self.remove_barrier(task_id, done))
        self._signal_change()

    def remove_barrier(self, task_id: str, barrier: asyncio.Future[Any]) -> None:
        barriers = self._barriers.get(task_id)
        if barriers is not None:
            barriers.discard(barrier)
            if not barriers:
                self._barriers.pop(task_id, None)
            self._signal_change()

    def barriers(self, task_id: str) -> tuple[asyncio.Future[Any], ...]:
        return tuple(self._barriers.get(task_id, ()))

    def register_node_canceller(self, node_id: str, cancel: Callable[[], bool]) -> None:
        self._node_cancellers[node_id] = cancel

    def unregister_node_canceller(self, node_id: str) -> None:
        self._node_cancellers.pop(node_id, None)

    def cancel_node(self, node_id: str) -> bool:
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
        self._credits: asyncio.Queue[None] | None = None
        self._dispatched: set[asyncio.Future[Any]] = set()
        self.closed = False

    def _credit_queue(self) -> asyncio.Queue[None]:
        if self._credits is None:
            self._credits = asyncio.Queue(self.capacity)
            for _ in range(self.capacity):
                self._credits.put_nowait(None)
        return self._credits

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
        credits = self._credit_queue()
        await credits.get()
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
                credits.put_nowait(None)
            else:
                future.add_done_callback(lambda _future: credits.put_nowait(None))
            raise
        except BaseException:
            credits.put_nowait(None)
            raise
        else:
            credits.put_nowait(None)
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


class ConcurrentWorkerLane:
    """Bounded concurrent Runtime worker lane."""

    def __init__(self, offloader: SyncOffloader) -> None:
        self.offloader = offloader
        self._identity = object()
        self._observability_id = f"concurrent:{secrets.token_hex(6)}"
        self._queued = 0
        self._running = 0
        self._high_water = 0
        self._lifecycle_state: Callable[[], str] = lambda: "idle"
        self._state_publisher: Callable[..., None] | None = None

    def set_lifecycle_state(self, state: Callable[[], str]) -> None:
        self._lifecycle_state = state

    def set_state_publisher(self, publisher: Callable[..., None]) -> None:
        self._state_publisher = publisher

    def _publish_state(self) -> None:
        if self._state_publisher is not None:
            try:
                self._state_publisher(
                    queued=self._queued, running=self._running,
                    high_water=self._high_water,
                )
            except Exception:
                # Observation is best effort. A metrics callback must not turn
                # accepted worker work into a lifecycle or mailbox failure.
                pass

    @property
    def observability_id(self) -> str:
        return self._observability_id

    def load_snapshot(self) -> tuple[int, int, int]:
        return self._queued, self._running, self._high_water

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
        lifecycle = self._lifecycle_state()
        if lifecycle in {"closing", "closed"}:
            raise ScopeNotActive(f"worker lane is {lifecycle}")

        self._queued += 1
        self._high_water = max(self._high_water, self._queued)
        self._publish_state()
        try:
            token = _worker_lane_context.set(self._identity)
            self._queued -= 1
            self._running += 1
            self._publish_state()
            return await self.offloader.run_observed(
                fn, *args, on_dispatch=on_dispatch, on_future=on_future,
                on_complete=on_complete, **kwargs
            )
        finally:
            if 'token' in locals():
                _worker_lane_context.reset(token)
                self._running -= 1
            else:
                self._queued -= 1
            self._publish_state()

    async def aclose(self, timeout: float | None = None) -> None:
        if self._lifecycle_state() == "closed":
            return
        await self.offloader.wait_for_dispatched(timeout)
        self._running = 0
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
        if self.closed and kind != "reconciliation":
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

        reconciliation = self._spawn_reconciliation(
            context, spec, cancel=outcome != "completed"
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

    def _spawn_reconciliation(
        self, parent: ExecutionContext, parent_spec: TaskSpec, *, cancel: bool
    ) -> asyncio.Task[None]:
        """Register the terminal barrier before its coroutine can execute."""
        context = ExecutionContext(
            parent.trace_id, uuid.uuid4().hex, parent.task_id, parent.scope_id
        )
        spec = TaskSpec(
            f"{parent_spec.name}:reconcile-children", "reconciliation", {}, False
        )

        async def reconcile() -> None:
            token = _execution_context.set(context)
            self._notify(
                "task_started",
                TaskStarted(context, spec.name, spec.kind, {}, False),
            )
            try:
                await self._reconcile_children(parent.task_id, cancel=cancel)
            except BaseException as error:
                self._notify("task_failed", TaskFailed(context, error))
                raise
            else:
                self._notify("task_completed", TaskCompleted(context))
            finally:
                self.registry.remove(context.task_id)
                _execution_context.reset(token)

        task = asyncio.get_running_loop().create_task(reconcile(), name=spec.name)
        try:
            self.registry.add(TaskEntry(context, task, False, spec))
        except BaseException:
            task.cancel()
            raise
        return task

    def _cancel_descendants(self, task_id: str) -> None:
        for entry in self.registry.descendants(task_id):
            if entry.cancelable and entry.task is not None and not entry.task.done():
                entry.task.cancel()

    async def _reconcile_children(self, task_id: str, *, cancel: bool) -> None:
        while True:
            registry_revision = self.registry.revision
            current = asyncio.current_task()
            children = tuple(
                entry for entry in self.registry.child_entries(task_id)
                if entry.task is not current
            )
            barriers = self.registry.barriers(task_id)
            if not children and not barriers:
                return
            tasks = [entry.task for entry in children if entry.task is not None and not entry.task.done()]
            if cancel:
                self._cancel_descendants(task_id)
            waits: list[asyncio.Future[Any] | asyncio.Task[Any]] = [*tasks, *barriers]
            if not waits:
                await self.registry.wait_for_change(registry_revision)
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
