from __future__ import annotations

import asyncio
import inspect
import uuid
from collections import Counter
from collections.abc import Callable
from concurrent.futures import Executor
from typing import Any, TypeVar

from .performance import MetricGroupAggregator
from .runtime_services import (
    Borrowed,
    ExecutionContext,
    ExecutionScope,
    FailurePolicy,
    MetricSinkProtocol,
    Owned,
    ResourceDeclaration,
    ScopeNotActive,
    ScopeState,
    SerializedWorkerLane,
    SyncOffloader,
    TaskCompleted,
    TaskCancelled,
    TaskEntry,
    TaskFailed,
    TaskFailureEvent,
    TaskRegistry,
    TaskScheduler,
    TaskSpec,
    TaskStarted,
    current_execution_context,
    reset_execution_context,
    set_execution_context,
    use_execution_scope,
)
from .tracing.service import TraceService, TraceSubscription

T = TypeVar("T")


class RuntimeObservability:
    """Scoped query/cancellation surface owned by one Runtime."""

    def __init__(self, runtime: "Runtime") -> None:
        self._runtime = runtime

    def _trace_id(self) -> str | None:
        root = self._runtime.root_context
        return root.trace_id if root is not None else None

    def live_tree(self):
        return self._runtime.trace_live_tree(scope_trace_id=self._trace_id())

    def live_running(self, include_duration: bool = False):
        return self._runtime.trace_live_running(
            include_duration=include_duration, scope_trace_id=self._trace_id()
        )

    def running_signature(self):
        return self._runtime.trace_running_signature(scope_trace_id=self._trace_id())

    def metric_snapshots(self):
        return self._runtime.trace_groups(self._trace_id())

    def subscribe(self, *, maxsize: int = 1024) -> TraceSubscription:
        return self._runtime.trace_subscribe(maxsize=maxsize, peer_id=self._runtime.scope_id)

    def cancel(self, node_id: str) -> bool:
        return self._runtime.cancel(node_id, peer_id=self._runtime.scope_id)


class Runtime(ExecutionScope):
    """The resource-owning execution scope for one peer connection.

    A Runtime owns its scheduler, task hierarchy, trace service, logical worker
    lane and diagnostics.  Physical executors and metric sinks have explicit
    ownership declarations; resources created by Runtime are owned implicitly.
    """

    def __init__(
        self,
        *,
        scope_id: str | None = None,
        executor: ResourceDeclaration[Executor] | None = None,
        metric_sink: ResourceDeclaration[MetricSinkProtocol] | None = None,
        offload_capacity: int = 32,
        max_workers: int = 4,
        max_pending_offloads: int | None = None,
        shutdown_timeout: float = 2.0,
        trace_context_limit: int = 4096,
        trace_subscriber_batch_interval: float = 1.0,
        task_observers=(),
        failure_observers=(),
    ) -> None:
        self.scope_id = scope_id
        self.shutdown_timeout = shutdown_timeout
        self.diagnostics: Counter[str] = Counter()
        self.task_registry = TaskRegistry()
        self._tracing = TraceService(
            self.task_registry,
            trace_context_limit=trace_context_limit,
            trace_subscriber_batch_interval=trace_subscriber_batch_interval,
            diagnostics=self.diagnostics,
        )
        self._failure_observers = tuple(failure_observers)
        self.task_scheduler = TaskScheduler(
            self.task_registry,
            [self._tracing, *task_observers],
            [self, *failure_observers],
        )

        executor_resource, executor_owned = self._resource(executor, name="executor")
        capacity = max_pending_offloads if max_pending_offloads is not None else offload_capacity
        self.sync_offloader = SyncOffloader(
            executor_resource,
            capacity=capacity,
            max_workers=max_workers,
            owns_executor=executor_owned,
        )
        self.worker_lane = SerializedWorkerLane(self.sync_offloader)

        if metric_sink is None:
            sink, sink_owned = MetricGroupAggregator(), True
        else:
            sink, sink_owned = self._resource(metric_sink, name="metric_sink")
        self.metric_sink = sink
        self._owns_metric_sink = sink_owned

        self.state = ScopeState.NEW
        self._close_lock: asyncio.Lock | None = None
        self._root_context: ExecutionContext | None = None
        self._root_error: BaseException | None = None
        self._scope_activation = None
        self._scope_manager = None
        self._execution_token = None
        self.observability = RuntimeObservability(self)

    @staticmethod
    def _resource(value, *, name: str):
        if isinstance(value, Owned):
            return value.resource, True
        if isinstance(value, Borrowed):
            return value.resource, False
        if value is None:
            return None, True
        raise TypeError(f"injected {name} must be declared as Owned(...) or Borrowed(...)")

    @property
    def trace_service(self) -> TraceService:
        return self._tracing

    @property
    def shutdown_started(self) -> bool:
        return self.state in (ScopeState.CLOSING, ScopeState.CLOSED)

    @property
    def root_context(self) -> ExecutionContext | None:
        return self._root_context

    @staticmethod
    def current_execution_context() -> ExecutionContext | None:
        return current_execution_context()

    async def __aenter__(self) -> Runtime:
        if self.state is not ScopeState.NEW:
            raise ScopeNotActive(f"execution scope is {self.state.value}")

        # No await occurs before activation, so task creation and close cannot
        # observe a half-activated Runtime.
        self.state = ScopeState.ACTIVE
        self._scope_manager = use_execution_scope(self)
        self._scope_activation = self._scope_manager.__enter__()
        root = ExecutionContext(
            trace_id=uuid.uuid4().hex,
            task_id=uuid.uuid4().hex,
            scope_id=self.scope_id,
        )
        self._root_context = root
        self._execution_token = set_execution_context(root)
        spec = TaskSpec("execution.root", "scope", {"scope_id": self.scope_id}, False)
        self.task_registry.add(TaskEntry(root, asyncio.current_task(), False, spec))
        self.task_scheduler._notify(
            "task_started",
            TaskStarted(root, spec.name, spec.kind, dict(spec.metadata), spec.cancelable),
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._root_error = exc
        try:
            await self.aclose()
        finally:
            self._deactivate()

    def _deactivate(self) -> None:
        if self._execution_token is not None:
            reset_execution_context(self._execution_token)
            self._execution_token = None
        if self._scope_manager is not None:
            self._scope_manager.__exit__(None, None, None)
            self._scope_manager = None
            self._scope_activation = None

    def start(
        self,
        factory: Callable[[], Any],
        *,
        name: str,
        kind: str = "application",
        metadata=None,
        failure: FailurePolicy = FailurePolicy.REPORT,
    ) -> asyncio.Task[T]:
        """Start a genuinely dynamic managed child from a coroutine factory."""
        if self.state is not ScopeState.ACTIVE:
            raise ScopeNotActive(f"execution scope is {self.state.value}")
        return self.task_scheduler.spawn_factory(
            factory,
            name=name,
            kind=kind,
            metadata=metadata,
            scope_id=self.scope_id,
            failure=failure,
        )

    def observe_task_failure(self, event: TaskFailureEvent) -> None:
        # TaskScheduler already fans out to configured failure observers.  The
        # Runtime hook is the stable ExecutionScope protocol surface.
        self.diagnostics["task_failures"] += 1

    def trace_live_tree(self, *, scope_trace_id=None):
        return self._tracing.live_tree(scope_trace_id)

    def trace_groups(self, trace_id=None):
        snapshots = getattr(self.metric_sink, "snapshots", lambda *_: ())(trace_id)
        live_task_ids = {
            task["task_id"]
            for task in self._tracing.live_tree(trace_id)
            if isinstance(task.get("task_id"), str)
        }
        return [
            snapshot.to_dict()
            for snapshot in snapshots
            if snapshot.task_id in live_task_ids
        ]

    def trace_live_running(self, include_duration=False, *, scope_trace_id=None):
        return self._tracing.live_running(include_duration=include_duration, trace_id=scope_trace_id)

    def trace_running_signature(self, *, scope_trace_id=None):
        return self._tracing.running_signature(trace_id=scope_trace_id)

    def trace_subscribe(self, *, maxsize=1024, peer_id=None) -> TraceSubscription:
        return self._tracing.trace_subscribe(maxsize=maxsize, peer_id=peer_id)

    def cancel(self, node_id: str, *, peer_id=None) -> bool:
        return self._tracing.cancel(node_id, peer_id=peer_id)

    async def aclose(self) -> None:
        if self.state is ScopeState.CLOSED:
            return
        if self._close_lock is None:
            self._close_lock = asyncio.Lock()

        # Reject intake before the first suspension.  Concurrent start()/worker
        # calls therefore see either ACTIVE or CLOSING, never an intermediate.
        if self.state in (ScopeState.NEW, ScopeState.ACTIVE):
            self.state = ScopeState.CLOSING
            self.task_scheduler.closed = True
            self.sync_offloader.closed = True
            self.worker_lane.state = ScopeState.CLOSING

        async with self._close_lock:
            if self.state is ScopeState.CLOSED:
                return
            root_ids = (self._root_context.task_id,) if self._root_context is not None else ()
            deadline = asyncio.get_running_loop().time() + self.shutdown_timeout
            await self.task_scheduler.aclose(
                exclude_task_ids=root_ids,
                timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
            )
            # May raise ScopeShutdownTimeout.  In that case state remains
            # CLOSING and every resource stays available for a truthful retry.
            await self.worker_lane.aclose(
                max(0.0, deadline - asyncio.get_running_loop().time())
            )

            root = self._root_context
            if root is not None and self.task_registry.get(root.task_id) is not None:
                if isinstance(self._root_error, asyncio.CancelledError):
                    self.task_scheduler._notify("task_cancelled", TaskCancelled(root))
                elif self._root_error is not None:
                    self.task_scheduler._notify("task_failed", TaskFailed(root, self._root_error))
                else:
                    self.task_scheduler._notify("task_completed", TaskCompleted(root))
                self.task_registry.remove(root.task_id)

            self._tracing.close()
            if self._owns_metric_sink:
                await self._close_resource(self.metric_sink)
            self.sync_offloader.shutdown(wait=False, cancel_futures=True)
            self.state = ScopeState.CLOSED

    @staticmethod
    async def _close_resource(resource: Any) -> None:
        closer = getattr(resource, "aclose", None) or getattr(resource, "close", None)
        if closer is None:
            return
        result = closer()
        if inspect.isawaitable(result):
            await result

    def shutdown(self, *, wait=False, cancel_futures=True) -> None:
        """Synchronous shutdown for non-async compatibility callers."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.aclose())
            return
        raise RuntimeError("Runtime.shutdown() cannot run on an event loop; await Runtime.aclose()")
