from __future__ import annotations

import asyncio
import inspect
import time
import uuid
from collections import Counter
from collections.abc import Callable
from concurrent.futures import Executor
from typing import Any, TypeVar, cast

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
from .tracing.events import JournalSubscription, ObservableDiagnostics, TracePatchTransport
from .activity import ActivityGroupStore, DrainedMetricSinkAdapter
from .observability import ObservabilityService, ProducerDot
from .state_machine import NullTransitionController
from .domain_events import TraceHealthChanged, emit_domain_event, get_domain_event_dispatcher
from .state_facets import DomainStateFacetAdapter, StateTaskProjection
from .machine_specs import MACHINE_SPECS
from .diagnostic_capture import CaptureAuthorization, DiagnosticCaptureManager

T = TypeVar("T")


class _NullMetricSink:
    def emit(self, event) -> None:
        del event


class RuntimeObservability:
    """Scoped query/cancellation surface owned by one Runtime."""

    def __init__(self, runtime: "Runtime") -> None:
        self._runtime = runtime

    def _trace_id(self) -> str | None:
        root = self._runtime.root_context
        return root.trace_id if root is not None else None

    @property
    def machines(self):
        return self._runtime.projection.machines

    @property
    def facets(self):
        return self._runtime.projection.facets

    @property
    def controls(self):
        return self._runtime.projection.controls

    @property
    def activity_groups(self):
        return self._runtime.activity_groups

    def terminate_entity_epoch(self, entity_id: str, epoch: int):
        return self._runtime.projection.terminate_entity_epoch(entity_id, epoch)

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
        transition_controller: ResourceDeclaration[Any] | None = None,
        offload_capacity: int = 32,
        max_workers: int = 4,
        max_pending_offloads: int | None = None,
        shutdown_timeout: float = 2.0,
        trace_context_limit: int = 4096,
        activity_group_limit: int = 4096,
        activity_overflow_group_limit: int = 256,
        activity_exemplar_limit: int = 256,
        trace_capture_limit: int = 8,
        trace_capture_max_seconds: float = 60.0,
        trace_capture_max_calls: int = 1_000,
        trace_capture_record_limit: int = 1_024,
        trace_subscriber_batch_interval: float = 1.0,
        trace_patch_cadence: float = 0.15,
        trace_journal_limit: int = 128,
        trace_transition_journal_limit: int = 512,
        trace_patch_record_budget: int = 256,
        trace_patch_byte_budget: int = 256 * 1024,
        srtp_delivery_facet_cadence: float = 1.0,
        task_observers=(),
        failure_observers=(),
    ) -> None:
        self.scope_id = scope_id
        self.shutdown_timeout = shutdown_timeout
        self.diagnostics: Counter[str] = ObservableDiagnostics()
        self.runtime_epoch = time.monotonic_ns()
        self.observability_epoch = 1
        # Runtime-owned projection operations are one ordered producer.  A new
        # producer id per operation makes replay bookkeeping grow with total
        # call count and defeats the bounded-memory projection contract.
        self._producer_sequence = 0
        self.task_registry = TaskRegistry()
        self._tracing = TraceService(
            self.task_registry,
            peer_id=scope_id,
            trace_context_limit=trace_context_limit,
            trace_subscriber_batch_interval=trace_subscriber_batch_interval,
            diagnostics=self.diagnostics,
        )
        self._failure_observers = tuple(failure_observers)
        self.task_scheduler = TaskScheduler(
            self.task_registry,
            # Runtime ownership is not a frontend observability plane.  The
            # schema-1 TraceService remains only as an inert query shim during
            # API removal; default task lifecycle never enters it.
            [*task_observers],
            [self, *failure_observers],
            diagnostics=self.diagnostics,
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

        self.activity_groups = ActivityGroupStore(
            max_groups=activity_group_limit,
            max_overflow_groups=activity_overflow_group_limit,
            max_exemplars=activity_exemplar_limit,
            runtime_epoch=self.runtime_epoch,
            diagnostics=self.diagnostics,
        )
        self.projection = ObservabilityService(
            runtime_epoch=self.runtime_epoch, scope_id=scope_id,
            diagnostics=self.diagnostics, activity_groups=self.activity_groups,
            transition_limit=trace_transition_journal_limit,
        )
        self.capture_manager = DiagnosticCaptureManager(
            diagnostics=self.diagnostics,
            max_active=trace_capture_limit,
            max_duration_seconds=trace_capture_max_seconds,
            max_call_budget=trace_capture_max_calls,
            max_records=trace_capture_record_limit,
        )
        self.trace_transport = TracePatchTransport(
            activity_groups=self.activity_groups,
            projection=self.projection,
            captures=self.capture_manager,
            diagnostics=self.diagnostics,
            cadence=trace_patch_cadence,
            journal_limit=trace_journal_limit,
            max_batch_records=trace_patch_record_budget,
            max_batch_bytes=trace_patch_byte_budget,
            health_callback=self._trace_health_changed,
        )
        self.activity_groups.set_dirty_callback(self.trace_transport.dirty)
        self.projection.set_dirty_callback(self.trace_transport.dirty)
        self.capture_manager.set_dirty_callback(self.trace_transport.dirty)
        self._diagnostic_health: tuple[int, int] | None = None
        self._publishing_diagnostic_health = False
        self._event_loop: asyncio.AbstractEventLoop | None = None
        self.diagnostics.set_dirty_callback(self._diagnostics_changed)

        if transition_controller is None:
            controller, controller_owned = NullTransitionController(), True
        else:
            controller, controller_owned = self._resource(
                transition_controller, name="transition_controller"
            )
        self.transition_controller = controller
        self._owns_transition_controller = controller_owned

        if metric_sink is None:
            sink = _NullMetricSink()
            sink_owned = True
            self._external_metric_adapter = None
        else:
            sink, sink_owned = self._resource(metric_sink, name="metric_sink")
            self._external_metric_adapter = DrainedMetricSinkAdapter(sink, self.diagnostics)
        self.metric_sink = cast(MetricSinkProtocol, sink)
        self._owns_metric_sink = sink_owned

        self.state = ScopeState.NEW
        self._close_lock: asyncio.Lock | None = None
        self._root_context: ExecutionContext | None = None
        self._root_error: BaseException | None = None
        self._scope_activation = None
        self._scope_manager = None
        self._execution_token = None
        self.observability = RuntimeObservability(self)
        self._state_facet_adapter = DomainStateFacetAdapter(
            self, srtp_delivery_cadence=srtp_delivery_facet_cadence
        )
        self._state_task_projection = StateTaskProjection(self)
        self.task_scheduler.observers.append(self._state_task_projection)

    def new_producer_dot(self) -> ProducerDot:
        """Return the next dot for the Runtime's event-loop-owned producer."""
        self._producer_sequence += 1
        return ProducerDot(self.runtime_epoch, 1, self._producer_sequence)

    def _trace_health_changed(
        self, admitted: bool, subscriber_count: int, journal_depth: int
    ) -> None:
        dispatcher_health = (
            self.diagnostics["domain_dispatcher_dropped"],
            self.diagnostics["domain_dispatcher_observer_failures"],
        )
        suspension = self.diagnostics.suspend_notifications()
        with suspension:
            emit_domain_event(
                TraceHealthChanged, admitted=admitted,
                subscriber_count=subscriber_count, journal_depth=journal_depth,
                dispatcher_drops=self.diagnostics["domain_dispatcher_dropped"],
                dispatcher_observer_failures=self.diagnostics[
                    "domain_dispatcher_observer_failures"
                ],
            )
        # A failing observer can increment dispatcher diagnostics while the
        # health event is being delivered. Notifications are suspended above
        # to prevent a health-event feedback loop, so reconcile that increment
        # directly into the semantic facet once, without emitting another
        # domain event that would fail again.
        current = (
            self.diagnostics["domain_dispatcher_dropped"],
            self.diagnostics["domain_dispatcher_observer_failures"],
        )
        self._diagnostic_health = current
        if current != dispatcher_health and self._root_context is not None:
            scope = self.scope_id or self._root_context.trace_id
            self.projection.merge_values(
                f"tracing:{scope}", self.new_producer_dot(), {
                    "dispatcher_drops": current[0],
                    "dispatcher_observer_failures": current[1],
                },
            )

    def _diagnostics_changed(self) -> None:
        owner_loop = self._event_loop
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if owner_loop is not None and running_loop is not owner_loop:
            if not owner_loop.is_closed():
                try:
                    owner_loop.call_soon_threadsafe(self._diagnostics_changed)
                except RuntimeError:
                    pass
            return
        self.trace_transport.dirty()
        current = (
            self.diagnostics["domain_dispatcher_dropped"],
            self.diagnostics["domain_dispatcher_observer_failures"],
        )
        if (
            current == self._diagnostic_health
            or self._publishing_diagnostic_health
            or self._root_context is None
        ):
            return
        self._diagnostic_health = current
        scope = self.scope_id or self._root_context.trace_id
        self._publishing_diagnostic_health = True
        try:
            self.projection.merge_values(
                f"tracing:{scope}", self.new_producer_dot(), {
                    "dispatcher_drops": current[0],
                    "dispatcher_observer_failures": current[1],
                },
            )
        finally:
            self._publishing_diagnostic_health = False

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
        self._event_loop = asyncio.get_running_loop()
        self._scope_manager = use_execution_scope(self)
        self._scope_activation = self._scope_manager.__enter__()
        root = ExecutionContext(
            trace_id=uuid.uuid4().hex,
            task_id=uuid.uuid4().hex,
            scope_id=self.scope_id,
        )
        self._root_context = root
        self.projection.bind_trace(root.trace_id)
        peer_identity = self.scope_id or root.trace_id
        self.projection.machines.register(
            f"peer:{peer_identity}", MACHINE_SPECS["peer"],
            epoch=self.observability_epoch,
        )
        dispatcher = get_domain_event_dispatcher()
        dispatcher.add_diagnostic_sink(self.diagnostics)
        dispatcher.add_observer(self._state_facet_adapter)
        self._execution_token = set_execution_context(root)
        self._trace_health_changed(True, 0, self.trace_transport.journal_depth)
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
        # Compatibility query only: derive on demand from the authoritative
        # ownership registry without maintaining a duplicate live trace tree.
        now = time.time()
        records = []
        for task_id in self.task_registry.task_ids():
            entry = self.task_registry.get(task_id)
            if entry is None or (
                scope_trace_id is not None and entry.context.trace_id != scope_trace_id
            ):
                continue
            records.append({
                "trace_id": entry.context.trace_id,
                "task_id": task_id,
                "parent_task_id": entry.context.parent_task_id,
                "name": entry.spec.name,
                "kind": entry.spec.kind,
                "created_at": entry.started_at,
                "started_at": entry.started_at,
                "ended_at": None,
                "duration_ms": max(0.0, (now - entry.started_at) * 1000),
                "status": "running",
                "error": None,
                "metadata": {
                    "node_type": "task",
                    "owner_task_id": task_id,
                    "cancelable": entry.cancelable,
                    **dict(entry.spec.metadata),
                },
            })
        return records

    def trace_groups(self, trace_id=None):
        return [snapshot.to_dict() for snapshot in self.activity_groups.snapshots(trace_id)]

    def authorize_trace_capture(
        self, *, selector_kind: str, selector_value: int | str,
        duration_seconds: float, call_budget: int,
    ) -> CaptureAuthorization:
        from .performance import compiled_operation_strings

        match_value: int | str = selector_value
        if selector_kind == "operation":
            operations = compiled_operation_strings()
            if isinstance(selector_value, str):
                match = next((key for key, name in operations.items() if name == selector_value), None)
                if match is None:
                    raise ValueError("unknown capture operation")
                selector_value = match_value = match
            elif selector_value not in operations:
                raise ValueError("unknown capture operation")
        elif selector_kind == "control":
            handle = self.projection.controls.get(str(selector_value))
            if handle is None:
                raise ValueError("unknown capture control")
            match_value = handle.owner_entity_id
        elif selector_kind == "facet":
            facet = next(
                (item for item in self.projection.facets.snapshots()
                 if item.facet_id == str(selector_value)), None,
            )
            if facet is None:
                raise ValueError("unknown capture facet")
            match_value = facet.owner_entity_id
        elif selector_kind == "entity":
            known = (
                str(selector_value) == self.scope_id
                or self.projection.machines.get(str(selector_value)) is not None
                or any(item.owner_entity_id == selector_value
                       for item in self.activity_groups.snapshots())
            )
            if not known:
                raise ValueError("unknown capture entity")
        else:
            raise ValueError("unsupported capture selector")
        return self.capture_manager.authorize(
            selector_kind, selector_value, duration_seconds=duration_seconds,
            call_budget=call_budget, match_value=match_value,
        )

    def cancel_trace_capture(self, capture_id: int) -> bool:
        return self.capture_manager.cancel(capture_id)

    def drain_external_metrics(self) -> int:
        adapter = self._external_metric_adapter
        if adapter is None:
            return 0
        return adapter.drain(self.activity_groups.snapshots())

    def trace_live_running(self, include_duration=False, *, scope_trace_id=None):
        records = self.trace_live_tree(scope_trace_id=scope_trace_id)
        if not include_duration:
            for record in records:
                record["duration_ms"] = None
        return records

    def trace_running_signature(self, *, scope_trace_id=None):
        return tuple(
            (record["task_id"], record["parent_task_id"], record["status"])
            for record in self.trace_live_tree(scope_trace_id=scope_trace_id)
        )

    def trace_subscribe(self, *, maxsize=1024, peer_id=None) -> TraceSubscription:
        return self._tracing.trace_subscribe(maxsize=maxsize, peer_id=peer_id)

    def trace_patch_subscribe(self, *, maxsize=16, peer_id=None) -> JournalSubscription:
        return self.trace_transport.subscribe(maxsize=maxsize, peer_id=peer_id)

    def trace_patch_flush(self):
        """Drain dirty schema-2 records once and fan out the shared batches."""
        self._state_facet_adapter.flush_srtp_delivery()
        return self.trace_transport.flush()

    def trace_snapshot(self):
        return self.trace_transport.snapshot()

    def cancel(self, node_id: str, *, peer_id=None) -> bool:
        handle = self.projection.controls.get(node_id)
        if handle is not None:
            if not handle.cancelable or handle.runtime_task_id is None:
                return False
            return self.task_registry.cancel(handle.runtime_task_id)
        if self.task_registry.get(node_id) is not None:
            return self.task_registry.cancel(node_id)
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
            # Test checkpoints must never pin runtime teardown.
            self.transition_controller.release_all()
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
            # Publish the terminal tracing-health state while the semantic
            # adapter is still attached.
            self.trace_transport.close()
            dispatcher = get_domain_event_dispatcher()
            dispatcher.remove_observer(self._state_facet_adapter)
            dispatcher.remove_diagnostic_sink(self.diagnostics)
            self._state_facet_adapter.close()
            self.capture_manager.close()
            self.drain_external_metrics()
            if self._owns_metric_sink:
                await self._close_resource(self.metric_sink)
            if self._owns_transition_controller:
                await self._close_resource(self.transition_controller)
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
