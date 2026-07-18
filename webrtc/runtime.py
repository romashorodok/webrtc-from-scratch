from __future__ import annotations

import asyncio
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
    ImmutableWorkerResult,
    Owned,
    OwnedTaskHandle,
    OwnedTimerHandle,
    OwnedResourceHandle,
    ResourceDeclaration,
    ScopeNotActive,
    ScopeShutdownTimeout,
    ScopeState,
    ConcurrentWorkerLane,
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
    StaleOwnerEpoch,
    UntrackedRuntimeTask,
    WrongRuntimeLoop,
    current_execution_context,
    reset_execution_context,
    set_execution_context,
    use_execution_scope,
)
from .tracing.events import JournalSubscription, ObservableDiagnostics, TracePatchTransport
from .activity import ActivityGroupStore, DrainedMetricSinkAdapter
from .observability import MachineTransitionOp, ObservabilityService, ProducerDot
from .state_machine import (
    AsyncStateMachineRunner, MachineCommand, NullTransitionController,
    PreparedTransition, ReplyPort, TransitionCommit,
)
from .state_facets import AggregateFacetAdapter
from .machine_specs import MACHINE_SPECS
from .diagnostic_capture import CaptureAuthorization, DiagnosticCaptureManager

T = TypeVar("T")


class _NullMetricSink:
    def emit(self, event) -> None:
        del event


class _ObservabilityRunner(
    AsyncStateMachineRunner[MachineCommand[str, TransitionCommit]]
):
    """The sole lifecycle authority for schema-2 observation."""

    def __init__(self, runtime: "Runtime", entity_id: str) -> None:
        self.runtime = runtime
        super().__init__(
            MACHINE_SPECS["observability"], entity_id=entity_id,
            mailbox_capacity=16, dedupe_capacity=32,
            controller=runtime.transition_controller,
            transition_sink=self._project,
        )

    async def step(self, command: MachineCommand[str, TransitionCommit]):
        return PreparedTransition(
            self.state, command.payload, None, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    def _project(self, commit: TransitionCommit) -> None:
        self.runtime.assert_owner_epoch(self.entity_id, self.epoch)
        self.runtime.projection.transition(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state,
            commit.to_state, commit.epoch, commit.revision,
            self.runtime.new_producer_dot(), cause_id=commit.cause,
            monotonic_ns=commit.monotonic_ns,
        ))


class _LifecycleRunner(
    AsyncStateMachineRunner[MachineCommand[str, TransitionCommit]]
):
    """Typed lifecycle authority used by Runtime and its worker lane."""

    def __init__(self, runtime: "Runtime", machine_type: str, entity_id: str) -> None:
        self.runtime = runtime
        super().__init__(
            MACHINE_SPECS[machine_type], entity_id=entity_id,
            mailbox_capacity=32, dedupe_capacity=64,
            controller=runtime.transition_controller,
            transition_sink=self._project,
        )

    async def step(self, command: MachineCommand[str, TransitionCommit]):
        return PreparedTransition(
            self.state, command.payload, None, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    def _project(self, commit: TransitionCommit) -> None:
        self.runtime.assert_owner_epoch(self.entity_id, self.epoch)
        self.runtime.projection.transition(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state,
            commit.to_state, commit.epoch, commit.revision,
            self.runtime.new_producer_dot(), cause_id=commit.cause,
            monotonic_ns=commit.monotonic_ns,
        ))
        if commit.machine_type == "worker-lane":
            self.runtime._publish_worker_facets(commit.revision)


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

    def subscribe(self, *, maxsize: int = 16) -> JournalSubscription:
        return self._runtime.trace_patch_subscribe(
            maxsize=maxsize, peer_id=self._runtime.scope_id
        )

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
        tracing_enabled: bool = True,
        activity_group_limit: int = 4096,
        activity_overflow_group_limit: int = 256,
        activity_exemplar_limit: int = 256,
        trace_capture_limit: int = 8,
        trace_capture_max_seconds: float = 60.0,
        trace_capture_max_calls: int = 1_000,
        trace_capture_record_limit: int = 1_024,
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
        self.tracing_enabled = tracing_enabled
        self.shutdown_timeout = shutdown_timeout
        self.diagnostics: Counter[str] = ObservableDiagnostics()
        self.runtime_epoch = time.monotonic_ns()
        self.observability_epoch = 1
        # Runtime-owned projection operations are one ordered producer.  A new
        # producer id per operation makes replay bookkeeping grow with total
        # call count and defeats the bounded-memory projection contract.
        self._producer_sequence = 0
        self.task_registry = TaskRegistry()
        self._failure_observers = tuple(failure_observers)
        self.task_scheduler = TaskScheduler(
            self.task_registry,
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
        self.worker_lane = ConcurrentWorkerLane(self.sync_offloader)

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
            timer_factory=lambda delay, callback: self.call_later_owned(
                delay, callback, owner_entity_id=self._observability_entity_id,
                owner_epoch=self.observability_epoch,
            ),
        )
        if self.tracing_enabled:
            self.activity_groups.set_dirty_callback(self.trace_transport.dirty)
            self.projection.set_dirty_callback(self.trace_transport.dirty)
            self.capture_manager.set_dirty_callback(self.trace_transport.dirty)
        self._diagnostic_health: tuple[int, int] | None = None
        self._publishing_diagnostic_health = False
        self._event_loop: asyncio.AbstractEventLoop | None = None
        self._owner_epochs: dict[str, int] = {}
        self._owner_tasks: dict[tuple[str, int], set[OwnedTaskHandle[Any]]] = {}
        self._owner_timers: dict[tuple[str, int], set[OwnedTimerHandle]] = {}
        self._owner_resources: dict[
            tuple[str, int], set[OwnedResourceHandle]
        ] = {}
        self._worker_submission_id = 0
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

        self._close_handle: OwnedTaskHandle[None] | None = None
        self._root_context: ExecutionContext | None = None
        self._root_error: BaseException | None = None
        self._scope_activation = None
        self._scope_manager = None
        self._execution_token = None
        self.observability = RuntimeObservability(self)
        self._observability_entity_id = f"observability:{self.scope_id or self.runtime_epoch}"
        self._observability_runner = _ObservabilityRunner(
            self, self._observability_entity_id
        )
        self._observability_handle: OwnedTaskHandle[None] | None = None
        self._observability_command_id = 0
        self._observability_degraded = False
        self._observability_health_handle: OwnedTaskHandle[None] | None = None
        self._aggregate_facet_adapter = AggregateFacetAdapter(
            self, srtp_delivery_cadence=srtp_delivery_facet_cadence
        )
        identity = self.scope_id or self.runtime_epoch
        self._runtime_entity_id = f"runtime:{identity}"
        self._runtime_runner = _LifecycleRunner(
            self, "runtime", self._runtime_entity_id
        )
        self._runtime_handle: OwnedTaskHandle[None] | None = None
        self._runtime_command_id = 0
        self._worker_entity_id = (
            f"worker-lane:{identity}:{self.worker_lane.observability_id}"
        )
        self._worker_runner = _LifecycleRunner(
            self, "worker-lane", self._worker_entity_id
        )
        self._worker_handle: OwnedTaskHandle[None] | None = None
        self._worker_command_id = 0
        self._worker_desired_state = "idle"
        self.worker_lane.set_lifecycle_state(
            lambda: self._worker_runner.snapshot().state
        )
        self.worker_lane.set_state_publisher(self._worker_state_changed)

    @property
    def state(self) -> ScopeState:
        state = self._runtime_runner.snapshot().state
        if state == "new":
            return ScopeState.NEW
        if state in {"starting", "active"}:
            return ScopeState.ACTIVE
        if state == "closed":
            return ScopeState.CLOSED
        return ScopeState.CLOSING

    async def _move_lifecycle(
        self, runner: _LifecycleRunner, target: str, *, worker: bool = False,
    ) -> TransitionCommit:
        if worker:
            self._worker_command_id += 1
            command_id = self._worker_command_id
        else:
            self._runtime_command_id += 1
            command_id = self._runtime_command_id
        reply = ReplyPort[TransitionCommit]()
        runner.try_submit(MachineCommand(
            "move", command_id, runner.epoch, target, reply,
            expected_revision=runner.revision,
            cause_id=f"{runner.entity_id}:{target}:{command_id}",
        ))
        return await reply.wait()

    def _worker_state_changed(
        self, *, queued: int, running: int, high_water: int
    ) -> None:
        runner = self._worker_runner
        if self._worker_handle is None or runner.snapshot().terminal:
            return
        target = "running" if running else "queued" if queued else "idle"
        if target != self._worker_desired_state:
            self._worker_desired_state = target
            self._worker_command_id += 1
            runner.try_submit(MachineCommand(
                "move", self._worker_command_id, runner.epoch, target, None,
                expected_revision=None,
                cause_id=f"{runner.entity_id}:work:{self._worker_command_id}",
            ))
        elif runner.snapshot().state == target:
            self._publish_worker_facets(runner.revision)

    def _publish_worker_facets(self, revision: int) -> None:
        queued, running, high_water = self.worker_lane.load_snapshot()
        self.projection.merge_values(
            self._worker_entity_id, self.new_producer_dot(), {
                "queued": queued, "running": running,
                "high_water": high_water, "lane_kind": "concurrent",
            },
            observer_meta="exact", source_entity_id=self._worker_entity_id,
            source_epoch=self._worker_runner.epoch, source_revision=revision,
            source_order=self.projection.new_facet_source_order(),
        )

    def new_producer_dot(self) -> ProducerDot:
        """Return the next dot for the Runtime's event-loop-owned producer."""
        self._producer_sequence += 1
        return ProducerDot(self.runtime_epoch, 1, self._producer_sequence)

    def record_queue_state(self, **values: Any) -> None:
        self._assert_loop()
        self._aggregate_facet_adapter.queue_state(**values)

    def record_worker_state(self, **values: Any) -> None:
        self._assert_loop()
        self._aggregate_facet_adapter.worker_state(**values)

    def record_srtp_stream(self, **values: Any) -> None:
        self._assert_loop()
        self._aggregate_facet_adapter.srtp_stream(**values)

    def record_srtp_delivery(self, **values: Any) -> None:
        self._assert_loop()
        self._aggregate_facet_adapter.srtp_delivery(**values)

    async def _move_observability(self, state: str, cause_id: str) -> TransitionCommit:
        self._observability_command_id += 1
        reply = ReplyPort[TransitionCommit]()
        command = MachineCommand(
            "move", self._observability_command_id, self.observability_epoch,
            state, reply, expected_revision=self._observability_runner.revision,
            producer_id=1, producer_seq=self._observability_command_id,
            cause_id=cause_id,
        )
        await self._observability_runner.submit(command)
        return await reply.wait()

    async def _reconcile_observability_health(self) -> None:
        await asyncio.sleep(0)
        state = self._observability_runner.state
        target = "degraded" if self._observability_degraded else "active"
        if state in {"active", "degraded"} and state != target:
            await self._move_observability(target, f"trace-health-{target}")

    def _publish_observability_facets(
        self, admitted: bool, subscriber_count: int, journal_depth: int
    ) -> None:
        runner = self._observability_runner
        self.projection.merge_values(
            runner.entity_id, self.new_producer_dot(), {
                "enabled": self.tracing_enabled,
                "admitted": admitted,
                "subscriber_count": subscriber_count,
                "journal_depth": journal_depth,
                "subscriber_drops": self.diagnostics["trace_subscriber_drops"],
                "resyncs": self.diagnostics["trace_resync_required"],
                "failures": self.diagnostics["trace_transport_failures"],
            },
            observer_meta="exact", source_entity_id=runner.entity_id,
            source_epoch=runner.epoch, source_revision=runner.revision,
            source_order=self.projection.new_facet_source_order(),
        )

    def _trace_health_changed(
        self, admitted: bool, subscriber_count: int, journal_depth: int
    ) -> None:
        unhealthy = self.tracing_enabled and not admitted
        # During terminal drain health is retained as facets, but no recovery
        # command may race the terminal sequence.
        if self._observability_runner.state in {"active", "degraded"}:
            self._observability_degraded = unhealthy
            handle = self._observability_health_handle
            if handle is None or handle.done():
                self._observability_health_handle = self.start_pump(
                    self._reconcile_observability_health,
                    owner_entity_id=self._observability_entity_id,
                    owner_epoch=self.observability_epoch,
                    name="observability.health", kind="machine",
                    failure=FailurePolicy.REPORT,
                )
        self._publish_observability_facets(admitted, subscriber_count, journal_depth)

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
        current = (self.diagnostics["trace_subscriber_drops"],
                   self.diagnostics["trace_transport_failures"])
        if (
            current == self._diagnostic_health
            or self._publishing_diagnostic_health
            or self._root_context is None
        ):
            return
        self._diagnostic_health = current
        self._publishing_diagnostic_health = True
        try:
            self._publish_observability_facets(
                self.tracing_enabled, self.trace_transport.viewer_count,
                self.trace_transport.journal_depth,
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
        self._execution_token = set_execution_context(root)
        for runner in (self._runtime_runner, self._worker_runner):
            self.register_owner(runner.entity_id, epoch=runner.epoch)
            self.projection.machines.register(
                runner.entity_id, runner.spec, epoch=runner.epoch,
            )
        runtime_task = self.task_scheduler.spawn_factory(
            self._runtime_runner.run, name="machine:runtime", kind="machine",
            scope_id=self.scope_id, cancelable=False,
        )
        self._runtime_handle = OwnedTaskHandle(
            runtime_task, owner_entity_id=self._runtime_entity_id,
            owner_epoch=self._runtime_runner.epoch,
        )
        await self._move_lifecycle(self._runtime_runner, "starting")
        await self._move_lifecycle(self._runtime_runner, "active")
        self._worker_handle = self.start_machine(
            self._worker_runner, owner_entity_id=self._worker_entity_id,
            owner_epoch=self._worker_runner.epoch,
        )
        self.register_owner(self._observability_entity_id, epoch=self.observability_epoch)
        self.projection.machines.register(
            self._observability_entity_id, MACHINE_SPECS["observability"],
            epoch=self.observability_epoch,
        )
        self._observability_handle = self.start_machine(
            self._observability_runner,
            owner_entity_id=self._observability_entity_id,
            owner_epoch=self.observability_epoch,
            failure=FailurePolicy.REPORT,
        )
        await self._move_observability("starting", "runtime-observability-start")
        await self._move_observability("active", "runtime-observability-ready")
        self._trace_health_changed(
            self.tracing_enabled, 0, self.trace_transport.journal_depth
        )
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
    ) -> OwnedTaskHandle[T]:
        """Start a genuinely dynamic managed child from a coroutine factory."""
        if self.state is not ScopeState.ACTIVE:
            raise ScopeNotActive(f"execution scope is {self.state.value}")
        task = self.task_scheduler.spawn_factory(
            factory,
            name=name,
            kind=kind,
            metadata=metadata,
            scope_id=self.scope_id,
            failure=failure,
        )
        return OwnedTaskHandle(
            task, owner_entity_id="runtime", owner_epoch=self.runtime_epoch
        )

    def _assert_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._event_loop is not None and loop is not self._event_loop:
            self.diagnostics["wrong_loop_mutation"] += 1
            raise WrongRuntimeLoop("Runtime-owned state was accessed from another loop")
        return loop

    def register_owner(self, entity_id: str, *, epoch: int = 1) -> None:
        self._assert_loop()
        if epoch < 1:
            raise ValueError("owner epoch must be positive")
        current = self._owner_epochs.get(entity_id)
        if current is not None and epoch <= current:
            raise StaleOwnerEpoch(f"owner {entity_id} already has epoch {current}")
        self._owner_epochs[entity_id] = epoch

    def assert_owner_epoch(self, entity_id: str, epoch: int) -> None:
        self._assert_loop()
        if self._owner_epochs.get(entity_id) != epoch:
            self.diagnostics["wrong_epoch_access"] += 1
            raise StaleOwnerEpoch(f"owner {entity_id} epoch {epoch} is not active")

    def remove_owner(self, entity_id: str, epoch: int) -> None:
        self.assert_owner_epoch(entity_id, epoch)
        key = (entity_id, epoch)
        live_tasks = tuple(handle for handle in self._owner_tasks.get(key, ()) if not handle.done())
        live_timers = tuple(handle for handle in self._owner_timers.get(key, ()) if not handle.done())
        live_resources = tuple(
            handle for handle in self._owner_resources.get(key, ()) if not handle.done()
        )
        if live_tasks or live_timers or live_resources:
            self.diagnostics["terminal_entity_with_live_children"] += 1
            raise AssertionError(
                f"terminal owner {entity_id}@{epoch} has live children: "
                f"{len(live_tasks)} task(s), {len(live_timers)} timer(s), and "
                f"{len(live_resources)} resource(s)"
            )
        self._owner_tasks.pop(key, None)
        self._owner_timers.pop(key, None)
        self._owner_resources.pop(key, None)
        self.projection.terminate_entity_epoch(
            entity_id, epoch,
            preserve_activity=entity_id == self._runtime_entity_id,
        )
        self._owner_epochs.pop(entity_id, None)

    async def join_owner_children(self, entity_id: str, epoch: int) -> None:
        """Join all descendants except the caller performing terminal reconciliation."""
        self.assert_owner_epoch(entity_id, epoch)
        current = asyncio.current_task()
        handles = tuple(
            handle for handle in self._owner_tasks.get((entity_id, epoch), ())
            if not handle.done() and handle._task is not current
        )
        if handles:
            await asyncio.gather(
                *(handle.wait() for handle in handles), return_exceptions=True
            )

    def start_pump(
        self, factory: Callable[[], Any], *, owner_entity_id: str, owner_epoch: int,
        name: str, kind: str = "pump", failure: FailurePolicy = FailurePolicy.REPORT,
        metadata=None, cancelable: bool = True, _root_owned: bool = True,
    ) -> OwnedTaskHandle[T]:
        self.assert_owner_epoch(owner_entity_id, owner_epoch)
        context = None
        if _root_owned:
            root = self._root_context
            if root is None:
                raise ScopeNotActive("execution scope has no root context")
            # Entity-owned pumps belong to the Runtime root, not to whichever
            # finite operation happened to create the entity.  Otherwise
            # normal child reconciliation (for example after ICE gathering)
            # cancels the entity before component teardown.
            context = ExecutionContext(
                root.trace_id, uuid.uuid4().hex, root.task_id, root.scope_id,
            )
        task = self.task_scheduler.spawn_factory(
            factory, name=name, kind=kind, metadata=metadata, scope_id=self.scope_id,
            context=context, failure=failure, cancelable=cancelable,
        )
        handle = OwnedTaskHandle(
            task, owner_entity_id=owner_entity_id, owner_epoch=owner_epoch
        )
        key = (owner_entity_id, owner_epoch)
        owned = self._owner_tasks.setdefault(key, set())
        owned.add(handle)
        task.add_done_callback(lambda _done: owned.discard(handle))
        return handle

    def start_machine(
        self, runner: Any, *, owner_entity_id: str, owner_epoch: int,
        failure: FailurePolicy = FailurePolicy.FAIL_CONNECTION,
    ) -> OwnedTaskHandle[None]:
        if getattr(runner, "entity_id", None) != owner_entity_id:
            raise ValueError("machine entity and Runtime owner must match")
        if getattr(runner, "epoch", None) != owner_epoch:
            raise StaleOwnerEpoch("machine and Runtime owner epochs differ")
        return self.start_pump(
            runner.run, owner_entity_id=owner_entity_id, owner_epoch=owner_epoch,
            name=f"machine:{runner.spec.machine_type}:{owner_entity_id}",
            kind="machine", failure=failure,
        )

    def call_worker(
        self, fn: Callable[..., T], *args: Any, owner_entity_id: str,
        owner_epoch: int, name: str = "worker",
        on_dispatch: Callable[[], None] | None = None,
        on_future: Callable[[asyncio.Future[Any]], None] | None = None,
        on_complete: Callable[[Any], None] | None = None,
        **kwargs: Any,
    ) -> OwnedTaskHandle[ImmutableWorkerResult[T]]:
        self.assert_owner_epoch(owner_entity_id, owner_epoch)
        self._worker_submission_id += 1
        submission_id = self._worker_submission_id

        async def dispatch() -> ImmutableWorkerResult[T]:
            def physical_complete(event: Any) -> None:
                if self._owner_epochs.get(owner_entity_id) != owner_epoch:
                    self.diagnostics["worker_completion_after_close"] += 1
                if on_complete is not None:
                    on_complete(event)

            try:
                value, _, _ = await self.worker_lane.run_observed(
                    fn, *args, on_dispatch=on_dispatch, on_future=on_future,
                    on_complete=physical_complete, **kwargs
                )
            except BaseException as error:
                result = ImmutableWorkerResult[T](
                    submission_id, owner_entity_id, owner_epoch,
                    "cancelled" if isinstance(error, asyncio.CancelledError) else "error",
                    exception=error,
                )
            else:
                result = ImmutableWorkerResult(
                    submission_id, owner_entity_id, owner_epoch, "success", value=value
                )
            # A late worker result is immutable evidence, never permission to
            # mutate a removed entity epoch.
            if self._owner_epochs.get(owner_entity_id) != owner_epoch:
                self.diagnostics["worker_completion_after_close"] += 1
            return result

        return self.start_pump(
            dispatch, owner_entity_id=owner_entity_id, owner_epoch=owner_epoch,
            name=name, kind="worker", failure=FailurePolicy.REPORT,
            cancelable=False, _root_owned=False,
        )

    def call_later_owned(
        self, delay: float, callback: Callable[[], None], *,
        owner_entity_id: str, owner_epoch: int,
    ) -> OwnedTimerHandle:
        loop = self._assert_loop()
        self.assert_owner_epoch(owner_entity_id, owner_epoch)
        fired: asyncio.Future[bool] = loop.create_future()
        holder: list[OwnedTimerHandle] = []

        def invoke() -> None:
            handle = holder[0]
            self._owner_timers.get((owner_entity_id, owner_epoch), set()).discard(handle)
            if self._owner_epochs.get(owner_entity_id) != owner_epoch:
                self.diagnostics["wrong_epoch_timer"] += 1
                if not fired.done():
                    fired.set_result(False)
                return
            try:
                callback()
            finally:
                if not fired.done():
                    fired.set_result(True)

        raw = loop.call_later(delay, invoke)
        handle = OwnedTimerHandle(
            raw, fired, owner_entity_id=owner_entity_id, owner_epoch=owner_epoch
        )
        holder.append(handle)
        self._owner_timers.setdefault((owner_entity_id, owner_epoch), set()).add(handle)
        return handle

    def register_owned_resource(
        self, *, close: Callable[[], Any], wait_closed: Callable[[], Any],
        owner_entity_id: str, owner_epoch: int, name: str = "resource",
    ) -> OwnedResourceHandle:
        """Register a resource immediately with close initiation and a close barrier."""
        self.assert_owner_epoch(owner_entity_id, owner_epoch)
        handle = OwnedResourceHandle(
            close, wait_closed, owner_entity_id=owner_entity_id,
            owner_epoch=owner_epoch, name=name,
        )
        owned = self._owner_resources.setdefault(
            (owner_entity_id, owner_epoch), set()
        )
        owned.add(handle)
        handle._closed.add_done_callback(lambda _done: owned.discard(handle))
        return handle

    def assert_task_tracked(self, task: asyncio.Task[Any]) -> None:
        self._assert_loop()
        if not any(
            entry is not None and entry.task is task
            for task_id in self.task_registry.task_ids()
            if (entry := self.task_registry.get(task_id)) is not None
        ):
            self.diagnostics["untracked_runtime_work"] += 1
            raise UntrackedRuntimeTask("task was not created by the Runtime scheduler")

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

    def trace_patch_subscribe(self, *, maxsize=16, peer_id=None) -> JournalSubscription:
        return self.trace_transport.subscribe(maxsize=maxsize, peer_id=peer_id)

    def trace_patch_flush(self):
        """Drain dirty schema-2 records once and fan out the shared batches."""
        self._aggregate_facet_adapter.flush_srtp_delivery()
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
        return False

    async def aclose(self) -> None:
        if self.state is ScopeState.CLOSED:
            return
        self._assert_loop()
        if self._close_handle is None or self._close_handle.done():
            task = self.task_scheduler.spawn_factory(
                self._close_impl, name="runtime:close", kind="reconciliation",
                scope_id=self.scope_id, cancelable=False,
            )
            self._close_handle = OwnedTaskHandle(
                task, owner_entity_id="runtime", owner_epoch=self.runtime_epoch
            )
        await self._close_handle.wait()

    async def _close_impl(self) -> None:
        if self.state is ScopeState.CLOSED:
            return

        # Reject intake before the first suspension.  Concurrent start()/worker
        # calls therefore see either ACTIVE or CLOSING, never an intermediate.
        if self._runtime_runner.state == "new":
            # A never-entered Runtime has no running lifecycle mailbox.
            self._runtime_runner.commit("closed")
        elif self._runtime_runner.state == "active":
            await self._move_lifecycle(self._runtime_runner, "quiescing")
            await self._move_lifecycle(self._runtime_runner, "draining")
            # Test checkpoints must never pin runtime teardown.
            self.transition_controller.release_all()
            self.task_scheduler.closed = True
            self.sync_offloader.closed = True
            if self._worker_runner.state not in {"closing", "closed"}:
                await self._move_lifecycle(
                    self._worker_runner, "closing", worker=True
                )

        root_ids = (self._root_context.task_id,) if self._root_context is not None else ()
        health = self._observability_health_handle
        if health is not None and not health.done():
            await health.wait()
        observability_ids = tuple(
            task_id for task_id in self.task_registry.task_ids()
            if (
                (entry := self.task_registry.get(task_id)) is not None
                and self._observability_handle is not None
                and entry.task is self._observability_handle._task
            )
        )
        lifecycle_ids = tuple(
            task_id for task_id in self.task_registry.task_ids()
            if (
                (entry := self.task_registry.get(task_id)) is not None
                and any(
                    handle is not None and entry.task is handle._task
                    for handle in (self._runtime_handle, self._worker_handle)
                )
            )
        )
        deadline = asyncio.get_running_loop().time() + self.shutdown_timeout
        for timers in tuple(self._owner_timers.values()):
            for timer in tuple(timers):
                timer.cancel()
        await self.task_scheduler.aclose(
            exclude_task_ids=(*root_ids, *observability_ids, *lifecycle_ids),
            timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
        )
        for resources in tuple(self._owner_resources.values()):
            for resource in tuple(resources):
                remaining = max(0.0, deadline - asyncio.get_running_loop().time())
                try:
                    async with asyncio.timeout(remaining):
                        await resource.aclose()
                except TimeoutError as exc:
                    raise ScopeShutdownTimeout(
                        f"owned resource {resource.name} did not close"
                    ) from exc
            # May raise ScopeShutdownTimeout.  In that case state remains
            # CLOSING and every resource stays available for a truthful retry.
        await self.worker_lane.aclose(
            max(0.0, deadline - asyncio.get_running_loop().time())
        )
        if self._worker_runner.state == "closing":
            await self._move_lifecycle(self._worker_runner, "closed", worker=True)
        if self._worker_handle is not None:
            await self._worker_handle.wait()
            self.remove_owner(self._worker_entity_id, self._worker_runner.epoch)

        root = self._root_context
        if root is not None and self.task_registry.get(root.task_id) is not None:
            if isinstance(self._root_error, asyncio.CancelledError):
                self.task_scheduler._notify("task_cancelled", TaskCancelled(root))
            elif self._root_error is not None:
                self.task_scheduler._notify("task_failed", TaskFailed(root, self._root_error))
            else:
                self.task_scheduler._notify("task_completed", TaskCompleted(root))
            self.task_registry.remove(root.task_id)

        # The observability entity owns the final schema-2 drain. No producer
        # can publish after its terminal commit because adapters are detached
        # immediately after this barrier.
        if self._observability_runner.state in {"active", "degraded", "starting"}:
            await self._move_observability("draining", "runtime-final-flush")
            self._aggregate_facet_adapter.flush_srtp_delivery()
            self.trace_transport.flush()
            self._publish_observability_facets(
                False, self.trace_transport.viewer_count,
                self.trace_transport.journal_depth,
            )
            await self._move_observability("stopped", "runtime-final-flush-complete")
            self._publish_observability_facets(
                False, self.trace_transport.viewer_count,
                self.trace_transport.journal_depth,
            )
            self.trace_transport.flush()
            self.trace_transport.finalize()
            self.trace_transport.seal_health()
        # Publish the terminal tracing-health state while the semantic adapter
        # is still attached.
        self.trace_transport.close()
        self._aggregate_facet_adapter.close()
        self.capture_manager.close()
        if self._observability_handle is not None:
            await self._observability_handle.wait()
        if self._owner_epochs.get(self._observability_entity_id) == self.observability_epoch:
            self.remove_owner(self._observability_entity_id, self.observability_epoch)
        self.drain_external_metrics()
        if self._owns_metric_sink:
            await self._close_resource(self.metric_sink)
        self.sync_offloader.shutdown(wait=False, cancel_futures=True)
        if self._runtime_runner.state == "draining":
            await self._move_lifecycle(self._runtime_runner, "closed")
        if self._runtime_handle is not None:
            await self._runtime_handle.wait()
            self.remove_owner(self._runtime_entity_id, self._runtime_runner.epoch)
        if self._owns_transition_controller:
            await self._close_resource(self.transition_controller)
        self._owner_tasks.clear()
        self._owner_timers.clear()
        self._owner_resources.clear()
        self._owner_epochs.clear()

    @staticmethod
    async def _close_resource(resource: Any) -> None:
        async_closer = getattr(resource, "aclose", None)
        if async_closer is not None:
            await async_closer()
            return
        closer = getattr(resource, "close", None)
        if closer is not None:
            closer()
