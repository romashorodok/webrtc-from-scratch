from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import itertools
import time
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Generic, ParamSpec, Protocol, TypeVar, cast

from .activity import (
    ActivityGroupRecord,
    WorkerObservationDelta,
    begin_local,
    end_local,
)

from .runtime_services import (
    FailurePolicy,
    MissingExecutionScope,
    TraceNodeCompleted,
    TraceNodeCancelabilityChanged,
    TraceNodeDescriptor,
    TraceNodeStarted,
    TraceNodeType,
    WorkerCallCompleted,
    current_execution_context,
    current_execution_scope,
    require_execution_scope,
    reset_execution_context,
    set_execution_context,
)

T = TypeVar("T")
P = ParamSpec("P")
Scalar = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class WorkerOwnerBinding:
    """Authoritative Runtime entity epoch for a component's worker descendants."""

    runtime: Any
    entity_id: str
    epoch: int
    role: str | None = None


def _attributes(values: Mapping[str, Any] | None, limit: int = 32) -> Mapping[str, Scalar]:
    if not values:
        return MappingProxyType({})
    result: dict[str, Scalar] = {}
    for key, value in values.items():
        if len(result) == limit:
            break
        if isinstance(key, str) and (value is None or isinstance(value, (str, int, float, bool))):
            result[key[:128]] = value if not isinstance(value, str) else value[:512]
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class MetricEvent:
    trace_id: str
    task_id: str
    operation: str
    outcome: str
    duration_ms: float
    attributes: Mapping[str, Scalar] = field(default_factory=lambda: MappingProxyType({}))
    timestamp: float = field(default_factory=time.time)
    group: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", _attributes(self.attributes))


class MetricSink(Protocol):
    def emit(self, event: MetricEvent) -> None: ...


class CaptureMetricSink:
    def __init__(self, limit: int = 100_000) -> None:
        self.limit = max(0, limit)
        self._events: list[MetricEvent] = []

    def emit(self, event: MetricEvent) -> None:
        if len(self._events) < self.limit:
            self._events.append(event)

    def events(self) -> tuple[MetricEvent, ...]:
        return tuple(self._events)


@dataclass(frozen=True, slots=True)
class CallInfo:
    args: tuple[Any, ...]
    kwargs: Mapping[str, Any]

@dataclass(frozen=True, slots=True)
class SuccessInfo(Generic[T]):
    call: CallInfo
    result: T

@dataclass(frozen=True, slots=True)
class ErrorInfo:
    call: CallInfo
    exception: BaseException

@dataclass(frozen=True, slots=True)
class PerformanceSpec:
    name: str
    group: str | None = None
    on_call: Callable[[CallInfo], Mapping[str, Any]] | None = None
    on_success: Callable[[SuccessInfo[Any]], Mapping[str, Any]] | None = None
    on_error: Callable[[ErrorInfo], Mapping[str, Any]] | None = None


class TraceDetail(str, Enum):
    STATE = "state"
    AGGREGATE = "aggregate"
    EXACT = "exact"
    OFF = "off"


@dataclass(frozen=True, slots=True)
class CompiledObservation:
    operation_id: int
    operation: str
    group: str
    detail: TraceDetail
    slow_ms: float | None
    capture_failures: bool
    slow_ns: int | None = None
    method: str | None = None
    workflow: bool = False
    cadence_ms: int | None = None


@dataclass(frozen=True, slots=True)
class ObservationSpec:
    detail: TraceDetail
    group: str | None = None
    slow_ms: float | None = None
    capture_failures: bool = True


_operation_ids = itertools.count(1)
_operation_ids_by_name: dict[str, int] = {}
_operation_names_by_id: dict[int, str] = {}


def _intern_operation(operation: str) -> int:
    # This runs only while a class is created, never on an observed call.
    operation_id = _operation_ids_by_name.get(operation)
    if operation_id is None:
        operation_id = next(_operation_ids)
        _operation_ids_by_name[operation] = operation_id
        _operation_names_by_id[operation_id] = operation
    return operation_id


def compiled_operation_strings() -> Mapping[int, str]:
    """Snapshot the intern table for a future schema-2 snapshot/patch."""
    return MappingProxyType(dict(_operation_names_by_id))


def compile_observation_policy(
    *, method: str, operation: str, detail: TraceDetail | str, group: str,
    slow_ms: float | None = None, capture_failures: bool = True,
    workflow: bool = False, cadence_ms: int | None = None,
) -> CompiledObservation:
    """Compile one externally declared Runtime observation policy record."""
    selected = TraceDetail(detail)
    if not method or not operation or not group:
        raise ValueError("external observation method, operation, and group are required")
    if slow_ms is not None and slow_ms < 0:
        raise ValueError("slow_ms must be non-negative")
    if cadence_ms is not None and cadence_ms <= 0:
        raise ValueError("cadence_ms must be positive")
    return CompiledObservation(
        _intern_operation(operation), operation, group, selected, slow_ms,
        bool(capture_failures),
        int(slow_ms * 1_000_000) if slow_ms is not None else None,
        method, bool(workflow), cadence_ms,
    )


def observe(
    *, detail: TraceDetail | str, group: str | None = None,
    slow_ms: float | None = None, capture_failures: bool = True,
):
    """Override the automatically selected observation policy for a method."""
    detail = TraceDetail(detail)
    if group is not None and not group:
        raise ValueError("observation group must not be empty")
    if slow_ms is not None and slow_ms < 0:
        raise ValueError("slow_ms must be non-negative")
    spec = ObservationSpec(detail, group, slow_ms, bool(capture_failures))

    def mark(fn):
        setattr(fn, "__observation_spec__", spec)
        return fn

    return mark


def performance(*, name: str, group: str | None = None, on_call=None, on_success=None, on_error=None):
    if not name:
        raise ValueError("performance name must not be empty")
    spec = PerformanceSpec(name, group, on_call, on_success, on_error)
    def mark(fn):
        setattr(fn, "__performance_spec__", spec)
        return fn
    return mark

@dataclass(frozen=True, slots=True)
class TaskSpec:
    name: str | None = None
    kind: str = "task"
    metadata: Callable[[CallInfo], Mapping[str, Any]] | Mapping[str, Any] | None = None
    failure: FailurePolicy = FailurePolicy.REPORT


class MethodPolicy(str, Enum):
    EVENT_LOOP = "event-loop"
    WORKER = "worker"


def task(*, name: str | None = None, kind: str = "task", metadata=None,
         failure: FailurePolicy = FailurePolicy.REPORT):
    spec = TaskSpec(name, kind, metadata, FailurePolicy(failure))
    def mark(fn):
        if not inspect.iscoroutinefunction(fn):
            raise TypeError("@task requires an async method")
        setattr(fn, "__task_spec__", spec)
        return fn
    return mark


def _marker(name):
    def decorate(fn):
        setattr(fn, name, True)
        return fn
    return decorate


unobserved = _marker("__unobserved__")
event_loop = _marker("__event_loop__")
worker = _marker("__worker__")


def _extract_attributes(extractor, info, diagnostics):
    if extractor is None:
        return {}
    try:
        values = extractor(info)
        return dict(values) if isinstance(values, Mapping) else {}
    except Exception:
        diagnostics["extractor_failures"] += 1
        return {}


def _operation(fn, spec):
    return spec.name if spec is not None else fn.__qualname__


def _record_metric(scope, context, operation, group, outcome, started, attributes,
                   *, duration_ms=None):
    if context is None:
        return
    try:
        scope.metric_sink.emit(MetricEvent(
            context.trace_id, context.task_id, operation, outcome,
            duration_ms if duration_ms is not None else (time.monotonic_ns() - started) / 1_000_000,
            attributes, group=group,
        ))
    except Exception:
        scope.diagnostics["sink_failures"] += 1


def _notify_trace(scope, method, event):
    callback = getattr(scope.trace_service, method, None)
    if callback is None:
        scope.diagnostics["missing_trace_hooks"] += 1
        return
    try:
        callback(event)
    except Exception:
        scope.diagnostics["trace_failures"] += 1


_current_activity_group: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "webrtc_activity_group", default=None
)
_worker_observation_delta: contextvars.ContextVar[WorkerObservationDelta | None] = (
    contextvars.ContextVar("webrtc_worker_observation_delta", default=None)
)


def _worker_owner(scope, args) -> WorkerOwnerBinding:
    subject = args[0] if args else None
    if subject is not None:
        binding = scope.observation_registry.get(subject)
        if binding is None and isinstance(subject, ObservedComponent):
            binding = _ensure_receiver_binding(scope, subject)
        if binding is not None:
            return WorkerOwnerBinding(
                scope, binding.entity_id, binding.owner_epoch, binding.role.value
            )
    entity_id = getattr(scope, "_runtime_entity_id", None)
    epoch = getattr(getattr(scope, "_runtime_runner", None), "epoch", None)
    if entity_id is None or epoch is None:
        raise MissingExecutionScope("worker submission requires a Runtime owner")
    return WorkerOwnerBinding(scope, entity_id, epoch, "runtime")


def _aggregate_identity(scope, binding: WorkerOwnerBinding | None = None):
    context = current_execution_context()
    root = getattr(scope, "root_context", None)
    owner = binding.entity_id if binding is not None else getattr(scope, "_runtime_entity_id", "")
    if context is not None:
        return context.trace_id, owner
    if root is not None:
        return root.trace_id, owner
    return "", getattr(scope, "scope_id", None) or ""


def _ensure_receiver_binding(scope, subject):
    binding = scope.observation_registry.get(subject)
    if binding is not None:
        return binding
    if not isinstance(subject, ObservedComponent):
        return None
    from .operation_policy import is_production_component
    if is_production_component(subject):
        raise MissingExecutionScope(
            f"{type(subject).__name__} requires explicit Runtime observation composition"
        )
    if getattr(type(subject), "__requires_observation_binding__", False):
        raise MissingExecutionScope(
            f"{type(subject).__name__} requires Runtime composition before observed use"
        )
    root_entity = getattr(scope, "_runtime_entity_id", None)
    root_epoch = getattr(getattr(scope, "_runtime_runner", None), "epoch", None)
    if root_entity is None or root_epoch is None:
        raise MissingExecutionScope("observed receiver requires a Runtime owner")
    from .observation_registry import default_semantic_role
    return scope.bind_observation(
        subject, entity_id=root_entity, role=default_semantic_role(subject),
        entity_role="runtime", owner_epoch=root_epoch,
        runtime_root_utility=True,
    )


def _validate_production_composition(scope, args) -> None:
    """Enforce Runtime composition independently of observation policy.

    This runs before every tracing fast path. It neither selects a detail
    level nor creates work; it only checks the external production catalog and
    the Runtime sidecar binding.
    """
    if not args:
        return
    subject = args[0]
    from .operation_policy import is_production_component
    if not is_production_component(subject):
        return
    # Outside an execution scope there is no Runtime-side observation path to
    # validate. Domain-only compatibility remains until Stage 7; once a
    # Runtime is active, composition is mandatory regardless of trace mode.
    if scope is None:
        return
    if scope.observation_registry.get(subject) is None:
        raise MissingExecutionScope(
            f"{type(subject).__name__} requires explicit Runtime observation composition"
        )


def _component_binding(scope, args) -> WorkerOwnerBinding | None:
    if not args:
        return None
    binding = _ensure_receiver_binding(scope, args[0])
    if binding is None:
        return None
    return WorkerOwnerBinding(
        scope, binding.entity_id, binding.owner_epoch, binding.role.value
    )


def _bound_policy(scope, args, fallback: CompiledObservation) -> CompiledObservation:
    if not args:
        return fallback
    binding = _ensure_receiver_binding(scope, args[0])
    if binding is None:
        return fallback
    if fallback.method is not None:
        policy = binding.operation_policy.get(fallback.method)
        if policy is not None:
            return policy
    for policy in binding.operation_policy.values():
        if getattr(policy, "operation_id", None) == fallback.operation_id:
            return policy
    if binding.policy_is_authoritative:
        return replace(fallback, detail=TraceDetail.OFF)
    return fallback


def _aggregate_record(scope, policy, binding: WorkerOwnerBinding | None = None) -> ActivityGroupRecord:
    trace_id, owner_id = _aggregate_identity(scope, binding)
    return scope.activity_groups.resolve(
        policy,
        trace_id=trace_id,
        owner_entity_id=owner_id,
        parent_ref_id=_current_activity_group.get(),
        owner_epoch=(binding.epoch if binding is not None
                     else getattr(scope, "observability_epoch", 1)),
        owner_role=(binding.role if binding is not None else "runtime"),
    )


def _aggregate_call_info(args, kwargs, spec):
    if spec is None or not (spec.on_call or spec.on_success or spec.on_error):
        return None
    return CallInfo(args, MappingProxyType(dict(kwargs)))


def _activity_failed(scope) -> None:
    scope.diagnostics["activity_failures"] += 1


def _finish_activity(
    scope, finish, record, outcome, duration_ns, finished_ns, failure_class,
    slow_ns, capture_failures,
) -> None:
    try:
        finish(
            record, outcome, duration_ns, finished_ns, failure_class,
            slow_ns, capture_failures,
        )
    except Exception:
        _activity_failed(scope)


def _run_aggregate_inline(scope, fn, args, kwargs, spec, policy):
    binding = _component_binding(scope, args)
    delta = _worker_observation_delta.get()
    started = time.monotonic_ns()
    try:
        if delta is None:
            record = _aggregate_record(scope, policy, binding)
            scope.activity_groups.begin(record, started)
        else:
            record = delta.resolve(policy, _current_activity_group.get())
            begin_local(record, started)
    except Exception:
        _activity_failed(scope)
        return fn(*args, **kwargs)
    token = _current_activity_group.set(record.group_id)
    call = _aggregate_call_info(args, kwargs, spec)
    if call is not None:
        _extract_attributes(spec.on_call, call, scope.diagnostics)
    try:
        result = fn(*args, **kwargs)
    except BaseException as error:
        finished = time.monotonic_ns()
        outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
        if call is not None:
            _extract_attributes(spec.on_error, ErrorInfo(call, error), scope.diagnostics)
        finish = scope.activity_groups.end if delta is None else end_local
        _finish_activity(
            scope, finish, record, outcome, finished - started, finished,
            type(error).__name__, policy.slow_ns, policy.capture_failures,
        )
        raise
    else:
        finished = time.monotonic_ns()
        if call is not None:
            _extract_attributes(spec.on_success, SuccessInfo(call, result), scope.diagnostics)
        finish = scope.activity_groups.end if delta is None else end_local
        _finish_activity(
            scope, finish, record, "success", finished - started, finished,
            None, policy.slow_ns, policy.capture_failures,
        )
        return result
    finally:
        _current_activity_group.reset(token)


async def _invoke_aggregate_async(scope, fn, args, kwargs, spec, policy):
    binding = _component_binding(scope, args)
    started = time.monotonic_ns()
    try:
        record = _aggregate_record(scope, policy, binding)
        scope.activity_groups.begin(record, started)
    except Exception:
        _activity_failed(scope)
        return await fn(*args, **kwargs)
    token = _current_activity_group.set(record.group_id)
    call = _aggregate_call_info(args, kwargs, spec)
    if call is not None:
        _extract_attributes(spec.on_call, call, scope.diagnostics)
    try:
        result = await fn(*args, **kwargs)
    except BaseException as error:
        finished = time.monotonic_ns()
        outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
        if call is not None:
            _extract_attributes(spec.on_error, ErrorInfo(call, error), scope.diagnostics)
        _finish_activity(
            scope, scope.activity_groups.end, record,
            outcome, finished - started, finished, type(error).__name__,
            policy.slow_ns, policy.capture_failures,
        )
        raise
    else:
        finished = time.monotonic_ns()
        if call is not None:
            _extract_attributes(spec.on_success, SuccessInfo(call, result), scope.diagnostics)
        _finish_activity(
            scope, scope.activity_groups.end, record,
            "success", finished - started, finished, None,
            policy.slow_ns, policy.capture_failures,
        )
        return result
    finally:
        _current_activity_group.reset(token)


def _start_node(scope, fn, node_type, *, cancelable=False, metadata=None):
    context = current_execution_context()
    node_id = uuid.uuid4().hex
    trace_id = context.trace_id if context else uuid.uuid4().hex
    descriptor = TraceNodeDescriptor(
        node_id, trace_id, fn.__qualname__, node_type,
        context.task_id if context else None,
        (context.node_id or context.task_id) if context else None,
        cancelable,
        metadata or {},
    )
    _notify_trace(scope, "node_started", TraceNodeStarted(descriptor))
    nested = replace(context, node_id=node_id) if context else None
    return descriptor, context, nested


def _finish_node(scope, descriptor, outcome, started, exception=None):
    _notify_trace(scope, "node_completed", TraceNodeCompleted(
        descriptor, outcome, (time.monotonic_ns() - started) / 1_000_000, exception
    ))


def _invoke_with_outcome(scope, fn, call, spec, descriptor, invoke):
    context = current_execution_context()
    started = time.monotonic_ns()
    attributes = _extract_attributes(spec.on_call if spec else None, call, scope.diagnostics)
    try:
        result = invoke()
    except BaseException as error:
        outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
        attributes.update(_extract_attributes(spec.on_error if spec else None,
                                              ErrorInfo(call, error), scope.diagnostics))
        attributes.setdefault("exception", type(error).__name__)
        _record_metric(scope, context, _operation(fn, spec), spec.group if spec else None,
                       outcome, started, attributes)
        _finish_node(scope, descriptor, outcome, started, error)
        raise
    attributes.update(_extract_attributes(spec.on_success if spec else None,
                                          SuccessInfo(call, result), scope.diagnostics))
    _record_metric(scope, context, _operation(fn, spec), spec.group if spec else None,
                   "success", started, attributes)
    _finish_node(scope, descriptor, "success", started)
    return result


async def _invoke_observed(scope, fn, args, kwargs, spec):
    call = CallInfo(args, MappingProxyType(dict(kwargs)))
    descriptor, _, nested = _start_node(scope, fn, TraceNodeType.ASYNC_CALL)
    token = set_execution_context(nested) if nested is not None else None
    context = current_execution_context()
    started = time.monotonic_ns()
    attributes = _extract_attributes(spec.on_call if spec else None, call, scope.diagnostics)
    try:
        result = await fn(*args, **kwargs)
    except BaseException as error:
        outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
        attributes.update(_extract_attributes(spec.on_error if spec else None,
                                              ErrorInfo(call, error), scope.diagnostics))
        attributes.setdefault("exception", type(error).__name__)
        _record_metric(scope, context, _operation(fn, spec), spec.group if spec else None,
                       outcome, started, attributes)
        _finish_node(scope, descriptor, outcome, started, error)
        raise
    else:
        attributes.update(_extract_attributes(spec.on_success if spec else None,
                                              SuccessInfo(call, result), scope.diagnostics))
        _record_metric(scope, context, _operation(fn, spec), spec.group if spec else None,
                       "success", started, attributes)
        _finish_node(scope, descriptor, "success", started)
        return result
    finally:
        if token is not None:
            reset_execution_context(token)


def _run_inline_call(scope, fn, args, kwargs, spec):
    call = CallInfo(args, MappingProxyType(dict(kwargs)))
    descriptor, _, nested = _start_node(scope, fn, TraceNodeType.INLINE_SYNC_CALL)
    token = set_execution_context(nested) if nested is not None else None
    try:
        return _invoke_with_outcome(scope, fn, call, spec, descriptor,
                                    lambda: fn(*args, **kwargs))
    finally:
        if token is not None:
            reset_execution_context(token)


async def _call_owned_worker(scope, fn, args, kwargs, *, name: str):
    binding = _worker_owner(scope, args)
    result = await scope.call_worker(
        fn, *args, owner_entity_id=binding.entity_id, owner_epoch=binding.epoch,
        name=name, **kwargs,
    ).wait()
    if result.outcome == "success":
        return result.value
    if result.exception is not None:
        raise result.exception
    raise RuntimeError(f"worker submission {result.outcome}")


async def _run_aggregate_worker(
    scope, fn, args, kwargs, spec, policy,
    *, binding_override: WorkerOwnerBinding | None = None,
):
    started = time.monotonic_ns()
    binding = binding_override or _worker_owner(scope, args)
    try:
        record = _aggregate_record(scope, policy, binding)
        scope.activity_groups.begin(record, started)
    except Exception:
        _activity_failed(scope)
        return await _call_owned_worker(
            scope, fn, args, kwargs, name=f"worker:{policy.operation}"
        )
    parent_token = _current_activity_group.set(record.group_id)
    trace_id, owner_id = _aggregate_identity(scope, binding)
    call = _aggregate_call_info(args, kwargs, spec)
    if call is not None:
        _extract_attributes(spec.on_call, call, scope.diagnostics)
    dispatched = False
    physically_completed = False
    terminal_recorded = False
    caller_cancelled = False
    delta_holder: list[WorkerObservationDelta | None] = [None]
    owner_context = current_execution_context()
    worker_dot = scope.new_producer_dot()

    def invoke_in_worker():
        delta = WorkerObservationDelta(record.group_id, worker_dot)
        delta_holder[0] = delta
        token = _worker_observation_delta.set(delta)
        try:
            return fn(*args, **kwargs)
        finally:
            _worker_observation_delta.reset(token)

    def finish(event: WorkerCallCompleted, outcome: str) -> None:
        nonlocal terminal_recorded
        if terminal_recorded:
            return
        terminal_recorded = True
        try:
            scope.activity_groups.merge_worker_delta(
                event.observation_delta, trace_id=trace_id,
                owner_entity_id=owner_id,
                owner_epoch=binding.epoch,
                owner_role=binding.role,
            )
            failure = type(event.exception).__name__ if event.exception is not None else None
            scope.activity_groups.end(
                record,
                outcome, event.total_ns, started + event.total_ns, failure,
                policy.slow_ns, policy.capture_failures,
                event.queue_ns, event.worker_ns,
            )
        except Exception:
            _activity_failed(scope)

    def on_dispatch() -> None:
        nonlocal dispatched
        dispatched = True
        if owner_context is not None:
            scope.task_registry.block_cancel(owner_context.task_id)

    def on_complete(event: WorkerCallCompleted) -> None:
        nonlocal physically_completed
        physically_completed = True
        if event.observation_delta is None:
            event = replace(event, observation_delta=delta_holder[0])
        finish(event, "cancelled" if caller_cancelled else event.outcome)
        if owner_context is not None:
            scope.task_registry.unblock_cancel(owner_context.task_id)

    def on_future(future) -> None:
        if owner_context is not None:
            scope.task_registry.add_barrier(owner_context.task_id, future)

    try:
        handle = scope.call_worker(
            invoke_in_worker, owner_entity_id=binding.entity_id,
            owner_epoch=binding.epoch, name=f"worker:{policy.operation}",
            on_dispatch=on_dispatch,
            on_future=on_future,
            on_complete=on_complete,
        )
        immutable = await handle.wait()
        if immutable.outcome == "success":
            result = immutable.value
            queue_ms = worker_ms = 0.0
        else:
            error = immutable.exception
            if error is None:
                error = RuntimeError(f"worker submission {immutable.outcome}")
            raise error
    except asyncio.CancelledError:
        caller_cancelled = True
        if not dispatched or physically_completed:
            elapsed = time.monotonic_ns() - started
            finish(WorkerCallCompleted(
                "cancelled", elapsed, 0, elapsed,
                observation_delta=delta_holder[0],
            ), "cancelled")
        raise
    except BaseException as error:
        if call is not None:
            _extract_attributes(spec.on_error, ErrorInfo(call, error), scope.diagnostics)
        if not terminal_recorded:
            elapsed = time.monotonic_ns() - started
            finish(WorkerCallCompleted(
                "error", elapsed, 0, elapsed, error, delta_holder[0]
            ), "error")
        raise
    else:
        if call is not None:
            _extract_attributes(spec.on_success, SuccessInfo(call, result), scope.diagnostics)
        if not terminal_recorded:
            elapsed = time.monotonic_ns() - started
            finish(WorkerCallCompleted(
                "success", int(queue_ms * 1_000_000), int(worker_ms * 1_000_000), elapsed,
                observation_delta=delta_holder[0],
            ), "success")
        return result
    finally:
        _current_activity_group.reset(parent_token)


async def observe_worker(execution, method, *args, name: str | None = None, **kwargs):
    """Observe an explicitly selected worker dispatch without selecting it.

    ``execution`` is the authority for scheduling and ownership.  This adapter
    only records the already-explicit operation, and its disabled fast path
    uses the exact same execution port and return contract.
    """
    scope = execution.runtime
    wrapper = getattr(method, "__func__", method)
    subject = getattr(method, "__self__", None)
    physical = getattr(wrapper, "__wrapped__", wrapper)
    call_args = ((subject,) if subject is not None else ()) + args
    policy = getattr(wrapper, "__compiled_observation__", None)
    spec = getattr(wrapper, "__performance_spec__", None)
    component_binding = None
    if subject is not None:
        binding = _ensure_receiver_binding(scope, subject)
        if binding is not None:
            policy = binding.operation_policy.get(getattr(physical, "__name__", ""))
            if policy is None and binding.policy_is_authoritative:
                policy = None
            component_binding = WorkerOwnerBinding(
                scope, binding.entity_id, binding.owner_epoch, binding.role.value,
            )
    if (
        not getattr(scope, "tracing_enabled", True)
        or policy is None
        or policy.detail not in (TraceDetail.AGGREGATE, TraceDetail.EXACT)
    ):
        return await execution.run_worker(
            physical, *call_args,
            name=name or f"worker:{getattr(policy, 'operation', physical.__qualname__)}",
            **kwargs,
        )
    binding = component_binding or WorkerOwnerBinding(
        scope, execution.owner_entity_id, execution.owner_epoch, "worker-lane"
    )
    return await _run_aggregate_worker(
        scope, physical, call_args, kwargs, spec, policy,
        binding_override=binding,
    )


async def _invoke_task_body(scope, fn, args, kwargs, spec):
    call = CallInfo(args, MappingProxyType(dict(kwargs)))
    context = current_execution_context()
    started = time.monotonic_ns()
    attributes = _extract_attributes(spec.on_call if spec else None, call, scope.diagnostics)
    try:
        result = await fn(*args, **kwargs)
    except BaseException as error:
        outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
        attributes.update(_extract_attributes(spec.on_error if spec else None,
                                              ErrorInfo(call, error), scope.diagnostics))
        attributes.setdefault("exception", type(error).__name__)
        _record_metric(scope, context, _operation(fn, spec), spec.group if spec else None,
                       outcome, started, attributes)
        raise
    attributes.update(_extract_attributes(spec.on_success if spec else None,
                                          SuccessInfo(call, result), scope.diagnostics))
    _record_metric(scope, context, _operation(fn, spec), spec.group if spec else None,
                   "success", started, attributes)
    return result


_LOOP_AFFINE_NAMES = frozenset({
    "asyncio", "create_task", "get_running_loop", "call_soon", "call_later",
    "run_in_executor", "add_reader", "remove_reader", "set_result", "set_exception",
    "transport", "protocol", "_transport", "_protocol", "_loop", "_event", "_ready",
})
_AMBIGUOUS_NAMES = frozenset({"getattr", "setattr", "vars", "eval", "exec", "__dict__"})


def _classify_sync_affinity(fn):
    if getattr(fn, "__event_loop__", False):
        return MethodPolicy.EVENT_LOOP
    if getattr(fn, "__worker__", False):
        return MethodPolicy.WORKER
    # Compatibility for not-yet-migrated/test components.  Production classes
    # opt into explicit execution at class composition and never reach this
    # automatic legacy fallback.
    return MethodPolicy.WORKER


def _begin_capture(scope, policy, args=()):
    if _worker_observation_delta.get() is not None:
        return None
    manager = scope.capture_manager
    if not manager.has_active_rules:
        return None
    _, owner_id = _aggregate_identity(scope, _component_binding(scope, args))
    try:
        return manager.begin(
            policy, owner_id, getattr(scope, "scope_id", None), None
        )
    except Exception:
        scope.diagnostics["capture_failures"] += 1
        return None


def _capture_metadata(record) -> dict[str, Any]:
    return {
        "diagnostic_capture": True,
        "capture_id": record.capture_id,
        "capture_record_id": record.record_id,
        "selector_kind": record.selector_kind,
        "selector_value": record.selector_value,
    }


async def _invoke_captured_async(scope, fn, args, kwargs, spec, policy, capture):
    async def invoke(*call_args, **call_kwargs):
        try:
            result = await fn(*call_args, **call_kwargs)
        except BaseException as error:
            outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
            scope.capture_manager.finish(capture, outcome, error)
            raise
        else:
            scope.capture_manager.finish(capture, "success")
            return result
    return await _invoke_aggregate_async(scope, invoke, args, kwargs, spec, policy)


def _run_captured_inline(scope, fn, args, kwargs, spec, policy, capture):
    def invoke(*call_args, **call_kwargs):
        try:
            result = fn(*call_args, **call_kwargs)
        except BaseException as error:
            outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
            scope.capture_manager.finish(capture, outcome, error)
            raise
        else:
            scope.capture_manager.finish(capture, "success")
            return result
    return _run_aggregate_inline(scope, invoke, args, kwargs, spec, policy)


async def _run_captured_worker(scope, fn, args, kwargs, spec, policy, capture):
    try:
        result = await _run_aggregate_worker(scope, fn, args, kwargs, spec, policy)
    except BaseException as error:
        outcome = "cancelled" if isinstance(error, asyncio.CancelledError) else "error"
        scope.capture_manager.finish(capture, outcome, error)
        raise
    else:
        scope.capture_manager.finish(capture, "success")
        return result


def _compile_async_call(fn, spec, observation):
    @functools.wraps(fn)
    async def observed(*args, **kwargs):
        scope = current_execution_scope()
        _validate_production_composition(scope, args)
        if scope is None or not getattr(scope, "tracing_enabled", True):
            return await fn(*args, **kwargs)
        policy = _bound_policy(scope, args, observation)
        capture = _begin_capture(scope, policy, args)
        if capture is not None:
            return await _invoke_captured_async(
                scope, fn, args, kwargs, spec, policy, capture
            )
        if policy.detail in (TraceDetail.AGGREGATE, TraceDetail.EXACT):
            return await _invoke_aggregate_async(scope, fn, args, kwargs, spec, policy)
        return await fn(*args, **kwargs)
    return observed


def _compile_sync_call(fn, spec, affinity, observation):
    if affinity is MethodPolicy.WORKER:
        @functools.wraps(fn)
        def observed_worker(*args, **kwargs):
            scope = current_execution_scope()
            _validate_production_composition(scope, args)
            policy = _bound_policy(scope, args, observation) if scope is not None else observation
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                in_physical_worker = True
            else:
                in_physical_worker = False
            if (
                scope is not None
                and _worker_observation_delta.get() is not None
                and scope.worker_lane.is_current_worker_context()
                and in_physical_worker
            ):
                if not getattr(scope, "tracing_enabled", True):
                    return fn(*args, **kwargs)
                capture = _begin_capture(scope, policy, args)
                if capture is not None:
                    return _run_captured_inline(
                        scope, fn, args, kwargs, spec, policy, capture
                    )
                if policy.detail in (TraceDetail.AGGREGATE, TraceDetail.EXACT):
                    return _run_aggregate_inline(
                        scope, fn, args, kwargs, spec, policy
                    )
                return fn(*args, **kwargs)

            if scope is None:
                raise MissingExecutionScope(
                    f"worker operation {fn.__qualname__} requires an active Runtime"
                )

            async def dispatch():
                if not getattr(scope, "tracing_enabled", True):
                    return await _call_owned_worker(
                        scope, fn, args, kwargs, name=f"worker:{policy.operation}"
                    )
                capture = _begin_capture(scope, policy, args)
                if capture is not None:
                    return await _run_captured_worker(
                        scope, fn, args, kwargs, spec, policy, capture
                    )
                if policy.detail not in (TraceDetail.AGGREGATE, TraceDetail.EXACT):
                    return await _call_owned_worker(
                        scope, fn, args, kwargs, name=f"worker:{policy.operation}"
                    )
                return await _run_aggregate_worker(
                    scope, fn, args, kwargs, spec, policy
                )

            return dispatch()
        return observed_worker

    @functools.wraps(fn)
    def observed(*args, **kwargs):
        scope = current_execution_scope()
        _validate_production_composition(scope, args)
        if scope is None:
            return fn(*args, **kwargs)
        if not getattr(scope, "tracing_enabled", True):
            return fn(*args, **kwargs)
        policy = _bound_policy(scope, args, observation)
        capture = _begin_capture(scope, policy, args)
        if capture is not None:
            return _run_captured_inline(
                scope, fn, args, kwargs, spec, policy, capture
            )
        if policy.detail not in (TraceDetail.AGGREGATE, TraceDetail.EXACT):
            return fn(*args, **kwargs)
        return _run_aggregate_inline(scope, fn, args, kwargs, spec, policy)
    return observed


def _compile_task_entry(fn, performance_spec, task_spec, observation):
    @functools.wraps(fn)
    def scheduled(*args, **kwargs):
        scope = require_execution_scope()
        _validate_production_composition(scope, args)
        policy = _bound_policy(scope, args, observation)
        call = CallInfo(args, MappingProxyType(dict(kwargs)))
        metadata = task_spec.metadata
        if callable(metadata):
            metadata = _extract_attributes(metadata, call, scope.diagnostics)
        metadata = dict(metadata or {})
        if policy.detail in (TraceDetail.AGGREGATE, TraceDetail.EXACT):
            factory = lambda: _invoke_aggregate_async(
                scope, fn, args, kwargs, performance_spec, policy
            )
        else:
            factory = lambda: fn(*args, **kwargs)
        return scope.start(
            factory,
            name=task_spec.name or fn.__qualname__,
            kind=task_spec.kind,
            metadata=metadata,
            failure=task_spec.failure,
        )
    return scheduled


def compile_runtime_operation_adapter(fn, policy: CompiledObservation):
    """Build an external, execution-neutral adapter for an allowlisted method.

    Production classes use this entry point from the Runtime-owned operation
    catalog.  Unlike ``ObservedMeta`` it does not discover methods, attach
    policy to the class, or select worker/task execution semantics.
    """
    if inspect.iscoroutinefunction(fn):
        return _compile_async_call(fn, None, policy)
    return _compile_sync_call(fn, None, MethodPolicy.EVENT_LOOP, policy)


def _validate_markers(owner, attr, fn):
    marked = {
        "unobserved": bool(getattr(fn, "__unobserved__", False)),
        "event_loop": bool(getattr(fn, "__event_loop__", False)),
        "worker": bool(getattr(fn, "__worker__", False)),
        "task": getattr(fn, "__task_spec__", None) is not None,
        "performance": getattr(fn, "__performance_spec__", None) is not None,
        "observe": getattr(fn, "__observation_spec__", None) is not None,
    }
    where = f"{owner}.{attr}"
    if marked["unobserved"] and any(value for key, value in marked.items() if key != "unobserved"):
        raise TypeError(f"@unobserved cannot be combined with other markers: {where}")
    if marked["event_loop"] and marked["worker"]:
        raise TypeError(f"@event_loop and @worker are mutually exclusive: {where}")
    if inspect.iscoroutinefunction(fn) and (marked["event_loop"] or marked["worker"]):
        raise TypeError(f"affinity markers require a synchronous method: {where}")
    if marked["task"] and not inspect.iscoroutinefunction(fn):
        raise TypeError(f"@task requires an async method: {where}")


def _compile_observation(owner, attr, fn, performance_spec, task_spec):
    explicit = getattr(fn, "__observation_spec__", None)
    operation = performance_spec.name if performance_spec is not None else fn.__qualname__
    if explicit is not None:
        detail = explicit.detail
    elif task_spec is not None:
        detail = TraceDetail.OFF
    else:
        detail = TraceDetail.AGGREGATE
    group = (
        explicit.group if explicit is not None and explicit.group is not None
        else performance_spec.group if performance_spec is not None and performance_spec.group
        else operation
    )
    return CompiledObservation(
        _intern_operation(operation), operation, group, detail,
        explicit.slow_ms if explicit is not None else None,
        explicit.capture_failures if explicit is not None else True,
        int(explicit.slow_ms * 1_000_000)
        if explicit is not None and explicit.slow_ms is not None else None,
        attr,
    )


class ObservedMeta(type):
    def __new__(mcls, name, bases, namespace, **kwargs):
        cls = super().__new__(mcls, name, bases, namespace, **kwargs)
        observations = {}
        for base in bases:
            observations.update(getattr(base, "__observations__", {}))
        for attr, descriptor in namespace.items():
            if attr == "__init__" or (attr.startswith("__") and attr.endswith("__")):
                continue
            if isinstance(descriptor, property):
                continue
            fn = descriptor.__func__ if isinstance(descriptor, (staticmethod, classmethod)) else descriptor
            if not inspect.isfunction(fn):
                continue
            _validate_markers(name, attr, fn)
            if getattr(fn, "__unobserved__", False):
                continue
            performance_spec = getattr(fn, "__performance_spec__", None)
            task_spec = getattr(fn, "__task_spec__", None)
            policy = _compile_observation(name, attr, fn, performance_spec, task_spec)
            if task_spec is not None:
                wrapped = _compile_task_entry(fn, performance_spec, task_spec, policy)
            elif inspect.iscoroutinefunction(fn):
                wrapped = _compile_async_call(fn, performance_spec, policy)
            else:
                affinity = (
                    MethodPolicy.EVENT_LOOP
                    if getattr(cls, "__explicit_execution__", False)
                    else _classify_sync_affinity(fn)
                )
                wrapped = _compile_sync_call(fn, performance_spec, affinity, policy)
            if isinstance(descriptor, staticmethod):
                wrapped = staticmethod(wrapped)
            elif isinstance(descriptor, classmethod):
                wrapped = classmethod(wrapped)
            target = wrapped.__func__ if isinstance(wrapped, (staticmethod, classmethod)) else wrapped
            setattr(target, "__compiled_observation__", policy)
            observations[attr] = policy
            setattr(cls, attr, wrapped)
        cls.__observations__ = MappingProxyType(observations)
        return cls


class ObservedComponent(metaclass=ObservedMeta):
    """Stateless opt-in base that compiles observation policy at class creation."""
    def __bind_worker_owner__(
        self, runtime: Any, entity_id: str, epoch: int, *, role: str | None = None,
    ) -> None:
        runtime.bind_observation(
            self, entity_id=entity_id,
            role=role or "component",
            owner_epoch=epoch,
        )
