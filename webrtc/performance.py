from __future__ import annotations

import asyncio
import functools
import inspect
import time
import uuid
from collections import OrderedDict, Counter
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Any, Generic, ParamSpec, Protocol, TypeVar, cast

from .runtime_services import (
    FailurePolicy,
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
T_co = TypeVar("T_co", covariant=True)
P = ParamSpec("P")
Scalar = str | int | float | bool | None


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
        self._lock = RLock()

    def emit(self, event: MetricEvent) -> None:
        with self._lock:
            if len(self._events) < self.limit:
                self._events.append(event)

    def events(self) -> tuple[MetricEvent, ...]:
        with self._lock:
            return tuple(self._events)


@dataclass(frozen=True, slots=True)
class GroupSnapshot:
    trace_id: str
    task_id: str
    group: str
    operation: str
    calls: int
    successes: int
    cancellations: int
    errors: int
    total_duration_ms: float
    average_duration_ms: float
    min_duration_ms: float
    max_duration_ms: float
    latest_failure_class: str | None

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


class MetricGroupAggregator:
    def __init__(self, max_groups: int = 4096) -> None:
        self.max_groups = max(1, max_groups)
        self._groups: OrderedDict[tuple[str, str, str, str], dict[str, Any]] = OrderedDict()
        self.diagnostics: Counter[str] = Counter()
        self._lock = RLock()

    def emit(self, event: MetricEvent) -> None:
        try:
            key = (event.trace_id, event.task_id, event.group or event.operation, event.operation)
            with self._lock:
                value = self._groups.pop(key, None)
                if value is None:
                    if len(self._groups) >= self.max_groups:
                        self._groups.popitem(last=False)
                        self.diagnostics["evicted_groups"] += 1
                    value = {"calls": 0, "successes": 0, "cancellations": 0, "errors": 0,
                             "total": 0.0, "min": float("inf"), "max": 0.0, "failure": None}
                value["calls"] += 1
                value["total"] += event.duration_ms
                value["min"] = min(value["min"], event.duration_ms)
                value["max"] = max(value["max"], event.duration_ms)
                if event.outcome == "success": value["successes"] += 1
                elif event.outcome == "cancelled": value["cancellations"] += 1
                else:
                    value["errors"] += 1
                    value["failure"] = event.attributes.get("exception")
                self._groups[key] = value
        except Exception:
            self.diagnostics["aggregation_failures"] += 1

    def snapshots(self, trace_id: str | None = None) -> tuple[GroupSnapshot, ...]:
        with self._lock:
            items = list(self._groups.items())
        return tuple(GroupSnapshot(*key, v["calls"], v["successes"], v["cancellations"],
            v["errors"], v["total"], v["total"] / v["calls"], v["min"], v["max"], v["failure"])
            for key, v in items if trace_id is None or key[0] == trace_id)


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


async def _run_worker_call(scope, fn, args, kwargs, spec):
    call = CallInfo(args, MappingProxyType(dict(kwargs)))
    descriptor, owner_context, nested = _start_node(
        scope, fn, TraceNodeType.WORKER_CALL, cancelable=True
    )
    started = time.monotonic_ns()
    attributes = _extract_attributes(spec.on_call if spec else None, call, scope.diagnostics)
    dispatched = False
    caller_cancelled = False
    physical_completed = False
    completed_event = None
    terminal_recorded = False
    loop = asyncio.get_running_loop()
    queue_cancelled: asyncio.Future[bool] = loop.create_future()
    lane_task = None

    def cancel_queued() -> bool:
        if dispatched or queue_cancelled.done():
            return False
        queue_cancelled.set_result(True)
        return True

    scope.task_registry.register_node_canceller(descriptor.node_id, cancel_queued)

    def record_terminal(event: WorkerCallCompleted, outcome: str) -> None:
        nonlocal terminal_recorded
        if terminal_recorded:
            return
        terminal_recorded = True
        operation = _operation(fn, spec)
        group = (spec.group if spec else None) or operation
        if event.exception is not None:
            attributes.setdefault("exception", type(event.exception).__name__)
        for suffix, duration in (
            ("queue", event.queue_ms),
            ("worker", event.worker_ms),
            (None, event.total_ms),
        ):
            metric_operation = operation if suffix is None else f"{operation}.{suffix}"
            _record_metric(scope, owner_context, metric_operation, group,
                           outcome, started, attributes, duration_ms=duration)
        _finish_node(scope, descriptor, outcome, started, event.exception)

    def on_dispatch():
        nonlocal dispatched
        dispatched = True
        scope.task_registry.unregister_node_canceller(descriptor.node_id)
        _notify_trace(scope, "node_cancelability_changed",
                      TraceNodeCancelabilityChanged(descriptor.node_id, False))
        if owner_context is not None:
            scope.task_registry.block_cancel(owner_context.task_id)

    def on_complete(event: WorkerCallCompleted):
        nonlocal physical_completed, completed_event
        physical_completed = True
        completed_event = event
        if caller_cancelled:
            record_terminal(event, "completed_after_cancellation")
        if owner_context is not None:
            scope.task_registry.unblock_cancel(owner_context.task_id)

    def on_future(future):
        if owner_context is not None:
            scope.task_registry.add_barrier(owner_context.task_id, future)

    token = set_execution_context(nested) if nested is not None else None
    try:
        lane_task = asyncio.create_task(
            scope.worker_lane.run_observed(
                fn, *args, on_dispatch=on_dispatch, on_future=on_future,
                on_complete=on_complete, **kwargs
            )
        )
        done, _ = await asyncio.wait(
            (lane_task, queue_cancelled), return_when=asyncio.FIRST_COMPLETED
        )
        if queue_cancelled in done and not dispatched:
            lane_task.cancel()
            await asyncio.gather(lane_task, return_exceptions=True)
            raise asyncio.CancelledError
        result, queue_ms, worker_ms = await lane_task
    except asyncio.CancelledError:
        caller_cancelled = True
        if lane_task is not None and not lane_task.done():
            lane_task.cancel()
            await asyncio.gather(lane_task, return_exceptions=True)
        if not dispatched or physical_completed:
            elapsed = (time.monotonic_ns() - started) / 1_000_000
            record_terminal(WorkerCallCompleted("cancelled", elapsed, 0.0, elapsed), "cancelled")
        raise
    except BaseException as error:
        attributes.update(_extract_attributes(spec.on_error if spec else None,
                                              ErrorInfo(call, error), scope.diagnostics))
        attributes.setdefault("exception", type(error).__name__)
        if not terminal_recorded:
            event = completed_event
            if event is None:
                elapsed = (time.monotonic_ns() - started) / 1_000_000
                event = WorkerCallCompleted("error", elapsed, 0.0, elapsed, error)
            record_terminal(event, "error")
        raise
    else:
        attributes.update(_extract_attributes(spec.on_success if spec else None,
                                              SuccessInfo(call, result), scope.diagnostics))
        if not terminal_recorded:
            total_ms = (time.monotonic_ns() - started) / 1_000_000
            event = completed_event or WorkerCallCompleted(
                "success", queue_ms, worker_ms, total_ms
            )
            record_terminal(event, "success")
        return result
    finally:
        scope.task_registry.unregister_node_canceller(descriptor.node_id)
        if token is not None:
            reset_execution_context(token)


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
    names = set(fn.__code__.co_names)
    if names & _AMBIGUOUS_NAMES:
        raise TypeError(
            f"ambiguous synchronous affinity for {fn.__qualname__}; "
            "mark it @event_loop or @worker"
        )
    if names & _LOOP_AFFINE_NAMES:
        return MethodPolicy.EVENT_LOOP
    raise TypeError(
        f"ambiguous synchronous affinity for {fn.__qualname__}; "
        "mark it @event_loop or @worker"
    )


def _compile_async_call(fn, spec):
    @functools.wraps(fn)
    async def observed(*args, **kwargs):
        scope = current_execution_scope()
        if scope is None:
            return await fn(*args, **kwargs)
        return await _invoke_observed(scope, fn, args, kwargs, spec)
    return observed


def _compile_sync_call(fn, spec, policy):
    @functools.wraps(fn)
    def observed(*args, **kwargs):
        scope = current_execution_scope()
        if scope is None:
            return fn(*args, **kwargs)
        if policy is MethodPolicy.EVENT_LOOP or scope.worker_lane.is_current_worker_context():
            return _run_inline_call(scope, fn, args, kwargs, spec)
        return _run_worker_call(scope, fn, args, kwargs, spec)
    if policy is MethodPolicy.WORKER:
        # Runtime reflection contract used by generated/application protocols:
        # in an active Runtime this callable's result must be awaited.
        setattr(observed, "__runtime_worker__", True)
        setattr(
            observed,
            "__runtime_result_annotation__",
            fn.__annotations__.get("return", Any),
        )
    return observed


def _compile_task_entry(fn, performance_spec, task_spec):
    @functools.wraps(fn)
    def scheduled(*args, **kwargs):
        scope = require_execution_scope()
        call = CallInfo(args, MappingProxyType(dict(kwargs)))
        metadata = task_spec.metadata
        if callable(metadata):
            metadata = _extract_attributes(metadata, call, scope.diagnostics)
        return scope.task_scheduler.spawn_factory(
            lambda: _invoke_task_body(scope, fn, args, kwargs, performance_spec),
            name=task_spec.name or fn.__qualname__,
            kind=task_spec.kind,
            metadata=metadata or {},
            failure=task_spec.failure,
        )
    return scheduled


def _validate_markers(owner, attr, fn):
    marked = {
        "unobserved": bool(getattr(fn, "__unobserved__", False)),
        "event_loop": bool(getattr(fn, "__event_loop__", False)),
        "worker": bool(getattr(fn, "__worker__", False)),
        "task": getattr(fn, "__task_spec__", None) is not None,
        "performance": getattr(fn, "__performance_spec__", None) is not None,
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


class ObservedMeta(type):
    def __new__(mcls, name, bases, namespace, **kwargs):
        cls = super().__new__(mcls, name, bases, namespace, **kwargs)
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
            if task_spec is not None:
                wrapped = _compile_task_entry(fn, performance_spec, task_spec)
            elif inspect.iscoroutinefunction(fn):
                wrapped = _compile_async_call(fn, performance_spec)
            else:
                wrapped = _compile_sync_call(fn, performance_spec, _classify_sync_affinity(fn))
            if isinstance(descriptor, staticmethod):
                wrapped = staticmethod(wrapped)
            elif isinstance(descriptor, classmethod):
                wrapped = classmethod(wrapped)
            setattr(cls, attr, wrapped)
        return cls


class ObservedComponent(metaclass=ObservedMeta):
    """Stateless opt-in base that compiles observation policy at class creation."""

    pass


class AsyncWorkerMethod(Protocol[P, T_co]):
    """Static application view of a worker-classified synchronous method."""

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> Awaitable[T_co]: ...


def async_worker_method(method: Callable[P, T]) -> AsyncWorkerMethod[P, T]:
    """Return the typed active-Runtime view without changing runtime behavior."""
    if not getattr(method, "__runtime_worker__", False):
        raise TypeError("method is not worker-classified")
    return cast(AsyncWorkerMethod[P, T], method)
