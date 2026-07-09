from __future__ import annotations

import contextvars
import functools
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Any, ParamSpec, TypeVar

P = ParamSpec("P")
T = TypeVar("T")

FrozenMetadata = Mapping[str, Any]

_current_performance_recorder: contextvars.ContextVar["PerformanceRecorder | None"] = (
    contextvars.ContextVar("webrtc_current_performance_recorder", default=None)
)


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_value(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_freeze_value(item) for item in value)
    return value


def _freeze_metadata(metadata: Mapping[str, Any] | None) -> FrozenMetadata:
    if not metadata:
        return MappingProxyType({})
    return MappingProxyType({str(key): _freeze_value(value) for key, value in metadata.items()})


@dataclass(frozen=True, slots=True)
class PerfEvent:
    component: str
    phase: str
    state: str
    sequence: int
    monotonic_ns: int
    timestamp: float = field(default_factory=time.time)
    duration_ms: float | None = None
    metadata: FrozenMetadata = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def name(self) -> str:
        return f"{self.component}.{self.phase}.{self.state}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "phase": self.phase,
            "state": self.state,
            "name": self.name,
            "sequence": self.sequence,
            "monotonic_ns": self.monotonic_ns,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "metadata": _thaw_value(self.metadata),
        }


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_value(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(_thaw_value(item) for item in value)
    return value


class PerformanceRecorder:
    def __init__(self) -> None:
        self._lock = RLock()
        self._sequence = 0
        self._events: list[PerfEvent] = []

    def mark(
        self,
        component: str,
        phase: str,
        state: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        duration_ms: float | None = None,
    ) -> PerfEvent:
        event_metadata = _metadata_with_task_context(metadata)
        with self._lock:
            self._sequence += 1
            event = PerfEvent(
                component=component,
                phase=phase,
                state=state,
                sequence=self._sequence,
                monotonic_ns=time.monotonic_ns(),
                duration_ms=duration_ms,
                metadata=event_metadata,
            )
            self._events.append(event)
            return event

    def events(self) -> tuple[PerfEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._sequence = 0

    def use(self) -> Iterator["PerformanceRecorder"]:
        return use_performance_recorder(self)


def get_current_performance_recorder() -> PerformanceRecorder | None:
    return _current_performance_recorder.get()


@contextmanager
def use_performance_recorder(recorder: PerformanceRecorder | None) -> Iterator[PerformanceRecorder | None]:
    token = _current_performance_recorder.set(recorder)
    try:
        yield recorder
    finally:
        _current_performance_recorder.reset(token)


def perf_mark(
    component: str,
    phase: str,
    state: str,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> PerfEvent | None:
    recorder = get_current_performance_recorder()
    if recorder is None:
        return None
    return recorder.mark(component, phase, state, metadata=metadata)


@contextmanager
def measure_perf(
    component: str,
    phase: str,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> Iterator[None]:
    recorder = get_current_performance_recorder()
    if recorder is None:
        yield
        return

    started_ns = time.monotonic_ns()
    recorder.mark(component, phase, "started", metadata=metadata)
    try:
        yield
    except BaseException as exc:
        recorder.mark(
            component,
            phase,
            "failed",
            duration_ms=(time.monotonic_ns() - started_ns) / 1_000_000,
            metadata={**(metadata or {}), "exception_class": exc.__class__.__name__},
        )
        raise
    else:
        recorder.mark(
            component,
            phase,
            "completed",
            duration_ms=(time.monotonic_ns() - started_ns) / 1_000_000,
            metadata=metadata,
        )


@asynccontextmanager
async def measure_perf_async(
    component: str,
    phase: str,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> AsyncIterator[None]:
    recorder = get_current_performance_recorder()
    if recorder is None:
        yield
        return

    started_ns = time.monotonic_ns()
    recorder.mark(component, phase, "started", metadata=metadata)
    try:
        yield
    except BaseException as exc:
        recorder.mark(
            component,
            phase,
            "failed",
            duration_ms=(time.monotonic_ns() - started_ns) / 1_000_000,
            metadata={**(metadata or {}), "exception_class": exc.__class__.__name__},
        )
        raise
    else:
        recorder.mark(
            component,
            phase,
            "completed",
            duration_ms=(time.monotonic_ns() - started_ns) / 1_000_000,
            metadata=metadata,
        )


def perf_measured(
    component: str,
    phase: str,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def decorate(fn: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            with measure_perf(component, phase, metadata=metadata):
                return fn(*args, **kwargs)

        return wrapper

    return decorate


def perf_measured_async(
    component: str,
    phase: str,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    def decorate(fn: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            async with measure_perf_async(component, phase, metadata=metadata):
                return await fn(*args, **kwargs)

        return wrapper

    return decorate


def _metadata_with_task_context(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = dict(metadata or {})
    try:
        from webrtc.runtime import get_current_task_context
    except ImportError:
        return merged

    context = get_current_task_context()
    if context is None:
        return merged

    task_metadata = context.metadata
    merged.setdefault("trace_id", context.trace_id)
    if context.parent_id is not None:
        merged.setdefault("parent_trace_id", context.parent_id)
    merged.setdefault("task_name", context.name)
    merged.setdefault("task_kind", context.kind)
    for key in ("peer_id", "component", "bounded", "app_task"):
        if key in task_metadata:
            merged.setdefault(key, task_metadata[key])
    return merged
