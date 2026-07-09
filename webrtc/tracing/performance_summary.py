from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .performance import PerfEvent


@dataclass(frozen=True, slots=True)
class BaselineCheck:
    ok: bool
    failures: tuple[str, ...] = ()


def build_performance_summary(
    events: Iterable[PerfEvent | Mapping[str, Any]],
    *,
    scenario: str | None = None,
    required_events: Iterable[str] = (),
    forbidden_events: Iterable[str] = (),
    ordering: Iterable[Sequence[str]] = (),
) -> dict[str, Any]:
    normalized = [_event_dict(event) for event in events]
    normalized.sort(key=lambda event: (int(event["sequence"]), int(event["monotonic_ns"])))

    event_names = [str(event["name"]) for event in normalized]
    forbidden_found = [name for name in forbidden_events if name in event_names]
    missing_required = [name for name in required_events if name not in event_names]
    ordering_failures = _ordering_failures(event_names, ordering)

    phase_ms = _phase_durations(normalized)
    counters = _counters(normalized)
    total_ms = _total_ms(normalized)
    incomplete_phases = _incomplete_phases(normalized)
    failed_events = [event["name"] for event in normalized if event["state"] == "failed"]

    status = "completed"
    if forbidden_found:
        status = "forbidden"
    elif missing_required or incomplete_phases or ordering_failures:
        status = "incomplete"
    elif failed_events:
        status = "failed"

    return {
        "scenario": scenario,
        "status": status,
        "event_count": len(normalized),
        "total_ms": total_ms,
        "events": event_names,
        "counters": counters,
        "phase_ms": phase_ms,
        "missing_required_events": missing_required,
        "forbidden_events": forbidden_found,
        "ordering_failures": ordering_failures,
        "incomplete_phases": incomplete_phases,
        "failed_events": failed_events,
    }


def check_required_events(
    events: Iterable[PerfEvent | Mapping[str, Any]],
    required_events: Iterable[str],
) -> BaselineCheck:
    present = {_event_dict(event)["name"] for event in events}
    failures = tuple(f"missing required event: {name}" for name in required_events if name not in present)
    return BaselineCheck(ok=not failures, failures=failures)


def check_forbidden_events(
    events: Iterable[PerfEvent | Mapping[str, Any]],
    forbidden_events: Iterable[str],
) -> BaselineCheck:
    present = {_event_dict(event)["name"] for event in events}
    failures = tuple(f"forbidden event present: {name}" for name in forbidden_events if name in present)
    return BaselineCheck(ok=not failures, failures=failures)


def check_event_ordering(
    events: Iterable[PerfEvent | Mapping[str, Any]],
    ordering: Iterable[Sequence[str]],
) -> BaselineCheck:
    event_names = [_event_dict(event)["name"] for event in events]
    failures = tuple(_ordering_failures(event_names, ordering))
    return BaselineCheck(ok=not failures, failures=failures)


def check_counters(
    counters: Mapping[str, int | float],
    expected: Mapping[str, Mapping[str, int | float]],
) -> BaselineCheck:
    failures: list[str] = []
    for name, rule in expected.items():
        value = counters.get(name, 0)
        if "min" in rule and value < rule["min"]:
            failures.append(f"counter {name} below min {rule['min']}: {value}")
        if "max" in rule and value > rule["max"]:
            failures.append(f"counter {name} above max {rule['max']}: {value}")
        if "equals" in rule and value != rule["equals"]:
            failures.append(f"counter {name} expected {rule['equals']}: {value}")
    return BaselineCheck(ok=not failures, failures=tuple(failures))


def check_smoke_thresholds(
    summary: Mapping[str, Any],
    thresholds: Mapping[str, int | float | Mapping[str, int | float]],
) -> BaselineCheck:
    failures: list[str] = []
    for dotted_key, limit in thresholds.items():
        value = _lookup_dotted(summary, dotted_key)
        if isinstance(limit, Mapping):
            if "min" in limit and (value is None or value < limit["min"]):
                failures.append(f"{dotted_key} below min {limit['min']}: {value}")
            if "max" in limit and (value is None or value > limit["max"]):
                failures.append(f"{dotted_key} above max {limit['max']}: {value}")
        elif value is None or value > limit:
            failures.append(f"{dotted_key} above max {limit}: {value}")
    return BaselineCheck(ok=not failures, failures=tuple(failures))


def _event_dict(event: PerfEvent | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(event, PerfEvent):
        data = event.to_dict()
    else:
        data = dict(event)

    name = data.get("name") or ".".join(str(data[key]) for key in ("component", "phase", "state"))
    return {
        "component": str(data["component"]),
        "phase": str(data["phase"]),
        "state": str(data["state"]),
        "name": str(name),
        "sequence": int(data.get("sequence", 0)),
        "monotonic_ns": int(data.get("monotonic_ns", 0)),
        "duration_ms": data.get("duration_ms"),
        "metadata": data.get("metadata") if isinstance(data.get("metadata"), Mapping) else {},
    }


def _phase_key(event: Mapping[str, Any]) -> str:
    return f"{event['component']}.{event['phase']}"


def _phase_durations(events: list[dict[str, Any]]) -> dict[str, float]:
    starts: dict[str, int] = {}
    durations: dict[str, float] = {}
    for event in events:
        key = _phase_key(event)
        if event["state"] == "started":
            starts[key] = int(event["monotonic_ns"])
        elif event["state"] in {"completed", "failed"}:
            duration_ms = event.get("duration_ms")
            if duration_ms is None and key in starts:
                duration_ms = max(0.0, (int(event["monotonic_ns"]) - starts[key]) / 1_000_000)
            if duration_ms is not None:
                durations[key] = float(duration_ms)
    return durations


def _counters(events: list[dict[str, Any]]) -> dict[str, int]:
    counters: dict[str, int] = {"events.total": len(events)}
    for event in events:
        counters[f"events.{event['name']}"] = counters.get(f"events.{event['name']}", 0) + 1
        counters[f"components.{event['component']}"] = counters.get(f"components.{event['component']}", 0) + 1
        counters[f"states.{event['state']}"] = counters.get(f"states.{event['state']}", 0) + 1
        metadata = event.get("metadata")
        if isinstance(metadata, Mapping):
            for key, value in metadata.items():
                if key.startswith("counter.") and isinstance(value, int):
                    counters[key.removeprefix("counter.")] = counters.get(key.removeprefix("counter."), 0) + value
    return counters


def _total_ms(events: list[dict[str, Any]]) -> float | None:
    if len(events) < 2:
        return None
    first = int(events[0]["monotonic_ns"])
    last = int(events[-1]["monotonic_ns"])
    return max(0.0, (last - first) / 1_000_000)


def _incomplete_phases(events: list[dict[str, Any]]) -> list[str]:
    open_phases: set[str] = set()
    for event in events:
        key = _phase_key(event)
        if event["state"] == "started":
            open_phases.add(key)
        elif event["state"] in {"completed", "failed"}:
            open_phases.discard(key)
    return sorted(open_phases)


def _ordering_failures(event_names: Sequence[str], ordering: Iterable[Sequence[str]]) -> list[str]:
    positions: dict[str, int] = {}
    for index, name in enumerate(event_names):
        positions.setdefault(name, index)

    failures: list[str] = []
    for rule in ordering:
        previous_name: str | None = None
        previous_position: int | None = None
        for name in rule:
            position = positions.get(name)
            if position is None:
                failures.append(f"ordering event missing: {name}")
                break
            if previous_position is not None and position < previous_position:
                failures.append(f"event out of order: {previous_name} before {name}")
                break
            previous_name = name
            previous_position = position
    return failures


def _lookup_dotted(data: Mapping[str, Any], dotted_key: str) -> Any:
    value: Any = data
    parts = dotted_key.split(".")
    for index, part in enumerate(parts):
        if not isinstance(value, Mapping) or part not in value:
            remaining = ".".join(parts[index:])
            if isinstance(value, Mapping) and remaining in value:
                return value[remaining]
            return None
        value = value[part]
    return value
