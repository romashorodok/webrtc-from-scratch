from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .observability import ProducerDot


_MACHINE = 0
_CONTROL = 1
_GROUP = 2
_ROOT = 3
_OVERFLOW_OPERATION_ID = 0


@dataclass(slots=True)
class ActivityExemplar:
    outcome: str
    duration_ns: int
    finished_ns: int
    failure_class: str | None


@dataclass(slots=True)
class ActivityGroupRecord:
    group_id: int
    trace_id: str
    owner_entity_id: str
    parent_ref_type: int
    parent_ref_id: int | str | None
    operation_id: int
    operation: str
    group: str
    owner_epoch: int = 1
    calls: int = 0
    in_flight: int = 0
    successes: int = 0
    cancellations: int = 0
    errors: int = 0
    total_duration_ns: int = 0
    min_duration_ns: int = -1
    max_duration_ns: int = 0
    total_queue_ns: int = 0
    total_worker_ns: int = 0
    max_queue_ns: int = 0
    max_worker_ns: int = 0
    last_started_ns: int = 0
    last_finished_ns: int = 0
    latest_failure_class: str | None = None
    revision: int = 0
    exemplars: list[ActivityExemplar] | None = None
    overflow: bool = False


@dataclass(frozen=True, slots=True)
class ActivityGroupSnapshot:
    group_id: int
    trace_id: str
    task_id: str
    owner_entity_id: str
    owner_epoch: int
    parent_ref_type: str
    parent_ref_id: int | str | None
    operation_id: int
    operation: str
    group: str
    calls: int
    in_flight: int
    successes: int
    cancellations: int
    errors: int
    total_duration_ns: int
    min_duration_ns: int
    max_duration_ns: int
    total_queue_ns: int
    total_worker_ns: int
    max_queue_ns: int
    max_worker_ns: int
    last_started_ns: int
    last_finished_ns: int
    latest_failure_class: str | None
    revision: int
    overflow: bool
    exemplars: tuple[dict[str, Any], ...]

    @property
    def total_duration_ms(self) -> float:
        return self.total_duration_ns / 1_000_000

    @property
    def average_duration_ms(self) -> float:
        return self.total_duration_ms / self.calls if self.calls else 0.0

    @property
    def min_duration_ms(self) -> float:
        return max(0, self.min_duration_ns) / 1_000_000

    @property
    def max_duration_ms(self) -> float:
        return self.max_duration_ns / 1_000_000

    @property
    def total_queue_ms(self) -> float:
        return self.total_queue_ns / 1_000_000

    @property
    def total_worker_ms(self) -> float:
        return self.total_worker_ns / 1_000_000

    def to_dict(self) -> dict[str, Any]:
        # Transport allocation is deliberately delayed until a query/drain.
        return {
            "group_id": self.group_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "owner_entity_id": self.owner_entity_id,
            "owner_epoch": self.owner_epoch,
            "parent_ref_type": self.parent_ref_type,
            "parent_ref_id": self.parent_ref_id,
            "operation_id": self.operation_id,
            "operation": self.operation,
            "group": self.group,
            "calls": self.calls,
            "in_flight": self.in_flight,
            "successes": self.successes,
            "cancellations": self.cancellations,
            "errors": self.errors,
            "total_duration_ms": self.total_duration_ms,
            "average_duration_ms": self.average_duration_ms,
            "min_duration_ms": self.min_duration_ms,
            "max_duration_ms": self.max_duration_ms,
            "total_queue_ms": self.total_queue_ms,
            "total_worker_ms": self.total_worker_ms,
            "latest_failure_class": self.latest_failure_class,
            "revision": self.revision,
            "overflow": self.overflow,
            "exemplars": list(self.exemplars),
        }


@dataclass(frozen=True, slots=True)
class DrainedActivityMetric:
    """Lower-rate absolute update offered to an optional external sink."""

    snapshot: ActivityGroupSnapshot


class DrainedMetricSinkAdapter:
    def __init__(self, sink: Any, diagnostics: Counter[str]) -> None:
        self.sink = sink
        self.diagnostics = diagnostics
        self._revisions: dict[int, int] = {}

    def drain(self, snapshots: tuple[ActivityGroupSnapshot, ...]) -> int:
        emitted = 0
        for snapshot in snapshots:
            if snapshot.revision <= self._revisions.get(snapshot.group_id, -1):
                continue
            try:
                callback = getattr(self.sink, "emit_snapshot", None)
                if callback is not None:
                    callback(snapshot)
                else:
                    self.sink.emit(DrainedActivityMetric(snapshot))
                self._revisions[snapshot.group_id] = snapshot.revision
                emitted += 1
            except Exception:
                self.diagnostics["external_metric_sink_failures"] += 1
        return emitted


class WorkerObservationDelta:
    """Submission-local aggregate records; never shared between workers."""

    __slots__ = ("_next_id", "_records", "_by_key", "parent_group_id", "dot")

    def __init__(self, parent_group_id: int | None, dot: ProducerDot | None = None) -> None:
        self._next_id = -1
        self._records: list[ActivityGroupRecord] = []
        self._by_key: dict[tuple[int | str | None, int], ActivityGroupRecord] = {}
        self.parent_group_id = parent_group_id
        self.dot = dot

    def resolve(self, policy: Any, parent_ref_id: int | str | None) -> ActivityGroupRecord:
        key = (parent_ref_id, policy.operation_id)
        record = self._by_key.get(key)
        if record is None:
            record = ActivityGroupRecord(
                self._next_id, "", "", _GROUP, parent_ref_id,
                policy.operation_id, policy.operation, policy.group, 1,
            )
            self._next_id -= 1
            self._by_key[key] = record
            self._records.append(record)
        return record

    @property
    def records(self) -> tuple[ActivityGroupRecord, ...]:
        return tuple(self._records)


class ActivityGroupStore:
    """Compact loop-owned aggregation store for observed repeated activity."""

    def __init__(
        self,
        *,
        max_groups: int = 4096,
        max_overflow_groups: int = 256,
        max_exemplars: int = 256,
        exemplars_per_group: int = 2,
        max_dirty_groups: int | None = None,
        max_producer_components: int = 256,
        runtime_epoch: int | None = None,
        diagnostics: Counter[str] | None = None,
    ) -> None:
        self.max_groups = max(1, max_groups)
        self.max_overflow_groups = max(1, max_overflow_groups)
        self.max_exemplars = max(0, max_exemplars)
        self.exemplars_per_group = max(0, exemplars_per_group)
        self.max_dirty_groups = max(1, max_dirty_groups or max_groups + max_overflow_groups)
        self.max_producer_components = max(1, max_producer_components)
        self.diagnostics = diagnostics if diagnostics is not None else Counter()
        self.runtime_epoch = runtime_epoch
        self._next_group_id = 1
        self._records: dict[int, ActivityGroupRecord] = {}
        self._by_key: dict[
            tuple[str, str, int, int, int | str | None, int], ActivityGroupRecord
        ] = {}
        self._overflow: dict[tuple[str, str, int, str], ActivityGroupRecord] = {}
        self._key_by_group: dict[int, tuple[Any, ...]] = {}
        self._overflow_key_by_group: dict[int, tuple[Any, ...]] = {}
        self._owner_index: dict[tuple[str, int], set[int]] = {}
        self._dirty: set[int] = set()
        self._final_dirty: dict[int, ActivityGroupSnapshot] = {}
        self._removed: dict[int, ActivityGroupTombstone] = {}
        self._removal_checkpoint = 0
        self._worker_dots: dict[tuple[int, int], int] = {}
        self._components: dict[int, dict[tuple[int, int], ActivityProducerComponent]] = {}
        self._owner_thread: int | None = None
        self._exemplar_count = 0
        self._dirty_callback = None

    def set_dirty_callback(self, callback) -> None:
        """Install the loop-local transport wakeup without coupling hot records to it."""
        self._dirty_callback = callback

    def _assert_owner(self) -> None:
        owner = threading.get_ident()
        if self._owner_thread is None:
            self._owner_thread = owner
        elif self._owner_thread != owner:
            self.diagnostics["activity_wrong_thread"] += 1
            raise RuntimeError("ActivityGroupStore may only be mutated by its owning loop thread")

    def resolve(
        self,
        policy: Any,
        *,
        trace_id: str,
        owner_entity_id: str,
        parent_ref_id: int | str | None,
        owner_epoch: int = 1,
    ) -> ActivityGroupRecord:
        self._assert_owner()
        parent_type = _GROUP if isinstance(parent_ref_id, int) else _ROOT
        key = (trace_id, owner_entity_id, owner_epoch, parent_type, parent_ref_id,
               policy.operation_id)
        record = self._by_key.get(key)
        if record is not None:
            return record
        if len(self._by_key) >= self.max_groups:
            return self._resolve_overflow(policy, trace_id, owner_entity_id, owner_epoch)
        record = self._new_record(
            trace_id, owner_entity_id, parent_type, parent_ref_id,
            policy.operation_id, policy.operation, policy.group, False, owner_epoch,
        )
        self._by_key[key] = record
        self._key_by_group[record.group_id] = key
        return record

    def _resolve_overflow(self, policy: Any, trace_id: str, owner_entity_id: str,
                          owner_epoch: int):
        self.diagnostics["group_cardinality_overflow"] += 1
        key = (trace_id, owner_entity_id, owner_epoch, policy.group)
        record = self._overflow.get(key)
        if record is not None:
            return record
        if len(self._overflow) >= self.max_overflow_groups:
            # Keep memory bounded even if owner/component cardinality itself
            # is hostile.  Existing records are never evicted while active;
            # the oldest overflow record becomes the final accounting sink.
            self.diagnostics["overflow_group_cardinality_overflow"] += 1
            return next(iter(self._overflow.values()))
        record = self._new_record(
            trace_id, owner_entity_id, _ROOT, None, _OVERFLOW_OPERATION_ID,
            "__overflow__", policy.group, True, owner_epoch,
        )
        self._overflow[key] = record
        self._overflow_key_by_group[record.group_id] = key
        return record

    def _new_record(
        self, trace_id, owner_entity_id, parent_type, parent_id,
        operation_id, operation, group, overflow, owner_epoch,
    ) -> ActivityGroupRecord:
        group_id = self._next_group_id
        self._next_group_id += 1
        record = ActivityGroupRecord(
            group_id, trace_id, owner_entity_id, parent_type, parent_id,
            operation_id, operation, group, owner_epoch, overflow=overflow,
        )
        self._records[group_id] = record
        self._owner_index.setdefault((owner_entity_id, owner_epoch), set()).add(group_id)
        return record

    def begin(self, record: ActivityGroupRecord, started_ns: int) -> None:
        self._assert_owner()
        record.calls += 1
        record.in_flight += 1
        record.last_started_ns = started_ns
        record.revision += 1
        self._mark_dirty(record.group_id)

    def end(
        self,
        record: ActivityGroupRecord,
        outcome: str,
        duration_ns: int,
        finished_ns: int,
        failure_class: str | None = None,
        slow_ns: int | None = None,
        capture_failures: bool = True,
        queue_ns: int = 0,
        worker_ns: int = 0,
    ) -> None:
        self._assert_owner()
        if record.in_flight <= 0:
            self.diagnostics["activity_unbalanced_finish"] += 1
        else:
            record.in_flight -= 1
        self._add_terminal(
            record, outcome, duration_ns, finished_ns, failure_class,
            slow_ns, capture_failures, queue_ns, worker_ns,
        )

    def _add_terminal(
        self, record, outcome, duration_ns, finished_ns, failure_class,
        slow_ns, capture_failures, queue_ns, worker_ns,
    ) -> None:
        duration_ns = max(0, int(duration_ns))
        record.total_duration_ns += duration_ns
        record.min_duration_ns = (
            duration_ns if record.min_duration_ns < 0 else min(record.min_duration_ns, duration_ns)
        )
        record.max_duration_ns = max(record.max_duration_ns, duration_ns)
        record.total_queue_ns += max(0, int(queue_ns))
        record.total_worker_ns += max(0, int(worker_ns))
        record.max_queue_ns = max(record.max_queue_ns, max(0, int(queue_ns)))
        record.max_worker_ns = max(record.max_worker_ns, max(0, int(worker_ns)))
        record.last_finished_ns = finished_ns
        if outcome == "success":
            record.successes += 1
        elif outcome == "cancelled":
            record.cancellations += 1
        else:
            record.errors += 1
            if failure_class is not None:
                record.latest_failure_class = failure_class[:128]
        record.revision += 1
        self._mark_dirty(record.group_id)
        anomalous = (
            outcome not in ("success", "cancelled") and capture_failures
        ) or (slow_ns is not None and duration_ns >= slow_ns)
        if anomalous:
            self._retain_exemplar(record, outcome, duration_ns, finished_ns, failure_class)

    def merge_worker_delta(
        self,
        delta: WorkerObservationDelta | None,
        *,
        trace_id: str,
        owner_entity_id: str,
        owner_epoch: int = 1,
    ) -> None:
        if delta is None:
            return
        self._assert_owner()
        if delta.dot is not None:
            key = (delta.dot.runtime_epoch, delta.dot.producer_id)
            if delta.dot.producer_seq <= self._worker_dots.get(key, 0):
                self.diagnostics["duplicate_worker_deltas"] += 1
                return
            self._worker_dots[key] = delta.dot.producer_seq
        resolved: dict[int, int] = {}
        for local in delta.records:
            parent = local.parent_ref_id
            if isinstance(parent, int) and parent < 0:
                parent = resolved[parent]
            policy = _DeltaPolicy(local.operation_id, local.operation, local.group)
            target = self.resolve(
                policy, trace_id=trace_id, owner_entity_id=owner_entity_id,
                owner_epoch=owner_epoch,
                parent_ref_id=parent,
            )
            resolved[local.group_id] = target.group_id
            target.calls += local.calls
            target.in_flight += local.in_flight
            target.successes += local.successes
            target.cancellations += local.cancellations
            target.errors += local.errors
            target.total_duration_ns += local.total_duration_ns
            if local.min_duration_ns >= 0:
                target.min_duration_ns = (
                    local.min_duration_ns if target.min_duration_ns < 0
                    else min(target.min_duration_ns, local.min_duration_ns)
                )
            target.max_duration_ns = max(target.max_duration_ns, local.max_duration_ns)
            target.last_started_ns = max(target.last_started_ns, local.last_started_ns)
            target.last_finished_ns = max(target.last_finished_ns, local.last_finished_ns)
            if local.latest_failure_class is not None:
                target.latest_failure_class = local.latest_failure_class[:128]
            target.revision += max(1, local.revision)
            self._mark_dirty(target.group_id)
            if local.exemplars:
                for exemplar in local.exemplars:
                    self._retain_exemplar(
                        target, exemplar.outcome, exemplar.duration_ns,
                        exemplar.finished_ns, exemplar.failure_class,
                    )

    def _retain_exemplar(self, record, outcome, duration_ns, finished_ns, failure_class):
        if self.exemplars_per_group == 0 or self.max_exemplars == 0:
            self.diagnostics["exemplar_overflow"] += 1
            return
        if record.exemplars is None:
            record.exemplars = []
        if len(record.exemplars) >= self.exemplars_per_group:
            record.exemplars.pop(0)
            self._exemplar_count -= 1
        elif self._exemplar_count >= self.max_exemplars:
            self.diagnostics["exemplar_overflow"] += 1
            # Prefer the latest anomaly for a group without exceeding the
            # global bound.  A group that already owns a slot may replace it.
            if record.exemplars:
                record.exemplars.pop(0)
                self._exemplar_count -= 1
            else:
                return
        record.exemplars.append(ActivityExemplar(
            outcome, duration_ns, finished_ns,
            failure_class[:128] if failure_class is not None else None,
        ))
        self._exemplar_count += 1

    def _mark_dirty(self, group_id: int) -> None:
        if group_id in self._dirty:
            return
        if len(self._dirty) >= self.max_dirty_groups:
            self.diagnostics["dirty_group_overflow"] += 1
            return
        self._dirty.add(group_id)
        if self._dirty_callback is not None:
            self._dirty_callback()

    def snapshots(self, trace_id: str | None = None) -> tuple[ActivityGroupSnapshot, ...]:
        return tuple(
            self._snapshot(self._records[group_id]) for group_id in sorted(self._records)
            if trace_id is None or self._records[group_id].trace_id == trace_id
        )

    def drain_dirty(self) -> tuple[ActivityGroupSnapshot, ...]:
        self._assert_owner()
        group_ids = tuple(sorted(self._dirty))
        self._dirty.clear()
        snapshots = [self._snapshot(self._records[group_id]) for group_id in group_ids]
        snapshots.extend(self._final_dirty[key] for key in sorted(self._final_dirty))
        self._final_dirty.clear()
        return tuple(snapshots)

    def remove_owner_epoch(
        self, owner_entity_id: str, owner_epoch: int, *, flush: bool = True
    ) -> tuple[tuple[ActivityGroupSnapshot, ...], tuple[int, ...]]:
        """Flush and remove exactly the groups in one indexed owner epoch."""
        self._assert_owner()
        group_ids = tuple(self._owner_index.pop((owner_entity_id, owner_epoch), ()))
        final = tuple(self._snapshot(self._records[group_id]) for group_id in group_ids) if flush else ()
        if flush:
            for snapshot in final:
                if len(self._final_dirty) >= self.max_dirty_groups:
                    self.diagnostics["final_dirty_group_overflow"] += 1
                    break
                self._final_dirty[snapshot.group_id] = snapshot
        if group_ids:
            self._removal_checkpoint += 1
        for group_id in group_ids:
            record = self._records.pop(group_id)
            self._dirty.discard(group_id)
            key = self._key_by_group.pop(group_id, None)
            if key is not None:
                self._by_key.pop(key, None)
            overflow_key = self._overflow_key_by_group.pop(group_id, None)
            if overflow_key is not None:
                self._overflow.pop(overflow_key, None)
            self._components.pop(group_id, None)
            self._removed[group_id] = ActivityGroupTombstone(
                group_id, owner_entity_id, owner_epoch, self._removal_checkpoint
            )
            if record.exemplars:
                self._exemplar_count -= len(record.exemplars)
        if group_ids and self._dirty_callback is not None:
            self._dirty_callback()
        return final, group_ids

    def removed(self) -> tuple["ActivityGroupTombstone", ...]:
        return tuple(self._removed.values())

    @property
    def removal_checkpoint(self) -> int:
        return self._removal_checkpoint

    def gc_tombstones(self, acknowledged_checkpoint: int) -> int:
        """Drop tombstones covered by a replication checkpoint/acknowledgment."""
        self._assert_owner()
        removed = 0
        for group_id, tombstone in tuple(self._removed.items()):
            if tombstone.checkpoint <= acknowledged_checkpoint:
                del self._removed[group_id]
                removed += 1
        return removed

    def apply_delta(self, delta: "ActivityGroupDelta") -> bool:
        """Merge an immutable absolute producer component idempotently."""
        self._assert_owner()
        if self.runtime_epoch is not None and delta.dot.runtime_epoch != self.runtime_epoch:
            self.diagnostics["activity_epoch_mismatch"] += 1
            return False
        if delta.finishes > delta.starts:
            self.diagnostics["activity_negative_in_flight"] += 1
            return False
        if any(t.owner_entity_id == delta.owner_entity_id
               and t.owner_epoch >= delta.owner_epoch for t in self._removed.values()):
            self.diagnostics["stale_activity_epoch"] += 1
            return False
        policy = _DeltaPolicy(delta.operation_id, delta.operation, delta.group)
        record = self.resolve(policy, trace_id=delta.trace_id,
                              owner_entity_id=delta.owner_entity_id,
                              owner_epoch=delta.owner_epoch,
                              parent_ref_id=delta.parent_ref_id)
        components = self._components.setdefault(record.group_id, {})
        key = (delta.dot.runtime_epoch, delta.dot.producer_id)
        previous = components.get(key)
        if previous is None and len(components) >= self.max_producer_components:
            self.diagnostics["activity_producer_overflow"] += 1
            return False
        incoming = ActivityProducerComponent.from_delta(delta)
        merged = incoming if previous is None else previous.merge(incoming)
        if previous == merged:
            self.diagnostics["duplicate_projection_ops"] += 1
            return False
        components[key] = merged
        self._project_components(record, components)
        record.revision += 1
        self._mark_dirty(record.group_id)
        return True

    @staticmethod
    def _project_components(record: ActivityGroupRecord,
                            components: dict[tuple[int, int], "ActivityProducerComponent"]) -> None:
        values = tuple(components.values())
        record.calls = sum(value.calls for value in values)
        starts = sum(value.starts for value in values)
        finishes = sum(value.finishes for value in values)
        record.in_flight = max(0, starts - finishes)
        record.successes = sum(value.successes for value in values)
        record.cancellations = sum(value.cancellations for value in values)
        record.errors = sum(value.errors for value in values)
        record.total_duration_ns = sum(value.total_duration_ns for value in values)
        minima = [value.min_duration_ns for value in values if value.min_duration_ns >= 0]
        record.min_duration_ns = min(minima) if minima else -1
        record.max_duration_ns = max((value.max_duration_ns for value in values), default=0)
        record.last_started_ns = max((value.last_started_ns for value in values), default=0)
        record.last_finished_ns = max((value.last_finished_ns for value in values), default=0)
        latest = max((value for value in values if value.latest_failure_class is not None),
                     key=lambda value: value.dot, default=None)
        record.latest_failure_class = latest.latest_failure_class if latest else None

    def _snapshot(self, record: ActivityGroupRecord) -> ActivityGroupSnapshot:
        ref_names = ("machine", "control", "group", "root")
        exemplars = tuple(
            {
                "outcome": item.outcome,
                "duration_ms": item.duration_ns / 1_000_000,
                "finished_ns": item.finished_ns,
                "failure_class": item.failure_class,
            }
            for item in (record.exemplars or ())
        )
        return ActivityGroupSnapshot(
            record.group_id, record.trace_id, record.owner_entity_id,
            record.owner_entity_id, record.owner_epoch,
            ref_names[record.parent_ref_type], record.parent_ref_id,
            record.operation_id, record.operation, record.group, record.calls,
            record.in_flight, record.successes, record.cancellations, record.errors,
            record.total_duration_ns, record.min_duration_ns, record.max_duration_ns,
            record.total_queue_ns, record.total_worker_ns, record.max_queue_ns,
            record.max_worker_ns, record.last_started_ns, record.last_finished_ns,
            record.latest_failure_class, record.revision, record.overflow, exemplars,
        )

    def __len__(self) -> int:
        return len(self._records)


@dataclass(frozen=True, slots=True)
class _DeltaPolicy:
    operation_id: int
    operation: str
    group: str


@dataclass(frozen=True, slots=True)
class ActivityGroupTombstone:
    group_id: int
    owner_entity_id: str
    owner_epoch: int
    checkpoint: int


@dataclass(frozen=True, slots=True)
class ActivityGroupDelta:
    """Absolute values for one producer component of an activity group."""

    trace_id: str
    owner_entity_id: str
    owner_epoch: int
    parent_ref_id: int | str | None
    operation_id: int
    operation: str
    group: str
    dot: ProducerDot
    calls: int
    starts: int
    finishes: int
    successes: int
    cancellations: int
    errors: int
    total_duration_ns: int
    min_duration_ns: int = -1
    max_duration_ns: int = 0
    last_started_ns: int = 0
    last_finished_ns: int = 0
    latest_failure_class: str | None = None


@dataclass(frozen=True, slots=True)
class ActivityProducerComponent:
    dot: ProducerDot
    calls: int
    starts: int
    finishes: int
    successes: int
    cancellations: int
    errors: int
    total_duration_ns: int
    min_duration_ns: int
    max_duration_ns: int
    last_started_ns: int
    last_finished_ns: int
    latest_failure_class: str | None

    @classmethod
    def from_delta(cls, delta: ActivityGroupDelta) -> "ActivityProducerComponent":
        return cls(
            delta.dot, max(0, delta.calls), max(0, delta.starts),
            max(0, delta.finishes), max(0, delta.successes),
            max(0, delta.cancellations), max(0, delta.errors),
            max(0, delta.total_duration_ns), delta.min_duration_ns,
            max(0, delta.max_duration_ns), max(0, delta.last_started_ns),
            max(0, delta.last_finished_ns),
            delta.latest_failure_class[:128] if delta.latest_failure_class else None,
        )

    def merge(self, other: "ActivityProducerComponent") -> "ActivityProducerComponent":
        minima = [value for value in (self.min_duration_ns, other.min_duration_ns)
                  if value >= 0]
        if other.latest_failure_class is None:
            failure = self.latest_failure_class
        elif self.latest_failure_class is None or other.dot >= self.dot:
            failure = other.latest_failure_class
        else:
            failure = self.latest_failure_class
        return ActivityProducerComponent(
            max(self.dot, other.dot), max(self.calls, other.calls),
            max(self.starts, other.starts), max(self.finishes, other.finishes),
            max(self.successes, other.successes),
            max(self.cancellations, other.cancellations), max(self.errors, other.errors),
            max(self.total_duration_ns, other.total_duration_ns),
            min(minima) if minima else -1,
            max(self.max_duration_ns, other.max_duration_ns),
            max(self.last_started_ns, other.last_started_ns),
            max(self.last_finished_ns, other.last_finished_ns),
            failure,
        )


def begin_local(record: ActivityGroupRecord, started_ns: int) -> None:
    record.calls += 1
    record.in_flight += 1
    record.last_started_ns = started_ns
    record.revision += 1


def end_local(
    record: ActivityGroupRecord,
    outcome: str,
    duration_ns: int,
    finished_ns: int,
    failure_class: str | None,
    slow_ns: int | None,
    capture_failures: bool,
) -> None:
    record.in_flight -= 1
    record.total_duration_ns += duration_ns
    record.min_duration_ns = (
        duration_ns if record.min_duration_ns < 0 else min(record.min_duration_ns, duration_ns)
    )
    record.max_duration_ns = max(record.max_duration_ns, duration_ns)
    record.last_finished_ns = finished_ns
    if outcome == "success":
        record.successes += 1
    elif outcome == "cancelled":
        record.cancellations += 1
    else:
        record.errors += 1
        record.latest_failure_class = failure_class[:128] if failure_class else None
    record.revision += 1
    if ((outcome not in ("success", "cancelled") and capture_failures)
            or (slow_ns is not None and duration_ns >= slow_ns)):
        if record.exemplars is None:
            record.exemplars = []
        # The loop-owned store applies the global bound during merge.  The
        # submission-local bound prevents a pathological worker from growing.
        if len(record.exemplars) >= 2:
            record.exemplars.pop(0)
        record.exemplars.append(ActivityExemplar(
            outcome, duration_ns, finished_ns,
            failure_class[:128] if failure_class else None,
        ))
