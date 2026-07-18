"""Loop-owned, convergent projection stores for live observability.

The records in this module are deliberately independent from protocol state.
They consume immutable operations and are never fed back into ICE/DTLS/media
behaviour.  Every mutating method enforces a single owning thread; producer
dots make retrying or reordering immutable operations harmless.
"""

from __future__ import annotations

import threading
import math
from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .state_machine import MachineSpec

_REJECTED = object()
_FACET_PROVENANCE_KEYS = frozenset({
    "observer_meta", "source_entity_id", "source_epoch", "source_revision",
    "source_order", "observerMeta", "source_machine_entity_id",
    "source_machine_epoch", "source_machine_revision",
})
MAX_TRANSITION_JOURNAL_LIMIT = 4096


@dataclass(frozen=True, order=True, slots=True)
class ProducerDot:
    runtime_epoch: int
    producer_id: int
    producer_seq: int


class ProducerClock:
    """A producer-local sequence allocator; it needs no shared atomic."""

    __slots__ = ("runtime_epoch", "producer_id", "_sequence")

    def __init__(self, runtime_epoch: int, producer_id: int) -> None:
        self.runtime_epoch = runtime_epoch
        self.producer_id = producer_id
        self._sequence = 0

    def next(self) -> ProducerDot:
        self._sequence += 1
        return ProducerDot(self.runtime_epoch, self.producer_id, self._sequence)


class _LoopOwned:
    def __init__(self, diagnostics: Counter[str], diagnostic: str) -> None:
        self._owner_thread: int | None = None
        self._diagnostics = diagnostics
        self._wrong_thread_diagnostic = diagnostic
        self._dirty_callback = None

    def set_dirty_callback(self, callback) -> None:
        self._dirty_callback = callback

    def _changed(self) -> None:
        if self._dirty_callback is not None:
            self._dirty_callback()

    def _assert_owner(self) -> None:
        current = threading.get_ident()
        if self._owner_thread is None:
            self._owner_thread = current
        elif self._owner_thread != current:
            self._diagnostics[self._wrong_thread_diagnostic] += 1
            raise RuntimeError("observability projection may only be mutated by its owning loop")


@dataclass(frozen=True, slots=True)
class MachineTransitionOp:
    entity_id: str
    machine_type: str
    from_state: str
    to_state: str
    machine_epoch: int
    revision: int
    dot: ProducerDot
    cause_id: int | str | None = None
    monotonic_ns: int = 0


@dataclass(frozen=True, slots=True)
class MachineSnapshot:
    entity_id: str
    machine_type: str
    state: str
    machine_epoch: int
    revision: int
    cause_id: int | str | None
    monotonic_ns: int


@dataclass(frozen=True, slots=True)
class MachineTransitionRecord:
    """One committed machine edge in the runtime-wide observed order."""

    order: int
    entity_id: str
    machine_type: str
    from_state: str
    to_state: str
    machine_epoch: int
    revision: int
    cause_id: int | str | None
    monotonic_ns: int


@dataclass(slots=True)
class _MachineRecord:
    spec: MachineSpec
    state: str
    epoch: int
    revision: int = 0
    dot: ProducerDot | None = None
    cause_id: int | str | None = None
    monotonic_ns: int = 0


class MachineStore(_LoopOwned):
    def __init__(self, *, runtime_epoch: int | None = None,
                 diagnostics: Counter[str] | None = None,
                 seen_limit: int = 4096, pending_limit: int = 256,
                 transition_limit: int = 512) -> None:
        diagnostics = diagnostics if diagnostics is not None else Counter()
        super().__init__(diagnostics, "machine_wrong_thread")
        self.diagnostics = diagnostics
        self.runtime_epoch = runtime_epoch
        self.seen_limit = max(1, seen_limit)
        self.pending_limit = max(1, pending_limit)
        self.transition_limit = min(
            max(1, transition_limit), MAX_TRANSITION_JOURNAL_LIMIT
        )
        self._records: dict[str, _MachineRecord] = {}
        self._seen: set[ProducerDot] = set()
        self._seen_order: deque[ProducerDot] = deque()
        self._pending: dict[str, dict[int, MachineTransitionOp]] = defaultdict(dict)
        self._removed_owner_epochs: OrderedDict[str, int] = OrderedDict()
        self._invalid_exemplar: MachineTransitionOp | None = None
        self._transitions: deque[MachineTransitionRecord] = deque(
            maxlen=self.transition_limit
        )
        self._transition_order = 0

    def register(self, entity_id: str, spec: MachineSpec, *, epoch: int = 1) -> MachineSnapshot:
        self._assert_owner()
        removed_epoch = self._removed_owner_epochs.get(entity_id, -1)
        if epoch <= removed_epoch:
            self.diagnostics["stale_machine_epoch"] += 1
            raise ValueError(
                f"machine {entity_id}@{epoch} was already observed-removed"
            )
        existing = self._records.get(entity_id)
        if existing is None or epoch > existing.epoch:
            existing = _MachineRecord(spec, spec.initial, epoch)
            self._records[entity_id] = existing
            self._changed()
        return self._snapshot(entity_id, existing)

    def apply(self, op: MachineTransitionOp, spec: MachineSpec | None = None) -> bool:
        self._assert_owner()
        if self.runtime_epoch is not None and op.dot.runtime_epoch != self.runtime_epoch:
            self.diagnostics["machine_epoch_mismatch"] += 1
            return False
        if op.dot in self._seen:
            self.diagnostics["duplicate_projection_ops"] += 1
            return False
        if op.machine_epoch <= self._removed_owner_epochs.get(op.entity_id, -1):
            self._remember(op.dot)
            self.diagnostics["stale_machine_epoch"] += 1
            return False
        record = self._records.get(op.entity_id)
        if record is None:
            if spec is None:
                self.diagnostics["unknown_machine"] += 1
                return False
            record = _MachineRecord(spec, spec.initial, op.machine_epoch)
            self._records[op.entity_id] = record
        if op.machine_type != record.spec.machine_type:
            self.diagnostics["invalid_transitions"] += 1
            self._invalid_exemplar = op
            return False
        if op.machine_epoch < record.epoch:
            self._remember(op.dot)
            self.diagnostics["stale_machine_epoch"] += 1
            return False
        if op.machine_epoch > record.epoch:
            record.state = record.spec.initial
            record.epoch = op.machine_epoch
            record.revision = 0
            record.dot = None
            self._pending.pop(op.entity_id, None)
        # Revision is authoritative for the state register.  A future revision
        # cannot be committed until its declared source state is current.
        if op.revision <= record.revision:
            self._remember(op.dot)
            self.diagnostics["stale_machine_revision"] += 1
            return False
        if op.revision > record.revision + 1:
            pending = self._pending[op.entity_id]
            previous = pending.get(op.revision)
            if previous is None and len(pending) >= self.pending_limit:
                self.diagnostics["machine_pending_overflow"] += 1
                self._remember(op.dot)
                return False
            if previous is None or op.dot > previous.dot:
                pending[op.revision] = op
            self._remember(op.dot)
            self.diagnostics["reordered_machine_ops"] += 1
            return False
        if op.from_state != record.state:
            self.diagnostics["invalid_transitions"] += 1
            self._invalid_exemplar = op
            return False
        try:
            record.spec.validate(record.state, op.to_state)
        except ValueError:
            self.diagnostics["invalid_transitions"] += 1
            self._invalid_exemplar = op
            return False
        self._commit(record, op)
        self._remember(op.dot)
        while True:
            pending = self._pending.get(op.entity_id, {}).pop(record.revision + 1, None)
            if pending is None:
                break
            if pending.from_state != record.state:
                self.diagnostics["invalid_transitions"] += 1
                self._invalid_exemplar = pending
                continue
            try:
                record.spec.validate(record.state, pending.to_state)
            except ValueError:
                self.diagnostics["invalid_transitions"] += 1
                self._invalid_exemplar = pending
                continue
            self._commit(record, pending)
        self._changed()
        return True

    def remove_owner(self, entity_id: str, epoch: int) -> bool:
        """Observed-remove one machine epoch and retain a bounded tombstone."""
        self._assert_owner()
        record = self._records.get(entity_id)
        removed = record is not None and record.epoch == epoch
        if removed:
            self._records.pop(entity_id, None)
        self._pending.pop(entity_id, None)
        previous = self._removed_owner_epochs.pop(entity_id, -1)
        self._removed_owner_epochs[entity_id] = max(previous, epoch)
        while len(self._removed_owner_epochs) > self.seen_limit:
            self._removed_owner_epochs.popitem(last=False)
        if removed:
            self._changed()
        return removed

    def _remember(self, dot: ProducerDot) -> None:
        if dot in self._seen:
            return
        self._seen.add(dot)
        self._seen_order.append(dot)
        while len(self._seen_order) > self.seen_limit:
            self._seen.discard(self._seen_order.popleft())

    def _commit(self, record: _MachineRecord, op: MachineTransitionOp) -> None:
        record.state = op.to_state
        record.revision = op.revision
        record.dot = op.dot
        record.cause_id = op.cause_id
        record.monotonic_ns = op.monotonic_ns
        self._transition_order += 1
        self._transitions.append(MachineTransitionRecord(
            self._transition_order, op.entity_id, op.machine_type,
            op.from_state, op.to_state, op.machine_epoch, op.revision,
            op.cause_id, op.monotonic_ns,
        ))

    @property
    def invalid_exemplar(self) -> MachineTransitionOp | None:
        return self._invalid_exemplar

    def get(self, entity_id: str) -> MachineSnapshot | None:
        record = self._records.get(entity_id)
        return None if record is None else self._snapshot(entity_id, record)

    def snapshots(self) -> tuple[MachineSnapshot, ...]:
        return tuple(self._snapshot(key, value) for key, value in self._records.items())

    @property
    def transition_order(self) -> int:
        return self._transition_order

    def transition_snapshots(self) -> tuple[MachineTransitionRecord, ...]:
        return tuple(self._transitions)

    def transitions_after(
        self, order: int
    ) -> tuple[tuple[MachineTransitionRecord, ...], bool]:
        """Return retained edges after ``order`` and whether the cursor wrapped."""
        if not self._transitions:
            return (), False
        first = self._transitions[0].order
        reset = order < first - 1
        return tuple(item for item in self._transitions if item.order > order), reset

    @staticmethod
    def _snapshot(entity_id: str, record: _MachineRecord) -> MachineSnapshot:
        return MachineSnapshot(entity_id, record.spec.machine_type, record.state,
                               record.epoch, record.revision, record.cause_id,
                               record.monotonic_ns)


@dataclass(frozen=True, slots=True)
class FacetOp:
    facet_id: str
    owner_entity_id: str
    owner_epoch: int
    value: str | int | float | bool | None
    revision: int
    dot: ProducerDot
    observer_meta: str
    source_entity_id: str
    source_epoch: int
    source_revision: int
    source_order: int


@dataclass(frozen=True, slots=True)
class FacetSnapshot:
    facet_id: str
    owner_entity_id: str
    owner_epoch: int
    value: str | int | float | bool | None
    revision: int
    observer_meta: str
    source_entity_id: str
    source_epoch: int
    source_revision: int
    source_order: int


class FacetStore(_LoopOwned):
    def __init__(self, *, runtime_epoch: int | None = None,
                 diagnostics: Counter[str] | None = None, limit: int = 1024,
                 max_string_length: int = 128) -> None:
        diagnostics = diagnostics if diagnostics is not None else Counter()
        super().__init__(diagnostics, "facet_wrong_thread")
        self.diagnostics = diagnostics
        self.runtime_epoch = runtime_epoch
        self.limit = max(1, limit)
        self.max_string_length = max(1, max_string_length)
        self._records: dict[str, tuple[FacetOp, FacetSnapshot]] = {}
        self._owner_index: dict[tuple[str, int], set[str]] = defaultdict(set)
        self._removed_owner_epochs: OrderedDict[str, int] = OrderedDict()

    def apply(self, op: FacetOp) -> bool:
        self._assert_owner()
        if op.owner_epoch <= self._removed_owner_epochs.get(op.owner_entity_id, -1):
            self.diagnostics["stale_facet_owner_epoch"] += 1
            return False
        if op.observer_meta not in {"exact", "coalesced", "aggregate"}:
            self.diagnostics["invalid_facet_observer_meta"] += 1
            return False
        if not isinstance(op.source_order, int) or op.source_order < 1:
            self.diagnostics["invalid_facet_source_order"] += 1
            return False
        if (
            not isinstance(op.source_entity_id, str) or not op.source_entity_id
            or not isinstance(op.source_epoch, int) or op.source_epoch < 1
            or not isinstance(op.source_revision, int) or op.source_revision < 0
        ):
            self.diagnostics["invalid_facet_source"] += 1
            return False
        if op.observer_meta == "exact" and op.source_revision < 0:
            self.diagnostics["invalid_exact_facet_source"] += 1
            return False
        if self.runtime_epoch is not None and op.dot.runtime_epoch != self.runtime_epoch:
            self.diagnostics["facet_epoch_mismatch"] += 1
            return False
        value = self._bounded_value(op.facet_id, op.value)
        if value is _REJECTED:
            return False
        if op.facet_id not in self._records and len(self._records) >= self.limit:
            self.diagnostics["facet_cardinality_overflow"] += 1
            return False
        if value != op.value:
            op = FacetOp(op.facet_id, op.owner_entity_id, op.owner_epoch,
                         value, op.revision, op.dot, op.observer_meta,
                         op.source_entity_id, op.source_epoch,
                         op.source_revision, op.source_order)
        previous = self._records.get(op.facet_id)
        if previous is not None:
            prior_op, prior = previous
            if op.owner_epoch < prior.owner_epoch or (
                op.owner_epoch == prior.owner_epoch
                and (op.revision < prior.revision
                     or (op.revision == prior.revision and op.dot <= prior_op.dot))
            ):
                self.diagnostics["stale_facet_ops"] += 1
                return False
            if (op.owner_epoch, op.revision, op.dot) == (
                prior.owner_epoch, prior.revision, prior_op.dot
            ):
                self.diagnostics["duplicate_projection_ops"] += 1
                return False
            self._owner_index[(prior.owner_entity_id, prior.owner_epoch)].discard(op.facet_id)
        snapshot = FacetSnapshot(
            op.facet_id, op.owner_entity_id, op.owner_epoch, op.value, op.revision,
            op.observer_meta, op.source_entity_id, op.source_epoch,
            op.source_revision, op.source_order,
        )
        self._records[op.facet_id] = (op, snapshot)
        self._owner_index[(op.owner_entity_id, op.owner_epoch)].add(op.facet_id)
        self._changed()
        return True

    def _bounded_value(self, facet_id: str, value):
        key = facet_id.rsplit(":", 1)[-1].lower()
        # Readiness is a boolean state, not key material.  The previous broad
        # substring check silently dropped the `srtp_keys_ready` facet and
        # reported a false redaction on every successful DTLS handshake.
        safe_key_state = key.endswith("keys_ready") and isinstance(value, bool)
        if not safe_key_state and any(word in key for word in (
            "payload", "sdp", "key", "certificate", "password", "secret",
            "address", "exception", "traceback",
        )):
            self.diagnostics["facet_redactions"] += 1
            return _REJECTED
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            bounded = max(-(2 ** 53), min(2 ** 53, value))
            if bounded != value:
                self.diagnostics["facet_value_truncations"] += 1
            return bounded
        if isinstance(value, float):
            if not math.isfinite(value):
                self.diagnostics["facet_redactions"] += 1
                return _REJECTED
            return value
        if isinstance(value, str):
            if len(value) > self.max_string_length:
                self.diagnostics["facet_value_truncations"] += 1
                return value[:self.max_string_length]
            return value
        self.diagnostics["facet_redactions"] += 1
        return _REJECTED

    def remove_owner(self, owner_entity_id: str, owner_epoch: int) -> tuple[str, ...]:
        self._assert_owner()
        ids = tuple(self._owner_index.pop((owner_entity_id, owner_epoch), ()))
        for facet_id in ids:
            self._records.pop(facet_id, None)
        self._remember_removed_owner(owner_entity_id, owner_epoch)
        if ids:
            self._changed()
        return ids

    def _remember_removed_owner(self, owner_entity_id: str, owner_epoch: int) -> None:
        previous = self._removed_owner_epochs.pop(owner_entity_id, -1)
        self._removed_owner_epochs[owner_entity_id] = max(previous, owner_epoch)
        while len(self._removed_owner_epochs) > self.limit:
            self._removed_owner_epochs.popitem(last=False)

    def snapshots(self) -> tuple[FacetSnapshot, ...]:
        return tuple(value[1] for value in self._records.values())


@dataclass(frozen=True, slots=True)
class ControlHandle:
    handle_id: str
    trace_id: str
    owner_entity_id: str
    owner_epoch: int
    name: str
    cancelable: bool
    runtime_task_id: str | None = None


class ControlHandleStore(_LoopOwned):
    """Small explicit mapping; it intentionally does not mirror TaskRegistry."""

    def __init__(self, *, limit: int = 256,
                 diagnostics: Counter[str] | None = None) -> None:
        diagnostics = diagnostics if diagnostics is not None else Counter()
        super().__init__(diagnostics, "control_wrong_thread")
        self.diagnostics = diagnostics
        self.limit = max(1, limit)
        self._records: dict[str, ControlHandle] = {}
        self._owner_index: dict[tuple[str, int], set[str]] = defaultdict(set)
        self._removed_owner_epochs: OrderedDict[str, int] = OrderedDict()

    def expose(self, handle: ControlHandle) -> bool:
        self._assert_owner()
        if handle.owner_epoch <= self._removed_owner_epochs.get(handle.owner_entity_id, -1):
            self.diagnostics["stale_control_owner_epoch"] += 1
            return False
        if handle.handle_id not in self._records and len(self._records) >= self.limit:
            self.diagnostics["control_handle_limit_rejections"] += 1
            return False
        old = self._records.get(handle.handle_id)
        if old is not None:
            self._owner_index[(old.owner_entity_id, old.owner_epoch)].discard(handle.handle_id)
        self._records[handle.handle_id] = handle
        self._owner_index[(handle.owner_entity_id, handle.owner_epoch)].add(handle.handle_id)
        self._changed()
        return True

    def remove(self, handle_id: str) -> ControlHandle | None:
        self._assert_owner()
        value = self._records.pop(handle_id, None)
        if value is not None:
            self._owner_index[(value.owner_entity_id, value.owner_epoch)].discard(handle_id)
            self._changed()
        return value

    def remove_owner(self, owner_entity_id: str, owner_epoch: int) -> tuple[str, ...]:
        self._assert_owner()
        ids = tuple(self._owner_index.pop((owner_entity_id, owner_epoch), ()))
        for handle_id in ids:
            self._records.pop(handle_id, None)
        previous = self._removed_owner_epochs.pop(owner_entity_id, -1)
        self._removed_owner_epochs[owner_entity_id] = max(previous, owner_epoch)
        while len(self._removed_owner_epochs) > self.limit:
            self._removed_owner_epochs.popitem(last=False)
        if ids:
            self._changed()
        return ids

    def get(self, handle_id: str) -> ControlHandle | None:
        return self._records.get(handle_id)

    def snapshots(self) -> tuple[ControlHandle, ...]:
        return tuple(self._records.values())


class ObservabilityService:
    """One runtime's single-writer projection and direct cleanup indexes."""

    def __init__(self, *, runtime_epoch: int, trace_id: str = "", scope_id: str | None = None,
                 diagnostics: Counter[str] | None = None, activity_groups: Any = None,
                 transition_limit: int = 512) -> None:
        self.runtime_epoch = runtime_epoch
        self.trace_id = trace_id
        self.scope_id = scope_id
        self.diagnostics = diagnostics if diagnostics is not None else Counter()
        self.machines = MachineStore(
            runtime_epoch=runtime_epoch, diagnostics=self.diagnostics,
            transition_limit=transition_limit,
        )
        self.facets = FacetStore(runtime_epoch=runtime_epoch, diagnostics=self.diagnostics)
        self.controls = ControlHandleStore(diagnostics=self.diagnostics)
        self.activity_groups = activity_groups
        self._facet_revisions: dict[str, int] = defaultdict(int)
        self._facet_source_order = 0
        self._pending_facets: dict[
            str, list[tuple[ProducerDot, dict[str, Any], str, str, int, int, int]]
        ] = defaultdict(list)

    def new_facet_source_order(self) -> int:
        """Allocate an order only when a producer explicitly requests one."""
        self._facet_source_order += 1
        return self._facet_source_order

    def transition(self, operation: MachineTransitionOp) -> None:
        self.machines.apply(operation)
        machine = self.machines.get(operation.entity_id)
        if machine is None:
            return
        pending = self._pending_facets.get(operation.entity_id, [])
        self._pending_facets[operation.entity_id] = []
        for dot, values, meta, source_entity, source_epoch, source_revision, source_order in pending:
            if source_revision > machine.revision:
                self._pending_facets[operation.entity_id].append(
                    (dot, values, meta, source_entity, source_epoch,
                     source_revision, source_order)
                )
            else:
                self.merge_values(
                    operation.entity_id, dot, values,
                    observer_meta=meta, source_entity_id=source_entity,
                    source_epoch=source_epoch, source_revision=source_revision,
                    source_order=source_order,
                )
        if not self._pending_facets[operation.entity_id]:
            self._pending_facets.pop(operation.entity_id, None)

    def merge_values(
        self, entity_id: str, dot: ProducerDot, values, *,
        observer_meta: str, source_entity_id: str, source_epoch: int,
        source_revision: int, source_order: int,
    ) -> None:
        """Merge a bounded value set as independently revisioned scalar facets."""
        machine = self.machines.get(entity_id)
        if observer_meta not in {"exact", "coalesced", "aggregate"}:
            self.diagnostics["invalid_facet_observer_meta"] += 1
            return
        if (
            not isinstance(source_entity_id, str) or not source_entity_id
            or not isinstance(source_epoch, int) or source_epoch < 1
            or not isinstance(source_revision, int) or source_revision < 0
            or not isinstance(source_order, int) or source_order < 1
        ):
            self.diagnostics["invalid_facet_source"] += 1
            return
        if observer_meta == "exact" and source_entity_id != entity_id:
            self.diagnostics["facet_source_entity_mismatch"] += 1
            return
        if observer_meta == "exact" and machine is None:
            self.diagnostics["facet_source_revision_mismatch"] += 1
            return
        if machine is not None and source_entity_id == entity_id:
            if source_epoch != machine.machine_epoch:
                self.diagnostics["facet_source_epoch_mismatch"] += 1
                return
            if source_revision > machine.revision:
                pending = self._pending_facets[entity_id]
                if len(pending) >= 64:
                    pending.pop(0)
                    self.diagnostics["facet_pending_overflow"] += 1
                pending.append((
                    dot, dict(values), observer_meta, source_entity_id,
                    source_epoch, source_revision, source_order,
                ))
                self.diagnostics["facet_future_gap_withheld"] += 1
                return
            if observer_meta == "exact" and source_revision < machine.revision:
                self.diagnostics["facet_stale_source_revision"] += 1
                return
        owner_epoch = machine.machine_epoch if machine is not None else 1
        for name, value in values.items():
            if name in _FACET_PROVENANCE_KEYS:
                self.diagnostics["facet_provenance_value_rejections"] += 1
                continue
            facet_id = f"{entity_id}:{name}"
            self._facet_revisions[facet_id] += 1
            self.facets.apply(FacetOp(
                facet_id, entity_id, owner_epoch, value,
                self._facet_revisions[facet_id], dot,
                observer_meta, source_entity_id, source_epoch,
                source_revision, source_order,
            ))

    def remove(self, entity_id: str, epoch: int, dot: ProducerDot) -> None:
        del dot
        self.facets.remove_owner(entity_id, epoch)

    def bind_trace(self, trace_id: str) -> None:
        self.trace_id = trace_id

    def set_dirty_callback(self, callback) -> None:
        self.machines.set_dirty_callback(callback)
        self.facets.set_dirty_callback(callback)
        self.controls.set_dirty_callback(callback)

    def terminate_entity_epoch(
        self, entity_id: str, epoch: int, *, preserve_activity: bool = False
    ):
        """Snapshot dirty final groups, then remove only directly indexed state."""
        final_groups = ()
        removed_groups = ()
        if self.activity_groups is not None and not preserve_activity:
            final_groups, removed_groups = self.activity_groups.remove_owner_epoch(
                entity_id, epoch, flush=True
            )
        removed_facets = self.facets.remove_owner(entity_id, epoch)
        removed_controls = self.controls.remove_owner(entity_id, epoch)
        removed_machine = self.machines.remove_owner(entity_id, epoch)
        self._pending_facets.pop(entity_id, None)
        return final_groups, removed_groups, removed_facets, removed_controls, removed_machine
