from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Any
import json
import weakref


@dataclass(eq=False)
class TraceSubscriber:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop
    peer_id: str | None = None
    pending_events: list[dict[str, Any]] = field(default_factory=list)
    flush_handle: asyncio.TimerHandle | None = None


class TraceEventBus:
    def __init__(self, *, batch_interval: float = 1.0, max_pending_events: int = 2048) -> None:
        self._lock = RLock()
        self._subscribers: set[TraceSubscriber] = weakref.WeakSet()
        self._sequence = 0
        self._batch_interval = batch_interval
        self._max_pending_events = max_pending_events

    def publish(self, event_name: str, data: dict[str, Any]) -> None:
        event = {"event": event_name, "data": {"sequence": 0, **data}}
        with self._lock:
            self._sequence += 1
            event["data"]["sequence"] = self._sequence
            subs = list(self._subscribers)
        for sub in subs:
            self._deliver(sub, event)

    def subscribe(
        self,
        *,
        maxsize: int = 1024,
        peer_id: str | None = None,
    ) -> TraceSubscriber:
        loop = asyncio.get_running_loop()
        sub = TraceSubscriber(asyncio.Queue(maxsize=maxsize), loop, peer_id=peer_id)
        with self._lock:
            self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: TraceSubscriber) -> None:
        with self._lock:
            self._subscribers.discard(sub)
            handle = sub.flush_handle
            sub.flush_handle = None
            sub.pending_events.clear()
        if handle is not None:
            handle.cancel()

    def close(self) -> None:
        """Detach subscribers and cancel all owned batching timers."""
        with self._lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            self.unsubscribe(subscriber)

    def batch_event(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return {"event": "trace:batch", "data": {"events": events}}

    def _deliver(self, sub: TraceSubscriber, event: dict[str, Any]) -> None:
        if sub.peer_id is not None and self._event_peer_id(event) != sub.peer_id:
            return

        def offer() -> None:
            self._append_pending(sub, event)
            if sub.flush_handle is None:
                sub.flush_handle = sub.loop.call_later(self._batch_interval, self._flush, sub)

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is sub.loop:
            offer()
        elif not sub.loop.is_closed():
            sub.loop.call_soon_threadsafe(offer)

    def _flush(self, sub: TraceSubscriber) -> None:
        events = self._coalesce(sub.pending_events)
        sub.pending_events = []
        sub.flush_handle = None
        if not events:
            return
        self._offer(sub.queue, self.batch_event(events))

    def _append_pending(self, sub: TraceSubscriber, event: dict[str, Any]) -> None:
        sub.pending_events.append(event)
        self._trim_pending_events(sub)

    def _trim_pending_events(self, sub: TraceSubscriber) -> None:
        overflow = len(sub.pending_events) - self._max_pending_events
        if overflow <= 0:
            return

        del sub.pending_events[:overflow]
    @classmethod
    def _coalesce(cls, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Coalesce updates without crossing task lifecycle boundaries."""
        output: list[dict[str, Any]] = []
        segment: list[dict[str, Any]] = []

        def flush_segment() -> None:
            if not segment:
                return
            output.extend(cls._coalesce_segment(segment))
            segment.clear()

        for event in events:
            if event.get("event") in {"trace:init", "trace:complete", "trace:delete"}:
                flush_segment()
                if output and cls._event_signature(output[-1]) == cls._event_signature(event):
                    cls._retain_highest_sequence(output[-1], event)
                else:
                    output.append(event)
            else:
                segment.append(event)
        flush_segment()
        return output

    @classmethod
    def _coalesce_segment(cls, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        update_position: int | None = None
        update_tasks: dict[str, dict[str, Any]] = {}
        update_data: dict[str, Any] = {}

        for event in events:
            if event.get("event") != "trace:update":
                cls._append_distinct(output, event)
                continue
            data = event.get("data")
            if not isinstance(data, dict):
                cls._append_distinct(output, event)
                continue
            if update_position is None:
                update_position = len(output)
                output.append({"event": "trace:update", "data": {}})
            sequence = data.get("sequence")
            previous_sequence = update_data.get("sequence")
            if isinstance(sequence, int) and (
                not isinstance(previous_sequence, int) or sequence > previous_sequence
            ):
                update_data["sequence"] = sequence
            for key, value in data.items():
                if key not in {"tasks", "sequence", "groups"}:
                    update_data[key] = value
            if "groups" in data:
                update_data["groups"] = data["groups"]
            tasks = data.get("tasks")
            if isinstance(tasks, list):
                for task in tasks:
                    task_id = task.get("task_id") if isinstance(task, dict) else None
                    if isinstance(task_id, str):
                        update_tasks[task_id] = task

        if update_position is not None:
            output[update_position] = {
                "event": "trace:update",
                "data": {**update_data, "tasks": list(update_tasks.values())},
            }
        return output

    @staticmethod
    def _append_distinct(output: list[dict[str, Any]], event: dict[str, Any]) -> None:
        signature = TraceEventBus._event_signature(event)
        for existing in reversed(output):
            if existing.get("event") in {"trace:init", "trace:complete", "trace:delete"}:
                break
            if TraceEventBus._event_signature(existing) == signature:
                TraceEventBus._retain_highest_sequence(existing, event)
                return
        output.append(event)

    @staticmethod
    def _event_signature(event: dict[str, Any]) -> str:
        data = event.get("data")
        normalized = {key: value for key, value in data.items() if key != "sequence"} if isinstance(data, dict) else data
        return json.dumps({"event": event.get("event"), "data": normalized}, sort_keys=True, default=str)

    @staticmethod
    def _retain_highest_sequence(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
        existing_data = existing.get("data")
        incoming_data = incoming.get("data")
        if not isinstance(existing_data, dict) or not isinstance(incoming_data, dict):
            return
        current = existing_data.get("sequence")
        candidate = incoming_data.get("sequence")
        if isinstance(candidate, int) and (not isinstance(current, int) or candidate > current):
            existing_data["sequence"] = candidate

    @staticmethod
    def _event_peer_id(event: dict[str, Any]) -> str | None:
        data = event.get("data")
        if not isinstance(data, dict):
            return None

        peer_id = data.get("peer_id")
        if isinstance(peer_id, str):
            return peer_id

        if event.get("event") not in {"trace:init", "trace:update", "trace:complete"}:
            return None

        for trace in TraceEventBus._event_traces(event):
            metadata = trace.get("metadata")
            if isinstance(metadata, dict):
                trace_peer_id = metadata.get("peer_id")
                if isinstance(trace_peer_id, str):
                    return trace_peer_id

        return None

    @staticmethod
    def _event_traces(event: dict[str, Any]) -> list[dict[str, Any]]:
        data = event.get("data")
        if not isinstance(data, dict):
            return []

        tasks = data.get("tasks")
        return [item for item in tasks if isinstance(item, dict)] if isinstance(tasks, list) else []

    @staticmethod
    def _offer(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        try:
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)
        except Exception:
            return


@dataclass(eq=False, slots=True, weakref_slot=True)
class JournalSubscriber:
    """A bounded replica cursor over the runtime's shared change journal."""

    queue: asyncio.Queue[dict[str, Any]]
    cursor: int
    peer_id: str | None = None
    acknowledged: int = 0
    needs_snapshot: bool = False
    closed: bool = False


@dataclass(slots=True)
class JournalSubscription:
    transport: "TracePatchTransport"
    subscriber: JournalSubscriber

    async def get(self) -> dict[str, Any]:
        item = await self.subscriber.queue.get()
        # A queue of size one can still deliver the required resync marker and
        # a fresh snapshot in order.  Enqueue the snapshot only after the
        # marker has been consumed.
        if item.get("event") == "trace:resync_required":
            self.transport._enqueue_fresh_snapshot(self.subscriber)
        else:
            self.transport._acknowledge(self.subscriber, item)
        return item

    def close(self) -> None:
        self.transport.unsubscribe(self.subscriber)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.close()


class TracePatchTransport:
    """Schema-2 snapshot/patch transport with one journal for all viewers.

    Projection records stay mutable and allocation-light.  Only a cadence
    drain, while at least one viewer exists, creates transport dictionaries.
    Each resulting batch object is appended once and offered by identity to
    every matching subscriber.
    """

    def __init__(
        self,
        *,
        activity_groups: Any,
        projection: Any,
        captures: Any = None,
        diagnostics: Counter[str] | None = None,
        cadence: float = 0.15,
        journal_limit: int = 128,
        max_batch_records: int = 256,
        max_batch_bytes: int = 256 * 1024,
    ) -> None:
        from collections import Counter

        self.activity_groups = activity_groups
        self.projection = projection
        self.captures = captures
        self.diagnostics = diagnostics if diagnostics is not None else Counter()
        self.cadence = max(0.0, cadence)
        self.journal_limit = max(1, journal_limit)
        self.max_batch_records = max(1, max_batch_records)
        self.max_batch_bytes = max(1024, max_batch_bytes)
        self._journal: deque[tuple[int, dict[str, Any]]] = deque()
        self._subscribers: weakref.WeakSet[JournalSubscriber] = weakref.WeakSet()
        self._sequence = 0
        self._published_removal_checkpoint = 0
        self._removal_checkpoint_by_sequence: dict[int, int] = {}
        self._machine_revisions: dict[str, tuple[int, int]] = {}
        self._facet_revisions: dict[str, tuple[int, int]] = {}
        self._control_signatures: dict[str, tuple[Any, ...]] = {}
        self._control_revisions: dict[str, int] = {}
        self._flush_handle: asyncio.TimerHandle | None = None

    @property
    def journal_depth(self) -> int:
        return len(self._journal)

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def viewer_count(self) -> int:
        return len(self._subscribers)

    def subscribe(self, *, maxsize: int = 16, peer_id: str | None = None) -> JournalSubscription:
        had_viewers = bool(self._subscribers)
        subscriber = JournalSubscriber(
            asyncio.Queue(maxsize=max(1, maxsize)), self._sequence,
            peer_id=peer_id, acknowledged=self._sequence,
        )
        self._subscribers.add(subscriber)
        # A consistent snapshot is captured synchronously on the single writer.
        # Dirty records represented by it need not be repeated in the next patch.
        snapshot = self.snapshot()
        if not had_viewers:
            self.activity_groups.drain_dirty()
            if self.captures is not None:
                self.captures.drain_dirty()
                self.captures.drain_removed()
            self._published_removal_checkpoint = self.activity_groups.removal_checkpoint
            self.activity_groups.gc_tombstones(self._published_removal_checkpoint)
            self._capture_projection_baseline()
        subscriber.queue.put_nowait(snapshot)
        return JournalSubscription(self, subscriber)

    def unsubscribe(self, subscriber: JournalSubscriber) -> None:
        subscriber.closed = True
        self._subscribers.discard(subscriber)
        while not subscriber.queue.empty():
            subscriber.queue.get_nowait()
        if not self._subscribers and self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None

    def close(self) -> None:
        for subscriber in tuple(self._subscribers):
            self.unsubscribe(subscriber)

    def dirty(self) -> None:
        """Schedule one source-side coalescing drain when viewers are present."""
        if not self._subscribers:
            # No replica can require a historical remove: a future subscriber
            # starts from a complete snapshot.
            self.activity_groups.gc_tombstones(self.activity_groups.removal_checkpoint)
            return
        if self._flush_handle is not None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._flush_handle = loop.call_later(self.cadence, self.flush)

    def flush(self) -> tuple[dict[str, Any], ...]:
        if self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None
        if not self._subscribers:
            return ()

        groups = self.activity_groups.drain_dirty()
        captures = () if self.captures is None else self.captures.drain_dirty()
        capture_removals = () if self.captures is None else self.captures.drain_removed()
        removals = tuple(
            tombstone.group_id for tombstone in self.activity_groups.removed()
            if tombstone.checkpoint > self._published_removal_checkpoint
        )
        self._published_removal_checkpoint = self.activity_groups.removal_checkpoint
        projection_events = self._drain_projection()
        if not groups and not removals and not projection_events and not captures and not capture_removals:
            return ()

        events: list[dict[str, Any]] = list(projection_events)
        if captures:
            events.append({
                "type": "capture:upsert",
                "records": [record.to_dict() for record in captures],
            })
        if capture_removals:
            events.append({"type": "capture:remove", "ids": list(capture_removals)})
        records = [snapshot.to_dict() for snapshot in groups]
        if records:
            events.append({"type": "group:upsert", "records": records})
        if removals:
            events.append({"type": "group:remove", "ids": list(removals)})
        events.append({"type": "diagnostics:patch", "values": dict(self.diagnostics)})
        chunks = self._budget_events(events)
        batches: list[dict[str, Any]] = []
        for chunk in chunks:
            batch = self._append_batch(chunk)
            self._removal_checkpoint_by_sequence[
                batch["data"]["sequence"]
            ] = self._published_removal_checkpoint
            self._gc_acknowledged_tombstones()
            batches.append(batch)
        self.diagnostics["trace_patch_batches"] += len(batches)
        return tuple(batches)

    def snapshot(self) -> dict[str, Any]:
        from webrtc.performance import compiled_operation_strings

        groups = [item.to_dict() for item in self.activity_groups.snapshots()]
        snapshot = {
            "event": "trace:snapshot",
            "data": {
                "schema": 2,
                "trace_id": self.projection.trace_id,
                "snapshot_sequence": self._sequence,
                "server_monotonic_ms": self._monotonic_ms(),
                "machines": [self._machine(item) for item in self.projection.machines.snapshots()],
                "controls": [
                    self._control(item, self._control_revisions.get(item.handle_id, 1))
                    for item in self.projection.controls.snapshots()
                ],
                "groups": groups,
                "facets": [self._facet(item) for item in self.projection.facets.snapshots()],
                "captures": (
                    [] if self.captures is None
                    else [item.to_dict() for item in self.captures.snapshots()]
                ),
                "operation_strings": dict(compiled_operation_strings()),
                "diagnostics": dict(self.diagnostics),
            },
        }
        self.diagnostics["trace_snapshots"] += 1
        return snapshot

    def _append_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        from webrtc.performance import compiled_operation_strings

        self._sequence += 1
        operation_ids = {
            record.get("operation_id")
            for event in events if event.get("type") == "group:upsert"
            for record in event.get("records", ())
        }
        names = compiled_operation_strings()
        batch = {
            "event": "trace:batch",
            "data": {
                "schema": 2,
                "trace_id": self.projection.trace_id,
                "sequence": self._sequence,
                "server_monotonic_ms": self._monotonic_ms(),
                "operation_strings": {
                    operation_id: names[operation_id]
                    for operation_id in operation_ids if operation_id in names
                },
                "events": events,
            },
        }
        self._journal.append((self._sequence, batch))
        while len(self._journal) > self.journal_limit:
            self._journal.popleft()
        self._broadcast(batch)
        return batch

    def _broadcast(self, batch: dict[str, Any]) -> None:
        head = self._journal[0][0]
        for subscriber in tuple(self._subscribers):
            if subscriber.closed or subscriber.needs_snapshot:
                continue
            if subscriber.cursor < head - 1 or subscriber.queue.full():
                self._force_resync(subscriber)
                continue
            subscriber.queue.put_nowait(batch)
            subscriber.cursor = self._sequence

    def _force_resync(self, subscriber: JournalSubscriber) -> None:
        while not subscriber.queue.empty():
            subscriber.queue.get_nowait()
        subscriber.needs_snapshot = True
        # This replica will converge from a fresh snapshot and therefore no
        # longer needs historical removal tombstones while it waits to consume
        # the marker.
        subscriber.cursor = self._sequence
        subscriber.acknowledged = self._sequence
        subscriber.queue.put_nowait({
            "event": "trace:resync_required",
            "data": {
                "schema": 2,
                "trace_id": self.projection.trace_id,
                "sequence": self._sequence,
            },
        })
        self.diagnostics["trace_resync_required"] += 1
        self._gc_acknowledged_tombstones()

    def _enqueue_fresh_snapshot(self, subscriber: JournalSubscriber) -> None:
        if subscriber.closed or not subscriber.needs_snapshot:
            return
        snapshot = self.snapshot()
        subscriber.cursor = self._sequence
        subscriber.needs_snapshot = False
        subscriber.acknowledged = self._sequence
        subscriber.queue.put_nowait(snapshot)
        self._gc_acknowledged_tombstones()

    def _acknowledge(self, subscriber: JournalSubscriber, item: dict[str, Any]) -> None:
        data = item.get("data")
        if not isinstance(data, dict):
            return
        sequence = data.get("sequence", data.get("snapshot_sequence"))
        if isinstance(sequence, int):
            subscriber.acknowledged = max(subscriber.acknowledged, sequence)
            self._gc_acknowledged_tombstones()

    def _gc_acknowledged_tombstones(self) -> None:
        subscribers = tuple(
            subscriber for subscriber in self._subscribers
            if not subscriber.needs_snapshot and not subscriber.closed
        )
        if not subscribers:
            acknowledged = self._sequence
            checkpoint = self.activity_groups.removal_checkpoint
        else:
            acknowledged = min(item.acknowledged for item in subscribers)
            checkpoint = max(
                (value for sequence, value in self._removal_checkpoint_by_sequence.items()
                 if sequence <= acknowledged),
                default=0,
            )
        if checkpoint:
            self.activity_groups.gc_tombstones(checkpoint)
        for sequence in tuple(self._removal_checkpoint_by_sequence):
            if sequence <= acknowledged:
                del self._removal_checkpoint_by_sequence[sequence]

    def _budget_chunks(
        self, records: list[dict[str, Any]], removals: tuple[int, ...]
    ) -> list[tuple[list[dict[str, Any]], list[int]]]:
        chunks: list[tuple[list[dict[str, Any]], list[int]]] = []
        current_records: list[dict[str, Any]] = []
        current_removals: list[int] = []
        size = 0
        for record in records:
            item_size = len(json.dumps(record, separators=(",", ":"), default=str))
            if current_records and (
                len(current_records) + len(current_removals) >= self.max_batch_records
                or size + item_size > self.max_batch_bytes
            ):
                chunks.append((current_records, current_removals))
                current_records, current_removals, size = [], [], 0
            current_records.append(record)
            size += item_size
        for group_id in removals:
            if current_records or current_removals:
                if len(current_records) + len(current_removals) >= self.max_batch_records:
                    chunks.append((current_records, current_removals))
                    current_records, current_removals, size = [], [], 0
            current_removals.append(group_id)
        if current_records or current_removals:
            chunks.append((current_records, current_removals))
        return chunks

    def _budget_events(self, events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        """Split every record/id event, not only activity groups, by both budgets."""
        chunks: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        count = 0
        size = 0

        def flush() -> None:
            nonlocal current, count, size
            if current:
                chunks.append(current)
            current, count, size = [], 0, 0

        def append_item(event_type: str, field: str, item: Any) -> None:
            nonlocal count, size
            item_size = len(json.dumps(item, separators=(",", ":"), default=str))
            if current and (
                count >= self.max_batch_records or size + item_size > self.max_batch_bytes
            ):
                flush()
            if current and current[-1].get("type") == event_type and field in current[-1]:
                current[-1][field].append(item)
            else:
                current.append({"type": event_type, field: [item]})
            count += 1
            size += item_size

        for event in events:
            event_type = event.get("type")
            records = event.get("records")
            ids = event.get("ids")
            if isinstance(event_type, str) and isinstance(records, list):
                for record in records:
                    append_item(event_type, "records", record)
            elif isinstance(event_type, str) and isinstance(ids, list):
                for item_id in ids:
                    append_item(event_type, "ids", item_id)
            else:
                event_size = len(json.dumps(event, separators=(",", ":"), default=str))
                if current and size + event_size > self.max_batch_bytes:
                    flush()
                current.append(event)
                size += event_size
        flush()
        return chunks

    @staticmethod
    def _machine(item: Any) -> dict[str, Any]:
        return {
            "entity_id": item.entity_id, "machine_type": item.machine_type,
            "state": item.state, "machine_epoch": item.machine_epoch,
            "revision": item.revision, "cause_id": item.cause_id,
            "monotonic_ns": item.monotonic_ns,
        }

    @staticmethod
    def _control(item: Any, revision: int = 1) -> dict[str, Any]:
        return {
            "handle_id": item.handle_id, "trace_id": item.trace_id,
            "owner_entity_id": item.owner_entity_id, "owner_epoch": item.owner_epoch,
            "name": item.name, "cancelable": item.cancelable,
            "revision": revision,
        }

    @staticmethod
    def _facet(item: Any) -> dict[str, Any]:
        return {
            "facet_id": item.facet_id, "owner_entity_id": item.owner_entity_id,
            "owner_epoch": item.owner_epoch, "value": item.value,
            "revision": item.revision,
        }

    @staticmethod
    def _monotonic_ms() -> float:
        import time
        return time.monotonic_ns() / 1_000_000

    @staticmethod
    def _control_signature(item: Any) -> tuple[Any, ...]:
        return (
            item.trace_id, item.owner_entity_id, item.owner_epoch,
            item.name, item.cancelable, item.runtime_task_id,
        )

    def _capture_projection_baseline(self) -> None:
        self._machine_revisions = {
            item.entity_id: (item.machine_epoch, item.revision)
            for item in self.projection.machines.snapshots()
        }
        self._facet_revisions = {
            item.facet_id: (item.owner_epoch, item.revision)
            for item in self.projection.facets.snapshots()
        }
        controls = self.projection.controls.snapshots()
        self._control_signatures = {
            item.handle_id: self._control_signature(item) for item in controls
        }
        self._control_revisions = {item.handle_id: 1 for item in controls}

    def _drain_projection(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        machines = self.projection.machines.snapshots()
        changed_machines = [
            item for item in machines
            if (item.machine_epoch, item.revision) > self._machine_revisions.get(
                item.entity_id, (-1, -1)
            )
        ]
        if changed_machines:
            changed_machines.sort(key=lambda item: item.entity_id)
            events.append({
                "type": "machine:transition",
                "records": [self._machine(item) for item in changed_machines],
            })
        self._machine_revisions = {
            item.entity_id: (item.machine_epoch, item.revision) for item in machines
        }

        controls = self.projection.controls.snapshots()
        current_controls = {item.handle_id: item for item in controls}
        control_upserts = []
        for handle_id in sorted(current_controls):
            item = current_controls[handle_id]
            signature = self._control_signature(item)
            if signature == self._control_signatures.get(handle_id):
                continue
            revision = self._control_revisions.get(handle_id, 0) + 1
            self._control_revisions[handle_id] = revision
            control_upserts.append(self._control(item, revision))
        control_removes = sorted(set(self._control_signatures) - set(current_controls))
        if control_upserts:
            events.append({"type": "control:upsert", "records": control_upserts})
        if control_removes:
            events.append({"type": "control:remove", "ids": control_removes})
        self._control_signatures = {
            key: self._control_signature(item) for key, item in current_controls.items()
        }

        facets = self.projection.facets.snapshots()
        current_facets = {item.facet_id: item for item in facets}
        facet_upserts = [
            item for item in facets
            if (item.owner_epoch, item.revision) > self._facet_revisions.get(
                item.facet_id, (-1, -1)
            )
        ]
        facet_removes = sorted(set(self._facet_revisions) - set(current_facets))
        if facet_upserts:
            facet_upserts.sort(key=lambda item: item.facet_id)
            events.append({
                "type": "state:upsert",
                "records": [self._facet(item) for item in facet_upserts],
            })
        if facet_removes:
            events.append({"type": "state:remove", "ids": facet_removes})
        self._facet_revisions = {
            item.facet_id: (item.owner_epoch, item.revision) for item in facets
        }
        return events
