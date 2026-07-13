"""Adapters from semantic domain events to bounded observability facets."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .domain_events import (
    DomainEvent, DtlsStateChanged, IcePairNominated, IceStateChanged,
    MediaStateChanged, PeerStateChanged, QueueStateChanged,
    SrtpKeysReady, SrtpPacketDelivery, SrtpSessionReady, SrtpStreamCreated,
    TraceHealthChanged, TransceiverStateChanged, TransportStateChanged,
    WorkerLaneStateChanged,
)
from .machine_specs import MACHINE_SPECS
from .observability import MachineTransitionOp
from .runtime_services import TaskCancelled, TaskCompleted, TaskFailed, TaskStarted


@dataclass(slots=True)
class _SrtpDeliveryAggregate:
    delivered_packets: int = 0
    dropped_packets: int = 0
    interval_delivered: int = 0
    interval_dropped: int = 0
    health: str = "unknown"
    last_failure: str | None = None
    emitted: dict[str, object] = field(default_factory=dict)


class DomainStateFacetAdapter:
    """Scope-filtered semantic adapter; protocol objects never import tracing."""

    def __init__(self, runtime, *, srtp_delivery_cadence: float = 1.0) -> None:
        self.runtime = runtime
        self.srtp_delivery_cadence = max(0.0, srtp_delivery_cadence)
        self._srtp_delivery: dict[str, _SrtpDeliveryAggregate] = {}
        self._srtp_flush_handle: asyncio.TimerHandle | None = None
        self._trace_health: tuple[bool, int, int, int, int] | None = None

    def on_domain_event(self, event: DomainEvent) -> None:
        root = self.runtime.root_context
        if root is None or event.context.trace_id != root.trace_id:
            return
        scope = self.runtime.scope_id or root.trace_id
        entity = f"peer:{scope}"
        values: dict[str, object]
        if isinstance(event, PeerStateChanged):
            values = {
                "lifecycle": event.lifecycle, "signaling": event.signaling,
                "connection": event.connection,
            }
        elif isinstance(event, IceStateChanged):
            entity = f"ice:{scope}"
            values = {"gathering": event.gathering, "connection": event.connection}
        elif isinstance(event, IcePairNominated):
            entity = f"ice:{scope}"
            # Addresses are intentionally not copied into live state.
            values = {"selected_pair": True}
            if event.pair_id is not None:
                values["selected_pair_id"] = event.pair_id
        elif isinstance(event, TransportStateChanged):
            entity = f"transport:{scope}"
            values = {
                "lifecycle": event.lifecycle, "selected": event.selected,
            }
            if event.pair_id is not None:
                values["selected_pair_id"] = event.pair_id
        elif isinstance(event, DtlsStateChanged):
            entity = f"dtls:{scope}"
            values = {"state": event.state, "transition_revision": event.revision}
        elif isinstance(event, TransceiverStateChanged):
            entity = f"transceiver:{scope}:{event.transceiver_id}"
            values = {
                "direction": event.direction, "active": event.active,
                "lifecycle": event.lifecycle,
            }
        elif isinstance(event, MediaStateChanged):
            entity = f"media:{scope}:{event.media_id}"
            values = {
                "direction": event.direction, "active": event.active,
                "lifecycle": event.lifecycle,
            }
        elif isinstance(event, QueueStateChanged):
            entity = f"queue:{scope}:{event.queue_instance_id or event.queue_id}"
            values = {
                "depth": event.depth, "high_water": event.high_water,
                "queue_kind": event.queue_id,
            }
        elif isinstance(event, WorkerLaneStateChanged):
            entity = f"worker:{scope}:{event.lane_instance_id or event.lane_id}"
            values = {
                "queued": event.queued, "running": event.running,
                "lane_kind": event.lane_id,
            }
        elif isinstance(event, TraceHealthChanged):
            current_health = (
                event.admitted, event.subscriber_count, event.journal_depth,
                event.dispatcher_drops, event.dispatcher_observer_failures,
            )
            if current_health == self._trace_health:
                return
            self._trace_health = current_health
            entity = f"tracing:{scope}"
            values = {
                "admitted": event.admitted,
                "subscriber_count": event.subscriber_count,
                "journal_depth": event.journal_depth,
                "dispatcher_drops": event.dispatcher_drops,
                "dispatcher_observer_failures": event.dispatcher_observer_failures,
            }
        elif isinstance(event, SrtpKeysReady):
            entity = f"dtls:{scope}"
            values = {"srtp_keys_ready": True, "srtp_profile": event.profile}
        elif isinstance(event, SrtpSessionReady):
            entity = f"media:{scope}:{event.session_id or event.protocol}"
            values = {
                "active": True, "protocol": event.protocol,
                "media_kind": "srtp_session",
            }
        elif isinstance(event, SrtpStreamCreated):
            entity = f"media:{scope}:{event.stream_id or event.protocol}"
            values = {
                "stream_active": True, "protocol": event.protocol,
                "media_kind": "srtp_stream", "stream_count": event.stream_count,
            }
            if event.session_id is not None:
                values["session_id"] = event.session_id
            if event.ssrc_id is not None:
                values["ssrc_id"] = event.ssrc_id
        elif isinstance(event, SrtpPacketDelivery):
            self._on_srtp_delivery(scope, event)
            return
        else:
            return
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(), values
        )

    def _on_srtp_delivery(self, scope: str, event: SrtpPacketDelivery) -> None:
        entity = f"queue:{scope}:{event.stream_id or event.protocol}"
        aggregate = self._srtp_delivery.setdefault(entity, _SrtpDeliveryAggregate())
        if event.delivered:
            aggregate.delivered_packets += 1
            aggregate.interval_delivered += 1
        else:
            aggregate.dropped_packets += 1
            aggregate.interval_dropped += 1
            aggregate.last_failure = event.failure_reason or "delivery_failed"
            if aggregate.health != "degraded":
                aggregate.health = "degraded"
                self._publish_srtp_delivery(entity, aggregate)
                # The health transition closes this reporting interval.  Any
                # following successes must fill a new drop-free interval before
                # recovery is published.
                aggregate.interval_delivered = 0
                aggregate.interval_dropped = 0
                if self._srtp_flush_handle is not None:
                    self._srtp_flush_handle.cancel()
                    self._srtp_flush_handle = None
        self._schedule_srtp_flush()

    def _schedule_srtp_flush(self) -> None:
        if self._srtp_flush_handle is not None:
            return
        loop = asyncio.get_running_loop()
        self._srtp_flush_handle = loop.call_later(
            self.srtp_delivery_cadence, self.flush_srtp_delivery
        )

    def flush_srtp_delivery(self) -> None:
        """Publish one cumulative SRTP delivery update per active protocol."""
        if self._srtp_flush_handle is not None:
            self._srtp_flush_handle.cancel()
            self._srtp_flush_handle = None
        for entity, aggregate in self._srtp_delivery.items():
            if not (aggregate.interval_delivered or aggregate.interval_dropped):
                continue
            if aggregate.interval_dropped:
                aggregate.health = "degraded"
            elif aggregate.interval_delivered:
                # Recovery means a complete reporting interval delivered packets
                # without another queue drop, not merely that the last packet won.
                aggregate.health = "healthy"
            self._publish_srtp_delivery(entity, aggregate)
            aggregate.interval_delivered = 0
            aggregate.interval_dropped = 0

    def _publish_srtp_delivery(
        self, entity: str, aggregate: _SrtpDeliveryAggregate
    ) -> None:
        current: dict[str, object] = {
            "delivered_packets": aggregate.delivered_packets,
            "dropped_packets": aggregate.dropped_packets,
            "delivery_health": aggregate.health,
        }
        if aggregate.last_failure is not None:
            current["last_failure"] = aggregate.last_failure
        changed = {
            name: value for name, value in current.items()
            if aggregate.emitted.get(name) != value
        }
        if not changed:
            return
        aggregate.emitted.update(changed)
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(), changed
        )

    def close(self) -> None:
        """Flush pending counters and release the cadence timer."""
        self.flush_srtp_delivery()


class StateTaskProjection:
    """Project only explicitly selected controller tasks onto stable machines."""

    _START = {
        "peer": ("starting", "connected"), "ice": ("checking", "connected"),
        "transport": ("starting", "ready"), "worker": ("queued", "running"),
        "transceiver": ("active",), "media": ("active",),
    }
    _COMPLETE = {
        "peer": ("closing", "closed"), "ice": ("completed", "closed"),
        "transport": ("draining", "closed"), "worker": ("idle",),
        "transceiver": ("stopping", "stopped"), "media": ("ended",),
    }

    def __init__(self, runtime) -> None:
        self.runtime = runtime
        # Every scheduled descendant inherits the nearest selected machine
        # owner.  The boolean distinguishes the task that drives the machine
        # lifecycle from descendants that merely inherit its ownership.
        self._owners: dict[str, tuple[str, str, bool]] = {}

    def task_started(self, event: TaskStarted) -> None:
        machine_type = event.metadata.get("_observable_machine")
        # DTLS phase execution supplies the stronger authoritative stream.
        if machine_type not in self._START:
            parent = self._owners.get(event.context.parent_task_id or "")
            if parent is not None:
                entity_id, inherited_type, _ = parent
                self._owners[event.context.task_id] = (
                    entity_id, inherited_type, False,
                )
            return
        scope = self.runtime.scope_id or event.context.trace_id
        entity_id = f"{machine_type}:{scope}"
        self.runtime.projection.machines.register(entity_id, MACHINE_SPECS[machine_type])
        self._owners[event.context.task_id] = (entity_id, machine_type, True)
        for state in self._START[machine_type]:
            self._advance(entity_id, machine_type, state)

    def task_completed(self, event: TaskCompleted) -> None:
        self._terminal(event.context.task_id, "completed")

    def task_cancelled(self, event: TaskCancelled) -> None:
        self._terminal(event.context.task_id, "cancelled")

    def task_failed(self, event: TaskFailed) -> None:
        self._terminal(event.context.task_id, "failed")

    def owner_entity_id(self, task_id: str) -> str | None:
        owner = self._owners.get(task_id)
        return None if owner is None else owner[0]

    def _terminal(self, task_id: str, outcome: str) -> None:
        owner = self._owners.pop(task_id, None)
        if owner is None:
            return
        entity_id, machine_type, drives_lifecycle = owner
        if not drives_lifecycle:
            return
        snapshot = self.runtime.projection.machines.get(entity_id)
        if snapshot is None:
            return
        if outcome == "failed" and "failed" in MACHINE_SPECS[machine_type].states:
            self._advance(entity_id, machine_type, "failed")
            return
        for state in self._COMPLETE[machine_type]:
            self._advance(entity_id, machine_type, state)

    def _advance(self, entity_id: str, machine_type: str, to_state: str) -> None:
        current = self.runtime.projection.machines.get(entity_id)
        if current is None or current.state == to_state:
            return
        self.runtime.projection.machines.apply(MachineTransitionOp(
            entity_id, machine_type, current.state, to_state,
            current.machine_epoch, current.revision + 1,
            self.runtime.new_producer_dot(), None,
        ))
