"""Adapters from semantic domain events to bounded observability facets."""

from __future__ import annotations

from .domain_events import (
    DomainEvent, DtlsStateChanged, IcePairNominated, IceStateChanged,
    MediaStateChanged, PeerStateChanged, QueueStateChanged,
    SrtpKeysReady, SrtpPacketDelivery, SrtpSessionReady, SrtpStreamCreated,
    TraceHealthChanged, TransceiverStateChanged, WorkerLaneStateChanged,
)
from .machine_specs import MACHINE_SPECS
from .observability import MachineTransitionOp
from .runtime_services import TaskCancelled, TaskCompleted, TaskFailed, TaskStarted


class DomainStateFacetAdapter:
    """Scope-filtered semantic adapter; protocol objects never import tracing."""

    def __init__(self, runtime) -> None:
        self.runtime = runtime

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
        elif isinstance(event, DtlsStateChanged):
            entity = f"dtls:{scope}"
            values = {"state": event.state, "transition_revision": event.revision}
        elif isinstance(event, TransceiverStateChanged):
            entity = f"transceiver:{scope}:{event.transceiver_id}"
            values = {"direction": event.direction, "active": event.active}
        elif isinstance(event, MediaStateChanged):
            entity = f"media:{scope}:{event.media_id}"
            values = {"direction": event.direction, "active": event.active}
        elif isinstance(event, QueueStateChanged):
            entity = f"queue:{scope}:{event.queue_id}"
            values = {"depth": event.depth, "high_water": event.high_water}
        elif isinstance(event, WorkerLaneStateChanged):
            entity = f"worker:{scope}:{event.lane_id}"
            values = {"queued": event.queued, "running": event.running}
        elif isinstance(event, TraceHealthChanged):
            entity = f"tracing:{scope}"
            values = {
                "admitted": event.admitted,
                "subscriber_count": event.subscriber_count,
                "journal_depth": event.journal_depth,
            }
        elif isinstance(event, SrtpKeysReady):
            entity = f"dtls:{scope}"
            values = {"srtp_keys_ready": True, "srtp_profile": event.profile}
        elif isinstance(event, SrtpSessionReady):
            entity = f"media:{scope}:{event.protocol}"
            values = {"active": True, "protocol": event.protocol}
        elif isinstance(event, SrtpStreamCreated):
            entity = f"media:{scope}:{event.protocol}"
            values = {"stream_active": True}
        elif isinstance(event, SrtpPacketDelivery):
            entity = f"queue:{scope}:{event.protocol}"
            values = {"delivery_ok": event.delivered}
        else:
            return
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(), values
        )


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
        self._owners: dict[str, tuple[str, str]] = {}

    def task_started(self, event: TaskStarted) -> None:
        machine_type = event.metadata.get("_observable_machine")
        # DTLS phase execution supplies the stronger authoritative stream.
        if machine_type not in self._START:
            return
        scope = self.runtime.scope_id or event.context.trace_id
        entity_id = f"{machine_type}:{scope}"
        self.runtime.projection.machines.register(entity_id, MACHINE_SPECS[machine_type])
        self._owners[event.context.task_id] = (entity_id, machine_type)
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
        entity_id, machine_type = owner
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
