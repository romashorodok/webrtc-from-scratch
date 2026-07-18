"""Runtime-owned reducers for non-lifecycle aggregate facets."""

from __future__ import annotations

from dataclasses import dataclass, field
from .runtime_services import OwnedTimerHandle


@dataclass(slots=True)
class _SrtpDeliveryAggregate:
    delivered_packets: int = 0
    dropped_packets: int = 0
    interval_delivered: int = 0
    interval_dropped: int = 0
    health: str = "unknown"
    last_failure: str | None = None
    emitted: dict[str, object] = field(default_factory=dict)


class AggregateFacetAdapter:
    """Scope-filtered adapter for non-lifecycle aggregate facets only."""

    def __init__(self, runtime, *, srtp_delivery_cadence: float = 1.0) -> None:
        self.runtime = runtime
        self.srtp_delivery_cadence = max(0.0, srtp_delivery_cadence)
        self._srtp_delivery: dict[str, _SrtpDeliveryAggregate] = {}
        self._srtp_flush_handle: OwnedTimerHandle | None = None
        self._closed = False

    def _scope_identity(self) -> str:
        root = self.runtime.root_context
        return self.runtime.scope_id or (
            root.trace_id if root is not None else f"runtime-{self.runtime.runtime_epoch}"
        )

    def queue_state(self, *, queue_id: str, queue_instance_id: str,
                    depth: int, high_water: int) -> None:
        if self._closed:
            return
        scope = self._scope_identity()
        entity = f"queue:{scope}:{queue_instance_id}"
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(),
            {"depth": depth, "high_water": high_water, "queue_kind": queue_id},
            observer_meta="aggregate", source_entity_id=entity,
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )

    def worker_state(self, *, lane_id: str, lane_instance_id: str,
                     queued: int, running: bool) -> None:
        if self._closed:
            return
        scope = self._scope_identity()
        entity = f"worker:{scope}:{lane_instance_id}"
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(),
            {"queued": queued, "running": running, "lane_kind": lane_id},
            observer_meta="aggregate", source_entity_id=entity,
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )

    def srtp_stream(self, *, protocol: str, session_id: str, stream_id: str,
                    ssrc_id: str, stream_count: int) -> None:
        if self._closed:
            return
        scope = self._scope_identity()
        entity = f"media:{scope}:{stream_id}"
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(), {
                "protocol": protocol, "media_kind": "srtp_stream",
                "stream_count": stream_count, "session_id": session_id,
                "ssrc_id": ssrc_id,
            },
            observer_meta="aggregate", source_entity_id=entity,
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )

    def srtp_delivery(self, *, protocol: str, stream_id: str,
                      delivered: bool, failure_reason: str | None = None) -> None:
        if self._closed:
            return
        scope = self._scope_identity()
        entity = f"queue:{scope}:{stream_id}"
        aggregate = self._srtp_delivery.setdefault(entity, _SrtpDeliveryAggregate())
        if delivered:
            aggregate.delivered_packets += 1
            aggregate.interval_delivered += 1
        else:
            aggregate.dropped_packets += 1
            aggregate.interval_dropped += 1
            aggregate.last_failure = failure_reason or "delivery_failed"
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
        self._srtp_flush_handle = self.runtime.call_later_owned(
            self.srtp_delivery_cadence, self.flush_srtp_delivery,
            owner_entity_id=self.runtime._observability_entity_id,
            owner_epoch=self.runtime.observability_epoch,
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
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(), changed,
            observer_meta="aggregate", source_entity_id=entity,
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )

    def close(self) -> None:
        """Flush pending counters and release the cadence timer."""
        self.flush_srtp_delivery()
        self._closed = True
