"""Runtime-owned, bounded reducers for high-rate telemetry.

Protocol objects report immutable samples here.  They do not retain counters or
perform projection work on their admission paths.
"""

from __future__ import annotations

import hashlib
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from .logger import Component, get_logger
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


@dataclass(slots=True)
class _QueueAggregate:
    queue_kind: str
    projected_entity: str
    source_entity: str
    failure_diagnostic: str = "queue_facet_publish_failures"
    capacity: int | None = None
    depth: int = 0
    high_water: int = 0
    counters: dict[str, int] = field(default_factory=dict)
    pending: bool = False


@dataclass(slots=True)
class _SrtpPacketAggregate:
    protocol: str
    packets: int = 0
    errors: int = 0
    ssrc_aliases: OrderedDict[str, int] = field(default_factory=OrderedDict)


@dataclass(slots=True)
class _AudioAggregate:
    frames: int = 0


class AggregateFacetAdapter:
    """Scope-filtered adapter for non-lifecycle aggregate facets only."""

    def __init__(self, runtime, *, srtp_delivery_cadence: float = 1.0,
                 max_keys: int = 256, max_ssrcs: int = 64) -> None:
        self.runtime = runtime
        self.srtp_delivery_cadence = max(0.0, srtp_delivery_cadence)
        self._srtp_delivery: OrderedDict[str, _SrtpDeliveryAggregate] = OrderedDict()
        self._srtp_delivery_retry: OrderedDict[str, _SrtpDeliveryAggregate] = OrderedDict()
        self._srtp_delivery_overflow: _SrtpDeliveryAggregate | None = None
        self._srtp_flush_handle: OwnedTimerHandle | None = None
        self._queues: OrderedDict[str, _QueueAggregate] = OrderedDict()
        self._srtp_packets: OrderedDict[str, _SrtpPacketAggregate] = OrderedDict()
        self._audio: OrderedDict[str, _AudioAggregate] = OrderedDict()
        self._max_keys = max(1, max_keys)
        self._max_ssrcs = max(1, max_ssrcs)
        self._max_retry_keys = min(32, self._max_keys)
        self._redaction_key = secrets.token_bytes(16)
        self._closed = False

    def _bounded(self, values: OrderedDict, key: str, factory):
        value = values.get(key)
        if value is not None:
            values.move_to_end(key)
            return value
        if len(values) >= self._max_keys:
            values.popitem(last=False)
            self.runtime.diagnostics["telemetry_key_evictions"] += 1
        value = factory()
        values[key] = value
        return value

    def _alias(self, namespace: str, value: object) -> str:
        digest = hashlib.blake2s(
            str(value).encode("utf-8", "replace"), key=self._redaction_key,
            digest_size=8,
        ).hexdigest()
        return f"telemetry:{namespace}:{digest}"

    def _invalid_sample(self) -> None:
        self.runtime.diagnostics["telemetry_invalid_samples"] += 1

    def _scope_identity(self) -> str:
        root = self.runtime.root_context
        return self.runtime.scope_id or (
            root.trace_id if root is not None else f"runtime-{self.runtime.runtime_epoch}"
        )

    def queue_state(self, *, queue_id: str, queue_instance_id: str,
                    depth: int, high_water: int) -> None:
        if self._closed:
            return
        entity = self._alias("queue", queue_instance_id)
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(),
            {"depth": depth, "high_water": high_water, "queue_kind": queue_id},
            observer_meta="aggregate", source_entity_id=self._alias("source", queue_instance_id),
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )

    def queue_activity(self, *, entity_id: str, queue_kind: str, depth: int,
                       capacity: int | None = None,
                       deltas: dict[str, int] | None = None,
                       gauges: dict[str, int] | None = None,
                       failure_diagnostic: str = "queue_facet_publish_failures",
                       exact: bool = False) -> None:
        """Reduce a queue sample and coalesce publication to one per loop turn."""
        if self._closed:
            return
        if depth < 0:
            self._invalid_sample()
            depth = 0
        if capacity is not None and capacity < 0:
            self._invalid_sample()
            capacity = 0
        reducer_key = self._alias("queue-key", entity_id)
        aggregate = self._bounded(
            self._queues, reducer_key,
            lambda: _QueueAggregate(
                queue_kind=queue_kind,
                projected_entity=self._alias("queue", entity_id),
                source_entity=self._alias("source", entity_id),
            ),
        )
        aggregate.queue_kind = queue_kind
        aggregate.failure_diagnostic = failure_diagnostic
        aggregate.capacity = capacity
        aggregate.depth = max(0, depth)
        aggregate.high_water = max(aggregate.high_water, aggregate.depth)
        for name, delta in (deltas or {}).items():
            if not isinstance(delta, int) or delta < 0:
                self._invalid_sample()
                continue
            aggregate.counters[name] = aggregate.counters.get(name, 0) + delta
        for name, value in (gauges or {}).items():
            if not isinstance(value, int) or value < 0:
                self._invalid_sample()
                continue
            aggregate.counters[name] = value
        if exact:
            self._safe_publish_queue(aggregate)
        elif not aggregate.pending:
            aggregate.pending = True
            self.runtime._event_loop.call_soon(
                self._flush_queue, reducer_key, aggregate,
            )

    def _flush_queue(self, reducer_key: str, aggregate: _QueueAggregate) -> None:
        aggregate.pending = False
        if self._closed or self._queues.get(reducer_key) is not aggregate:
            return
        self._safe_publish_queue(aggregate)

    def _safe_publish_queue(self, aggregate: _QueueAggregate) -> None:
        try:
            self._publish_queue(aggregate, "aggregate")
        except BaseException:
            try:
                with self.runtime.diagnostics.suspend_notifications():
                    self.runtime.diagnostics[aggregate.failure_diagnostic] += 1
            except Exception:
                pass

    def _publish_queue(self, aggregate: _QueueAggregate,
                       observer_meta: str) -> None:
        values: dict[str, Any] = {
            "depth": aggregate.depth, "high_water": aggregate.high_water,
            "queue_kind": aggregate.queue_kind,
        }
        if aggregate.capacity is not None:
            values["capacity"] = aggregate.capacity
        values.update(aggregate.counters)
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            aggregate.projected_entity, self.runtime.new_producer_dot(), values,
            observer_meta=observer_meta,
            source_entity_id=aggregate.source_entity,
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )

    def queue_snapshot(self, entity_id: str) -> dict[str, int]:
        aggregate = self._queues.get(self._alias("queue-key", entity_id))
        if aggregate is None:
            return {}
        return {
            "depth": aggregate.depth, "high_water": aggregate.high_water,
            **aggregate.counters,
        }

    def audio_frame(self, *, analyzer_id: str, features: dict[str, Any]) -> None:
        if self._closed:
            return
        aggregate = self._bounded(
            self._audio, self._alias("audio-key", analyzer_id), _AudioAggregate,
        )
        aggregate.frames += 1
        if aggregate.frames <= 5 or aggregate.frames % 100 == 0:
            get_logger().debug(
                Component.OPUS, "Analyzed frame", count=aggregate.frames,
                rms=features.get("rms"), zcr=features.get("zcr"),
                centroid=features.get("spectral_centroid"),
                is_voice=features.get("is_voice"),
            )

    def srtp_packet(self, *, session_id: str, protocol: str, error: bool = False,
                    ssrc: int | None = None, error_detail: str | None = None,
                    sequence: int | None = None, log_errors: bool = True,
                    log_counts: bool = False) -> None:
        if self._closed:
            return
        aggregate = self._bounded(
            self._srtp_packets, self._alias("session-key", session_id),
            lambda: _SrtpPacketAggregate(protocol=protocol),
        )
        aggregate.packets += 1
        if error:
            aggregate.errors += 1
            # Preserve the old useful cadence without storing counters in the
            # crypto/session authority.  Error text is a log field, never a key.
            if log_errors and (aggregate.errors <= 20 or aggregate.errors % 100 == 0):
                get_logger().error(
                    Component.SRTP,
                    f"Decrypt error #{aggregate.errors}/{aggregate.packets}",
                    seq=sequence, error=error_detail,
                )
        if ssrc is not None:
            alias = "ssrc-" + hashlib.blake2s(
                ssrc.to_bytes(4, "big", signed=False), key=self._redaction_key,
                digest_size=6,
            ).hexdigest()
            if alias in aggregate.ssrc_aliases:
                aggregate.ssrc_aliases[alias] += 1
                aggregate.ssrc_aliases.move_to_end(alias)
            elif len(aggregate.ssrc_aliases) < self._max_ssrcs:
                aggregate.ssrc_aliases[alias] = 1
            else:
                self.runtime.diagnostics["telemetry_ssrc_overflow"] += 1
            if log_counts and aggregate.packets % 100 == 0 and protocol == "rtp":
                pct = 100 * aggregate.errors / aggregate.packets
                get_logger().log_stats(
                    Component.SRTP, packets=aggregate.packets,
                    errors=aggregate.errors, error_pct=f"{pct:.1f}%",
                    SSRCs=len(aggregate.ssrc_aliases),
                )

    def worker_state(self, *, lane_id: str, lane_instance_id: str,
                     queued: int, running: bool) -> None:
        if self._closed:
            return
        entity = self._alias("worker", lane_instance_id)
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
        entity = self._alias("media", stream_id)
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(), {
                "protocol": protocol, "media_kind": "srtp_stream",
                "stream_count": stream_count,
                "session_id": self._alias("session", session_id),
                "ssrc_id": self._alias("ssrc", ssrc_id),
            },
            observer_meta="aggregate", source_entity_id=entity,
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )

    def srtp_delivery(self, *, protocol: str, stream_id: str,
                      delivered: bool, failure_reason: str | None = None) -> None:
        if self._closed:
            return
        entity = self._alias("srtp-delivery", stream_id)
        aggregate = self._srtp_delivery.get(entity)
        if aggregate is None:
            # A failed eviction retains the authoritative cumulative baseline.
            # Re-entry moves that same aggregate back to active ownership.
            aggregate = self._srtp_delivery_retry.pop(entity, None)
            if len(self._srtp_delivery) >= self._max_keys:
                self._evict_srtp_delivery()
            if aggregate is None:
                aggregate = _SrtpDeliveryAggregate()
            self._srtp_delivery[entity] = aggregate
        else:
            self._srtp_delivery.move_to_end(entity)
        if delivered:
            aggregate.delivered_packets += 1
            aggregate.interval_delivered += 1
        else:
            aggregate.dropped_packets += 1
            aggregate.interval_dropped += 1
            aggregate.last_failure = self._failure_category(failure_reason)
            if aggregate.health != "degraded":
                aggregate.health = "degraded"
                if self._safe_publish_srtp_delivery(entity, aggregate):
                    # The acknowledged health transition closes this interval.
                    aggregate.interval_delivered = 0
                    aggregate.interval_dropped = 0
                    if self._srtp_flush_handle is not None:
                        self._srtp_flush_handle.cancel()
                        self._srtp_flush_handle = None
        self._schedule_srtp_flush()

    def _evict_srtp_delivery(self) -> None:
        old_entity, old_aggregate = self._srtp_delivery.popitem(last=False)
        self._prepare_delivery_health(old_aggregate)
        if not self._safe_publish_srtp_delivery(old_entity, old_aggregate):
            if len(self._srtp_delivery_retry) >= self._max_retry_keys:
                _, displaced = self._srtp_delivery_retry.popitem(last=False)
                self._coalesce_delivery_overflow(displaced)
            self._srtp_delivery_retry[old_entity] = old_aggregate
        self.runtime.diagnostics["srtp_delivery_key_evictions"] += 1

    def _coalesce_delivery_overflow(
        self, aggregate: _SrtpDeliveryAggregate,
    ) -> None:
        """Preserve un-emitted totals when keyed retry identity is exhausted."""
        delivered = aggregate.delivered_packets - int(
            aggregate.emitted.get("delivered_packets", 0)
        )
        dropped = aggregate.dropped_packets - int(
            aggregate.emitted.get("dropped_packets", 0)
        )
        overflow = self._srtp_delivery_overflow
        if overflow is None:
            overflow = self._srtp_delivery_overflow = _SrtpDeliveryAggregate()
        overflow.delivered_packets += max(0, delivered)
        overflow.dropped_packets += max(0, dropped)
        overflow.interval_delivered += max(0, delivered)
        overflow.interval_dropped += max(0, dropped)
        if aggregate.last_failure is not None:
            overflow.last_failure = aggregate.last_failure
        self.runtime.diagnostics["srtp_delivery_identity_coalesced"] += 1

    @staticmethod
    def _failure_category(reason: str | None) -> str:
        allowed = {
            "stream_queue_full", "stream_closed", "admission_rejected",
            "delivery_failed",
        }
        return reason if reason in allowed else "other"

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
        overflow = self._srtp_delivery_overflow
        if overflow is not None and (
            overflow.interval_delivered or overflow.interval_dropped
        ):
            self._prepare_delivery_health(overflow)
            overflow_entity = self._alias("srtp-delivery-overflow", "coalesced")
            if self._safe_publish_srtp_delivery(overflow_entity, overflow):
                overflow.interval_delivered = 0
                overflow.interval_dropped = 0
        for entity, aggregate in tuple(self._srtp_delivery_retry.items()):
            self._prepare_delivery_health(aggregate)
            if self._safe_publish_srtp_delivery(entity, aggregate):
                self._srtp_delivery_retry.pop(entity, None)
        for entity, aggregate in self._srtp_delivery.items():
            if not (aggregate.interval_delivered or aggregate.interval_dropped):
                continue
            self._prepare_delivery_health(aggregate)
            if self._safe_publish_srtp_delivery(entity, aggregate):
                aggregate.interval_delivered = 0
                aggregate.interval_dropped = 0

    @staticmethod
    def _prepare_delivery_health(aggregate: _SrtpDeliveryAggregate) -> None:
        if aggregate.interval_dropped:
            aggregate.health = "degraded"
        elif aggregate.interval_delivered:
            # Recovery is a complete reporting interval without another drop.
            aggregate.health = "healthy"

    def _safe_publish_srtp_delivery(
        self, entity: str, aggregate: _SrtpDeliveryAggregate,
    ) -> bool:
        try:
            self._publish_srtp_delivery(entity, aggregate)
            return True
        except BaseException:
            try:
                with self.runtime.diagnostics.suspend_notifications():
                    self.runtime.diagnostics[
                        "srtp_delivery_facet_publish_failures"
                    ] += 1
            except Exception:
                pass
            return False

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
        source_order = self.runtime.projection.new_facet_source_order()
        self.runtime.projection.merge_values(
            entity, self.runtime.new_producer_dot(), changed,
            observer_meta="aggregate", source_entity_id=entity,
            source_epoch=1, source_revision=source_order,
            source_order=source_order,
        )
        aggregate.emitted.update(changed)

    def close(self) -> None:
        """Flush pending counters and release the cadence timer."""
        self.flush_srtp_delivery()
        self._closed = True
