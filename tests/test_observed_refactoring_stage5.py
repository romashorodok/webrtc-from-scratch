import asyncio
import inspect
from pathlib import Path

from webrtc.ice.net.udp_mux import Interceptor
from webrtc.peer_components import PeerConnectionLogInbox, PeerEventInbox
from webrtc.queue_machine import RuntimeOwnedQueue
from webrtc.runtime import Runtime
from webrtc.srtp.session import Session, Stream


def test_runtime_telemetry_key_and_ssrc_cardinality_are_bounded_and_redacted():
    async def scenario():
        async with Runtime(scope_id="stage5-bounds") as runtime:
            reducer = runtime._aggregate_facet_adapter
            for index in range(300):
                runtime.record_queue_activity(
                    entity_id=f"queue:{index}", queue_kind="test", depth=1,
                )
            for ssrc in range(100):
                runtime.record_srtp_packet(
                    session_id="session", protocol="rtp", ssrc=ssrc,
                )
            for index in range(1000):
                runtime.record_srtp_delivery(
                    protocol="rtp", stream_id=f"untrusted-stream-{index}",
                    delivered=True,
                )
            assert len(reducer._queues) <= 256
            assert len(reducer._srtp_delivery) <= 256
            packet_key = reducer._alias("session-key", "session")
            assert len(reducer._srtp_packets[packet_key].ssrc_aliases) == 64
            assert all(key.startswith("ssrc-") for key in
                       reducer._srtp_packets[packet_key].ssrc_aliases)
            assert runtime.diagnostics["telemetry_key_evictions"] > 0
            assert runtime.diagnostics["telemetry_ssrc_overflow"] == 36
            assert runtime.diagnostics["srtp_delivery_key_evictions"] == 744

    asyncio.run(scenario())


def test_queue_reducer_coalesces_and_projection_failure_is_isolated():
    async def scenario():
        async with Runtime(scope_id="stage5-coalesce") as runtime:
            queue = RuntimeOwnedQueue[int](4, entity_id="queue:stage5", queue_kind="test")
            calls = 0
            original = runtime.projection.merge_values

            def count(*args, **kwargs):
                nonlocal calls
                calls += 1
                return original(*args, **kwargs)

            runtime.projection.merge_values = count
            queue.put_nowait(1)
            queue.put_nowait(2)
            assert queue.get_nowait() == 1
            assert calls == 0
            await asyncio.sleep(0)
            assert calls == 1

            runtime.projection.merge_values = lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("projection failed")
            )
            assert queue.get_nowait() == 2
            await asyncio.sleep(0)
            assert runtime.diagnostics["queue_facet_publish_failures"] == 1
            runtime.projection.merge_values = original
            await queue.close()

    asyncio.run(scenario())


def test_protocol_and_component_objects_do_not_declare_telemetry_counter_fields():
    forbidden = (
        "frame_count", "_decrypt_count", "_decrypt_errors", "_ssrc_counters",
        "_queue_high_water", "_queue_delivered", "_queue_dequeued",
        "_queue_dropped", "_media_send_high_water",
        "_dtls_count", "_rtcp_count", "_rtp_count", "_total_packets",
        "send_count", "_debug_count",
    )
    sources = Path("webrtc/audio/analyzer.py").read_text() + "\n" + "\n".join(
        inspect.getsource(item) for item in (
        Session, Stream, Interceptor,
        PeerEventInbox, PeerConnectionLogInbox,
    ))
    assert not any(f"self.{name} =" in sources for name in forbidden)


def test_telemetry_failure_and_tracing_toggle_do_not_change_queue_protocol_result():
    async def run(enabled: bool, fail_telemetry: bool):
        async with Runtime(tracing_enabled=enabled) as runtime:
            if fail_telemetry:
                runtime._aggregate_facet_adapter.queue_activity = (
                    lambda **_values: (_ for _ in ()).throw(RuntimeError("telemetry"))
                )
            queue = RuntimeOwnedQueue[int](2, entity_id=f"queue:{enabled}", queue_kind="parity")
            queue.put_nowait(7)
            result = queue.get_nowait()
            await queue.close()
            return result, queue._state

    assert asyncio.run(run(False, False)) == asyncio.run(run(True, False)) == (7, "closed")
    assert asyncio.run(run(True, True)) == (7, "closed")


def test_invalid_deltas_never_create_negative_telemetry_totals():
    async def scenario():
        async with Runtime() as runtime:
            runtime.record_queue_activity(
                entity_id="queue:invalid", queue_kind="test", depth=1,
                deltas={"admitted": 5},
            )
            runtime.record_queue_activity(
                entity_id="queue:invalid", queue_kind="test", depth=-4,
                deltas={"admitted": -8}, gauges={"running": -1},
            )
            snapshot = runtime.queue_telemetry_snapshot("queue:invalid")
            assert snapshot["admitted"] == 5
            assert snapshot["depth"] == 0
            assert "running" not in snapshot
            assert runtime.diagnostics["telemetry_invalid_samples"] == 3

    asyncio.run(scenario())


def test_raw_telemetry_identifiers_are_never_projected():
    async def scenario():
        secret = "customer@example.test/session/123"
        async with Runtime(scope_id=secret) as runtime:
            runtime.record_queue_activity(
                entity_id=secret, queue_kind="packets", depth=1, exact=True,
            )
            runtime.record_srtp_stream(
                protocol="rtp", session_id=secret, stream_id=secret,
                ssrc_id=secret, stream_count=1,
            )
            rendered = "\n".join(
                f"{item.facet_id}|{item.owner_entity_id}|{item.source_entity_id}|{item.value}"
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id.startswith("telemetry:")
            )
            assert secret not in rendered
            assert "telemetry:queue:" in rendered
            assert "telemetry:media:" in rendered

    asyncio.run(scenario())


def test_srtp_final_flush_projection_failure_cannot_fail_runtime_shutdown():
    async def scenario():
        runtime = Runtime(srtp_delivery_facet_cadence=60)
        await runtime.__aenter__()
        runtime.record_srtp_delivery(
            protocol="rtp", stream_id="pending", delivered=True,
        )
        runtime.projection.merge_values = lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("projection unavailable")
        )
        await runtime.__aexit__(None, None, None)
        assert runtime.diagnostics["srtp_delivery_facet_publish_failures"] >= 1

    asyncio.run(scenario())


def test_srtp_failed_cadence_publish_retains_interval_until_recovery():
    async def scenario():
        async with Runtime(srtp_delivery_facet_cadence=60) as runtime:
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="recover", delivered=True,
            )
            original = runtime.projection.merge_values
            runtime.projection.merge_values = lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("projection unavailable")
            )
            runtime._aggregate_facet_adapter.flush_srtp_delivery()
            aggregate = next(iter(runtime._aggregate_facet_adapter._srtp_delivery.values()))
            assert aggregate.delivered_packets == aggregate.interval_delivered == 1
            assert aggregate.emitted == {}

            runtime.projection.merge_values = original
            runtime._aggregate_facet_adapter.flush_srtp_delivery()
            owner = runtime.telemetry_entity_id("srtp-delivery", "recover")
            delivered = next(
                item for item in runtime.projection.facets.snapshots()
                if item.facet_id == f"{owner}:delivered_packets"
            )
            assert delivered.value == 1
            assert aggregate.interval_delivered == 0

    asyncio.run(scenario())


def test_srtp_failed_eviction_publish_is_bounded_and_retried():
    async def scenario():
        async with Runtime(srtp_delivery_facet_cadence=60) as runtime:
            reducer = runtime._aggregate_facet_adapter
            for index in range(256):
                runtime.record_srtp_delivery(
                    protocol="rtp", stream_id=f"stream-{index}", delivered=True,
                )
            original = runtime.projection.merge_values
            runtime.projection.merge_values = lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("projection unavailable")
            )
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="stream-256", delivered=True,
            )
            assert len(reducer._srtp_delivery) == 256
            assert len(reducer._srtp_delivery_retry) == 1
            assert next(iter(reducer._srtp_delivery_retry.values())).delivered_packets == 1

            runtime.projection.merge_values = original
            reducer.flush_srtp_delivery()
            assert reducer._srtp_delivery_retry == {}
            old_owner = runtime.telemetry_entity_id("srtp-delivery", "stream-0")
            assert next(
                item.value for item in runtime.projection.facets.snapshots()
                if item.facet_id == f"{old_owner}:delivered_packets"
            ) == 1

    asyncio.run(scenario())


def test_srtp_failure_reason_is_a_closed_sanitized_category():
    async def scenario():
        raw = "customer@example.test/private/reason"
        async with Runtime(srtp_delivery_facet_cadence=60) as runtime:
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="reason", delivered=False,
                failure_reason=raw,
            )
            aggregate = next(iter(runtime._aggregate_facet_adapter._srtp_delivery.values()))
            assert aggregate.last_failure == "other"
            assert raw not in repr(aggregate)
            owner = runtime.telemetry_entity_id("srtp-delivery", "reason")
            reason = next(
                item.value for item in runtime.projection.facets.snapshots()
                if item.facet_id == f"{owner}:last_failure"
            )
            assert reason == "other"

    asyncio.run(scenario())


def test_srtp_retry_overflow_coalesces_all_totals_in_constant_space():
    async def scenario():
        async with Runtime(srtp_delivery_facet_cadence=60) as runtime:
            reducer = runtime._aggregate_facet_adapter
            original = runtime.projection.merge_values
            runtime.projection.merge_values = lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("projection unavailable")
            )
            for index in range(356):
                runtime.record_srtp_delivery(
                    protocol="rtp", stream_id=f"stress-{index}", delivered=True,
                )
            assert len(reducer._srtp_delivery) == 256
            assert len(reducer._srtp_delivery_retry) == 32
            assert reducer._srtp_delivery_overflow is not None
            assert reducer._srtp_delivery_overflow.delivered_packets == 68
            assert runtime.diagnostics["srtp_delivery_identity_coalesced"] == 68

            runtime.projection.merge_values = original
            reducer.flush_srtp_delivery()
            delivered_total = sum(
                item.value for item in runtime.projection.facets.snapshots()
                if item.facet_id.endswith(":delivered_packets")
                and item.owner_entity_id.startswith("telemetry:srtp-delivery")
            )
            assert delivered_total == 356
            assert reducer._srtp_delivery_retry == {}
            assert reducer._srtp_delivery_overflow.interval_delivered == 0

    asyncio.run(scenario())


def test_srtp_retry_key_reentry_merges_cumulative_baseline():
    async def scenario():
        async with Runtime(srtp_delivery_facet_cadence=60) as runtime:
            reducer = runtime._aggregate_facet_adapter
            for index in range(256):
                runtime.record_srtp_delivery(
                    protocol="rtp", stream_id=f"reentry-{index}", delivered=True,
                )
            original = runtime.projection.merge_values
            runtime.projection.merge_values = lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("projection unavailable")
            )
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="new-key", delivered=True,
            )
            reentry_entity = runtime.telemetry_entity_id(
                "srtp-delivery", "reentry-0"
            )
            assert reentry_entity in reducer._srtp_delivery_retry
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="reentry-0", delivered=True,
            )
            assert reentry_entity not in reducer._srtp_delivery_retry
            assert reducer._srtp_delivery[reentry_entity].delivered_packets == 2

            runtime.projection.merge_values = original
            reducer.flush_srtp_delivery()
            assert next(
                item.value for item in runtime.projection.facets.snapshots()
                if item.facet_id == f"{reentry_entity}:delivered_packets"
            ) == 2

    asyncio.run(scenario())
