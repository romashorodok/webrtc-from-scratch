import asyncio
import threading

from webrtc import Runtime
from webrtc.ice.net.types import Address, Packet
from webrtc.ice.net.udp_mux import Interceptor
from webrtc.peer_connection import PeerConnection
from webrtc.srtp.session import Session, SessionKeys
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection


def _facets(runtime: Runtime, owner: str) -> dict[str, object]:
    return {
        item.facet_id.rsplit(":", 1)[-1]: item.value
        for item in runtime.projection.facets.snapshots()
        if item.owner_entity_id == owner
    }


def _facet_snapshots(runtime: Runtime, owner: str):
    return [
        item for item in runtime.projection.facets.snapshots()
        if item.owner_entity_id == owner
    ]


def test_production_worker_lane_and_packet_queue_publish_live_state():
    async def scenario():
        async with Runtime(scope_id="scope", max_workers=1) as runtime:
            entered = threading.Event()
            release = threading.Event()

            def blocking():
                entered.set()
                release.wait(2)

            running = asyncio.create_task(runtime.worker_lane.run(blocking))
            await asyncio.to_thread(entered.wait, 1)
            waiting = asyncio.create_task(runtime.worker_lane.run(lambda: None))
            await asyncio.sleep(0)

            lane_owner = runtime._worker_entity_id
            lane = _facets(runtime, lane_owner)
            assert lane["queued"] == 0
            assert lane["running"] >= 1
            assert lane["lane_kind"] == "concurrent"
            assert {item.observer_meta for item in _facet_snapshots(runtime, lane_owner)} == {"aggregate"}

            queue = Interceptor(maxsize=2, queue_id="test-packets")
            queue.put_nowait(Packet(Address("127.0.0.1", 9), b"one"))
            queue.put_nowait(Packet(Address("127.0.0.1", 9), b"two"))
            await queue.get()
            await asyncio.sleep(0)
            queue_owner = runtime.telemetry_entity_id("queue", queue.entity_id)
            queue_facets = _facets(runtime, queue_owner)
            assert queue_facets["depth"] == 1
            assert queue_facets["high_water"] == 2
            assert queue_facets["queue_kind"] == "test-packets"
            assert {item.observer_meta for item in _facet_snapshots(runtime, queue_owner)} == {"aggregate"}

            release.set()
            await asyncio.gather(running, waiting)
            while _facets(runtime, lane_owner).get("running") != 0:
                await asyncio.sleep(0)
            lane = _facets(runtime, lane_owner)
            assert lane["queued"] == lane["running"] == 0
            assert lane["high_water"] >= 1
            assert lane["lane_kind"] == "concurrent"
            await queue.aclose()

    asyncio.run(scenario())


def test_same_kind_queues_have_stable_distinct_instance_entities():
    async def scenario():
        async with Runtime(scope_id="scope") as runtime:
            first = Interceptor(queue_id="packets")
            second = Interceptor(queue_id="packets")
            packet = Packet(Address("127.0.0.1", 9), b"one")

            first.put_nowait(packet)
            second.put_nowait(packet)
            await asyncio.sleep(0)
            first_owner = runtime.telemetry_entity_id("queue", first.entity_id)
            second_owner = runtime.telemetry_entity_id("queue", second.entity_id)
            assert first_owner != second_owner
            assert _facets(runtime, first_owner)["depth"] == 1
            assert _facets(runtime, second_owner)["depth"] == 1

            first_revision = next(
                item.revision for item in runtime.projection.facets.snapshots()
                if item.facet_id == f"{first_owner}:depth"
            )
            await first.get()
            await asyncio.sleep(0)
            assert _facets(runtime, first_owner)["depth"] == 0
            assert _facets(runtime, second_owner)["depth"] == 1
            assert next(
                item.revision for item in runtime.projection.facets.snapshots()
                if item.facet_id == f"{first_owner}:depth"
            ) == first_revision + 1

    asyncio.run(scenario())


def test_srtp_sessions_and_streams_do_not_collapse_and_repeat_open_is_stable():
    async def scenario():
        keys = SessionKeys(b"a" * 16, b"b" * 14, b"a" * 16, b"b" * 14)
        async with Runtime(scope_id="scope") as runtime:
            first = Session(keys, observability_id="srtp-rtp-a")
            second = Session(keys, observability_id="srtp-rtp-b")
            first_stream = await first.open_stream(0x12345678)
            second_stream = await second.open_stream(0x12345678)
            another_stream = await first.open_stream(0x87654321)

            owners = {
                runtime.telemetry_entity_id("media", first_stream.observability_id),
                runtime.telemetry_entity_id("media", second_stream.observability_id),
                runtime.telemetry_entity_id("media", another_stream.observability_id),
            }
            assert len(owners) == 3
            facets = [_facets(runtime, owner) for owner in owners]
            assert {item["stream_count"] for item in facets} == {1, 2}
            assert all(item["media_kind"] == "srtp_stream" for item in facets)
            assert all(item["ssrc_id"].startswith("telemetry:ssrc:") for item in facets)
            assert len({item["ssrc_id"] for item in facets}) == 3
            assert all("305419896" not in item["ssrc_id"] for item in facets)

            before = {
                item.facet_id: item.revision
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id in owners
            }
            assert await first.open_stream(0x12345678) is first_stream
            after = {
                item.facet_id: item.revision
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id in owners
            }
            assert after == before

    asyncio.run(scenario())


def test_peer_sendonly_transceiver_and_tracing_health_use_production_paths():
    async def scenario():
        async with Runtime(scope_id="scope", trace_patch_cadence=60) as runtime:
            peer = PeerConnection()
            peer.__compose_runtime__(runtime)
            assert runtime.projection.machines.get("peer:scope") is None
            assert peer._peer_runner.snapshot().state == "new"

            transceiver = await peer.add_transceiver_from_kind(
                RTPCodecKind.Audio, RTPTransceiverDirection.Sendonly
            )
            owner = transceiver.entity_id
            facets = _facets(runtime, owner)
            assert facets["direction"] == "sendonly"
            assert facets["active"] is True
            assert {item.observer_meta for item in _facet_snapshots(runtime, owner)} == {"exact"}

            second = await peer.add_transceiver_from_kind(
                RTPCodecKind.Audio, RTPTransceiverDirection.Sendonly
            )
            second_owner = second.entity_id
            assert transceiver.observability_id.endswith(":transceiver-1")
            assert second.observability_id.endswith(":transceiver-2")
            assert second_owner != owner
            assert _facets(runtime, second_owner)["direction"] == "sendonly"

            another_peer = PeerConnection()
            another_peer.__compose_runtime__(runtime)
            cross_peer = await another_peer.add_transceiver_from_kind(
                RTPCodecKind.Audio, RTPTransceiverDirection.Sendonly
            )
            assert cross_peer.observability_id.endswith(":transceiver-1")
            assert cross_peer.observability_id != transceiver.observability_id
            assert _facets(
                runtime, cross_peer.entity_id
            )["active"] is True

            subscription = runtime.trace_patch_subscribe(maxsize=4)
            await subscription.get()
            assert _facets(runtime, runtime._observability_entity_id)[
                "subscriber_count"
            ] == 1
            subscription.close()
            assert _facets(runtime, runtime._observability_entity_id)[
                "subscriber_count"
            ] == 0

            transceiver.stop()
            while transceiver._runner.snapshot().state != "stopped":
                await asyncio.sleep(0)
            await runtime.flush_observations()
            assert runtime.projection.machines.get(owner).state == "stopped"
            assert runtime.projection.machines.get(second_owner).state == "active"
            stopped_revisions = {
                item.facet_id: item.revision
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == owner
            }
            transceiver.stop()
            assert {
                item.facet_id: item.revision
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == owner
            } == stopped_revisions

    asyncio.run(scenario())
