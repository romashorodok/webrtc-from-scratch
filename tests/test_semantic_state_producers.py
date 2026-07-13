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

            lane_owner = f"worker:scope:{runtime.worker_lane.observability_id}"
            lane = _facets(runtime, lane_owner)
            assert lane == {
                "queued": 1, "running": True, "lane_kind": "serialized",
            }

            queue = Interceptor(maxsize=2, queue_id="test-packets")
            queue.put_nowait(Packet(Address("127.0.0.1", 9), b"one"))
            queue.put_nowait(Packet(Address("127.0.0.1", 9), b"two"))
            await queue.get()
            queue_owner = f"queue:scope:{queue.observability_id}"
            assert _facets(runtime, queue_owner) == {
                "depth": 1, "high_water": 2, "queue_kind": "test-packets",
            }

            release.set()
            await asyncio.gather(running, waiting)
            assert _facets(runtime, lane_owner) == {
                "queued": 0, "running": False, "lane_kind": "serialized",
            }

    asyncio.run(scenario())


def test_same_kind_queues_have_stable_distinct_instance_entities():
    async def scenario():
        async with Runtime(scope_id="scope") as runtime:
            first = Interceptor(queue_id="packets")
            second = Interceptor(queue_id="packets")
            packet = Packet(Address("127.0.0.1", 9), b"one")

            first.put_nowait(packet)
            second.put_nowait(packet)
            first_owner = f"queue:scope:{first.observability_id}"
            second_owner = f"queue:scope:{second.observability_id}"
            assert first_owner != second_owner
            assert _facets(runtime, first_owner)["depth"] == 1
            assert _facets(runtime, second_owner)["depth"] == 1

            first_revision = next(
                item.revision for item in runtime.projection.facets.snapshots()
                if item.facet_id == f"{first_owner}:depth"
            )
            await first.get()
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
                f"media:scope:{first_stream.observability_id}",
                f"media:scope:{second_stream.observability_id}",
                f"media:scope:{another_stream.observability_id}",
            }
            assert len(owners) == 3
            facets = [_facets(runtime, owner) for owner in owners]
            assert {item["stream_count"] for item in facets} == {1, 2}
            assert all(item["media_kind"] == "srtp_stream" for item in facets)
            assert all(item["ssrc_id"].startswith("ssrc-") for item in facets)
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
            initial = _facets(runtime, "peer:scope")
            assert initial == {
                "lifecycle": "new", "signaling": "stable", "connection": "new",
            }

            transceiver = await peer.add_transceiver_from_kind(
                RTPCodecKind.Audio, RTPTransceiverDirection.Sendonly
            )
            owner = f"transceiver:scope:{transceiver.observability_id}"
            assert _facets(runtime, owner) == {
                "direction": "sendonly", "active": True, "lifecycle": "active",
            }
            media_owner = f"media:scope:{transceiver.observability_id}"
            assert _facets(runtime, media_owner)["direction"] == "sendonly"

            second = await peer.add_transceiver_from_kind(
                RTPCodecKind.Audio, RTPTransceiverDirection.Sendonly
            )
            second_owner = f"transceiver:scope:{second.observability_id}"
            second_media_owner = f"media:scope:{second.observability_id}"
            assert transceiver.observability_id.endswith(":transceiver-1")
            assert second.observability_id.endswith(":transceiver-2")
            assert second_owner != owner
            assert _facets(runtime, second_owner)["direction"] == "sendonly"
            assert _facets(runtime, second_media_owner)["active"] is True

            another_peer = PeerConnection()
            cross_peer = await another_peer.add_transceiver_from_kind(
                RTPCodecKind.Audio, RTPTransceiverDirection.Sendonly
            )
            assert cross_peer.observability_id.endswith(":transceiver-1")
            assert cross_peer.observability_id != transceiver.observability_id
            assert _facets(
                runtime, f"transceiver:scope:{cross_peer.observability_id}"
            )["active"] is True

            subscription = runtime.trace_patch_subscribe(maxsize=4)
            await subscription.get()
            assert _facets(runtime, "tracing:scope") == {
                "admitted": True, "subscriber_count": 1, "journal_depth": 0,
                "dispatcher_drops": 0, "dispatcher_observer_failures": 0,
            }
            subscription.close()
            assert _facets(runtime, "tracing:scope")["subscriber_count"] == 0

            transceiver.stop()
            assert _facets(runtime, owner)["lifecycle"] == "stopped"
            assert _facets(runtime, media_owner)["lifecycle"] == "ended"
            assert _facets(runtime, second_owner)["lifecycle"] == "active"
            stopped_revisions = {
                item.facet_id: item.revision
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id in {owner, media_owner}
            }
            transceiver.stop()
            assert {
                item.facet_id: item.revision
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id in {owner, media_owner}
            } == stopped_revisions

    asyncio.run(scenario())
