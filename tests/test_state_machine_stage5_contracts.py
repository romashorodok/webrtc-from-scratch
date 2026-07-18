import asyncio
from types import SimpleNamespace

from webrtc import Runtime
from webrtc.peer_connection import PeerConnection
from webrtc.transceiver import (
    MediaCaps, RTPCodecKind, RTPCodecParameters, RTPDecodingParameters,
    RTPReceiver, RTPRtxParameters, RTPSender, RTPTransceiver,
    RTPTransceiverDirection, TrackLocal, TrackRemote,
)
from webrtc.state_machine import StaleMachineAccess


class _SnapshotOwner:
    def __init__(self, entity_id, machine_type, state, revision):
        self.value = SimpleNamespace(
            entity_id=entity_id, machine_type=machine_type, state=state,
            revision=revision, epoch=1, terminal=False,
        )

    def snapshot(self):
        return self.value


class _Session:
    def __init__(self, protocol):
        self._snapshot = SimpleNamespace(
            entity_id=f"srtp:{protocol}", machine_type="srtp-session",
            state="ready", revision=2, epoch=1, terminal=False,
        )

    def lifecycle_snapshot(self):
        return self._snapshot


class _Gatherer:
    async def start(self):
        return None

    async def aclose_controllers(self):
        return None

    async def aclose(self):
        return None


class _SelectedTransport:
    def __init__(self):
        self._runner = _SnapshotOwner("transport:test", "transport", "ready", 2)

    async def aclose(self):
        return None

    def selected_snapshot(self):
        return self._runner.snapshot().revision, self


class _DtlsTransport:
    def __init__(self):
        self._runner = _SnapshotOwner(
            "dtls:test", "dtls-transport", "connected", 4,
        )
        self._srtp_rtp = _Session("rtp")
        self._srtp_rtcp = _Session("rtcp")
        self.in_flight = 0
        self.max_in_flight = 0
        self.release = asyncio.Event()

    async def wait(self, *_args, **_kwargs):
        return None

    async def write_rtp_bytes(self, packet):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        await self.release.wait()
        self.in_flight -= 1
        return len(packet)

    async def write_rtcp_bytes(self, packet):
        return await self.write_rtp_bytes(packet)

    async def aclose(self):
        return None


def _facets(runtime, entity_id):
    return {
        item.facet_id.rsplit(":", 1)[-1]: item.value
        for item in runtime.projection.facets.snapshots()
        if item.owner_entity_id == entity_id
    }


def test_stage5_transceiver_configuration_has_one_exact_machine_authority():
    async def scenario():
        async with Runtime(scope_id="stage5-transceiver") as runtime:
            transceiver = RTPTransceiver(
                object(), MediaCaps(), RTPCodecKind.Audio,
                RTPTransceiverDirection.Sendonly,
                observability_id="peer:test:transceiver-1",
            )
            await transceiver.wait_active()
            codec = RTPCodecParameters("audio/opus", 48000, 50, 2, "", 111, "opus")
            await transceiver.set_prefered_codec(codec)
            await transceiver.set_mid(7)

            snapshot = transceiver._runner.snapshot()
            observed = runtime.projection.machines.get(transceiver.entity_id)
            facets = _facets(runtime, transceiver.entity_id)
            assert observed.state == snapshot.state == "active"
            # Activation and each complete configuration pass through the
            # authoritative negotiating state before the atomic active commit.
            assert observed.revision == snapshot.revision == 6
            assert facets["mid"] == "7"
            provenance = [
                item for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == transceiver.entity_id
            ]
            assert {item.observer_meta for item in provenance} == {"exact"}
            assert {item.source_revision for item in provenance} == {observed.revision}
            assert "_stopped" not in transceiver.__dict__

            replacement = transceiver.negotiated_snapshot
            replaced = await transceiver.apply_negotiated_snapshot(
                replacement, expected_epoch=snapshot.epoch,
                expected_revision=snapshot.revision,
            )
            assert replaced.revision == snapshot.revision + 2
            assert all(
                item.from_state != item.to_state
                for item in runtime.projection.machines.transition_snapshots()
                if item.entity_id == transceiver.entity_id
            )

            await transceiver.aclose()
            assert runtime.projection.machines.get(transceiver.entity_id) is None

    asyncio.run(scenario())


def test_stage5_media_send_lane_is_bounded_concurrent_and_reconciled():
    async def scenario():
        peer = PeerConnection()
        peer.gatherer = _Gatherer()
        peer._ice_transport = _SelectedTransport()
        dtls = _DtlsTransport()
        peer._dtls_transport = dtls

        async with Runtime(scope_id="stage5-media") as runtime:
            await peer.__aenter__()
            first = asyncio.create_task(peer.send_rtp_packet(b"first"))
            second = asyncio.create_task(peer.send_rtp_packets([b"two", b"three"]))
            for _ in range(20):
                if dtls.max_in_flight == 2:
                    break
                await asyncio.sleep(0)
            assert dtls.max_in_flight == 2
            assert peer._media_send_mailbox.capacity == 32
            assert peer.media_send_epoch == 1
            assert "_media_send_runner" not in peer.__dict__
            assert "_media_send_lock" not in peer.__dict__
            dtls.release.set()
            assert await first == 5
            assert await second == 8
            await peer.aclose()

            observed = runtime.projection.machines.get(peer.media_send_entity_id)
            facets = _facets(runtime, peer.media_send_entity_id)
            assert observed is None
            assert facets == {}

    asyncio.run(scenario())


def test_stage5_media_send_close_forgets_blocked_unadmitted_requests():
    async def scenario():
        peer = PeerConnection()
        peer.gatherer = _Gatherer()
        peer._ice_transport = _SelectedTransport()
        dtls = _DtlsTransport()
        peer._dtls_transport = dtls

        async with Runtime(scope_id="stage5-media-close-race"):
            await peer.__aenter__()
            sends = [
                asyncio.create_task(peer.send_rtp_packet(bytes([index])))
                for index in range(44)
            ]
            for _ in range(100):
                if peer._media_send_mailbox.depth == 32:
                    break
                await asyncio.sleep(0)
            assert peer._media_send_mailbox.depth == 32

            closing = asyncio.create_task(peer.aclose())
            for _ in range(20):
                if peer._media_send_mailbox.closed:
                    break
                await asyncio.sleep(0)
            dtls.release.set()
            await closing
            await asyncio.gather(*sends, return_exceptions=True)

            assert peer._media_send_requests == {}
            assert peer._media_send_results == {}
            assert peer._media_send_abandoned == set()
            assert peer._media_send_next_commit == peer._media_send_submission_id + 1

    asyncio.run(scenario())


def test_stage5_sender_receiver_and_tracks_are_runtime_owned_lifecycles():
    async def scenario():
        async with Runtime(scope_id="stage5-components") as runtime:
            codec = RTPCodecParameters("audio/opus", 48000, 50, 2, "", 111, "opus")
            local = TrackLocal("local", "stream", RTPCodecKind.Audio, codec)
            sender = RTPSender(MediaCaps(), observability_id="sender:test")
            await sender.add_encoding(local)
            await sender.bind(object())
            assert sender._runner.snapshot().state == "active"
            assert local._runner.snapshot().state == "live"
            await sender.pause()
            assert sender._runner.snapshot().state == "paused"
            await sender.resume()

            receiver = RTPReceiver(
                MediaCaps(), RTPCodecKind.Audio, observability_id="receiver:test",
            )
            receiver.receive(RTPDecodingParameters(
                "rid", 7, 111, RTPRtxParameters(8),
            ))
            receiver.bind(object())
            for _ in range(10):
                if receiver._runner.snapshot().state == "active":
                    break
                await asyncio.sleep(0)
            assert receiver._runner.snapshot().state == "active"
            assert runtime.projection.machines.get("receiver:test").state == "active"

            await local.mute()
            assert local._runner.snapshot().state == "muted"
            await local.unmute()
            try:
                await sender._transition(
                    sender._runner.spec.machine_type and "pause", expected_revision=0,
                )
            except StaleMachineAccess:
                pass
            else:
                raise AssertionError("stale sender revision was accepted")

            await receiver.aclose()
            await sender.aclose()
            assert receiver._runner.snapshot().state == "stopped"
            assert sender._runner.snapshot().state == "stopped"
            assert local._runner.snapshot().state == "ended"

    asyncio.run(scenario())


def test_stage5_remote_track_queue_overflow_is_explicit_and_bounded():
    async def scenario():
        async with Runtime(scope_id="stage5-track-overflow"):
            track = TrackRemote(RTPCodecKind.Audio, 1, 2, "rid")
            for _ in range(1000):
                assert await track.write_rtp_bytes(b"packet")
            assert not await track.write_rtp_bytes(b"overflow")
            await track.aclose()

    asyncio.run(scenario())
