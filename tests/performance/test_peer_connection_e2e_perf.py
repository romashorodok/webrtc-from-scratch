from __future__ import annotations

import asyncio
import json
import socket
from unittest.mock import patch

from webrtc.media.av1_payloader import AV1_PAYLOAD_TYPE, Av1Packetizer
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import (
    RtcpPacket,
    RunLengthChunk,
    TransportLayerCC,
    TypeTCCPacketReceivedSmallDelta,
)
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.media.rtp_packet import RtpPacket
from helpers import (
    PeerDriver,
    assert_matches_baseline,
    build_summary_from_baseline,
    load_baseline,
    media_credentials,
    wait_for_conditions,
)
from webrtc.ice import net
from webrtc.lifecycle import PeerCondition
from webrtc.peer_connection import ICEGatherer, PeerConnection
from webrtc.session_description import SessionDescriptionType
from webrtc.tracing import PerformanceRecorder, measure_perf, perf_mark, use_performance_recorder
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection


BASELINE = load_baseline("pc_e2e_loopback_ice_dtls_srtp.json")
AV1_E2E_BASELINE = load_baseline("pc_e2e_loopback_av1_rtp_rtcp_twcc.json")
READY_CONDITIONS = [
    PeerCondition.ICE_CANDIDATE_PAIR_SUCCEEDED,
    PeerCondition.ICE_NOMINATED,
    PeerCondition.NOMINATED_TRANSPORT_READY,
    PeerCondition.DTLS_HANDSHAKE_COMPLETE,
    PeerCondition.SRTP_READY,
]


def test_peer_connection_loopback_ice_dtls_srtp_perf(record_property):
    loopback_interfaces = net.interface_factory(
        net.InterfaceProvider.PSUTIL,
        [socket.AF_INET],
        True,
    )
    loopback_interfaces = [
        interface
        for interface in loopback_interfaces
        if str(interface.address).startswith("127.")
    ]
    assert loopback_interfaces, "no IPv4 loopback interface available for E2E test"

    original_create_agent = ICEGatherer._ICEGatherer__create_agent

    async def create_loopback_agent(self, port=0, interfaces=None):
        return await original_create_agent(self, port, loopback_interfaces)

    with patch.object(ICEGatherer, "_ICEGatherer__create_agent", create_loopback_agent):
        summary, cleanup, protocol_error, recorder = asyncio.run(_run_loopback_scenario())

    record_property("performance_summary", json.dumps(summary, sort_keys=True))

    assert cleanup == {
        "offerer_closed": True,
        "answerer_closed": True,
        "offerer_active_routines": 0,
        "answerer_active_routines": 0,
    }
    assert_matches_baseline(recorder, summary, BASELINE)
    assert protocol_error is None, protocol_error
    assert summary["status"] == "completed"


def test_peer_connection_loopback_av1_rtp_rtcp_twcc_e2e(record_property):
    """Exercise AV1 RTP and reverse TWCC over the negotiated secure transport.

    Sending, receiver-owned TWCC construction, and sender-side feedback
    acceptance all go through ``PeerContext`` public media APIs.
    """
    loopback_interfaces = [
        interface
        for interface in net.interface_factory(net.InterfaceProvider.PSUTIL, [socket.AF_INET], True)
        if str(interface.address).startswith("127.")
    ]
    assert loopback_interfaces, "no IPv4 loopback interface available for E2E test"

    original_create_agent = ICEGatherer._ICEGatherer__create_agent

    async def create_loopback_agent(self, port=0, interfaces=None):
        return await original_create_agent(self, port, loopback_interfaces)

    with patch.object(ICEGatherer, "_ICEGatherer__create_agent", create_loopback_agent):
        summary, recorder = asyncio.run(_run_av1_rtp_rtcp_twcc_scenario())

    record_property("performance_summary", json.dumps(summary, sort_keys=True))
    assert_matches_baseline(recorder, summary, AV1_E2E_BASELINE)
    assert summary["status"] == "completed"


async def _run_av1_rtp_rtcp_twcc_scenario():
    offerer = PeerDriver(PeerConnection(), "pc-av1-offerer")
    answerer = PeerDriver(PeerConnection(), "pc-av1-answerer")
    recorder = PerformanceRecorder()
    with use_performance_recorder(recorder):
        async with offerer, answerer:
            perf_mark("scenario", "run", "started", metadata={"scenario": AV1_E2E_BASELINE["scenario"]})
            await _setup_synthetic_video(offerer)
            await _setup_synthetic_video(answerer)
            await _negotiate_loopback(offerer, answerer, recorder, setup_media=False)

            # The remote track is the application-visible RTP boundary.
            remote_track = await answerer.call(
                lambda context: context.pc._transceivers[0]._receiver.track
            )
            assert remote_track is not None
            # The current SDP implementation assigns its receiver SSRC
            # independently from the local sender encoding; target the
            # negotiated receiver stream to test the actual delivery path.
            media_ssrc = remote_track.ssrc

            frame = _synthetic_av1_frame(payload_size=500)
            perf_mark("media", "frame", "generated", metadata={"counter.media.frames": 1})
            packetizer = Av1Packetizer(
                mtu=80, pt=AV1_PAYLOAD_TYPE, ssrc=media_ssrc,
                clock_rate=90_000, refresh_rate=1 / 30,
            )
            packetize_metadata = {
                "flow_direction": "tx",
                "codec": "AV1",
                "frame_bytes": len(frame),
                "mtu": packetizer.mtu,
            }
            with measure_perf("rtp", "frame.packetize", metadata=packetize_metadata):
                packets = packetizer.packetize(frame, samples=3000)
                packetize_metadata.update({
                    "packet_count": len(packets),
                    "ssrc": media_ssrc,
                    "timestamp": 3000,
                    "counter.rtp.frames_packetized": 1,
                    "counter.rtp.packets_packetized": len(packets),
                })
            assert len(packets) == 7, "fixture packet count is part of the baseline contract"
            twcc = Sequencer(initial_value=31000)
            transport_sequences: list[int] = []
            serialized_packets: list[bytes] = []
            for packet in packets:
                transport_sequence = twcc.next_sequence_number()
                packet.extensions.transport_sequence_number = transport_sequence
                transport_sequences.append(transport_sequence)
                serialized_packets.append(packet.serialize(DEFAULT_EXT_MAP))

            # The only transmission API used by this test is public.
            sent = await offerer.call(
                lambda context: context.send_rtp_packets(serialized_packets)
            )
            assert sent > 0
            received = []
            for _ in packets:
                received.append(RtpPacket.parse(
                    await asyncio.wait_for(remote_track.recv_rtp_pkt_sync(), timeout=5.0),
                    DEFAULT_EXT_MAP,
                ))

            assert [packet.payload_type for packet in received] == [AV1_PAYLOAD_TYPE] * len(packets)
            assert [packet.ssrc for packet in received] == [media_ssrc] * len(packets)
            assert [packet.sequence_number for packet in received] == [packet.sequence_number for packet in packets]
            assert [packet.timestamp for packet in received] == [3000] * len(packets)
            assert [packet.marker for packet in received] == [0] * (len(packets) - 1) + [1]
            assert [packet.extensions.transport_sequence_number for packet in received] == transport_sequences
            assert _depacketize_av1_payloads([packet.payload for packet in received]) == frame
            perf_mark(
                "rtp", "frame", "verified",
                metadata={
                    "flow_direction": "rx",
                    "codec": "AV1",
                    "frame_bytes": len(frame),
                    "packet_count": len(received),
                    "ssrc": media_ssrc,
                    "timestamp": received[0].timestamp,
                    "counter.rtp.frames_verified": 1,
                },
            )

            feedback = await answerer.call(
                lambda context: context.build_twcc_feedback(media_ssrc, transport_sequences)
            )
            assert await answerer.call(lambda context: context.send_rtcp_packet(feedback)) > 0
            parsed_feedback = await asyncio.wait_for(
                offerer.call(lambda context: context.recv_rtcp_feedback(media_ssrc)), timeout=5.0
            )
            assert len(parsed_feedback) == 1
            assert _confirmed_twcc_sequences(parsed_feedback[0]) == transport_sequences
            perf_mark("scenario", "run", "completed", metadata={"scenario": AV1_E2E_BASELINE["scenario"]})

    summary = build_summary_from_baseline(recorder, AV1_E2E_BASELINE)
    return summary, recorder


async def _setup_synthetic_video(peer: PeerDriver) -> None:
    await peer.call(
        lambda context: context.pc.add_transceiver_from_kind(
            RTPCodecKind.Video, RTPTransceiverDirection.Sendrecv
        )
    )


async def _run_loopback_scenario():
    recorder = PerformanceRecorder()
    offerer = PeerDriver(PeerConnection(), "pc-e2e-offerer")
    answerer = PeerDriver(PeerConnection(), "pc-e2e-answerer")
    protocol_error: str | None = None

    with use_performance_recorder(recorder):
        try:
            async with offerer, answerer:
                await _negotiate_loopback(offerer, answerer, recorder)
        except BaseException as exc:
            protocol_error = f"{exc.__class__.__name__}: {exc}"

    summary = build_summary_from_baseline(recorder, BASELINE)

    cleanup = {
        "offerer_closed": offerer.closed,
        "answerer_closed": answerer.closed,
        "offerer_active_routines": offerer.active_routines_after_close,
        "answerer_active_routines": answerer.active_routines_after_close,
    }
    return summary, cleanup, protocol_error, recorder


async def _negotiate_loopback(
    offerer: PeerDriver,
    answerer: PeerDriver,
    recorder: PerformanceRecorder,
    *,
    setup_media: bool = True,
) -> None:
    if setup_media:
        await _setup_synthetic_audio(offerer)
        await _setup_synthetic_audio(answerer)
    await offerer.call(lambda peer: peer.start())
    await answerer.call(lambda peer: peer.start())
    await asyncio.gather(
        wait_for_conditions(
            offerer,
            [PeerCondition.ICE_GATHERING_COMPLETE],
            timeout=5.0,
        ),
        wait_for_conditions(
            answerer,
            [PeerCondition.ICE_GATHERING_COMPLETE],
            timeout=5.0,
        ),
    )

    offer = await offerer.call(lambda peer: peer.pc.create_offer())
    await offerer.call(
        lambda peer: peer.pc.set_local_description(
            SessionDescriptionType.Offer,
            offer,
        )
    )

    await _set_remote_credentials(answerer, offer)
    await answerer.call(
        lambda peer: peer.pc.set_remote_description(
            SessionDescriptionType.Offer,
            offer,
        )
    )

    answer = await answerer.call(lambda peer: peer.pc.create_answer())
    await answerer.call(
        lambda peer: peer.pc.set_local_description(
            SessionDescriptionType.Answer,
            answer,
        )
    )

    await _set_remote_credentials(offerer, answer)
    await offerer.call(
        lambda peer: peer.pc.set_remote_description(
            SessionDescriptionType.Answer,
            answer,
        )
    )

    await _exchange_candidates(
        offerer_candidates=await _local_candidate_strings(offerer),
        answerer_candidates=await _local_candidate_strings(answerer),
        offerer=offerer,
        answerer=answerer,
    )
    await _wait_for_event_count(recorder, "ice.candidate_pair.created", 2, timeout=5.0)
    await answerer.call(lambda peer: peer.accept())
    await offerer.call(lambda peer: peer.dial())

    await asyncio.gather(
        wait_for_conditions(offerer, READY_CONDITIONS, timeout=15.0),
        wait_for_conditions(answerer, READY_CONDITIONS, timeout=15.0),
    )


async def _setup_synthetic_audio(peer: PeerDriver) -> None:
    await peer.call(
        lambda context: context.pc.add_transceiver_from_kind(
            RTPCodecKind.Audio,
            RTPTransceiverDirection.Sendrecv,
        )
    )


async def _local_candidate_strings(peer: PeerDriver) -> list[str]:
    candidates = await peer.call(lambda context: context.pc.gatherer.get_local_candidates())
    return [candidate.to_ice_str() for candidate in candidates or []]


async def _set_remote_credentials(peer: PeerDriver, desc) -> None:
    for ufrag, pwd in media_credentials(desc):
        await peer.call(
            lambda context, ufrag=ufrag, pwd=pwd: context.set_remote_credentials(
                ufrag,
                pwd,
            )
        )


async def _exchange_candidates(
    *,
    offerer_candidates: list[str],
    answerer_candidates: list[str],
    offerer: PeerDriver,
    answerer: PeerDriver,
) -> None:
    assert offerer_candidates, "offer SDP did not contain ICE candidates"
    assert answerer_candidates, "answer SDP did not contain ICE candidates"

    for candidate in offerer_candidates:
        await answerer.call(
            lambda context, candidate=candidate: context.add_remote_candidate(candidate)
        )
    for candidate in answerer_candidates:
        await offerer.call(
            lambda context, candidate=candidate: context.add_remote_candidate(candidate)
        )


async def _wait_for_event_count(
    recorder: PerformanceRecorder,
    name: str,
    min_count: int,
    *,
    timeout: float,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        count = sum(1 for event in recorder.events() if event.name == name)
        if count >= min_count:
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(f"timed out waiting for {min_count} {name} events")
        await asyncio.sleep(0.01)


def _synthetic_av1_frame(*, payload_size: int) -> bytes:
    return bytes([6 << 3]) + bytes(index % 251 for index in range(payload_size))


def _depacketize_av1_payloads(payloads: list[bytes]) -> bytes:
    chunks: list[bytes] = []
    for index, payload in enumerate(payloads):
        assert payload, f"empty AV1 RTP payload at index {index}"
        aggregation_header = payload[0]
        assert bool(aggregation_header & 0x80) == (index > 0)
        assert bool(aggregation_header & 0x40) == (index < len(payloads) - 1)
        assert ((aggregation_header >> 4) & 0x03) == 1
        chunks.append(payload[1:])
    return b"".join(chunks)


def _confirmed_twcc_sequences(feedback: TransportLayerCC) -> list[int]:
    assert isinstance(feedback, TransportLayerCC)
    confirmed: list[int] = []
    sequence = feedback.base_sequence_number
    delta_index = 0
    status_index = 0
    for chunk in feedback.packet_chunks:
        assert isinstance(chunk, RunLengthChunk)
        for _ in range(chunk.run_length):
            if status_index >= feedback.packet_status_count:
                break
            if chunk.packet_status_symbol == TypeTCCPacketReceivedSmallDelta:
                assert delta_index < len(feedback.recv_deltas)
                confirmed.append(sequence)
                delta_index += 1
            sequence = (sequence + 1) & 0xFFFF
            status_index += 1
    assert delta_index == len(feedback.recv_deltas)
    return confirmed
