from __future__ import annotations

import json
from collections.abc import Sequence

from webrtc.media.av1_payloader import AV1_PAYLOAD_TYPE, Av1Packetizer
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import (
    RecvDelta,
    RtcpPacket,
    RunLengthChunk,
    TransportLayerCC,
    TypeTCCPacketReceivedSmallDelta,
)
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.media.rtp_packet import RtpPacket
from webrtc.tracing import PerformanceRecorder, perf_mark

from helpers import assert_matches_baseline, build_summary_from_baseline, load_baseline


def test_av1_rtp_packetization_depacketization_and_twcc_confirmation(record_property):
    baseline = load_baseline("av1_rtp_packetization_twcc.json")
    recorder = PerformanceRecorder()
    frame = _synthetic_av1_frame(payload_size=500)
    packetizer = Av1Packetizer(
        mtu=80,
        pt=AV1_PAYLOAD_TYPE,
        ssrc=0xA71A71,
        clock_rate=90_000,
        refresh_rate=1 / 30,
    )
    twcc = Sequencer(initial_value=31000)

    with recorder.use():
        perf_mark("scenario", "run", "started", metadata={"scenario": baseline["scenario"]})
        perf_mark(
            "media",
            "frame",
            "generated",
            metadata={"codec": "AV1", "counter.media.frames": 1, "frame_bytes": len(frame)},
        )
        perf_mark("rtp", "packetize", "started", metadata={"codec": "AV1", "mtu": 80})
        packets = packetizer.packetize(frame, samples=3000)
        perf_mark(
            "rtp",
            "packetize",
            "completed",
            metadata={
                "codec": "AV1",
                "counter.rtp.packets": len(packets),
                "counter.rtp.frames": 1,
            },
        )

        parsed_packets: list[RtpPacket] = []
        transport_sequences: list[int] = []
        for index, packet in enumerate(packets):
            transport_sequence = twcc.next_sequence_number()
            packet.extensions.transport_sequence_number = transport_sequence
            serialized = packet.serialize(DEFAULT_EXT_MAP)
            parsed = RtpPacket.parse(serialized, DEFAULT_EXT_MAP)
            parsed_packets.append(parsed)
            transport_sequences.append(transport_sequence)

            assert parsed.payload_type == AV1_PAYLOAD_TYPE
            assert parsed.ssrc == packet.ssrc
            assert parsed.sequence_number == packet.sequence_number
            assert parsed.timestamp == 3000
            assert parsed.extensions.transport_sequence_number == transport_sequence
            assert parsed.marker == (1 if index == len(packets) - 1 else 0)

            perf_mark(
                "rtp",
                "packet",
                "serialized",
                metadata={
                    "codec": "AV1",
                    "sequence_number": parsed.sequence_number,
                    "transport_sequence_number": transport_sequence,
                    "payload_bytes": len(parsed.payload),
                    "counter.rtp.serialized": 1,
                },
            )

        depacketized_frame = _depacketize_av1_payloads([packet.payload for packet in parsed_packets])
        for parsed in parsed_packets:
            perf_mark(
                "rtp",
                "packet",
                "depacketized",
                metadata={
                    "codec": "AV1",
                    "sequence_number": parsed.sequence_number,
                    "counter.rtp.depacketized": 1,
                },
            )

        assert depacketized_frame == frame
        perf_mark(
            "media",
            "frame",
            "verified",
            metadata={"codec": "AV1", "counter.media.frames_verified": 1},
        )

        feedback = _build_twcc_feedback(
            media_ssrc=packetizer.ssrc,
            transport_sequences=transport_sequences,
        )
        rtcp_packets = RtcpPacket.parse(feedback)
        perf_mark(
            "rtcp",
            "twcc",
            "generated",
            metadata={"counter.rtcp.feedback_packets": 1},
        )
        confirmed = _confirmed_twcc_sequences(rtcp_packets[0])
        assert confirmed == transport_sequences
        perf_mark(
            "rtcp",
            "twcc",
            "confirmed",
            metadata={
                "counter.rtcp.confirmed_packets": len(confirmed),
                "base_sequence_number": transport_sequences[0],
            },
        )
        perf_mark("scenario", "run", "completed", metadata={"scenario": baseline["scenario"]})

    summary = build_summary_from_baseline(recorder, baseline)
    record_property("performance_summary", json.dumps(summary, sort_keys=True))
    assert_matches_baseline(recorder, summary, baseline)
    assert summary["status"] == "completed"


def _synthetic_av1_frame(*, payload_size: int) -> bytes:
    obu_type_frame = 6
    obu_header_without_size = obu_type_frame << 3
    payload = bytes((index % 251 for index in range(payload_size)))
    return bytes([obu_header_without_size]) + payload


def _depacketize_av1_payloads(payloads: Sequence[bytes]) -> bytes:
    chunks: list[bytes] = []
    for index, payload in enumerate(payloads):
        assert payload, f"empty AV1 RTP payload at index {index}"
        aggregation_header = payload[0]
        z_bit = bool(aggregation_header & 0x80)
        y_bit = bool(aggregation_header & 0x40)
        w_count = (aggregation_header >> 4) & 0x03

        assert z_bit == (index > 0)
        assert y_bit == (index < len(payloads) - 1)
        assert w_count == 1
        chunks.append(payload[1:])
    return b"".join(chunks)


def _build_twcc_feedback(*, media_ssrc: int, transport_sequences: Sequence[int]) -> bytes:
    return TransportLayerCC(
        sender_ssrc=0xCAFECAFE,
        media_ssrc=media_ssrc,
        base_sequence_number=transport_sequences[0],
        packet_status_count=len(transport_sequences),
        reference_time=12345,
        fb_pkt_count=1,
        packet_chunks=[
            RunLengthChunk(
                packet_status_symbol=TypeTCCPacketReceivedSmallDelta,
                run_length=len(transport_sequences),
            )
        ],
        recv_deltas=[
            RecvDelta(delta=250 * (index + 1), delta_type=TypeTCCPacketReceivedSmallDelta)
            for index in range(len(transport_sequences))
        ],
    ).marshal()


def _confirmed_twcc_sequences(feedback: TransportLayerCC) -> list[int]:
    assert isinstance(feedback, TransportLayerCC)
    statuses: list[int] = []
    for chunk in feedback.packet_chunks:
        assert isinstance(chunk, RunLengthChunk)
        statuses.extend([chunk.packet_status_symbol] * chunk.run_length)

    confirmed: list[int] = []
    sequence = feedback.base_sequence_number
    delta_index = 0
    for status in statuses[: feedback.packet_status_count]:
        if status == TypeTCCPacketReceivedSmallDelta:
            assert delta_index < len(feedback.recv_deltas)
            confirmed.append(sequence)
            delta_index += 1
        sequence = (sequence + 1) & 0xFFFF

    assert delta_index == len(feedback.recv_deltas)
    return confirmed
