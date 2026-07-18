"""TrackEncoding integration tests for complete-packet Kernel E dispatch."""

from __future__ import annotations

import asyncio
from fractions import Fraction
from typing import Any

import pytest

import webrtc.transceiver as transceiver
from webrtc.media.av1_payloader import AV1_PAYLOAD_TYPE
from webrtc.media.rtp_packet import RtpPacket
from webrtc.transceiver import (
    RTPCodecKind,
    RTPCodecParameters,
    TrackEncoding,
    TrackLocal,
)


def _track(payload_type: int) -> TrackLocal:
    return TrackLocal(
        "track",
        "stream",
        RTPCodecKind.Video,
        RTPCodecParameters(
            "video/AV1" if payload_type == AV1_PAYLOAD_TYPE else "video/VP8",
            90_000,
            1 / 30,
            0,
            "",
            payload_type,
            "stats",
        ),
    )


class _Transport:
    def __init__(self) -> None:
        self.packets: list[bytes] = []

    async def write_rtp_bytes(self, packet: bytes) -> int:
        assert type(packet) is bytes
        self.packets.append(packet)
        return len(packet)


def test_av1_track_sends_kernel_complete_packets_raw_and_commits_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoding = TrackEncoding(0x10203040, _track(AV1_PAYLOAD_TYPE))
    transport = _Transport()
    encoding.bind(transport)  # type: ignore[arg-type]
    encoding._packetizer.sequencer.sequence_number = 0xFFFE
    encoding._twcc_sequence = 0xFFFF
    expected_packets = (
        bytes.fromhex("90adffff0000000010203040bede000141000000103001"),
        bytes.fromhex("90ad00000000000010203040bede0001410001009002"),
    )
    calls: list[tuple[object, ...]] = []

    def packetize(*arguments: object) -> tuple[tuple[bytes, ...], int, int]:
        calls.append(arguments)
        return expected_packets, 0, 1

    monkeypatch.setattr(transceiver, "packetize_av1_frame", packetize)

    written = asyncio.run(encoding.write_frame(b"encoded-frame"))

    assert calls == [
        (b"encoded-frame", 1200, 0, 0x10203040, 0xFFFE, 0xFFFF)
    ]
    assert transport.packets == list(expected_packets)
    assert written == sum(map(len, expected_packets))
    assert encoding._packetizer.sequencer.sequence_number == 0
    assert encoding._twcc_sequence == 1


def test_av1_packetization_failure_sends_nothing_and_commits_no_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoding = TrackEncoding(7, _track(AV1_PAYLOAD_TYPE))
    transport = _Transport()
    encoding.bind(transport)  # type: ignore[arg-type]
    encoding._packetizer.sequencer.sequence_number = 123
    encoding._twcc_sequence = 456

    def fail(*arguments: object) -> tuple[tuple[bytes, ...], int, int]:
        raise ValueError("packetization failed")

    monkeypatch.setattr(transceiver, "packetize_av1_frame", fail)

    with pytest.raises(ValueError, match=r"^packetization failed$"):
        asyncio.run(encoding.write_frame(b"bad-frame"))
    assert transport.packets == []
    assert encoding._packetizer.sequencer.sequence_number == 123
    assert encoding._twcc_sequence == 456


class _NonAv1Packetizer:
    async def next_timestamp(self) -> tuple[int, Fraction]:
        return 321, Fraction(1, 90_000)

    def packetize(self, frame: bytes, timestamp: int) -> list[RtpPacket]:
        assert (frame, timestamp) == (b"vp8-frame", 321)
        return [
            RtpPacket(
                payload_type=96,
                marker=1,
                sequence_number=22,
                timestamp=timestamp,
                ssrc=33,
                payload=b"vp8-payload",
            )
        ]


def test_non_av1_path_still_serializes_packet_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoding = TrackEncoding(33, _track(96))
    encoding._packetizer = _NonAv1Packetizer()  # type: ignore[assignment]
    transport = _Transport()
    encoding.bind(transport)  # type: ignore[arg-type]

    def forbidden(*arguments: Any) -> Any:
        raise AssertionError("Kernel E must not handle non-AV1 media")

    monkeypatch.setattr(transceiver, "packetize_av1_frame", forbidden)
    expected = RtpPacket(
        payload_type=96,
        marker=1,
        sequence_number=22,
        timestamp=321,
        ssrc=33,
        payload=b"vp8-payload",
    ).serialize()

    assert asyncio.run(encoding.write_frame(b"vp8-frame")) == len(expected)
    assert transport.packets == [expected]
