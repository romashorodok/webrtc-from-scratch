import math
import os
import struct
from dataclasses import dataclass, field
from struct import pack, unpack, unpack_from
from typing import Any, Optional, Union

RTP_HISTORY_SIZE = 128

# reserved to avoid confusion with RTCP
FORBIDDEN_PAYLOAD_TYPES = range(72, 77)
DYNAMIC_PAYLOAD_TYPES = range(96, 128)

RTP_HEADER_LENGTH = 12
RTCP_HEADER_LENGTH = 4

PACKETS_LOST_MIN = -(1 << 23)
PACKETS_LOST_MAX = (1 << 23) - 1

RTCP_SR = 200
RTCP_RR = 201
RTCP_SDES = 202
RTCP_BYE = 203
RTCP_RTPFB = 205
RTCP_PSFB = 206

RTCP_RTPFB_NACK = 1

RTCP_PSFB_PLI = 1
RTCP_PSFB_SLI = 2
RTCP_PSFB_RPSI = 3
RTCP_PSFB_APP = 15


def pack_packets_lost(count: int) -> bytes:
    return pack("!l", count)[1:]


def unpack_packets_lost(d: bytes) -> int:
    if d[0] & 0x80:
        d = b"\xff" + d
    else:
        d = b"\x00" + d
    return unpack("!l", d)[0]


def pack_rtcp_packet(packet_type: int, count: int, payload: bytes) -> bytes:
    assert len(payload) % 4 == 0
    return pack("!BBH", (2 << 6) | count, packet_type, len(payload) // 4) + payload


def pack_remb_fci(bitrate: int, ssrcs: list[int]) -> bytes:
    """
    Pack the FCI for a Receiver Estimated Maximum Bitrate report.

    https://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03
    """
    data = b"REMB"
    exponent = 0
    mantissa = bitrate
    while mantissa > 0x3FFFF:
        mantissa >>= 1
        exponent += 1
    data += pack(
        "!BBH", len(ssrcs), (exponent << 2) | (mantissa >> 16), (mantissa & 0xFFFF)
    )
    for ssrc in ssrcs:
        data += pack("!L", ssrc)
    return data


def unpack_remb_fci(data: bytes) -> tuple[int, list[int]]:
    """
    Unpack the FCI for a Receiver Estimated Maximum Bitrate report.

    https://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03
    """
    if len(data) < 8 or data[0:4] != b"REMB":
        raise ValueError("Invalid REMB prefix")

    exponent = (data[5] & 0xFC) >> 2
    mantissa = ((data[5] & 0x03) << 16) | (data[6] << 8) | data[7]
    bitrate = mantissa << exponent

    pos = 8
    ssrcs = []
    for r in range(data[4]):
        ssrcs.append(unpack_from("!L", data, pos)[0])
        pos += 4

    return (bitrate, ssrcs)


@dataclass
class RtcpReceiverInfo:
    ssrc: int
    fraction_lost: int
    packets_lost: int
    highest_sequence: int
    jitter: int
    lsr: int
    dlsr: int

    def __bytes__(self) -> bytes:
        data = pack("!LB", self.ssrc, self.fraction_lost)
        data += pack_packets_lost(self.packets_lost)
        data += pack("!LLLL", self.highest_sequence, self.jitter, self.lsr, self.dlsr)
        return data

    @classmethod
    def parse(cls, data: bytes):
        ssrc, fraction_lost = unpack("!LB", data[0:5])
        packets_lost = unpack_packets_lost(data[5:8])
        highest_sequence, jitter, lsr, dlsr = unpack("!LLLL", data[8:])
        return cls(
            ssrc=ssrc,
            fraction_lost=fraction_lost,
            packets_lost=packets_lost,
            highest_sequence=highest_sequence,
            jitter=jitter,
            lsr=lsr,
            dlsr=dlsr,
        )


@dataclass
class RtcpSenderInfo:
    ntp_timestamp: int
    rtp_timestamp: int
    packet_count: int
    octet_count: int

    def __bytes__(self) -> bytes:
        return pack(
            "!QLLL",
            self.ntp_timestamp,
            self.rtp_timestamp,
            self.packet_count,
            self.octet_count,
        )

    @classmethod
    def parse(cls, data: bytes):
        ntp_timestamp, rtp_timestamp, packet_count, octet_count = unpack("!QLLL", data)
        return cls(
            ntp_timestamp=ntp_timestamp,
            rtp_timestamp=rtp_timestamp,
            packet_count=packet_count,
            octet_count=octet_count,
        )


@dataclass
class RtcpSourceInfo:
    ssrc: int
    items: list[tuple[Any, bytes]]


@dataclass
class RtcpByePacket:
    sources: list[int]

    def __bytes__(self) -> bytes:
        payload = b"".join([pack("!L", ssrc) for ssrc in self.sources])
        return pack_rtcp_packet(RTCP_BYE, len(self.sources), payload)

    @classmethod
    def parse(cls, data: bytes, count: int):
        if len(data) < 4 * count:
            raise ValueError("RTCP bye length is invalid")
        if count > 0:
            sources = list(unpack_from("!" + ("L" * count), data, 0))
        else:
            sources = []
        return cls(sources=sources)


@dataclass
class RtcpPsfbPacket:
    """
    Payload-Specific Feedback Message (RFC 4585).
    """

    fmt: int
    ssrc: int
    media_ssrc: int
    fci: bytes = b""

    def __bytes__(self) -> bytes:
        payload = pack("!LL", self.ssrc, self.media_ssrc) + self.fci
        return pack_rtcp_packet(RTCP_PSFB, self.fmt, payload)

    @classmethod
    def parse(cls, data: bytes, fmt: int):
        if len(data) < 8:
            raise ValueError("RTCP payload-specific feedback length is invalid")

        ssrc, media_ssrc = unpack("!LL", data[0:8])
        fci = data[8:]
        return cls(fmt=fmt, ssrc=ssrc, media_ssrc=media_ssrc, fci=fci)


@dataclass
class RtcpRrPacket:
    ssrc: int
    reports: list[RtcpReceiverInfo] = field(default_factory=list)

    def __bytes__(self) -> bytes:
        payload = pack("!L", self.ssrc)
        for report in self.reports:
            payload += bytes(report)
        return pack_rtcp_packet(RTCP_RR, len(self.reports), payload)

    @classmethod
    def parse(cls, data: bytes, count: int):
        if len(data) != 4 + 24 * count:
            raise ValueError("RTCP receiver report length is invalid")

        ssrc = unpack("!L", data[0:4])[0]
        pos = 4
        reports = []
        for r in range(count):
            reports.append(RtcpReceiverInfo.parse(data[pos : pos + 24]))
            pos += 24
        return cls(ssrc=ssrc, reports=reports)


@dataclass
class RtcpRtpfbPacket:
    """
    Generic RTP Feedback Message (RFC 4585).
    """

    fmt: int
    ssrc: int
    media_ssrc: int

    # generick NACK
    lost: list[int] = field(default_factory=list)

    def __bytes__(self) -> bytes:
        payload = pack("!LL", self.ssrc, self.media_ssrc)
        if self.lost:
            pid = self.lost[0]
            blp = 0
            for p in self.lost[1:]:
                d = p - pid - 1
                if d < 16:
                    blp |= 1 << d
                else:
                    payload += pack("!HH", pid, blp)
                    pid = p
                    blp = 0
            payload += pack("!HH", pid, blp)
        return pack_rtcp_packet(RTCP_RTPFB, self.fmt, payload)

    @classmethod
    def parse(cls, data: bytes, fmt: int):
        if len(data) < 8 or len(data) % 4:
            raise ValueError("RTCP RTP feedback length is invalid")

        ssrc, media_ssrc = unpack("!LL", data[0:8])
        lost = []
        for pos in range(8, len(data), 4):
            pid, blp = unpack("!HH", data[pos : pos + 4])
            lost.append(pid)
            for d in range(0, 16):
                if (blp >> d) & 1:
                    lost.append(pid + d + 1)
        return cls(fmt=fmt, ssrc=ssrc, media_ssrc=media_ssrc, lost=lost)


@dataclass
class RtcpSdesPacket:
    chunks: list[RtcpSourceInfo] = field(default_factory=list)

    def __bytes__(self) -> bytes:
        payload = b""
        for chunk in self.chunks:
            payload += pack("!L", chunk.ssrc)
            for d_type, d_value in chunk.items:
                payload += pack("!BB", d_type, len(d_value)) + d_value
            payload += b"\x00\x00"
        while len(payload) % 4:
            payload += b"\x00"
        return pack_rtcp_packet(RTCP_SDES, len(self.chunks), payload)

    @classmethod
    def parse(cls, data: bytes, count: int):
        pos = 0
        chunks = []
        for r in range(count):
            if len(data) < pos + 4:
                raise ValueError("RTCP SDES source is truncated")
            ssrc = unpack_from("!L", data, pos)[0]
            pos += 4

            items = []
            while pos < len(data) - 1:
                d_type, d_length = unpack_from("!BB", data, pos)
                pos += 2

                if len(data) < pos + d_length:
                    raise ValueError("RTCP SDES item is truncated")
                d_value = data[pos : pos + d_length]
                pos += d_length
                if d_type == 0:
                    break
                else:
                    items.append((d_type, d_value))
            chunks.append(RtcpSourceInfo(ssrc=ssrc, items=items))
        return cls(chunks=chunks)


@dataclass
class RtcpSrPacket:
    ssrc: int
    sender_info: RtcpSenderInfo
    reports: list[RtcpReceiverInfo] = field(default_factory=list)

    def __bytes__(self) -> bytes:
        payload = pack("!L", self.ssrc)
        payload += bytes(self.sender_info)
        for report in self.reports:
            payload += bytes(report)
        return pack_rtcp_packet(RTCP_SR, len(self.reports), payload)

    @classmethod
    def parse(cls, data: bytes, count: int):
        if len(data) != 24 + 24 * count:
            raise ValueError("RTCP sender report length is invalid")

        ssrc = unpack_from("!L", data)[0]
        sender_info = RtcpSenderInfo.parse(data[4:24])
        pos = 24
        reports = []
        for r in range(count):
            reports.append(RtcpReceiverInfo.parse(data[pos : pos + 24]))
            pos += 24
        return RtcpSrPacket(ssrc=ssrc, sender_info=sender_info, reports=reports)


AnyRtcpPacket = Union[
    RtcpByePacket,
    RtcpPsfbPacket,
    RtcpRrPacket,
    RtcpRtpfbPacket,
    RtcpSdesPacket,
    RtcpSrPacket,
]


class RtcpPacket:
    @classmethod
    def parse(cls, data: bytes) -> list[AnyRtcpPacket]:
        pos = 0
        packets = []

        while pos < len(data):
            if len(data) < pos + RTCP_HEADER_LENGTH:
                raise ValueError(
                    f"RTCP packet length is less than {RTCP_HEADER_LENGTH} bytes"
                )

            v_p_count, packet_type, length = unpack("!BBH", data[pos : pos + 4])
            version = v_p_count >> 6
            padding = (v_p_count >> 5) & 1
            count = v_p_count & 0x1F
            if version != 2:
                raise ValueError("RTCP packet has invalid version")
            pos += 4

            end = pos + length * 4
            if len(data) < end:
                raise ValueError("RTCP packet is truncated")
            payload = data[pos:end]
            pos = end

            if padding:
                if not payload or not payload[-1] or payload[-1] > len(payload):
                    raise ValueError("RTCP packet padding length is invalid")
                payload = payload[0 : -payload[-1]]

            if packet_type == RTCP_BYE:
                packets.append(RtcpByePacket.parse(payload, count))
            elif packet_type == RTCP_SDES:
                packets.append(RtcpSdesPacket.parse(payload, count))
            elif packet_type == RTCP_SR:
                packets.append(RtcpSrPacket.parse(payload, count))
            elif packet_type == RTCP_RR:
                packets.append(RtcpRrPacket.parse(payload, count))
            # elif packet_type == RTCP_RTPFB:
            # packets.append(RtcpRtpfbPacket.parse(payload, count))
            elif packet_type == RTCP_PSFB or packet_type == RTCP_RTPFB:
                match count:
                    case 15:
                        print("got TransportLayerCC format")
                        print(payload)
                        # packets.append(RtcpPsfbPacket.parse(payload, count))
                    case _:
                        pass

        return packets
