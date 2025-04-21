import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from struct import pack, unpack, unpack_from
from typing import List, Self, Union

RTP_HISTORY_SIZE = 128

# reserved to avoid confusion with RTCP
FORBIDDEN_PAYLOAD_TYPES = range(72, 77)
DYNAMIC_PAYLOAD_TYPES = range(96, 128)

RTP_HEADER_LENGTH = 12
RTCP_HEADER_LENGTH = 4

PACKETS_LOST_MIN = -(1 << 23)
PACKETS_LOST_MAX = (1 << 23) - 1

RTCP_BYE = 203
RTCP_RTPFB = 205

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


TypeTCCRunLengthChunk = 0
TypeTCCStatusVectorChunk = 1

TypeTCCPacketNotReceived = 0
TypeTCCPacketReceivedSmallDelta = 1
TypeTCCPacketReceivedLargeDelta = 2
TypeTCCPacketReceivedWithoutDelta = 3

TypeTCCSymbolSizeOneBit = 0
TypeTCCSymbolSizeTwoBit = 1

TypeTCCDeltaScaleFactor = 250


def set_n_bits_of_uint16(base: int, n: int, offset: int, val: int) -> int:
    mask = ((1 << n) - 1) << (16 - offset - n)
    return (base & ~mask) | ((val << (16 - offset - n)) & mask)


def get_n_bits_from_byte(b: int, offset: int, length: int) -> int:
    return (b >> (8 - offset - length)) & ((1 << length) - 1)


class PacketStatusChunk(ABC):
    @abstractmethod
    def marshal(self) -> bytes:
        pass

    @abstractmethod
    def unmarshal(self, raw: bytes):
        pass


class RunLengthChunk(PacketStatusChunk):
    def __init__(self, packet_status_symbol=0, run_length=0):
        self.type = TypeTCCRunLengthChunk
        self.packet_status_symbol = packet_status_symbol
        self.run_length = run_length

    def marshal(self) -> bytes:
        dst = set_n_bits_of_uint16(0, 1, 0, 0)
        dst = set_n_bits_of_uint16(dst, 2, 1, self.packet_status_symbol)
        dst = set_n_bits_of_uint16(dst, 13, 3, self.run_length)
        return struct.pack(">H", dst)

    def unmarshal(self, raw: bytes):
        if len(raw) != 2:
            raise ValueError("packet status chunk must be 2 bytes")
        b0, b1 = raw[0], raw[1]
        self.packet_status_symbol = get_n_bits_from_byte(b0, 1, 2)
        self.run_length = ((b0 & 0x1F) << 8) | b1

    def __repr__(self) -> str:
        return f"RunLengthChunk: type:{self.type}, packet_status_symbol:{self.packet_status_symbol}, run_length:{self.run_length}"


# TODO: not used why???
class StatusVectorChunk(PacketStatusChunk):
    def __init__(self):
        self.type = TypeTCCStatusVectorChunk
        self.symbol_size = 0
        self.symbol_list = []

    def marshal(self) -> bytes:
        dst = set_n_bits_of_uint16(0, 1, 0, 1)
        dst = set_n_bits_of_uint16(dst, 1, 1, self.symbol_size)
        bits_per_symbol = 1 if self.symbol_size == TypeTCCSymbolSizeOneBit else 2
        for i, sym in enumerate(self.symbol_list):
            dst = set_n_bits_of_uint16(
                dst, bits_per_symbol, 2 + i * bits_per_symbol, sym
            )
        return struct.pack(">H", dst)

    def unmarshal(self, raw: bytes):
        if len(raw) != 2:
            raise ValueError("packet status chunk must be 2 bytes")
        self.symbol_size = get_n_bits_from_byte(raw[0], 1, 1)
        self.symbol_list = []
        if self.symbol_size == TypeTCCSymbolSizeOneBit:
            for i in range(6):
                self.symbol_list.append(get_n_bits_from_byte(raw[0], 2 + i, 1))
            for i in range(8):
                self.symbol_list.append(get_n_bits_from_byte(raw[1], i, 1))
        elif self.symbol_size == TypeTCCSymbolSizeTwoBit:
            for i in range(3):
                self.symbol_list.append(get_n_bits_from_byte(raw[0], 2 + i * 2, 2))
            for i in range(4):
                self.symbol_list.append(get_n_bits_from_byte(raw[1], i * 2, 2))
        else:
            raise ValueError("invalid symbol size")

    def __repr__(self) -> str:
        return f"StatusVectorChunk: type:{self.type}, symbol_size:{self.symbol_size}, symbol_list={self.symbol_list}"


@dataclass
class RecvDelta:
    delta: int
    delta_type: int
    # def __init__(self, delta=0, delta_type=TypeTCCPacketReceivedSmallDelta):
    #     self.delta = delta
    #     self.type = delta_type

    def marshal(self) -> bytes:
        delta_units = self.delta // TypeTCCDeltaScaleFactor
        if (
            self.delta_type == TypeTCCPacketReceivedSmallDelta
            and 0 <= delta_units <= 255
        ):
            return struct.pack(">B", delta_units)
        elif (
            self.delta_type == TypeTCCPacketReceivedLargeDelta
            and -32768 <= delta_units <= 32767
        ):
            return struct.pack(">h", delta_units)
        else:
            raise ValueError("delta exceeds limit")

    @classmethod
    def unmarshal(cls, raw: bytes) -> Self:
        if len(raw) == 1:
            type = TypeTCCPacketReceivedSmallDelta
            delta = raw[0] * TypeTCCDeltaScaleFactor
        elif len(raw) == 2:
            type = TypeTCCPacketReceivedLargeDelta
            delta = struct.unpack(">h", raw)[0] * TypeTCCDeltaScaleFactor
        else:
            raise ValueError("invalid delta length")

        return cls(delta, type)


@dataclass
class TransportLayerCC:
    sender_ssrc: int
    media_ssrc: int
    base_sequence_number: int
    packet_status_count: int
    reference_time: int
    fb_pkt_count: int
    packet_chunks: List[PacketStatusChunk] = field(default_factory=list)
    recv_deltas: List[RecvDelta] = field(default_factory=list)

    def marshal(self) -> bytes:
        header = bytearray(20)
        struct.pack_into(
            ">BBHII",
            header,
            0,
            (2 << 6) | 15,  # V=2, PT=15
            205,  # FMT=15
            0,  # Length (placeholder)
            self.sender_ssrc,
            self.media_ssrc,
        )
        struct.pack_into(">H", header, 8, self.base_sequence_number)
        struct.pack_into(">H", header, 10, self.packet_status_count)
        struct.pack_into(
            ">I", header, 12, (self.reference_time << 8) | self.fb_pkt_count
        )

        chunks_bytes = b"".join(chunk.marshal() for chunk in self.packet_chunks)
        deltas_bytes = b"".join(delta.marshal() for delta in self.recv_deltas)

        padding = (4 - (len(chunks_bytes) + len(deltas_bytes)) % 4) % 4
        packet = header + chunks_bytes + deltas_bytes + bytes(padding)
        struct.pack_into(">H", packet, 2, (len(packet) // 4) - 1)  # Update Length field
        return bytes(packet)

    @classmethod
    def unmarshal(cls, raw: bytes) -> Self:
        if len(raw) < 20:
            raise ValueError("packet too short")

        # TODO: media_ssrc has different numbers
        sender_ssrc, media_ssrc = struct.unpack_from(">II", raw, 4)
        base_sequence_number, packet_status_count = struct.unpack_from(">HH", raw, 8)
        ref_time_and_count = struct.unpack_from(">I", raw, 12)[0]

        reference_time = ref_time_and_count >> 8
        fb_pkt_count = ref_time_and_count & 0xFF

        offset = 16
        packet_chunks = []
        processed_packets = 0
        while processed_packets < packet_status_count and offset + 2 <= len(raw):
            chunk_data = raw[offset : offset + 2]
            offset += 2
            if chunk_data[0] & 0x80 == 0:
                chunk = RunLengthChunk()
            else:
                chunk = StatusVectorChunk()
            chunk.unmarshal(chunk_data)
            packet_chunks.append(chunk)
            if isinstance(chunk, RunLengthChunk):
                processed_packets += chunk.run_length
            elif isinstance(chunk, StatusVectorChunk):
                processed_packets += len(chunk.symbol_list)

        recv_deltas = []
        while offset < len(raw):
            remaining = len(raw) - offset
            if remaining >= 2 and raw[offset] & 0x80:
                delta = RecvDelta.unmarshal(raw[offset : offset + 2])
                offset += 2
            else:
                delta = RecvDelta.unmarshal(raw[offset : offset + 1])
                offset += 1
            recv_deltas.append(delta)

        return cls(
            sender_ssrc,
            media_ssrc,
            base_sequence_number,  # pyright: ignore
            packet_status_count,
            reference_time,
            fb_pkt_count,
            packet_chunks,
            recv_deltas,
        )


AnyRtcpPacket = Union[
    RtcpByePacket,
    TransportLayerCC,
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
            elif packet_type == RTCP_RTPFB:
                if len(payload) < 20:
                    continue

                match count:
                    case 15:
                        twcc = TransportLayerCC.unmarshal(payload)
                        packets.append(twcc)
                    case _:
                        pass

        return packets
