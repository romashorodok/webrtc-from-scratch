import asyncio
from concurrent.futures import ThreadPoolExecutor

from datetime import datetime
import json
import threading
from typing import Any
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from ice.candidate_base import get_candidate_type_from_str, parse_candidate_str
import peer_connection
from ice.net.types import Packet, Address

import media
import secrets
from dataclasses import dataclass, field
import struct
import os
from struct import pack, unpack, unpack_from
import random
import time
import fractions


version = 2
padding = 0
extension = 0
csrc_count = 0
marker = 0
payload_type = 96
sequence_number = 12345
timestamp = 67890
ssrc_identifier = 123456789
# First byte: Version (2 bits), Padding (1 bit), Extension (1 bit), CSRC Count (4 bits)
first_byte = (version << 6) | (padding << 5) | (extension << 4) | csrc_count
# Second byte: Marker (1 bit), Payload Type (7 bits)
second_byte = (marker << 7) | payload_type
# Pack the RTP header into bytes
rtp_header = struct.pack(
    "!BBHII", first_byte, second_byte, sequence_number, timestamp, ssrc_identifier
)


app = FastAPI()

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


pc = peer_connection.PeerConnection()

lock = asyncio.Lock()


async def peer():
    yield pc


clock_rate = 90000


NANOSECOND = 1
MICROSECOND = 1000 * NANOSECOND
MILLISECOND = 1000 * MICROSECOND
SECOND = 1000 * MILLISECOND
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE

RTP_HISTORY_SIZE = 128

# reserved to avoid confusion with RTCP
FORBIDDEN_PAYLOAD_TYPES = range(72, 77)
DYNAMIC_PAYLOAD_TYPES = range(96, 128)

RTP_HEADER_LENGTH = 12
RTCP_HEADER_LENGTH = 4

PACKETS_LOST_MIN = -(1 << 23)
PACKETS_LOST_MAX = (1 << 23) - 1


@dataclass
class HeaderExtensions:
    abs_send_time: int | None = None
    audio_level: Any = None
    mid: Any = None
    repaired_rtp_stream_id: Any = None
    rtp_stream_id: Any = None
    transmission_offset: int | None = None
    transport_sequence_number: int | None = None


@dataclass
class RTCRtpHeaderExtensionParameters:
    """
    The :class:`RTCRtpHeaderExtensionParameters` dictionary enables a header
    extension to be configured for use within an :class:`RTCRtpSender` or
    :class:`RTCRtpReceiver`.
    """

    id: int
    "The value that goes in the packet."
    uri: str
    "The URI of the RTP header extension."


@dataclass
class RTCRtpParameters:
    headerExtensions: list[RTCRtpHeaderExtensionParameters] = field(
        default_factory=list
    )


def unpack_header_extensions(
    extension_profile: int, extension_value: bytes
) -> list[tuple[int, bytes]]:
    """
    Parse header extensions according to RFC 5285.
    """
    extensions = []
    pos = 0

    if extension_profile == 0xBEDE:
        # One-Byte Header
        while pos < len(extension_value):
            # skip padding byte
            if extension_value[pos] == 0:
                pos += 1
                continue

            x_id = (extension_value[pos] & 0xF0) >> 4
            x_length = (extension_value[pos] & 0x0F) + 1
            pos += 1

            if len(extension_value) < pos + x_length:
                raise ValueError("RTP one-byte header extension value is truncated")
            x_value = extension_value[pos : pos + x_length]
            extensions.append((x_id, x_value))
            pos += x_length
    elif extension_profile == 0x1000:
        # Two-Byte Header
        while pos < len(extension_value):
            # skip padding byte
            if extension_value[pos] == 0:
                pos += 1
                continue

            if len(extension_value) < pos + 2:
                raise ValueError("RTP two-byte header extension is truncated")
            x_id, x_length = unpack_from("!BB", extension_value, pos)
            pos += 2

            if len(extension_value) < pos + x_length:
                raise ValueError("RTP two-byte header extension value is truncated")
            x_value = extension_value[pos : pos + x_length]
            extensions.append((x_id, x_value))
            pos += x_length

    return extensions


def padl(length: int) -> int:
    """
    Return amount of padding needed for a 4-byte multiple.
    """
    return 4 * ((length + 3) // 4) - length


def pack_header_extensions(extensions: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """
    Serialize header extensions according to RFC 5285.
    """
    extension_profile = 0
    extension_value = b""

    if not extensions:
        return extension_profile, extension_value

    one_byte = True
    for x_id, x_value in extensions:
        x_length = len(x_value)
        assert x_id > 0 and x_id < 256
        assert x_length >= 0 and x_length < 256
        if x_id > 14 or x_length == 0 or x_length > 16:
            one_byte = False

    if one_byte:
        # One-Byte Header
        extension_profile = 0xBEDE
        extension_value = b""
        for x_id, x_value in extensions:
            x_length = len(x_value)
            extension_value += pack("!B", (x_id << 4) | (x_length - 1))
            extension_value += x_value
    else:
        # Two-Byte Header
        extension_profile = 0x1000
        extension_value = b""
        for x_id, x_value in extensions:
            x_length = len(x_value)
            extension_value += pack("!BB", x_id, x_length)
            extension_value += x_value

    extension_value += b"\x00" * padl(len(extension_value))
    return extension_profile, extension_value


class HeaderExtensionsMap:
    def __init__(self) -> None:
        self.__ids = HeaderExtensions()

    def configure(self, params: RTCRtpParameters) -> None:
        for ext in params.headerExtensions:
            if ext.uri == "urn:ietf:params:rtp-hdrext:sdes:mid":
                self.__ids.mid = ext.id
            elif ext.uri == "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id":
                self.__ids.repaired_rtp_stream_id = ext.id
            elif ext.uri == "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id":
                self.__ids.rtp_stream_id = ext.id
            elif (
                ext.uri == "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
            ):
                self.__ids.abs_send_time = ext.id
            elif ext.uri == "urn:ietf:params:rtp-hdrext:toffset":
                self.__ids.transmission_offset = ext.id
            elif ext.uri == "urn:ietf:params:rtp-hdrext:ssrc-audio-level":
                self.__ids.audio_level = ext.id
            elif (
                ext.uri
                == "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
            ):
                self.__ids.transport_sequence_number = ext.id

    def get(self, extension_profile: int, extension_value: bytes) -> HeaderExtensions:
        values = HeaderExtensions()
        for x_id, x_value in unpack_header_extensions(
            extension_profile, extension_value
        ):
            if x_id == self.__ids.mid:
                values.mid = x_value.decode("utf8")
            elif x_id == self.__ids.repaired_rtp_stream_id:
                values.repaired_rtp_stream_id = x_value.decode("ascii")
            elif x_id == self.__ids.rtp_stream_id:
                values.rtp_stream_id = x_value.decode("ascii")
            elif x_id == self.__ids.abs_send_time:
                values.abs_send_time = unpack("!L", b"\00" + x_value)[0]
            elif x_id == self.__ids.transmission_offset:
                values.transmission_offset = unpack("!l", x_value + b"\00")[0] >> 8
            elif x_id == self.__ids.audio_level:
                vad_level = unpack("!B", x_value)[0]
                values.audio_level = (vad_level & 0x80 == 0x80, vad_level & 0x7F)
            elif x_id == self.__ids.transport_sequence_number:
                values.transport_sequence_number = unpack("!H", x_value)[0]
        return values

    def set(self, values: HeaderExtensions):
        extensions = []
        if values.mid is not None and self.__ids.mid:
            extensions.append((self.__ids.mid, values.mid.encode("utf8")))
        if (
            values.repaired_rtp_stream_id is not None
            and self.__ids.repaired_rtp_stream_id
        ):
            extensions.append(
                (
                    self.__ids.repaired_rtp_stream_id,
                    values.repaired_rtp_stream_id.encode("ascii"),
                )
            )
        if values.rtp_stream_id is not None and self.__ids.rtp_stream_id:
            extensions.append(
                (self.__ids.rtp_stream_id, values.rtp_stream_id.encode("ascii"))
            )
        if values.abs_send_time is not None and self.__ids.abs_send_time:
            extensions.append(
                (self.__ids.abs_send_time, pack("!L", values.abs_send_time)[1:])
            )
        if values.transmission_offset is not None and self.__ids.transmission_offset:
            extensions.append(
                (
                    self.__ids.transmission_offset,
                    pack("!l", values.transmission_offset << 8)[0:2],
                )
            )
        if values.audio_level is not None and self.__ids.audio_level:
            extensions.append(
                (
                    self.__ids.audio_level,
                    pack(
                        "!B",
                        (0x80 if values.audio_level[0] else 0)
                        | (values.audio_level[1] & 0x7F),
                    ),
                )
            )
        if (
            values.transport_sequence_number is not None
            and self.__ids.transport_sequence_number
        ):
            extensions.append(
                (
                    self.__ids.transport_sequence_number,
                    pack("!H", values.transport_sequence_number),
                )
            )
        return pack_header_extensions(extensions)


class RtpPacket:
    def __init__(
        self,
        payload_type: int = 0,
        marker: int = 0,
        sequence_number: int = 0,
        timestamp: int = 0,
        ssrc: int = 0,
        payload: bytes = b"",
    ) -> None:
        self.version = 2
        self.marker = marker
        self.payload_type = payload_type
        self.sequence_number = sequence_number
        self.timestamp = timestamp
        self.ssrc = ssrc
        self.csrc: list[int] = []
        self.payload = payload
        self.padding_size = 0
        self.extensions = HeaderExtensions()

    def __repr__(self) -> str:
        return (
            f"RtpPacket(seq={self.sequence_number}, ts={self.timestamp}, "
            f"marker={self.marker}, payload={self.payload_type}, "
            f"{len(self.payload)} bytes)"
            f"exts: {self.extensions}"
        )

    @classmethod
    def parse(cls, data: bytes, extensions_map=HeaderExtensionsMap()):
        if len(data) < RTP_HEADER_LENGTH:
            raise ValueError(
                f"RTP packet length is less than {RTP_HEADER_LENGTH} bytes"
            )

        v_p_x_cc, m_pt, sequence_number, timestamp, ssrc = unpack("!BBHLL", data[0:12])
        version = v_p_x_cc >> 6
        padding = (v_p_x_cc >> 5) & 1
        extension = (v_p_x_cc >> 4) & 1
        cc = v_p_x_cc & 0x0F
        if version != 2:
            raise ValueError("RTP packet has invalid version")
        if len(data) < RTP_HEADER_LENGTH + 4 * cc:
            raise ValueError("RTP packet has truncated CSRC")

        packet = cls(
            marker=(m_pt >> 7),
            payload_type=(m_pt & 0x7F),
            sequence_number=sequence_number,
            timestamp=timestamp,
            ssrc=ssrc,
        )

        pos = RTP_HEADER_LENGTH
        for i in range(0, cc):
            packet.csrc.append(unpack_from("!L", data, pos)[0])
            pos += 4

        if extension:
            if len(data) < pos + 4:
                raise ValueError("RTP packet has truncated extension profile / length")
            extension_profile, extension_length = unpack_from("!HH", data, pos)
            extension_length *= 4
            pos += 4

            if len(data) < pos + extension_length:
                raise ValueError("RTP packet has truncated extension value")
            extension_value = data[pos : pos + extension_length]
            pos += extension_length
            packet.extensions = extensions_map.get(extension_profile, extension_value)

        if padding:
            padding_len = data[-1]
            if not padding_len or padding_len > len(data) - pos:
                raise ValueError("RTP packet padding length is invalid")
            packet.padding_size = padding_len
            packet.payload = data[pos:-padding_len]
        else:
            packet.payload = data[pos:]

        return packet

    def serialize(self, extensions_map=HeaderExtensionsMap()) -> bytes:
        extension_profile, extension_value = extensions_map.set(self.extensions)
        has_extension = bool(extension_value)

        padding = self.padding_size > 0
        data = pack(
            "!BBHLL",
            (self.version << 6)
            | (padding << 5)
            | (has_extension << 4)
            | len(self.csrc),
            (self.marker << 7) | self.payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc,
        )
        for csrc in self.csrc:
            data += pack("!L", csrc)

        if has_extension:
            data += pack("!HH", extension_profile, len(extension_value) >> 2)
            data += extension_value

        data += self.payload
        if padding:
            data += os.urandom(self.padding_size - 1)
            data += bytes([self.padding_size])
        return data


def uint32_add(a: int, b: int) -> int:
    """
    Return a + b.
    """
    return (a + b) & 0xFFFFFFFF


class VP8Payloader:
    VP8_HEADER_SIZE = 1

    def __init__(self, enable_picture_id: bool) -> None:
        self._enable_picture_id = enable_picture_id
        self._picture_id = 0

    def payload(self, mtu: int, payload: bytes) -> list[bytes]:
        # Define the initial header size
        header_size = self.VP8_HEADER_SIZE

        # Calculate header size if picture ID is enabled
        if self._enable_picture_id:
            if self._picture_id < 128:
                header_size += 2
            else:
                header_size += 3

        max_fragment_size = mtu - header_size
        payload_len = len(payload)

        if max_fragment_size <= 0 or payload_len <= 0:
            return []

        first = True
        fragments = []

        payload_data_remaining = payload_len
        payload_data_index = 0

        while payload_data_remaining > 0:
            current_fragment_size = min(max_fragment_size, payload_data_remaining)

            header = bytearray(header_size)

            if first:
                header[0] = 0x10  # Set the S bit
                first = False

            if self._enable_picture_id:
                if header_size == self.VP8_HEADER_SIZE + 2:
                    header[0] |= 0x80  # Set the X bit
                    header[1] = 0x80 | (self._picture_id & 0x7F)
                elif header_size == self.VP8_HEADER_SIZE + 3:
                    header[0] |= 0x80  # Set the X bit
                    header[1] = 0x80 | (self._picture_id >> 8 & 0x7F)
                    header[2] = self._picture_id & 0xFF

            fragment = bytearray(header_size + current_fragment_size)
            fragment[:header_size] = header
            fragment[header_size:] = payload[
                payload_data_index : payload_data_index + current_fragment_size
            ]

            fragments.append(fragment)

            payload_data_remaining -= current_fragment_size
            payload_data_index += current_fragment_size

        self._picture_id += 1
        self._picture_id &= 0x7FFF  # Ensure the picture ID stays within 15 bits

        return fragments


class VP8PayloaderOld:
    def __init__(self, enable_picture_id: bool = False):
        self.enable_picture_id = enable_picture_id
        self.picture_id = 0

    def payload(self, mtu: int, payload: bytes) -> list[bytes]:
        vp8_header_size = 1

        if self.enable_picture_id:
            if self.picture_id == 0:
                using_header_size = vp8_header_size
            elif self.picture_id < 128:
                using_header_size = vp8_header_size + 2
            else:
                using_header_size = vp8_header_size + 3
        else:
            using_header_size = vp8_header_size

        max_fragment_size = mtu - using_header_size
        payload_data = payload
        payload_data_remaining = len(payload)
        payload_data_index = 0
        payloads = []

        if min(max_fragment_size, payload_data_remaining) <= 0:
            return payloads

        first = True
        while payload_data_remaining > 0:
            current_fragment_size = min(max_fragment_size, payload_data_remaining)
            out = bytearray(using_header_size + current_fragment_size)

            if first:
                out[0] = 0x10
                first = False

            if self.enable_picture_id:
                if using_header_size == vp8_header_size + 2:
                    out[0] |= 0x80
                    out[1] = 0x80 | (self.picture_id & 0x7F)
                elif using_header_size == vp8_header_size + 3:
                    out[0] |= 0x80
                    out[1] = 0x80 | (self.picture_id >> 8 & 0x7F)
                    out[2] = self.picture_id & 0xFF

            out[using_header_size:] = payload_data[
                payload_data_index : payload_data_index + current_fragment_size
            ]
            payloads.append(out)

            payload_data_remaining -= current_fragment_size
            payload_data_index += current_fragment_size

        self.picture_id = (self.picture_id + 1) % (1 << 15)

        return payloads


# class Packetizer:
#     def __init__(self, payloader: VP8Payloader) -> None:
#         self._payloader = payloader
#         self._sequencer = media.Sequencer()
#         # self._timestamp_origin = secrets.randbits(32)
#
#     def packetize(
#         self, payload: memoryview, timestamp: int, ssrc: int
#     ) -> list[RtpPacket]:
#         packets = list[RtpPacket]()
#
#         if len(payload) == 0:
#             return packets
#
#         payloads = self._payloader.payload(1200 - 12, payload)
#
#         for i, frame in enumerate(payloads):
#             pkt = RtpPacket(
#                 payload_type=96,
#                 sequence_number=self._sequencer.next_seq_number(),
#                 # timestamp=uint32_add(self._timestamp_origin, timestamp),
#                 timestamp=timestamp,
#             )
#             pkt.ssrc = ssrc
#             pkt.payload = frame
#             pkt.marker = (i == len(payloads) - 1) and 1 or 0
#             pkt.extensions.abs_send_time = (
#                 peer_connection.current_ntp_time() >> 14
#             ) & 0x00FFFFFF
#
#             packets.append(pkt)
#
#         return packets


ext_map = HeaderExtensionsMap()
ext_map.configure(
    RTCRtpParameters(
        [
            RTCRtpHeaderExtensionParameters(
                id=1, uri="urn:ietf:params:rtp-hdrext:sdes:mid"
            ),
            RTCRtpHeaderExtensionParameters(
                id=3,
                uri="http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
            ),
        ]
    )
)


# Assuming constants for simplicity
FRAME_RATE = 30  # frames per second
FRAME_DURATION = 1 / FRAME_RATE  # duration of each frame in seconds
CLOCK_RATE = 90000  # RTP clock rate for video


AUDIO_PTIME = 0.020  # 20ms audio packetization
VIDEO_CLOCK_RATE = 90000
VIDEO_PTIME = 1 / 30  # 30fps
VIDEO_TIME_BASE = fractions.Fraction(1, VIDEO_CLOCK_RATE)


class Sequencer:
    def __init__(self, initial_value: int = random.randint(0, 65535)):
        self.sequence_number = initial_value

    def next_sequence_number(self) -> int:
        self.sequence_number += 1
        self.sequence_number &= 0xFFFF  # Wrap around to fit in uint16
        return self.sequence_number


def convert_timebase(
    pts: int, from_base: fractions.Fraction, to_base: fractions.Fraction
) -> int:
    if from_base != to_base:
        pts = int(pts * from_base / to_base)
    return pts


PACKET_MAX = 1300


class VpxPayloadDescriptor:
    def __init__(
        self,
        partition_start,
        partition_id,
        picture_id=None,
        tl0picidx=None,
        tid=None,
        keyidx=None,
    ) -> None:
        self.partition_start = partition_start
        self.partition_id = partition_id
        self.picture_id = picture_id
        self.tl0picidx = tl0picidx
        self.tid = tid
        self.keyidx = keyidx

    def __bytes__(self) -> bytes:
        octet = (self.partition_start << 4) | self.partition_id

        ext_octet = 0
        if self.picture_id is not None:
            ext_octet |= 1 << 7
        if self.tl0picidx is not None:
            ext_octet |= 1 << 6
        if self.tid is not None:
            ext_octet |= 1 << 5
        if self.keyidx is not None:
            ext_octet |= 1 << 4

        if ext_octet:
            data = pack("!BB", (1 << 7) | octet, ext_octet)
            if self.picture_id is not None:
                if self.picture_id < 128:
                    data += pack("!B", self.picture_id)
                else:
                    data += pack("!H", (1 << 15) | self.picture_id)
            if self.tl0picidx is not None:
                data += pack("!B", self.tl0picidx)
            if self.tid is not None or self.keyidx is not None:
                t_k = 0
                if self.tid is not None:
                    t_k |= (self.tid[0] << 6) | (self.tid[1] << 5)
                if self.keyidx is not None:
                    t_k |= self.keyidx
                data += pack("!B", t_k)
        else:
            data = pack("!B", octet)

        return data

    def __repr__(self) -> str:
        return (
            f"VpxPayloadDescriptor(S={self.partition_start}, "
            f"PID={self.partition_id}, pic_id={self.picture_id})"
        )


class Vp8Encoder:
    # # packetize
    # payloads = self._packetize(self.buffer[:length], self.picture_id)
    # timestamp = convert_timebase(frame.pts, frame.time_base, VIDEO_TIME_BASE)
    # self.picture_id = (self.picture_id + 1) % (1 << 15)
    # return payloads, timestamp

    # def pack(self, packet: Packet) -> Tuple[List[bytes], int]:
    #     payloads = self._packetize(bytes(packet), self.picture_id)
    #     timestamp = convert_timebase(packet.pts, packet.time_base, VIDEO_TIME_BASE)
    #     self.picture_id = (self.picture_id + 1) % (1 << 15)
    #     return payloads, timestamp

    @classmethod
    def _packetize(cls, buffer: bytes, picture_id: int) -> list[bytes]:
        payloads = []
        descr = VpxPayloadDescriptor(
            partition_start=1, partition_id=0, picture_id=picture_id
        )
        length = len(buffer)
        pos = 0
        while pos < length:
            descr_bytes = bytes(descr)
            size = min(length - pos, PACKET_MAX - len(descr_bytes))
            payloads.append(descr_bytes + buffer[pos : pos + size])
            descr.partition_start = 0
            pos += size
        return payloads


class Packetizer:
    def __init__(
        self, mtu: int, pt: int, ssrc: int, payloader: VP8Payloader, clock_rate: int
    ):
        self.mtu = mtu
        self.payload_type = pt
        self.ssrc = ssrc
        self.payloader = payloader
        self.sequencer = Sequencer()
        # self.timestamp = random.randint(0, 0xFFFFFFFF)
        self.clock_rate = clock_rate
        self.timegen = time.time_ns
        self._timestamp = None
        self.enc = Vp8Encoder()
        self.picture_id = 0

    def enable_abs_send_time(self, value: int):
        self.abs_send_time = value

    async def next_timestamp(self) -> tuple[int, fractions.Fraction]:
        if self._timestamp is not None:
            self._timestamp += int(VIDEO_PTIME * VIDEO_CLOCK_RATE)
            wait = self._start + (self._timestamp / VIDEO_CLOCK_RATE) - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
        else:
            self._start = time.time()
            self._timestamp = 0

        return self._timestamp, VIDEO_TIME_BASE

    async def ticker(self):
        while True:
            yield await self.next_timestamp()

    def packetize(self, payload: bytes, samples: int) -> list:
        if not payload:
            return []

        # payloads = self.payloader.payload(self.mtu - 12, payload)
        packets = []
        payloads = self.enc._packetize(payload, self.picture_id)
        self.picture_id = (self.picture_id + 1) % (1 << 15)

        for i, pp in enumerate(payloads):
            pkt = RtpPacket(
                payload_type=96,
                sequence_number=self.sequencer.next_sequence_number(),
                timestamp=samples,
            )
            pkt.ssrc = self.ssrc
            pkt.payload = pp
            pkt.marker = (i == len(payloads) - 1) and 1 or 0
            pkt.extensions.abs_send_time = (
                peer_connection.current_ntp_time() >> 14
            ) & 0x00FFFFFF

            packets.append(pkt)

        # self.timestamp += samples & 0x00FFFFFF

        return packets

    # def generate_padding(self, samples: int) -> list:
    #     if samples == 0:
    #         return []
    #
    #     packets = []
    #
    #     for _ in range(samples):
    #         pp = bytearray(255)
    #         pp[-1] = 255
    #
    #         packet = {
    #             "header": {
    #                 "version": 2,
    #                 "padding": True,
    #                 "extension": False,
    #                 "marker": False,
    #                 "payload_type": self.payload_type,
    #                 "sequence_number": self.sequencer.next_sequence_number(),
    #                 "timestamp": self.timestamp,
    #                 "ssrc": self.ssrc,
    #                 "csrc": [],
    #             },
    #             "payload": pp,
    #         }
    #         packets.append(packet)
    #
    #     return packets

    # def skip_samples(self, skipped_samples: int):
    #     self.timestamp += skipped_samples


#       		MTU:         rtpOutboundMTU,
# PayloadType: 0,
# SSRC:        0,
# Payloader:   payloader,
# Sequencer:   s.sequencer,
# Timestamp:   ice.GlobalMathRandomGenerator.Uint32(),
# ClockRate:   codec.ClockRate,
# timegen:     time.Now,

packetizer = Packetizer(
    mtu=1200, pt=96, ssrc=0, payloader=VP8Payloader(True), clock_rate=9000
)


async def ticker(wait_ms: float):
    while True:
        yield
        await asyncio.sleep(wait_ms)


def next_read_frame(reader: media.IVFReader):
    try:
        return next(reader)
    except StopIteration:
        return None, None


async def read_frame(reader: media.IVFReader):
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        return await loop.run_in_executor(executor, next_read_frame, reader)


async def pre_read_frames(file_path: str):
    frames: list[tuple[bytes, media.IVFFrameHeader]] = []
    with open(file_path, "rb") as file:
        reader = media.IVFReader(file)
        for frame, header in reader:
            frames.append((frame, header))
    return frames


async def write_routine(frames: list[tuple[bytes, media.IVFFrameHeader]]):
    packetizer = Packetizer(
        mtu=1200, pt=96, ssrc=0, payloader=VP8Payloader(True), clock_rate=CLOCK_RATE
    )
    loop = asyncio.get_event_loop()
    frame_index = 0

    async for _ in ticker(VIDEO_PTIME / 1000):
        if frame_index >= len(frames):
            print("All frames sent. Replay from beginning.")
            frame_index = 0

        frame, frame_header = frames[frame_index]
        frame_index += 1

        try:
            for t in pc._transceivers:
                track = t.track_local()
                sender = t._sender

                if not sender or not track:
                    print("Not found sender")
                    continue

                encodings = sender._track_encodings
                if not encodings:
                    print("Not found encoding")
                    continue
                enc = encodings[0]

                packetizer.ssrc = enc.ssrc

                pts, time_base = await packetizer.next_timestamp()

                pkts = packetizer.packetize(
                    frame, convert_timebase(pts, time_base, VIDEO_TIME_BASE)
                )

                for pkt in pkts:
                    data = pkt.serialize()
                    await track.write_rtp(Packet(Address("0.0.0.0", 0), data))

        except RuntimeError:
            pass

    # with open("output.ivf", "rb") as file:
    #     reader = media.IVFReader(file)
    #     file_header = reader.file_header
    #
    #     await asyncio.sleep(2)
    #     timebase_fraction = (
    #         file_header.timebase_numerator / file_header.timebase_denominator
    #     )
    #
    #     print("Timebase fraction", timebase_fraction)
    #
    #     # async for pts, _ in packetizer.ticker():
    #     # while True:
    #     async for _ in ticker(VIDEO_PTIME):
    #         try:
    #             for t in pc._transceivers:
    #                 track = t.track_local()
    #                 sender = t._sender
    #
    #                 if not sender or not track:
    #                     print("Not found sender")
    #                     continue
    #
    #                 encodings = sender._track_encodings
    #                 if not encodings:
    #                     print("Not found encoding")
    #                     continue
    #                 enc = encodings[0]
    #
    #                 frame, frame_header = next(reader)
    #
    #                 if not frame:
    #                     print("Not foound frame")
    #                     continue
    #
    #                 packetizer.ssrc = enc.ssrc
    #
    #                 # frame_duration_seconds = frame_header.timestamp / timebase_fraction
    #                 # frame_samples = int(frame_duration_seconds * clock_rate)
    #                 #
    #                 # rtp_frame_timestamp = clock_rate
    #                 pts, _ = await packetizer.next_timestamp()
    #
    #                 pkts = packetizer.packetize(frame, pts)
    #
    #                 for pkt in pkts:
    #                     data = pkt.serialize()
    #                     await track.write_rtp(
    #                         Packet(Address("0.0.0.0", 0), memoryview(data))
    #                     )
    #         except StopIteration:
    #             # file.seek(0)
    #             # file
    #             print("Reach EOF. Sleep 2 sec", "is seekable", file.seekable())
    #             # await asyncio.sleep(2)
    #             print("Set file seek to 0. Replay")
    #             loop.create_task(write_routine(frames))
    #             break


@app.get("/offer")
async def offer(pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        await pc.add_transceiver_from_kind(
            peer_connection.RTPCodecKind.Video,
            peer_connection.RTPTransceiverDirection.Sendrecv,
        )
        pc.gatherer.agent.dial()

        desc = await pc.create_offer()
        if not desc:
            return "unable create offer"
        return {"type": "offer", "sdp": desc.marshal()}


@app.get("/candidates")
async def candidates(pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        print(pc)
        await pc.gatherer.gather()
        candidates = await pc.gatherer.agent.get_local_candidates()
        c = candidates[0]
        return c.unwrap.to_ice_str()


@app.post("/ice")
async def ice(req: Request, pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        body = await req.body()
        body_dict: dict[str, Any] = json.loads(body)
        candidate = body_dict.get("candidate")
        if not candidate:
            return
        pc.gatherer.agent.add_remote_candidate(candidate)
        await pc.gatherer.gather()
        pc.gatherer.agent.dial()

        for dtls in pc._dtls_transports:
            await dtls.start()


def start_writer_loop():
    writer_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(writer_loop)
    frames = writer_loop.run_until_complete(pre_read_frames("output.ivf"))
    print("Done reading frames")
    writer_loop.create_task(write_routine(frames))
    writer_loop.run_forever()


writer_thread = threading.Thread(target=start_writer_loop)
writer_thread.start()


@app.post("/answer")
async def answer(req: Request, pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        body = await req.body()
        body_dict = json.loads(body)
        sdp_type = body_dict["type"]
        sdp = body_dict["sdp"]
        desc = peer_connection.SessionDescription.parse(sdp)
        media = desc.media_descriptions[0]

        for dtls in pc._dtls_transports:
            dtls._media_fingerprints.extend(media.fingerprints)

        candidate_str = media.candidates
        ufrag, pwd = media.ice_ufrag, media.ice_pwd
        if not ufrag or not pwd:
            return

        pc.gatherer.agent.set_remote_credentials(ufrag, pwd)

        pc.gatherer.agent.dial()
        await pc.gatherer.gather()

        for dtls in pc._dtls_transports:
            await dtls.start()

        print(candidate_str, ufrag, pwd)
