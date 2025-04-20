import os
import struct
from struct import pack, unpack, unpack_from

from .rtp_extensions import HeaderExtensions, HeaderExtensionsMap

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

RTP_HEADER_LENGTH = 12


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
        self._data: bytes | None = None

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
        for _ in range(0, cc):
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
