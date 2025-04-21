from typing import Any
from dataclasses import dataclass, field
from struct import pack, unpack, unpack_from


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
    id: int
    uri: str


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


DEFAULT_EXT_MAP = HeaderExtensionsMap()
DEFAULT_EXT_MAP.configure(
    RTCRtpParameters(
        [
            RTCRtpHeaderExtensionParameters(
                id=1,
                uri="http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
            )
            # RTCRtpHeaderExtensionParameters(
            #     id=1, uri="urn:ietf:params:rtp-hdrext:sdes:mid"
            # ),
            # RTCRtpHeaderExtensionParameters(
            #     id=3,
            #     uri="http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
            # ),
        ]
    )
)
