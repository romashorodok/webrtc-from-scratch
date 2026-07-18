"""Pure-Python executable specification for compiler Kernel E.

``packetize_av1_frame`` deliberately owns the complete frame-to-wire-packets
boundary.  In particular, it does not use the native ``webrtc_rs`` payloader
or the stateful media packetizer classes.

The exception policy is part of the executable specification:

* an argument whose concrete type is wrong raises ``TypeError`` with
  ``"<name> must be <type>"``;
* an integer outside its accepted range raises ``ValueError`` with
  ``"<name> must be in range <low>..<high>"``;
* an oversized frame raises ``ValueError`` with
  ``"frame must not exceed 16777216 bytes"``; and
* malformed OBU data raises ``ValueError`` prefixed by
  ``"malformed AV1 frame: "``.

All arguments are validated before packet construction.  A failing call has
no result and therefore cannot commit either sequence value.
"""

from dataclasses import dataclass

__all__ = ["packetize_av1_frame"]

_MAX_FRAME_SIZE = 16 * 1024 * 1024
_MAX_NUM_OBUS_TO_OMIT_SIZE = 3
_OBU_HAS_EXTENSION_BIT = 0x04
_OBU_HAS_SIZE_BIT = 0x02
_OBU_TYPE_MASK = 0x78
_OBU_TYPE_SEQUENCE_HEADER = 1
_IGNORED_OBU_TYPES = (2, 8, 15)


@dataclass(frozen=True, slots=True)
class _Obu:
    header: int
    extension_header: int
    payload: memoryview

    @property
    def header_size(self) -> int:
        return 2 if self.header & _OBU_HAS_EXTENSION_BIT else 1

    @property
    def size(self) -> int:
        return self.header_size + len(self.payload)


@dataclass(slots=True)
class _PacketMetadata:
    first_obu_index: int
    num_obu_elements: int = 0
    first_obu_offset: int = 0
    last_obu_size: int = 0
    packet_size: int = 0


def packetize_av1_frame(
    frame: bytes,
    fragmentation_limit: int,
    timestamp: int,
    ssrc: int,
    current_rtp_sequence: int,
    current_twcc_sequence: int,
) -> tuple[tuple[bytes, ...], int, int]:
    """Return complete RTP packets and the committed RTP/TWCC sequences.

    ``fragmentation_limit`` is the AV1 RTP payload budget, matching the current
    Rust payloader's ``mtu`` argument.  Each serialized packet consequently has
    20 additional bytes: twelve bytes of fixed RTP header and eight bytes for
    the padded transport-wide sequence extension.
    """

    _validate_types(
        frame,
        fragmentation_limit,
        timestamp,
        ssrc,
        current_rtp_sequence,
        current_twcc_sequence,
    )
    _validate_range("fragmentation_limit", fragmentation_limit, 3, 65_535)
    _validate_range("timestamp", timestamp, 0, 0xFFFF_FFFF)
    _validate_range("ssrc", ssrc, 0, 0xFFFF_FFFF)
    _validate_range("current_rtp_sequence", current_rtp_sequence, 0, 0xFFFF)
    _validate_range("current_twcc_sequence", current_twcc_sequence, 0, 0xFFFF)
    if len(frame) > _MAX_FRAME_SIZE:
        raise ValueError("frame must not exceed 16777216 bytes")

    obus = _parse_obus(frame)
    metadata = _packetize_obus(obus, fragmentation_limit)
    payloads = _build_av1_payloads(obus, metadata)

    packets: list[bytes] = []
    rtp_sequence = current_rtp_sequence
    twcc_sequence = current_twcc_sequence
    last_payload_index = len(payloads) - 1
    for index, payload in enumerate(payloads):
        rtp_sequence = (rtp_sequence + 1) & 0xFFFF
        twcc_sequence = (twcc_sequence + 1) & 0xFFFF
        packets.append(
            _serialize_rtp_packet(
                payload,
                index == last_payload_index,
                rtp_sequence,
                timestamp,
                ssrc,
                twcc_sequence,
            )
        )

    return tuple(packets), rtp_sequence, twcc_sequence


def _validate_types(
    frame: object,
    fragmentation_limit: object,
    timestamp: object,
    ssrc: object,
    current_rtp_sequence: object,
    current_twcc_sequence: object,
) -> None:
    if type(frame) is not bytes:
        raise TypeError("frame must be bytes")
    integer_arguments = (
        ("fragmentation_limit", fragmentation_limit),
        ("timestamp", timestamp),
        ("ssrc", ssrc),
        ("current_rtp_sequence", current_rtp_sequence),
        ("current_twcc_sequence", current_twcc_sequence),
    )
    for name, value in integer_arguments:
        # bool is intentionally not an integer in this wire-level contract.
        if type(value) is not int:
            raise TypeError(f"{name} must be int")


def _validate_range(name: str, value: int, low: int, high: int) -> None:
    if value < low or value > high:
        raise ValueError(f"{name} must be in range {low}..{high}")


def _malformed(reason: str) -> ValueError:
    return ValueError(f"malformed AV1 frame: {reason}")


def _read_leb128(data: memoryview, position: int) -> tuple[int, int]:
    value = 0
    for byte_index in range(5):
        if position + byte_index >= len(data):
            raise _malformed("truncated OBU size")
        octet = data[position + byte_index]
        if byte_index == 4 and octet > 0x0F:
            raise _malformed("OBU size exceeds 32-bit LEB128")
        value |= (octet & 0x7F) << (7 * byte_index)
        if octet & 0x80 == 0:
            return value, byte_index + 1
    raise _malformed("OBU size exceeds 32-bit LEB128")


def _parse_obus(frame: bytes) -> tuple[_Obu, ...]:
    data = memoryview(frame)
    obus: list[_Obu] = []
    position = 0
    while position < len(data):
        header = data[position]
        has_extension = bool(header & _OBU_HAS_EXTENSION_BIT)
        has_size = bool(header & _OBU_HAS_SIZE_BIT)
        header_size = 2 if has_extension else 1
        if len(data) - position < header_size:
            raise _malformed("truncated OBU extension header")

        extension_header = data[position + 1] if has_extension else 0
        payload_position = position + header_size
        if has_size:
            payload_size, size_field_length = _read_leb128(data, payload_position)
            payload_position += size_field_length
            payload_end = payload_position + payload_size
            if payload_end > len(data):
                raise _malformed("declared OBU size exceeds frame")
        else:
            payload_end = len(data)

        obu_type = (header & _OBU_TYPE_MASK) >> 3
        if obu_type not in _IGNORED_OBU_TYPES:
            obus.append(
                _Obu(header, extension_header, data[payload_position:payload_end])
            )
        position = payload_end

    return tuple(obus)


def _leb128_size(value: int) -> int:
    size = 1
    while value >= 0x80:
        size += 1
        value >>= 7
    return size


def _encode_leb128(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append(0x80 | (value & 0x7F))
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _additional_bytes_for_previous_obu(packet: _PacketMetadata) -> int:
    if (
        packet.packet_size == 0
        or packet.num_obu_elements > _MAX_NUM_OBUS_TO_OMIT_SIZE
    ):
        return 0
    return _leb128_size(packet.last_obu_size)


def _max_fragment_size(remaining_bytes: int) -> int:
    if remaining_bytes <= 1:
        return 0
    leb_size = 1
    while True:
        if remaining_bytes < (1 << (7 * leb_size)) + leb_size:
            return remaining_bytes - leb_size
        leb_size += 1


def _packetize_obus(
    obus: tuple[_Obu, ...], fragmentation_limit: int
) -> tuple[_PacketMetadata, ...]:
    if not obus:
        return ()

    max_payload_size = fragmentation_limit - 1
    packets = [_PacketMetadata(0)]
    packet_remaining_bytes = max_payload_size

    for obu_index, obu in enumerate(obus):
        is_last_obu = obu_index == len(obus) - 1
        packet = packets.pop()
        previous_obu_extra_size = _additional_bytes_for_previous_obu(packet)
        min_required_size = (
            2
            if packet.num_obu_elements >= _MAX_NUM_OBUS_TO_OMIT_SIZE
            else 1
        )
        if packet_remaining_bytes < previous_obu_extra_size + min_required_size:
            packets.append(packet)
            packet = _PacketMetadata(obu_index)
            packet_remaining_bytes = max_payload_size
            previous_obu_extra_size = 0

        packet.packet_size += previous_obu_extra_size
        packet_remaining_bytes -= previous_obu_extra_size
        packet.num_obu_elements += 1
        must_write_size = packet.num_obu_elements > _MAX_NUM_OBUS_TO_OMIT_SIZE

        required_bytes = obu.size
        if must_write_size:
            required_bytes += _leb128_size(obu.size)
        if required_bytes < packet_remaining_bytes:
            packet.last_obu_size = obu.size
            packet.packet_size += required_bytes
            packet_remaining_bytes -= required_bytes
            packets.append(packet)
            continue

        max_first_fragment_size = (
            _max_fragment_size(packet_remaining_bytes)
            if must_write_size
            else packet_remaining_bytes
        )
        first_fragment_size = min(obu.size - 1, max_first_fragment_size)
        if first_fragment_size == 0:
            packet.num_obu_elements -= 1
            packet.packet_size -= previous_obu_extra_size
        else:
            packet.packet_size += first_fragment_size
            if must_write_size:
                packet.packet_size += _leb128_size(first_fragment_size)
            packet.last_obu_size = first_fragment_size
        packets.append(packet)

        obu_offset = first_fragment_size
        while obu_offset + max_payload_size < obu.size:
            middle = _PacketMetadata(
                obu_index,
                num_obu_elements=1,
                first_obu_offset=obu_offset,
                last_obu_size=max_payload_size,
                packet_size=max_payload_size,
            )
            packets.append(middle)
            obu_offset += max_payload_size

        last_fragment_size = obu.size - obu_offset
        if is_last_obu and last_fragment_size > max_payload_size:
            semi_last_fragment_size = last_fragment_size // 2
            if semi_last_fragment_size >= last_fragment_size:
                semi_last_fragment_size = last_fragment_size - 1
            last_fragment_size -= semi_last_fragment_size
            packets.append(
                _PacketMetadata(
                    obu_index,
                    num_obu_elements=1,
                    first_obu_offset=obu_offset,
                    last_obu_size=semi_last_fragment_size,
                    packet_size=semi_last_fragment_size,
                )
            )
            obu_offset += semi_last_fragment_size

        packets.append(
            _PacketMetadata(
                obu_index,
                num_obu_elements=1,
                first_obu_offset=obu_offset,
                last_obu_size=last_fragment_size,
                packet_size=last_fragment_size,
            )
        )
        packet_remaining_bytes = max_payload_size - last_fragment_size

    # With the accepted minimum payload budget, the initial placeholder always
    # receives at least one byte.  Keep this guard explicit for future changes.
    if any(packet.num_obu_elements == 0 for packet in packets):
        raise _malformed("OBU cannot be represented at fragmentation limit")
    return tuple(packets)


def _aggregation_header(
    obus: tuple[_Obu, ...], packet: _PacketMetadata, packet_index: int
) -> int:
    header = 0
    if packet.first_obu_offset > 0:
        header |= 0x80

    last_obu_offset = (
        packet.first_obu_offset if packet.num_obu_elements == 1 else 0
    )
    last_obu = obus[packet.first_obu_index + packet.num_obu_elements - 1]
    if last_obu_offset + packet.last_obu_size < last_obu.size:
        header |= 0x40
    if packet.num_obu_elements <= _MAX_NUM_OBUS_TO_OMIT_SIZE:
        header |= packet.num_obu_elements << 4
    if (
        packet_index == 0
        and ((obus[0].header & _OBU_TYPE_MASK) >> 3)
        == _OBU_TYPE_SEQUENCE_HEADER
    ):
        header |= 0x08
    return header


def _append_obu_fragment(
    output: bytearray, obu: _Obu, obu_offset: int, fragment_size: int
) -> None:
    if obu_offset == 0 and fragment_size > 0:
        output.append(obu.header & ~_OBU_HAS_SIZE_BIT)
        fragment_size -= 1
    if (
        obu_offset <= 1
        and obu.header & _OBU_HAS_EXTENSION_BIT
        and fragment_size > 0
    ):
        output.append(obu.extension_header)
        fragment_size -= 1
    payload_offset = max(obu_offset - obu.header_size, 0)
    output.extend(obu.payload[payload_offset : payload_offset + fragment_size])


def _build_av1_payloads(
    obus: tuple[_Obu, ...], packets: tuple[_PacketMetadata, ...]
) -> tuple[bytes, ...]:
    payloads: list[bytes] = []
    for packet_index, packet in enumerate(packets):
        output = bytearray()
        output.append(_aggregation_header(obus, packet, packet_index))
        obu_offset = packet.first_obu_offset

        for relative_index in range(packet.num_obu_elements - 1):
            obu = obus[packet.first_obu_index + relative_index]
            fragment_size = obu.size - obu_offset
            output.extend(_encode_leb128(fragment_size))
            _append_obu_fragment(output, obu, obu_offset, fragment_size)
            obu_offset = 0

        last_obu = obus[
            packet.first_obu_index + packet.num_obu_elements - 1
        ]
        if packet.num_obu_elements > _MAX_NUM_OBUS_TO_OMIT_SIZE:
            output.extend(_encode_leb128(packet.last_obu_size))
        _append_obu_fragment(
            output, last_obu, obu_offset, packet.last_obu_size
        )
        payloads.append(bytes(output))
    return tuple(payloads)


def _serialize_rtp_packet(
    payload: bytes,
    marker: bool,
    sequence: int,
    timestamp: int,
    ssrc: int,
    twcc_sequence: int,
) -> bytes:
    output = bytearray(20 + len(payload))
    output[0] = 0x90  # RTP v2, extension present, no padding or CSRCs.
    output[1] = (0x80 if marker else 0) | 45
    output[2:4] = sequence.to_bytes(2, "big")
    output[4:8] = timestamp.to_bytes(4, "big")
    output[8:12] = ssrc.to_bytes(4, "big")
    output[12:16] = b"\xBE\xDE\x00\x01"
    output[16] = 0x41  # One-byte extension id 4, value length 2.
    output[17:19] = twcc_sequence.to_bytes(2, "big")
    output[19] = 0
    output[20:] = payload
    return bytes(output)
