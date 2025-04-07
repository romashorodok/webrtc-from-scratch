from struct import pack
from typing import Self

from struct import unpack_from

from .types import PayloaderProtocol
from webrtc.utils.types import impl_protocol


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

    @classmethod
    def parse(cls, data: bytes) -> tuple[Self, bytes]:
        if len(data) < 1:
            raise ValueError("VPX descriptor is too short")

        # first byte
        octet = data[0]
        extended = octet >> 7
        partition_start = (octet >> 4) & 1
        partition_id = octet & 0xF
        picture_id = None
        tl0picidx = None
        tid = None
        keyidx = None
        pos = 1

        # extended control bits
        if extended:
            if len(data) < pos + 1:
                raise ValueError("VPX descriptor has truncated extended bits")

            octet = data[pos]
            ext_I = (octet >> 7) & 1
            ext_L = (octet >> 6) & 1
            ext_T = (octet >> 5) & 1
            ext_K = (octet >> 4) & 1
            pos += 1

            # picture id
            if ext_I:
                if len(data) < pos + 1:
                    raise ValueError("VPX descriptor has truncated PictureID")

                if data[pos] & 0x80:
                    if len(data) < pos + 2:
                        raise ValueError("VPX descriptor has truncated long PictureID")

                    picture_id = unpack_from("!H", data, pos)[0] & 0x7FFF
                    pos += 2
                else:
                    picture_id = data[pos]
                    pos += 1

            # unused
            if ext_L:
                if len(data) < pos + 1:
                    raise ValueError("VPX descriptor has truncated TL0PICIDX")

                tl0picidx = data[pos]
                pos += 1
            if ext_T or ext_K:
                if len(data) < pos + 1:
                    raise ValueError("VPX descriptor has truncated T/K")

                t_k = data[pos]
                if ext_T:
                    tid = ((t_k >> 6) & 3, (t_k >> 5) & 1)
                if ext_K:
                    keyidx = t_k & 0x1F
                pos += 1

        obj = cls(
            partition_start=partition_start,
            partition_id=partition_id,
            picture_id=picture_id,
            tl0picidx=tl0picidx,
            tid=tid,
            keyidx=keyidx,
        )
        return obj, data[pos:]

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


def vp8_depayload(payload: bytes) -> bytes:
    descriptor, data = VpxPayloadDescriptor.parse(payload)
    return data


PACKET_MAX = 1300


@impl_protocol(PayloaderProtocol)
class VP8Payloader:
    @classmethod
    def packetize(cls, buffer: bytes, picture_id: int) -> list[bytes]:
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


# class VP8Payloader:
#     VP8_HEADER_SIZE = 1
#
#     def __init__(self, enable_picture_id: bool) -> None:
#         self._enable_picture_id = enable_picture_id
#         self._picture_id = 0
#
#     def payload(self, mtu: int, payload: bytes) -> list[bytes]:
#         header_size = self.VP8_HEADER_SIZE
#
#         if self._enable_picture_id:
#             if self._picture_id < 128:
#                 header_size += 2
#             else:
#                 header_size += 3
#
#         max_fragment_size = mtu - header_size
#         payload_len = len(payload)
#
#         if max_fragment_size <= 0 or payload_len <= 0:
#             return []
#
#         first = True
#         fragments = []
#         payload_data_remaining = payload_len
#         payload_data_index = 0
#
#         while payload_data_remaining > 0:
#             current_fragment_size = min(max_fragment_size, payload_data_remaining)
#
#             header = bytearray(header_size)
#
#             if first:
#                 header[0] = 0x10  # Set the S bit
#                 first = False
#
#             if self._enable_picture_id:
#                 if header_size == self.VP8_HEADER_SIZE + 2:
#                     header[0] |= 0x80  # Set the X bit
#                     header[1] = 0x80 | (self._picture_id & 0x7F)
#                 elif header_size == self.VP8_HEADER_SIZE + 3:
#                     header[0] |= 0x80  # Set the X bit
#                     header[1] = 0x80 | (self._picture_id >> 8 & 0x7F)
#                     header[2] = self._picture_id & 0xFF
#
#             fragment = bytearray(header_size + current_fragment_size)
#             fragment[:header_size] = header
#             fragment[header_size:] = payload[
#                 payload_data_index : payload_data_index + current_fragment_size
#             ]
#
#             fragments.append(fragment)
#
#             payload_data_remaining -= current_fragment_size
#             payload_data_index += current_fragment_size
#
#         self._picture_id += 1
#         self._picture_id &= 0x7FFF  # Ensure the picture ID stays within 15 bits
#
#         return fragments
