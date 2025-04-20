from dataclasses import dataclass, field
from enum import IntEnum

import ice.stun.utils as byteops


@dataclass
class Extension:
    id: int  # uint8
    payload: bytes


class ExtensionProfile(IntEnum):
    Unknown = 0
    OneByte = 0xBEDE
    TwoByte = 0x1000


# 8 bits = 1 byte
# 16 bits = 2 bytes
# 32 bits = 4 bytes
# 64 bits = 8 bytes


OUTBOUND_MTU = 1200


VERSION_SHIFT = 6
PADDING_SHIFT = 5
EXTENSION_SHIFT = 4

CSRC_LENGTH = 4


@dataclass
class RTPHeader:
    version: int  # uint8
    padding: bool
    extension: bool
    marker: bool
    payload_type: int  # uint8
    sequence_number: int  # uint16
    timestamp: int  # uint32
    ssrc: int  # uint32
    csrc: list[int] = field(default_factory=list)  # list[uint32]
    extension_profile: ExtensionProfile = field(default=ExtensionProfile.OneByte)
    extensions: list[Extension] = field(default_factory=list)

    def marshal_size(self) -> int:
        size = 12 + (len(self.csrc) * CSRC_LENGTH)

        if self.extension:
            ext_size = 4

            match self.extension_profile:
                case ExtensionProfile.OneByte:
                    for ext in self.extensions:
                        ext_size += 1 + len(ext.payload)
                case ExtensionProfile.TwoByte:
                    for ext in self.extensions:
                        ext_size += 2 + len(ext.payload)
                case _:
                    ext_size += len(self.extensions[0].payload)

            size += int(((ext_size + 3) / 4) * 4)

        return size

    def marshal(self) -> memoryview:
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |V=2|P|X|  CC   |M|     PT      |       sequence number         |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                           timestamp                           |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |           synchronization source (SSRC) identifier            |
        # +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
        # |            contributing source (CSRC) identifiers             |
        # |                             ....                              |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        data = bytearray(self.marshal_size())

        data[0] = (self.version << VERSION_SHIFT) | len(self.csrc)
        if self.padding:
            data[0] |= 1 << PADDING_SHIFT

        if self.extension:
            data[0] |= 1 << EXTENSION_SHIFT

        data[1] = self.payload_type

        if self.marker:
            data[1] |= 1 << EXTENSION_SHIFT

        data[2:4] = self.sequence_number.to_bytes(2, "big")
        data[4:8] = byteops.pack_unsigned(self.timestamp)
        data[8:12] = byteops.pack_unsigned(self.ssrc)

        n = 12
        for csrc in self.csrc:
            data[n : n + 4] = byteops.pack_unsigned(csrc)
            n += 4

        return memoryview(data)


class VP8Packet:
    def __init__(self, header: RTPHeader) -> None:
        self._header = header
        self._payload: bytes | None = None

    def copy_memoryview(self, view: memoryview):
        self._payload = view.tobytes()
