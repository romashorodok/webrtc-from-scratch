from enum import IntEnum
import io
import secrets
from typing import Self
from dataclasses import dataclass, field
import itertools
import time
from datetime import datetime

import ice.stun.utils as byteops

IVF_FILE_HEADER_SIGNATURE = "DKIF"
IVF_FILE_HEADER_SIZE = 32
IVF_FRAME_HEADER_SIZE = 12


@dataclass
class IVFFileHeader:
    signature: str
    version: int
    header_size: int
    four_cc: str
    width: int
    height: int
    timebase_denominator: int
    timebase_numerator: int
    num_frames: int
    unused: int

    @classmethod
    def parse(cls, data: memoryview) -> Self:
        return cls(
            signature=data[:4].tobytes().decode(),
            version=int.from_bytes(data[4:6], "little"),
            header_size=int.from_bytes(data[6:8], "little"),
            four_cc=data[8:12].tobytes().decode(),
            width=int.from_bytes(data[12:14], "little"),
            height=int.from_bytes(data[14:16], "little"),
            timebase_denominator=int.from_bytes(data[16:20], "little"),
            timebase_numerator=int.from_bytes(data[20:24], "little"),
            num_frames=int.from_bytes(data[24:28], "little"),
            unused=int.from_bytes(data[28:32], "little"),
        )


@dataclass
class IVFFrameHeader:
    frame_size: int
    timestamp: int

    @classmethod
    def parse(cls, data: memoryview) -> Self:
        return cls(
            frame_size=int.from_bytes(data[:4], "little"),
            timestamp=int.from_bytes(data[4:12], "little"),
        )


class IVFReader:
    def __init__(self, reader: io.BufferedReader) -> None:
        self._reader = reader
        self.read_succesfull_count = 0
        self.file_header = self._read_file_header()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> tuple[memoryview, IVFFrameHeader]:
        header = self._read_frame_header()
        if not header:
            raise StopIteration

        frame_payload = bytearray(header.frame_size)
        n = self._reader.readinto(frame_payload)
        if n == 0:
            raise StopIteration

        self.read_succesfull_count += n

        return memoryview(frame_payload), header

    def _read_frame_header(self) -> IVFFrameHeader | None:
        data = bytearray(IVF_FRAME_HEADER_SIZE)
        n = self._reader.readinto(data)
        if n == 0:
            return

        self.read_succesfull_count += n
        return IVFFrameHeader.parse(memoryview(data))

    def _read_file_header(self) -> IVFFileHeader:
        data = bytearray(IVF_FILE_HEADER_SIZE)
        n = self._reader.readinto(data)
        if n == 0:
            raise EOFError("EOF")

        if n != IVF_FILE_HEADER_SIZE:
            raise IOError(
                f"Failed to read ivf header Expected {IVF_FILE_HEADER_SIZE} bytes, got {n} bytes."
            )

        header = IVFFileHeader.parse(memoryview(data))

        if header.signature != IVF_FILE_HEADER_SIGNATURE:
            raise IOError("Signature mismatch. Use IVF container")

        if header.version != 0:
            raise ValueError("Unsuported header version")

        self.read_succesfull_count += n

        return header


VP8_HEADER_SIZE = 1


class VP8Payloader:
    def __init__(self, enable_picture_id: bool) -> None:
        self._enable_picture_id = enable_picture_id
        self._picture_id = 0

    def payload(self, mtu: int, payload: memoryview) -> list[memoryview]:
        # https://tools.ietf.org/html/rfc7741#section-4.2
        #
        #       0 1 2 3 4 5 6 7
        #      +-+-+-+-+-+-+-+-+
        #      |X|R|N|S|R| PID | (REQUIRED)
        #      +-+-+-+-+-+-+-+-+
        # X:   |I|L|T|K| RSV   | (OPTIONAL)
        #      +-+-+-+-+-+-+-+-+
        # I:   |M| PictureID   | (OPTIONAL)
        #      +-+-+-+-+-+-+-+-+
        # L:   |   TL0PICIDX   | (OPTIONAL)
        #      +-+-+-+-+-+-+-+-+
        # T/K: |TID|Y| KEYIDX  | (OPTIONAL)
        #      +-+-+-+-+-+-+-+-+
        #
        #  S: Start of VP8 partition.  SHOULD be set to 1 when the first payload
        #     octet of the RTP packet is the beginning of a new VP8 partition,
        #     and MUST NOT be 1 otherwise.  The S bit MUST be set to 1 for the
        #     first packet of each encoded frame.

        header_size = VP8_HEADER_SIZE
        if self._enable_picture_id:
            if self._picture_id < 128:
                header_size += 2
            elif self._picture_id:
                pass
            else:
                header_size += 3

        max_fragment_size = mtu - header_size
        payload_len = len(payload)

        if min(max_fragment_size, payload_len) <= 0:
            return list()

        first = True

        fragments = list[memoryview]()
        for frag_idx in range(payload_len):
            current_fragment_size = min(max_fragment_size, payload_len)

            header = bytearray(header_size)

            if first:
                header[0] = 0x10
                first = True

            if self._enable_picture_id:
                if VP8_HEADER_SIZE == header_size:
                    pass
                elif VP8_HEADER_SIZE + 2 == header_size:
                    header[0] |= 0x80
                    header[1] |= 0x80  # 10000000
                    header[2] |= self._picture_id & 0x7F  # 01111111
                elif VP8_HEADER_SIZE + 3 == header_size:
                    header[0] |= 0x80
                    header[1] |= 0x80
                    header[2] |= 0x80 | (self._picture_id >> 8) & 0x7F
                    header[3] |= self._picture_id & 0xFF  # 11111111

            fragment = bytearray(header_size + current_fragment_size)
            fragment[:header_size] = header
            fragment[header_size:] = payload[
                frag_idx : frag_idx + current_fragment_size
            ]

            fragments.append(memoryview(fragment))

        return fragments

    @staticmethod
    def get_payload_type() -> int:
        return 96


class Sequencer:
    def __init__(self, seq_number: int = secrets.randbits(16)) -> None:
        # Must be uint16
        self._seq_number: int = seq_number & 0xFFFF
        self._roll_over_count: int = 0

    def next_seq_number(self) -> int:
        self._seq_number = (self._seq_number + 1) & 0xFFFF

        if self._seq_number == 0:
            self._roll_over_count += 1

        return self._seq_number

    def roll_over_count(self) -> int:
        return self._roll_over_count


OUTBOUND_MTU = 1200


VERSION_SHIFT = 6
PADDING_SHIFT = 5
EXTENSION_SHIFT = 4

CSRC_LENGTH = 4


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

        if self.extension:
            ext_header_pos = n
            data[n : n + 2] = byteops.pack_unsigned_short(self.extension_profile)
            n += 4
            start_extensions_pos = n

            match self.extension_profile:
                case ExtensionProfile.OneByte:
                    for ext in self.extensions:
                        payload_len = len(ext.payload)
                        data[n] = ext.id << 4 | payload_len - 1
                        n += 1
                        data[n:payload_len] = ext.payload
                        n += payload_len
                case ExtensionProfile.TwoByte:
                    for ext in self.extensions:
                        data[n] = ext.id
                        n += 1
                        payload_len = len(ext.payload)
                        data[n] = len(ext.payload)
                        n += 1
                        data[n:payload_len] = ext.payload
                        n += payload_len
                case _:
                    raise ValueError("Unsupported")

            ext_size = n - start_extensions_pos
            rounded_ext_size = int(((ext_size + 3) / 4) * 4)

            data[ext_header_pos + 2 : ext_header_pos + 4] = byteops.pack_unsigned_short(
                rounded_ext_size
            )

            for _ in range(rounded_ext_size):
                data[n] = 0
                n += 1

        return memoryview(data)


class VP8Packet:
    def __init__(self, header: RTPHeader) -> None:
        self._header = header
        self._payload: bytes | None = None

    def copy_memoryview(self, view: memoryview):
        self._payload = view.tobytes()


class Packetizer:
    def __init__(self, ssrc: int, payloader: VP8Payloader) -> None:
        self._ssrc = ssrc
        self._payloader = payloader
        self._sequencer = Sequencer()

    def packetize(self, payload: memoryview, timestamp: int) -> list[VP8Packet]:
        packets = list[VP8Packet]()

        if len(payload) == 0:
            return packets

        payloads = self._payloader.payload(OUTBOUND_MTU - 12, payload)
        for i, payload in enumerate(payloads):
            header = RTPHeader(
                version=2,
                padding=False,
                extension=False,
                marker=i == len(payloads) - 1,
                payload_type=self._payloader.get_payload_type(),
                sequence_number=self._sequencer.next_seq_number(),
                timestamp=timestamp,
                ssrc=self._ssrc,
                csrc=list[int](),
            )
            packet = VP8Packet(header)
            packet.copy_memoryview(payload)
            packets.append(packet)

        # May be added send ntp time
        # https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/abs-send-time

        return packets


def tick(interval, initial_wait=False):
    start = time.perf_counter_ns()

    if not initial_wait:
        yield

    for i in itertools.count(1):
        current_time = time.perf_counter_ns()
        sleep_duration = (start + i * interval - current_time) / 1e9

        if sleep_duration > 0:
            time.sleep(sleep_duration)
        else:
            pass

        yield


packetizer = Packetizer(ssrc=secrets.randbits(32), payloader=VP8Payloader(True))

clock_rate = 90000
with open("output.ivf", "rb") as file:
    reader = IVFReader(file)
    file_header = reader.file_header

    # timebase_denominator and timebase_numerator define a timebase fraction
    # timebase_numerator / timebase_denominator = the time units per second.
    timebase_fraction = (
        file_header.timebase_numerator / file_header.timebase_denominator
    )
    interval_ns = timebase_fraction * 1e9

    # for _ in tick(interval_ns):
    while True:
        try:
            frame, frame_header = next(reader)

            frame_duration_seconds = frame_header.timestamp / timebase_fraction
            frame_samples = int(frame_duration_seconds * clock_rate)

            # Example for:
            # Duration: 00:00:30.00, start: 0.000000, bitrate: 144 kb/s
            # vp8 (VP80 / 0x30385056), yuv420p(progressive), 640x480, 30 tbr, 30 tbn

            # Last frame looks like:
            # frame_samples: 2427300000
            # frame_duration_seconds: 26970.0
            # rtp_frame_timestamp: 29.966666666666665
            # rtp_frame_timestamp = int(frame_header.timestamp * timebase_fraction)

            rtp_frame_timestamp = int(datetime.now().timestamp() + frame_samples)

            pkts = packetizer.packetize(frame, rtp_frame_timestamp)
            for pkt in pkts:
                header = pkt._header.marshal()
                payload = pkt._payload
                if not payload:
                    continue

                print(list(header.tobytes()))
                break
            break
        # data = header.tobytes() + payload
        # # print("frame", data)

        except StopIteration:
            print("Reach EOF")
            break
