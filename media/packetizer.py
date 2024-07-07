import secrets
from .rtp import RTPHeader, VP8Packet

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

        # ext_uri = ExtMap(value=rtp_ext.value, uri=rtp_ext.uri)

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


class Packetizer:
    def __init__(self, payloader: VP8Payloader) -> None:
        self._payloader = payloader
        self._sequencer = Sequencer()

    def packetize(
        self, payload: memoryview, timestamp: int, ssrc: int
    ) -> list[VP8Packet]:
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
                ssrc=ssrc,
                csrc=list[int](),
            )
            packet = VP8Packet(header)
            packet.copy_memoryview(payload)
            packets.append(packet)

        # May be added send ntp time
        # https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/abs-send-time

        return packets
