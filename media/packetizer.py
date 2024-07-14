import random
import time
import asyncio
import fractions

from .types import PayloaderProtocol
from .rtp_packet import RtpPacket


class Sequencer:
    def __init__(self, initial_value: int = random.randint(0, 65535)):
        self.sequence_number = initial_value

    def next_sequence_number(self) -> int:
        self.sequence_number += 1
        self.sequence_number &= 0xFFFF  # Wrap around to fit in uint16
        return self.sequence_number


VIDEO_CLOCK_RATE = 90000
VIDEO_TIME_BASE = fractions.Fraction(1, VIDEO_CLOCK_RATE)

VIDEO_PTIME = 1 / 30  # 30fps


class Packetizer:
    def __init__(
        self,
        mtu: int,
        pt: int,
        ssrc: int,
        payloader: PayloaderProtocol,
        clock_rate: int,
    ):
        self.mtu = mtu
        self.payload_type = pt
        self.ssrc = ssrc
        self.payloader = payloader
        self.sequencer = Sequencer()
        self.clock_rate = clock_rate
        self._timestamp = None
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

        packets = []
        payloads = self.payloader.packetize(payload, self.picture_id)
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
            # pkt.extensions.abs_send_time = (
            #     peer_connection.current_ntp_time() >> 14
            # ) & 0x00FFFFFF

            packets.append(pkt)

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
    #                 "timestamp": self._timestamp,
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
