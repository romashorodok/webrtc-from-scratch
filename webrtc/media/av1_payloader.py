import asyncio
from fractions import Fraction
import time
from webrtc_rs import Av1Payloader

from webrtc.media.rtp_packet import RtpPacket

from .packetizer import PacketizerBase, Sequencer

AV1_PAYLOAD_TYPE = 45


class Av1Packetizer(PacketizerBase):
    def __init__(
        self,
        mtu: int,
        pt: int,
        ssrc: int,
        clock_rate: int,
        refresh_rate: float,
    ) -> None:
        self.sequencer = Sequencer()
        self.__payloader = Av1Payloader()
        self.ssrc = ssrc
        self.mtu = mtu
        self.payload_type = pt
        self.ssrc = ssrc
        self.sequencer = Sequencer()
        self.clock_rate = clock_rate
        self.refresh_rate = refresh_rate
        self._timestamp = None
        self.timestamp = 0
        self.timestamp_increment = int(clock_rate * refresh_rate)  # 90000 * 1/30 = 3000
        self.start_time = 0

    async def next_timestamp(self) -> tuple[int, Fraction]:
        if self._timestamp is not None:
            self._timestamp += int(self.refresh_rate * self.clock_rate)
            wait = self._start + (self._timestamp / self.clock_rate) - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
        else:
            self._start = time.time()
            self._timestamp = 0

        VIDEO_TIME_BASE = Fraction(1, self.clock_rate)
        return self._timestamp, VIDEO_TIME_BASE

    async def ticker(self):
        while True:
            yield await self.next_timestamp()

    def packetize(self, payload: bytes, samples: int) -> list[RtpPacket]:
        payloads = self.__payloader.packetize(self.mtu, payload)

        packets = []

        for i, pp in enumerate(payloads):
            pkt = RtpPacket(
                payload_type=AV1_PAYLOAD_TYPE,
                sequence_number=self.sequencer.next_sequence_number(),
                timestamp=samples,
            )
            pkt.ssrc = self.ssrc
            pkt.payload = pp
            pkt.marker = (i == len(payloads) - 1) and 1 or 0
            packets.append(pkt)

        return packets
