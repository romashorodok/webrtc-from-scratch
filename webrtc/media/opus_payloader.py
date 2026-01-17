"""
Opus RTP Payloader and Depacketizer

Pure Python implementation of Opus RTP packetization following RFC 7587.
Opus frames are small enough to fit in single RTP packets, so no fragmentation is needed.
"""

import asyncio
import time
from fractions import Fraction
from typing import AsyncGenerator

from .types import PayloaderProtocol
from webrtc.utils.types import impl_protocol
from .packetizer import PacketizerBase, Sequencer
from .rtp_packet import RtpPacket

# Opus RTP constants
OPUS_PAYLOAD_TYPE = 111  # Standard Opus payload type
OPUS_CLOCK_RATE = 48000  # Standard for Opus RTP (always 48kHz for RTP timestamps)


@impl_protocol(PayloaderProtocol)
class OpusPayloader:
    """
    Opus RTP payloader.

    Opus frames are small (typically 60-480 bytes for 20-60ms of audio),
    so they fit in a single RTP packet without fragmentation.
    The RTP payload is simply the Opus frame with no additional headers.
    """

    @classmethod
    def packetize(cls, buffer: bytes, picture_id: int) -> list[bytes]:
        """
        Packetize an Opus frame into RTP payload(s).

        Since Opus frames are small, no fragmentation is needed.
        Returns a single payload containing the Opus frame.

        Args:
            buffer: Raw Opus encoded frame
            picture_id: Unused for audio (kept for interface compatibility)

        Returns:
            List containing single Opus payload (just the frame itself)
        """
        if not buffer or len(buffer) == 0:
            return []

        # Opus RTP payload is just the raw Opus frame
        # No additional headers needed (unlike VP8/AV1)
        return [buffer]


def opus_depayload(payload: bytes) -> bytes:
    """
    Depacketize Opus RTP payload to extract the Opus frame.

    Since Opus has no RTP payload header, the payload IS the Opus frame.

    Args:
        payload: RTP payload bytes

    Returns:
        Opus frame bytes (same as input)
    """
    return payload


class OpusPacketizer(PacketizerBase):
    """
    Opus RTP packetizer with timing control.

    Handles RTP packet creation with proper timing for audio streams.
    Generates timestamps and sequence numbers for Opus audio packets.
    """

    def __init__(
        self,
        mtu: int,
        pt: int,
        ssrc: int,
        clock_rate: int = OPUS_CLOCK_RATE,
        ptime: float = 0.020,  # 20ms default (standard for Opus)
    ) -> None:
        """
        Initialize Opus packetizer.

        Args:
            mtu: Maximum transmission unit (unused, kept for interface compatibility)
            pt: RTP payload type
            ssrc: Synchronization source identifier
            clock_rate: RTP clock rate (typically 48000 for Opus)
            ptime: Packet time in seconds (0.020 = 20ms, standard for Opus)
        """
        self.sequencer = Sequencer()
        self.ssrc = ssrc
        self.mtu = mtu
        self.payload_type = pt
        self.clock_rate = clock_rate
        self.ptime = ptime  # Packet time in seconds (e.g., 0.020 = 20ms)
        self._timestamp: int | None = None
        self._start: float | None = None

        # Calculate samples per packet based on clock rate and ptime
        # e.g., 48000 Hz * 0.020s = 960 samples per packet
        self.timestamp_increment = int(clock_rate * ptime)

    async def next_timestamp(self) -> tuple[int, Fraction]:
        """
        Generate next RTP timestamp with proper timing.

        Maintains consistent packet timing by sleeping when needed.

        Returns:
            Tuple of (timestamp, timebase) where timebase is 1/clock_rate
        """
        if self._timestamp is not None:
            self._timestamp += self.timestamp_increment
            # Calculate how long to wait to maintain timing
            wait = self._start + (self._timestamp / self.clock_rate) - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
        else:
            # First timestamp - initialize timing
            self._start = time.time()
            self._timestamp = 0

        AUDIO_TIME_BASE = Fraction(1, self.clock_rate)
        return self._timestamp, AUDIO_TIME_BASE

    async def ticker(self) -> AsyncGenerator[tuple[int, Fraction], None]:
        """
        Async generator that yields timestamps at configured packet rate.

        For 20ms packets (ptime=0.020), yields every 20ms.

        Yields:
            Tuple of (timestamp, timebase) for each packet time
        """
        while True:
            yield await self.next_timestamp()

    def packetize(self, payload: bytes, samples: int) -> list[RtpPacket]:
        """
        Packetize single Opus frame into RTP packet.

        Creates an RTP packet with the Opus frame as payload.
        No fragmentation is needed since Opus frames fit in single packets.

        Args:
            payload: Encoded Opus frame bytes
            samples: RTP timestamp value (number of samples)

        Returns:
            List with single RTP packet (no fragmentation)
        """
        if not payload or len(payload) == 0:
            return []

        # Create RTP packet
        pkt = RtpPacket(
            payload_type=self.payload_type,
            sequence_number=self.sequencer.next_sequence_number(),
            timestamp=samples,
        )
        pkt.ssrc = self.ssrc
        pkt.payload = payload
        pkt.marker = 1  # Always set marker bit for audio packets

        return [pkt]
