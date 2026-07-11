"""
SRTP Session with Stream demuxing, using Rust cipher backend.

This module provides the high-level Session interface that:
- Uses Rust SrtpContext for crypto (AES-CM, HMAC-SHA1, ROC tracking)
- Demultiplexes incoming packets by SSRC to Stream objects
- Provides async read interface for consuming decrypted packets
"""

import asyncio
from dataclasses import dataclass
from typing import Optional, Callable, Awaitable

# Import Rust SRTP context
from webrtc_rs import SrtpContext

# Import logger
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.tracing import measure_perf, perf_mark


# Buffer limits
SRTP_BUFFER_SIZE = 1_000_000  # 1MB for RTP
SRTCP_BUFFER_SIZE = 100_000  # 100KB for RTCP


def _packet_metadata(data: bytes, is_rtp: bool, *, size_key: str) -> dict[str, int | str]:
    """Return cheap, header-only tracing metadata for an SRTP operation."""
    metadata: dict[str, int | str] = {
        "packet_kind": "rtp" if is_rtp else "rtcp",
        size_key: len(data),
    }
    if is_rtp:
        if len(data) >= 4:
            metadata["sequence_number"] = int.from_bytes(data[2:4], "big")
        if len(data) >= 12:
            metadata["ssrc"] = int.from_bytes(data[8:12], "big")
    elif len(data) >= 8:
        # The sender SSRC is unencrypted in the RTCP common packet header.
        metadata["ssrc"] = int.from_bytes(data[4:8], "big")
    return metadata


def parse_rtp_ssrc(data: bytes) -> int:
    """Extract SSRC from RTP packet (bytes 8-11)."""
    if len(data) < 12:
        raise ValueError(f"RTP packet too small: {len(data)} < 12")
    return int.from_bytes(data[8:12], 'big')


def parse_rtcp_ssrc(data: bytes) -> int:
    """
    Extract the media source SSRC from RTCP feedback packet.

    For RTCP feedback packets (like TWCC, NACK, PLI), the structure is:
    - Bytes 0-3: Header (version, PT, length)
    - Bytes 4-7: Sender SSRC (who is sending this feedback - e.g., browser)
    - Bytes 8-11: Media Source SSRC (the stream being reported on - our sender's SSRC)

    We route based on media_ssrc so feedback gets to the correct sender stream.
    """
    if len(data) < 12:
        raise ValueError(f"RTCP packet too small for feedback: {len(data)} < 12")
    # Return media_ssrc (bytes 8-11) for proper routing of feedback
    return int.from_bytes(data[8:12], 'big')


class Stream:
    """
    Stream handles decrypted packets for a single SSRC.

    Each Stream maintains an async queue of decrypted packets
    that can be read by consumers.
    """

    def __init__(self, ssrc: int, is_rtp: bool, on_close: Optional[Callable[[int], Awaitable[None]]] = None):
        """
        Create a new Stream.

        Args:
            ssrc: The SSRC this stream handles
            is_rtp: True for RTP, False for RTCP
            on_close: Optional callback when stream is closed
        """
        self.ssrc = ssrc
        self.is_rtp = is_rtp
        self._on_close = on_close
        self._closed = False

        # Async queue for buffered packets
        # Use packet count limit rather than byte limit for simplicity
        self._queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)

    @property
    def closed(self) -> bool:
        return self._closed

    async def write(self, data: bytes) -> bool:
        """
        Write decrypted packet to stream buffer.

        Called by Session when a packet for this SSRC is received.

        Args:
            data: Decrypted packet data

        Returns:
            True if written, False if buffer full (packet dropped)
        """
        if self._closed:
            return False

        logger = get_logger()
        config = get_config()

        try:
            self._queue.put_nowait(data)
            queue_size = self._queue.qsize()

            # Log first N writes to see queue growth
            if queue_size <= config.log_first_n_packets:
                seq = int.from_bytes(data[2:4], 'big') if len(data) >= 4 else -1
                logger.log_queue_size(Component.SRTP, f"stream_{self.ssrc}", queue_size, self._queue.maxsize)
                logger.trace(Component.SRTP, f"Wrote packet to stream", ssrc=self.ssrc, seq=seq)
            return True
        except asyncio.QueueFull:
            # Drop packet when buffer full
            seq = int.from_bytes(data[2:4], 'big') if len(data) >= 4 else -1
            logger.warn(Component.SRTP, f"DROPPED packet - stream queue full",
                       ssrc=self.ssrc, seq=seq, maxsize=self._queue.maxsize)
            return False

    async def read(self) -> bytes:
        """
        Read the next decrypted packet.

        Blocks until a packet is available or stream is closed.

        Returns:
            Decrypted packet data

        Raises:
            RuntimeError: If stream is closed
        """
        if self._closed and self._queue.empty():
            raise RuntimeError("Stream closed")

        return await self._queue.get()

    async def close(self) -> None:
        """Close the stream."""
        if self._closed:
            return

        self._closed = True

        if self._on_close:
            await self._on_close(self.ssrc)


@dataclass
class SessionKeys:
    """Session keys for local and remote contexts."""
    local_master_key: bytes
    local_master_salt: bytes
    remote_master_key: bytes
    remote_master_salt: bytes


class Session:
    """
    SRTP Session with bidirectional encryption and stream demuxing.

    A Session manages:
    - Rust SrtpContext for crypto operations
    - Stream demultiplexing by SSRC for incoming packets

    This is the main interface for SRTP in the WebRTC stack.
    """

    def __init__(self, keys: SessionKeys, is_rtp: bool = True):
        """
        Create a new SRTP session.

        Args:
            keys: Session keys for local and remote contexts
            is_rtp: True for RTP session, False for RTCP session
        """
        self.is_rtp = is_rtp

        # Create Rust SRTP context
        # tx_key = local key + salt (for encryption)
        # rx_key = remote key + salt (for decryption)
        tx_key = keys.local_master_key + keys.local_master_salt
        rx_key = keys.remote_master_key + keys.remote_master_salt
        self._context = SrtpContext(tx_key, rx_key)

        # Stream management
        self._streams: dict[int, Stream] = {}
        self._streams_lock = asyncio.Lock()

        # Channel for notifying about new streams
        self._new_stream_queue: asyncio.Queue[tuple[Stream, int]] = asyncio.Queue()

        # Debug counters
        self._decrypt_count = 0
        self._decrypt_errors = 0
        self._ssrc_counters: dict[int, int] = {}

    @classmethod
    def from_keying_material(
        cls,
        tx_key: bytes,
        rx_key: bytes,
        is_rtp: bool = True,
    ) -> "Session":
        """
        Create session from DTLS-derived keying material.

        Args:
            tx_key: 30-byte key material for transmission (16 key + 14 salt)
            rx_key: 30-byte key material for reception (16 key + 14 salt)
            is_rtp: True for RTP, False for RTCP

        Returns:
            New Session instance
        """
        if len(tx_key) != 30 or len(rx_key) != 30:
            raise ValueError("Key material must be 30 bytes (16 key + 14 salt)")

        keys = SessionKeys(
            local_master_key=tx_key[:16],
            local_master_salt=tx_key[16:],
            remote_master_key=rx_key[:16],
            remote_master_salt=rx_key[16:],
        )
        return cls(keys, is_rtp)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt an outgoing packet (synchronous).

        Args:
            plaintext: RTP or RTCP packet to encrypt

        Returns:
            Encrypted SRTP or SRTCP packet
        """
        packet_type = "rtp" if self.is_rtp else "rtcp"
        phase = f"{packet_type}_encrypt"
        metadata = _packet_metadata(plaintext, self.is_rtp, size_key="plaintext_size_bytes")
        metadata["flow_direction"] = "tx"
        with measure_perf("srtp", phase, metadata=metadata):
            try:
                encrypted = (
                    self._context.encrypt_rtp(plaintext)
                    if self.is_rtp
                    else self._context.encrypt_rtcp(plaintext)
                )
            except BaseException:
                metadata[f"counter.srtp.{packet_type}_encrypt_failed"] = 1
                metadata["error_stage"] = "srtp_encrypt"
                raise
            # ``measure_perf`` retains this mapping until it emits completion,
            # letting the completed event describe both sides of the boundary.
            metadata["ciphertext_size_bytes"] = len(encrypted)
            metadata[f"counter.srtp.{packet_type}_encrypted"] = 1
            return encrypted

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt an incoming packet (synchronous).

        Args:
            ciphertext: SRTP or SRTCP packet to decrypt

        Returns:
            Decrypted RTP or RTCP packet
        """
        packet_type = "rtp" if self.is_rtp else "rtcp"
        phase = f"{packet_type}_decrypt"
        metadata = _packet_metadata(ciphertext, self.is_rtp, size_key="ciphertext_size_bytes")
        metadata["flow_direction"] = "rx"
        with measure_perf("srtp", phase, metadata=metadata):
            try:
                decrypted = (
                    self._context.decrypt_rtp(ciphertext)
                    if self.is_rtp
                    else self._context.decrypt_rtcp(ciphertext)
                )
            except BaseException:
                metadata[f"counter.srtp.{packet_type}_decrypt_failed"] = 1
                metadata["error_stage"] = "srtp_decrypt"
                raise
            metadata["plaintext_size_bytes"] = len(decrypted)
            metadata[f"counter.srtp.{packet_type}_decrypted"] = 1
            return decrypted

    async def encrypt_async(self, plaintext: bytes) -> bytes:
        """
        Encrypt an outgoing packet (async wrapper).

        Args:
            plaintext: RTP or RTCP packet to encrypt

        Returns:
            Encrypted SRTP or SRTCP packet
        """
        return self.encrypt(plaintext)

    async def decrypt_async(self, ciphertext: bytes) -> bytes:
        """
        Decrypt an incoming packet (async wrapper).

        Args:
            ciphertext: SRTP or SRTCP packet to decrypt

        Returns:
            Decrypted RTP or RTCP packet
        """
        return self.decrypt(ciphertext)

    async def _get_or_create_stream(self, ssrc: int) -> tuple[Stream, bool]:
        """
        Get existing stream or create new one for SSRC.

        Returns:
            Tuple of (stream, is_new)
        """
        async with self._streams_lock:
            if ssrc in self._streams:
                return self._streams[ssrc], False

            async def on_close(closed_ssrc: int) -> None:
                async with self._streams_lock:
                    self._streams.pop(closed_ssrc, None)

            stream = Stream(ssrc, self.is_rtp, on_close)
            self._streams[ssrc] = stream
            perf_mark(
                "srtp",
                "stream",
                "created",
                metadata={
                    "flow_direction": "rx",
                    "packet_kind": "rtp" if self.is_rtp else "rtcp",
                    "ssrc": ssrc,
                    "is_new": True,
                    "counter.srtp.streams_created": 1,
                },
            )
            return stream, True

    async def write_incoming(self, ciphertext: bytes) -> None:
        """
        Process an incoming encrypted packet.

        Decrypts the packet and routes it to the appropriate Stream
        based on SSRC. Creates new Stream if needed.

        Args:
            ciphertext: Encrypted incoming packet
        """
        logger = get_logger()
        config = get_config()

        self._decrypt_count += 1

        try:
            # Decrypt
            decrypted = self.decrypt(ciphertext)
        except Exception as e:
            self._decrypt_errors += 1
            if config.log_srtp_decrypt_errors and (self._decrypt_errors <= 20 or self._decrypt_errors % 100 == 0):
                # Extract sequence number from encrypted packet for debugging
                if len(ciphertext) >= 4:
                    seq = int.from_bytes(ciphertext[2:4], 'big')
                    logger.error(Component.SRTP, f"Decrypt error #{self._decrypt_errors}/{self._decrypt_count}",
                               seq=seq, error=str(e))
                else:
                    logger.error(Component.SRTP, f"Decrypt error #{self._decrypt_errors}/{self._decrypt_count}",
                               error=str(e))
            raise  # Re-raise so caller can handle

        # Get SSRC from decrypted packet
        if self.is_rtp:
            ssrc = parse_rtp_ssrc(decrypted)
        else:
            ssrc = parse_rtcp_ssrc(decrypted)

        # Track SSRC stats
        self._ssrc_counters[ssrc] = self._ssrc_counters.get(ssrc, 0) + 1
        if config.log_packet_counts and self._decrypt_count % 100 == 0 and self.is_rtp:
            error_pct = 100 * self._decrypt_errors / self._decrypt_count if self._decrypt_count > 0 else 0
            logger.log_stats(Component.SRTP,
                           packets=self._decrypt_count,
                           errors=self._decrypt_errors,
                           error_pct=f"{error_pct:.1f}%",
                           SSRCs=len(self._ssrc_counters))

        # Route to stream
        stream, is_new = await self._get_or_create_stream(ssrc)

        if is_new and config.log_srtp_new_streams:
            await self._new_stream_queue.put((stream, ssrc))
            logger.info(Component.SRTP, f"New stream created", ssrc=ssrc)

        # Check if write succeeded (could fail if stream queue is full).
        write_success = await stream.write(decrypted)
        packet_metadata = _packet_metadata(decrypted, self.is_rtp, size_key="plaintext_size_bytes")
        packet_metadata["flow_direction"] = "rx"
        packet_metadata["ssrc"] = ssrc
        if not write_success:
            seq = int.from_bytes(decrypted[2:4], 'big') if len(decrypted) >= 4 else -1
            perf_mark(
                "srtp",
                "stream",
                "dropped",
                metadata={
                    **packet_metadata,
                    "drop_reason": "stream_queue_full_or_closed",
                    "counter.srtp.stream_packets_dropped": 1,
                },
            )
            logger.warn(Component.SRTP, f"Stream write FAILED - queue full", ssrc=ssrc, seq=seq)
        else:
            perf_mark(
                "srtp",
                "stream",
                "delivered",
                metadata={
                    **packet_metadata,
                    "counter.srtp.stream_packets_delivered": 1,
                },
            )

    async def accept_stream(self) -> tuple[Stream, int]:
        """
        Wait for a new stream to be created.

        Called when a packet arrives with an SSRC we haven't seen before.

        Returns:
            Tuple of (new_stream, ssrc)
        """
        return await self._new_stream_queue.get()

    async def open_stream(self, ssrc: int) -> Stream:
        """
        Open or get an existing stream for an SSRC.

        Unlike accept_stream(), this doesn't wait - it creates immediately.

        Args:
            ssrc: SSRC to open stream for

        Returns:
            Stream for the SSRC
        """
        stream, _ = await self._get_or_create_stream(ssrc)
        return stream

    async def get_stream(self, ssrc: int) -> Optional[Stream]:
        """
        Get an existing stream by SSRC.

        Returns:
            Stream if exists, None otherwise
        """
        async with self._streams_lock:
            return self._streams.get(ssrc)

    async def close(self) -> None:
        """Close all streams and the session."""
        async with self._streams_lock:
            streams = list(self._streams.values())
            self._streams.clear()

        # Stream.close invokes the session's on_close callback, which also
        # acquires _streams_lock.  Close outside that lock to avoid deadlock.
        for stream in streams:
            await stream.close()
