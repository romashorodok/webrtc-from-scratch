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


# Buffer limits
SRTP_BUFFER_SIZE = 1_000_000  # 1MB for RTP
SRTCP_BUFFER_SIZE = 100_000  # 100KB for RTCP


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

        try:
            self._queue.put_nowait(data)
            return True
        except asyncio.QueueFull:
            # Silently drop when buffer full (like Rust impl)
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
        if self.is_rtp:
            return self._context.encrypt_rtp(plaintext)
        else:
            return self._context.encrypt_rtcp(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt an incoming packet (synchronous).

        Args:
            ciphertext: SRTP or SRTCP packet to decrypt

        Returns:
            Decrypted RTP or RTCP packet
        """
        if self.is_rtp:
            return self._context.decrypt_rtp(ciphertext)
        else:
            return self._context.decrypt_rtcp(ciphertext)

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
            return stream, True

    async def write_incoming(self, ciphertext: bytes) -> None:
        """
        Process an incoming encrypted packet.

        Decrypts the packet and routes it to the appropriate Stream
        based on SSRC. Creates new Stream if needed.

        Args:
            ciphertext: Encrypted incoming packet
        """
        # Decrypt
        decrypted = self.decrypt(ciphertext)

        # Get SSRC from decrypted packet
        if self.is_rtp:
            ssrc = parse_rtp_ssrc(decrypted)
        else:
            ssrc = parse_rtcp_ssrc(decrypted)

        # Route to stream
        stream, is_new = await self._get_or_create_stream(ssrc)

        if is_new:
            await self._new_stream_queue.put((stream, ssrc))

        await stream.write(decrypted)

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
            for stream in list(self._streams.values()):
                await stream.close()
            self._streams.clear()
