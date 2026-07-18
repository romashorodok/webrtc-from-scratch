"""
SRTP Session with Stream demuxing, using Rust cipher backend.

This module provides the high-level Session interface that:
- Uses Rust SrtpContext for crypto (AES-CM, HMAC-SHA1, ROC tracking)
- Demultiplexes incoming packets by SSRC to Stream objects
- Provides async read interface for consuming decrypted packets
"""

import asyncio
import hashlib
import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import Optional, Callable, Awaitable, Any

# Import Rust SRTP context
from webrtc_rs import SrtpContext

# Import logger
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.performance import (
    ObservedComponent, TraceDetail, event_loop, observe, performance, worker,
)
from webrtc.runtime_services import FailurePolicy, OwnedTaskHandle, current_execution_scope
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.observability import MachineTransitionOp
from webrtc.state_machine import (
    AsyncStateMachineRunner, MachineCommand, MachineSnapshot, PreparedTransition,
    ReplyPort, TransitionCommit,
)


# Buffer limits
SRTP_BUFFER_SIZE = 1_000_000  # 1MB for RTP
SRTCP_BUFFER_SIZE = 100_000  # 100KB for RTCP
MAX_SRTP_STREAMS = 128


class _LifecycleCommand(StrEnum):
    INITIALIZE = "initialize"
    READY = "ready"
    DRAIN = "drain"
    CLOSE = "close"
    ACTIVATE = "activate"


class _LifecycleRunner(AsyncStateMachineRunner[MachineCommand[object, TransitionCommit]]):
    def __init__(self, owner: Any, machine_type: str) -> None:
        self.owner = owner
        super().__init__(
            MACHINE_SPECS[machine_type], entity_id=owner.observability_id,
            mailbox_capacity=16,
            controller=getattr(owner._runtime, "transition_controller", None),
            transition_sink=owner._project_transition,
        )

    async def step(self, command):
        proposed = {
            _LifecycleCommand.INITIALIZE: "initializing",
            _LifecycleCommand.READY: "ready", _LifecycleCommand.ACTIVATE: "active",
            _LifecycleCommand.DRAIN: "draining", _LifecycleCommand.CLOSE: "closed",
        }[command.kind]
        return PreparedTransition(
            self.state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    async def after_commit(self, commit, effects):
        await self.owner._after_commit(commit)

    async def reconcile_terminal(self, prepared):
        await self.owner._reconcile_terminal()


class _PacketQueueRunner(AsyncStateMachineRunner):
    async def step(self, command):
        proposed = {"close": "closing", "drain": "drained", "closed": "closed"}[
            command.kind
        ]
        return PreparedTransition(
            self.snapshot().state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )


class _LifecycleOwner:
    def _init_lifecycle(self, machine_type: str) -> None:
        self._runtime = current_execution_scope()
        self._command_id = 0
        self._runner = _LifecycleRunner(self, machine_type)
        self._machine_handle: OwnedTaskHandle[None] | None = None
        if self._runtime is not None:
            self._runtime.projection.machines.register(self.observability_id, self._runner.spec)
            self._runtime.register_owner(self.observability_id, epoch=self._runner.epoch)
            self._machine_handle = self._runtime.start_machine(
                self._runner, owner_entity_id=self.observability_id,
                owner_epoch=self._runner.epoch, failure=FailurePolicy.FAIL_CONNECTION,
            )
            if isinstance(self, ObservedComponent):
                self.__bind_worker_owner__(
                    self._runtime, self.observability_id, self._runner.epoch
                )

    def _command(self, kind, reply=None):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            cause_id=f"{self.observability_id}:{self._command_id}",
        )

    def _project_transition(self, commit):
        if self._runtime is not None and self._runtime.tracing_enabled:
            self._runtime.projection.machines.apply(MachineTransitionOp(
                commit.entity_id, commit.machine_type, commit.from_state, commit.to_state,
                commit.epoch, commit.revision, self._runtime.new_producer_dot(),
                commit.cause, commit.monotonic_ns,
            ))

    async def _join_lifecycle(self):
        if self._machine_handle is not None:
            await self._machine_handle.wait()
            self._runtime.remove_owner(self.observability_id, self._runner.epoch)


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


class Stream(_LifecycleOwner):
    """
    Stream handles decrypted packets for a single SSRC.

    Each Stream maintains an async queue of decrypted packets
    that can be read by consumers.
    """

    def __init__(
        self, ssrc: int, is_rtp: bool,
        on_close: Optional[Callable[[int], Awaitable[None]]] = None,
        *, observability_id: str | None = None,
    ):
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
        self.observability_id = observability_id or f"stream-{secrets.token_hex(6)}"

        # Async queue for buffered packets
        # Use packet count limit rather than byte limit for simplicity
        self._queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)
        self._init_lifecycle("srtp-stream")
        self._queue_entity_id = f"{self.observability_id}:packet-queue"
        self._queue_command_id = 0
        self._queue_runner = _PacketQueueRunner(
            MACHINE_SPECS["queue"], entity_id=self._queue_entity_id,
            mailbox_capacity=8,
            controller=getattr(self._runtime, "transition_controller", None),
            transition_sink=self._project_queue_transition,
        )
        if self._runtime is not None:
            self._runtime.projection.machines.register(
                self._queue_entity_id, MACHINE_SPECS["queue"]
            )
            self._runtime.register_owner(
                self._queue_entity_id, epoch=self._queue_runner.epoch
            )
            self._queue_handle = self._runtime.start_machine(
                self._queue_runner, owner_entity_id=self._queue_entity_id,
                owner_epoch=self._queue_runner.epoch,
            )
            self._publish_queue_facets()
        else:
            self._queue_handle = None
        if self._machine_handle is not None:
            self._runner.try_submit(self._command(_LifecycleCommand.ACTIVATE))

    def _project_queue_transition(self, commit: TransitionCommit) -> None:
        if self._runtime is None:
            return
        self._runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state,
            commit.to_state, commit.epoch, commit.revision,
            self._runtime.new_producer_dot(), commit.cause, commit.monotonic_ns,
        ))
        self._publish_queue_facets(commit.revision)

    def _publish_queue_facets(self, revision: int | None = None) -> None:
        if self._runtime is None:
            return
        self._runtime.projection.merge_values(
            self._queue_entity_id, self._runtime.new_producer_dot(), {
                "depth": self._queue.qsize(), "capacity": self._queue.maxsize,
                "queue_kind": "srtp-stream-packets",
            },
            observer_meta="exact", source_entity_id=self._queue_entity_id,
            source_epoch=self._queue_runner.epoch,
            source_revision=(self._queue_runner.revision if revision is None else revision),
            source_order=self._runtime.projection.new_facet_source_order(),
        )

    def _submit_queue(self, kind: str, reply=None) -> None:
        self._queue_command_id += 1
        self._queue_runner.try_submit(MachineCommand(
            kind, self._queue_command_id, self._queue_runner.epoch, None, reply,
            expected_revision=None,
            cause_id=f"{self._queue_entity_id}:{kind}:{self._queue_command_id}",
        ))

    async def _close_packet_queue(self) -> None:
        if self._queue_handle is None or self._queue_runner.snapshot().terminal:
            return
        reply = ReplyPort[TransitionCommit]()
        self._submit_queue("close", reply)
        await reply.wait()
        while not self._queue.empty():
            self._queue.get_nowait()
        self._publish_queue_facets()
        for kind in ("drain", "closed"):
            reply = ReplyPort[TransitionCommit]()
            self._submit_queue(kind, reply)
            await reply.wait()
        await self._queue_handle.wait()
        self._runtime.remove_owner(self._queue_entity_id, self._queue_runner.epoch)

    @property
    def closed(self) -> bool:
        return self._runner.snapshot().terminal

    async def write(self, data: bytes) -> bool:
        """
        Write decrypted packet to stream buffer.

        Called by Session when a packet for this SSRC is received.

        Args:
            data: Decrypted packet data

        Returns:
            True if written, False if buffer full (packet dropped)
        """
        if self._runner.snapshot().state != "active":
            return False

        logger = get_logger()
        config = get_config()

        try:
            self._queue.put_nowait(data)
            self._publish_queue_facets()
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
        if self.closed and self._queue.empty():
            raise RuntimeError("Stream closed")

        packet = await self._queue.get()
        self._publish_queue_facets()
        return packet

    async def close(self) -> None:
        """Close the stream."""
        if self.closed:
            return
        if self._machine_handle is None:
            await self._reconcile_terminal()
            return
        while self._runner.snapshot().state == "new":
            await asyncio.sleep(0)
        await self._close_packet_queue()
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(_LifecycleCommand.DRAIN, reply))
        await reply.wait()
        while not self.closed:
            await asyncio.sleep(0)
        await self._join_lifecycle()

    async def _after_commit(self, commit: TransitionCommit) -> None:
        if commit.to_state == "draining":
            self._runner.try_submit(self._command(_LifecycleCommand.CLOSE))

    async def _reconcile_terminal(self) -> None:
        if self._on_close:
            await self._on_close(self.ssrc)


@dataclass
class SessionKeys:
    """Session keys for local and remote contexts."""
    local_master_key: bytes
    local_master_salt: bytes
    remote_master_key: bytes
    remote_master_salt: bytes


class Session(_LifecycleOwner, ObservedComponent):
    """
    SRTP Session with bidirectional encryption and stream demuxing.

    A Session manages:
    - Rust SrtpContext for crypto operations
    - Stream demultiplexing by SSRC for incoming packets

    This is the main interface for SRTP in the WebRTC stack.
    """

    def __init__(
        self, keys: SessionKeys, is_rtp: bool = True,
        *, observability_id: str | None = None,
    ):
        """
        Create a new SRTP session.

        Args:
            keys: Session keys for local and remote contexts
            is_rtp: True for RTP session, False for RTCP session
        """
        self.is_rtp = is_rtp
        protocol = "rtp" if is_rtp else "rtcp"
        self.observability_id = (
            observability_id or f"srtp-{protocol}-{secrets.token_hex(6)}"
        )
        self._observability_key = secrets.token_bytes(16)
        self._stream_sequence = 0
        # Create Rust SRTP context
        # tx_key = local key + salt (for encryption)
        # rx_key = remote key + salt (for decryption)
        tx_key = keys.local_master_key + keys.local_master_salt
        rx_key = keys.remote_master_key + keys.remote_master_salt
        self._context = SrtpContext(tx_key, rx_key)

        # Stream management
        self._streams: dict[int, Stream] = {}
        # Channel for notifying about new streams
        self._new_stream_queue: asyncio.Queue[tuple[Stream, int]] = asyncio.Queue(
            maxsize=MAX_SRTP_STREAMS
        )

        # Debug counters
        self._decrypt_count = 0
        self._decrypt_errors = 0
        self._ssrc_counters: dict[int, int] = {}
        self._inflight_operations = 0
        # Rust replay/sequence state is mutable.  Calls are admitted on the
        # owner loop and chained per session; separate Session instances still
        # execute concurrently on the Runtime worker pool.
        self._crypto_tail: asyncio.Future[None] | None = None
        self._init_lifecycle("srtp-session")
        if self._machine_handle is not None:
            self._runner.try_submit(self._command(_LifecycleCommand.INITIALIZE))

    @event_loop
    def lifecycle_snapshot(self) -> MachineSnapshot:
        return self._runner.snapshot()

    async def wait_ready(self) -> None:
        while self._runner.snapshot().state in {"new", "initializing"}:
            await asyncio.sleep(0)
        if self._runner.snapshot().state != "ready":
            raise RuntimeError("SRTP session failed to become ready")

    async def _after_commit(self, commit: TransitionCommit) -> None:
        if self._runtime is not None and self._runtime.tracing_enabled:
            self._runtime.projection.merge_values(
                self.observability_id, self._runtime.new_producer_dot(), {
                    "keys_ready": commit.to_state in {"ready", "draining"},
                    "protocol": "rtp" if self.is_rtp else "rtcp",
                },
                observer_meta="exact", source_entity_id=commit.entity_id,
                source_epoch=commit.epoch, source_revision=commit.revision,
                source_order=self._runtime.projection.new_facet_source_order(),
            )
        if commit.to_state == "initializing":
            self._runner.try_submit(self._command(_LifecycleCommand.READY))
        elif commit.to_state == "draining":
            for stream in tuple(self._streams.values()):
                await stream.close()
            self._streams.clear()
            while not self._new_stream_queue.empty():
                self._new_stream_queue.get_nowait()
            self._runner.try_submit(self._command(_LifecycleCommand.CLOSE))

    async def _reconcile_terminal(self) -> None:
        while self._inflight_operations:
            await asyncio.sleep(0)
        if self._runtime is not None:
            await self._runtime.join_owner_children(
                self.observability_id, self._runner.epoch
            )

    @classmethod
    @event_loop
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

    @observe(detail=TraceDetail.OFF)
    async def _ordered_crypto(self, operation, packet: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        predecessor = self._crypto_tail
        turn = loop.create_future()
        self._crypto_tail = turn
        if predecessor is not None:
            await asyncio.shield(predecessor)
        try:
            return await operation(packet)
        finally:
            if not turn.done():
                turn.set_result(None)
            if self._crypto_tail is turn:
                self._crypto_tail = None

    @worker
    @performance(
        name="srtp.encrypt", group="srtp.packet",
        on_call=lambda call: {"input_bytes": len(call.args[1])},
        on_success=lambda event: {"output_bytes": len(event.result)},
        on_error=lambda event: {"exception": type(event.exception).__name__},
    )
    def _encrypt_crypto(self, plaintext: bytes) -> bytes:
        return (
            self._context.encrypt_rtp(plaintext)
            if self.is_rtp else self._context.encrypt_rtcp(plaintext)
        )

    @worker
    @performance(
        name="srtp.decrypt", group="srtp.packet",
        on_call=lambda call: {"input_bytes": len(call.args[1])},
        on_success=lambda event: {"output_bytes": len(event.result)},
        on_error=lambda event: {"exception": type(event.exception).__name__},
    )
    def _decrypt_crypto(self, ciphertext: bytes) -> bytes:
        return (
            self._context.decrypt_rtp(ciphertext)
            if self.is_rtp else self._context.decrypt_rtcp(ciphertext)
        )

    @observe(detail=TraceDetail.OFF)
    async def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt an outgoing packet (synchronous).

        Args:
            plaintext: RTP or RTCP packet to encrypt

        Returns:
            Encrypted SRTP or SRTCP packet
        """
        return await self._ordered_crypto(self._encrypt_crypto, plaintext)

    @observe(detail=TraceDetail.OFF)
    async def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt an incoming packet (synchronous).

        Args:
            ciphertext: SRTP or SRTCP packet to decrypt

        Returns:
            Decrypted RTP or RTCP packet
        """
        return await self._ordered_crypto(self._decrypt_crypto, ciphertext)

    async def _get_or_create_stream(self, ssrc: int) -> tuple[Stream, bool]:
        """
        Get existing stream or create new one for SSRC.

        Returns:
            Tuple of (stream, is_new)
        """
        if self._runner.snapshot().state != "ready":
            raise RuntimeError(
                f"SRTP stream admission rejected while {self._runner.snapshot().state}"
            )
        if ssrc in self._streams:
            return self._streams[ssrc], False
        if len(self._streams) >= MAX_SRTP_STREAMS:
            raise RuntimeError("SRTP SSRC admission limit exceeded")

        async def on_close(closed_ssrc: int) -> None:
            self._streams.pop(closed_ssrc, None)

        self._stream_sequence += 1
        stream_id = f"{self.observability_id}:stream:{self._stream_sequence}"
        stream = Stream(
            ssrc, self.is_rtp, on_close, observability_id=stream_id,
        )
        self._streams[ssrc] = stream
        protocol = "rtp" if self.is_rtp else "rtcp"
        ssrc_id = "ssrc-" + hashlib.blake2s(
            ssrc.to_bytes(4, "big"), key=self._observability_key,
            digest_size=6,
        ).hexdigest()
        if self._runtime is not None:
            self._runtime.record_srtp_stream(
                protocol=protocol, session_id=self.observability_id,
                stream_id=stream_id, ssrc_id=ssrc_id,
                stream_count=len(self._streams),
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

        if self._runner.snapshot().state != "ready":
            raise RuntimeError(
                f"SRTP packet admission rejected while {self._runner.snapshot().state}"
            )
        self._inflight_operations += 1
        self._decrypt_count += 1

        try:
            # Decrypt
            decrypted = await self.decrypt(ciphertext)
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
        finally:
            self._inflight_operations -= 1

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
        if not write_success:
            seq = int.from_bytes(decrypted[2:4], 'big') if len(decrypted) >= 4 else -1
            if self._runtime is not None:
                self._runtime.record_srtp_delivery(
                    protocol="rtp" if self.is_rtp else "rtcp", delivered=False,
                    failure_reason="stream_queue_full", stream_id=stream.observability_id,
                )
            logger.warn(Component.SRTP, f"Stream write FAILED - queue full", ssrc=ssrc, seq=seq)
        else:
            if self._runtime is not None:
                self._runtime.record_srtp_delivery(
                    protocol="rtp" if self.is_rtp else "rtcp", delivered=True,
                    stream_id=stream.observability_id,
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
        state = self._runner.snapshot().state
        if state not in {"new", "initializing", "ready"}:
            raise RuntimeError(f"SRTP stream admission rejected while {state}")
        await self.wait_ready()
        stream, _ = await self._get_or_create_stream(ssrc)
        return stream

    async def get_stream(self, ssrc: int) -> Optional[Stream]:
        """
        Get an existing stream by SSRC.

        Returns:
            Stream if exists, None otherwise
        """
        return self._streams.get(ssrc)

    async def close(self) -> None:
        """Close all streams and the session."""
        if self._runner.snapshot().terminal:
            return
        if self._machine_handle is None:
            await self._reconcile_terminal()
            return
        await self.wait_ready()
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(_LifecycleCommand.DRAIN, reply))
        await reply.wait()
        while not self._runner.snapshot().terminal:
            await asyncio.sleep(0)
        await self._join_lifecycle()
