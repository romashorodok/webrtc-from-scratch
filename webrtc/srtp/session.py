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
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Optional, Callable, Awaitable, Any

# Import Rust SRTP context
from webrtc_rs import SrtpContext

# Import logger
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.runtime_services import FailurePolicy, OwnedTaskHandle, current_execution_scope
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.state_machine import (
    InlineStateMachineRunner, MachineCommand, PreparedTransition,
    ReplyPort, SynchronousStateReducer, TransitionCommit,
)


# Buffer limits
SRTP_BUFFER_SIZE = 1_000_000  # 1MB for RTP
SRTCP_BUFFER_SIZE = 100_000  # 100KB for RTCP
MAX_SRTP_STREAMS = 128


@dataclass(frozen=True, slots=True)
class SessionAdmissionSnapshot:
    """Fields that atomically control SRTP packet and stream admission."""

    state: str = "new"
    keys_ready: bool = False
    accepting_packets: bool = False
    accepting_streams: bool = False
    stream_count: int = 0
    inflight_operations: int = 0


@dataclass(frozen=True, slots=True)
class SessionReadinessSnapshot:
    """Narrow public SRTP lifecycle view used by readiness consumers."""

    state: str = "new"
    keys_ready: bool = False
    accepting_packets: bool = False
    accepting_streams: bool = False

    @property
    def ready(self) -> bool:
        return (
            self.state == "ready"
            and self.keys_ready
            and self.accepting_packets
            and self.accepting_streams
        )


class _LifecycleCommand(StrEnum):
    INITIALIZE = "initialize"
    READY = "ready"
    DRAIN = "drain"
    CLOSE = "close"
    ACTIVATE = "activate"


class _LifecycleRunner(InlineStateMachineRunner):
    def __init__(self, owner: Any, machine_type: str) -> None:
        self.owner = owner
        super().__init__(
            MACHINE_SPECS[machine_type], entity_id=owner.observability_id,
            mailbox_capacity=16,
            controller=getattr(owner._runtime, "transition_controller", None),
            transition_sink=None,
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

    def commit(self, proposed, cause=None):
        commit = super().commit(proposed, cause)
        self.owner._commit_admission(commit)
        return commit

    async def after_commit(self, commit, effects):
        await self.owner._after_commit(commit)

    async def reconcile_terminal(self, prepared):
        await self.owner._reconcile_terminal()


class _LifecycleOwner:
    def _init_lifecycle(self, machine_type: str) -> None:
        self._runtime = current_execution_scope()
        self._command_id = 0
        self._runner = _LifecycleRunner(self, machine_type)
        self._machine_handle: OwnedTaskHandle[None] | None = None
        if self._runtime is not None:
            self._machine_handle = self._runtime.compose_domain_runner(
                self, self._runner, role="srtp-session",
                adapter_name="srtp_readiness", capture_name="capture_srtp",
            )
            self._execution = self._runtime.execution_port(
                self.observability_id, self._runner.epoch
            )
        else:
            self._execution = None

    def _command(self, kind, reply=None):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            cause_id=f"{self.observability_id}:{self._command_id}",
        )

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
        self._runtime = current_execution_scope()
        self._runner = SynchronousStateReducer(
            MACHINE_SPECS["srtp-stream"], entity_id=self.observability_id,
            transition_sink=None,
        )
        if self._runtime is not None:
            self._runtime.compose_domain_machine(self._runner)
            self._record_queue_activity(exact=True)
        self._runner.transition("active", cause=f"{self.observability_id}:activate")

    def _record_queue_activity(self, *, delivered: int = 0,
                               dequeued: int = 0, dropped: int = 0,
                               exact: bool = False) -> None:
        if self._runtime is not None:
            self._runtime.record_queue_activity(
                entity_id=self.observability_id,
                queue_kind="srtp-stream-packets",
                depth=self._queue.qsize(), capacity=self._queue.maxsize,
                deltas={"delivered_packets": delivered,
                        "dequeued_packets": dequeued,
                        "dropped_packets": dropped},
                failure_diagnostic="srtp_queue_facet_publish_failures",
                exact=exact,
            )

    async def _close_packet_queue(self) -> None:
        while not self._queue.empty():
            self._queue.get_nowait()
        self._record_queue_activity(exact=True)

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
            self._record_queue_activity(delivered=1)
            queue_size = self._queue.qsize()

            # Log first N writes to see queue growth
            if queue_size <= config.log_first_n_packets:
                seq = int.from_bytes(data[2:4], 'big') if len(data) >= 4 else -1
                logger.log_queue_size(Component.SRTP, f"stream_{self.ssrc}", queue_size, self._queue.maxsize)
                logger.trace(Component.SRTP, f"Wrote packet to stream", ssrc=self.ssrc, seq=seq)
            return True
        except asyncio.QueueFull:
            # Drop packet when buffer full
            self._record_queue_activity(dropped=1)
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
        self._record_queue_activity(dequeued=1)
        return packet

    async def close(self) -> None:
        """Close the stream."""
        if self.closed:
            return
        await self._close_packet_queue()
        self._runner.transition("draining", cause=f"{self.observability_id}:drain")
        if self._on_close:
            await self._on_close(self.ssrc)
        self._runner.transition("closed", cause=f"{self.observability_id}:close")
        if self._runtime is not None:
            self._runtime.retire_domain_machine(
                self.observability_id, self._runner.epoch
            )


@dataclass
class SessionKeys:
    """Session keys for local and remote contexts."""
    local_master_key: bytes
    local_master_salt: bytes
    remote_master_key: bytes
    remote_master_salt: bytes


class Session(_LifecycleOwner):
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
        self._accept_waiters: list[asyncio.Future[tuple[Stream, int]]] = []

        self._inflight_operations = 0
        self._inflight_zero: asyncio.Future[None] | None = None
        # Rust replay/sequence state is mutable.  Calls are admitted on the
        # owner loop and chained per session; separate Session instances still
        # execute concurrently on the Runtime worker pool.
        self._crypto_tail: asyncio.Future[None] | None = None
        self._admission = SessionAdmissionSnapshot()
        self._admission_waiters: list[asyncio.Future[None]] = []
        self._init_lifecycle("srtp-session")
        if self._machine_handle is not None:
            for target in ("initializing", "ready"):
                commit = self._runner.commit(PreparedTransition(
                    self._runner.state, target, None,
                    f"{self.observability_id}:{target}",
                    self._runner.epoch, self._runner.revision,
                ))
                if self._runner._transition_sink is not None:
                    self._runner._transition_sink(commit)
            self._admission = replace(
                self._admission, state="ready",
                keys_ready=True, accepting_packets=True, accepting_streams=True,
            )

    def readiness_snapshot(self) -> SessionReadinessSnapshot:
        admission = self._admission
        return SessionReadinessSnapshot(
            admission.state, admission.keys_ready,
            admission.accepting_packets, admission.accepting_streams,
        )

    def lifecycle_snapshot(self) -> SessionReadinessSnapshot:
        """Compatibility name returning domain readiness, never machine metadata."""
        return self.readiness_snapshot()

    def admission_snapshot(self) -> SessionAdmissionSnapshot:
        return self._admission

    def _observation_revision(self) -> int:
        """Private bridge for trace provenance until the Runtime sidecar exists."""
        return self._runner.revision

    async def wait_ready(self) -> None:
        while True:
            admission = self._admission
            if admission.state == "ready":
                if self._runtime is not None:
                    await self._runtime.flush_observations()
                return
            if admission.state not in {"new", "initializing"}:
                raise RuntimeError("SRTP session failed to become ready")
            await self._wait_admission_change()

    async def _wait_admission_change(self) -> None:
        waiter = asyncio.get_running_loop().create_future()
        self._admission_waiters.append(waiter)
        try:
            await waiter
        finally:
            if waiter in self._admission_waiters:
                self._admission_waiters.remove(waiter)

    def _commit_admission(self, commit: TransitionCommit) -> None:
        accepting = commit.to_state == "ready"
        self._admission = replace(
            self._admission,
            state=commit.to_state,
            keys_ready=commit.to_state in {"ready", "draining"},
            accepting_packets=accepting,
            accepting_streams=accepting,
        )

    async def _after_commit(self, commit: TransitionCommit) -> None:
        waiters, self._admission_waiters = self._admission_waiters, []
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)
        if commit.to_state == "initializing":
            self._runner.try_submit(self._command(_LifecycleCommand.READY))
        elif commit.to_state == "draining":
            error = RuntimeError("SRTP stream admission rejected while draining")
            for waiter in self._accept_waiters:
                if not waiter.done():
                    waiter.set_exception(error)
            self._accept_waiters.clear()
            for stream in tuple(self._streams.values()):
                await stream.close()
            self._streams.clear()
            self._admission = replace(self._admission, stream_count=0)
            while not self._new_stream_queue.empty():
                self._new_stream_queue.get_nowait()
            self._runner.try_submit(self._command(_LifecycleCommand.CLOSE))

    async def _reconcile_terminal(self) -> None:
        if self._inflight_zero is not None:
            await asyncio.shield(self._inflight_zero)
        if self._runtime is not None:
            await self._runtime.join_owner_children(
                self.observability_id, self._runner.epoch
            )

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

    def _crypto_execution(self):
        if self._execution is not None:
            return self._execution
        runtime = current_execution_scope()
        if runtime is None:
            raise RuntimeError("SRTP crypto requires an active Runtime execution port")
        # Compatibility for sessions constructed immediately before entering
        # their Runtime. Production composition injects the session-owned port.
        return runtime.execution_port(
            runtime._runtime_entity_id, runtime._runtime_runner.epoch
        )

    def _encrypt_crypto(self, plaintext: bytes) -> bytes:
        return (
            self._context.encrypt_rtp(plaintext)
            if self.is_rtp else self._context.encrypt_rtcp(plaintext)
        )

    def _decrypt_crypto(self, ciphertext: bytes) -> bytes:
        return (
            self._context.decrypt_rtp(ciphertext)
            if self.is_rtp else self._context.decrypt_rtcp(ciphertext)
        )

    async def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt an outgoing packet (synchronous).

        Args:
            plaintext: RTP or RTCP packet to encrypt

        Returns:
            Encrypted SRTP or SRTCP packet
        """
        if self._runtime is not None and not self._admission.accepting_packets:
            raise RuntimeError(
                f"SRTP packet admission rejected while {self._admission.state}"
            )
        execution = self._crypto_execution()
        return await self._ordered_crypto(
            lambda packet: execution.run_worker(
                self._encrypt_crypto, packet, name="worker:srtp.encrypt"
            ),
            plaintext,
        )

    async def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt an incoming packet (synchronous).

        Args:
            ciphertext: SRTP or SRTCP packet to decrypt

        Returns:
            Decrypted RTP or RTCP packet
        """
        if self._runtime is not None and not self._admission.accepting_packets:
            raise RuntimeError(
                f"SRTP packet admission rejected while {self._admission.state}"
            )
        execution = self._crypto_execution()
        return await self._ordered_crypto(
            lambda packet: execution.run_worker(
                self._decrypt_crypto, packet, name="worker:srtp.decrypt"
            ),
            ciphertext,
        )

    async def _get_or_create_stream(self, ssrc: int) -> tuple[Stream, bool]:
        """
        Get existing stream or create new one for SSRC.

        Returns:
            Tuple of (stream, is_new)
        """
        admission = self._admission
        if not admission.accepting_streams:
            raise RuntimeError(
                f"SRTP stream admission rejected while {admission.state}"
            )
        if ssrc in self._streams:
            return self._streams[ssrc], False
        if len(self._streams) >= MAX_SRTP_STREAMS:
            raise RuntimeError("SRTP SSRC admission limit exceeded")

        async def on_close(closed_ssrc: int) -> None:
            self._streams.pop(closed_ssrc, None)
            self._admission = replace(
                self._admission, stream_count=len(self._streams),
            )

        self._stream_sequence += 1
        stream_id = f"{self.observability_id}:stream:{self._stream_sequence}"
        stream = Stream(
            ssrc, self.is_rtp, on_close, observability_id=stream_id,
        )
        self._streams[ssrc] = stream
        self._admission = replace(
            self._admission, stream_count=len(self._streams),
        )
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

        admission = self._admission
        if not admission.accepting_packets:
            raise RuntimeError(
                f"SRTP packet admission rejected while {admission.state}"
            )
        self._inflight_operations += 1
        self._admission = replace(
            self._admission, inflight_operations=self._inflight_operations,
        )
        if self._inflight_operations == 1:
            self._inflight_zero = asyncio.get_running_loop().create_future()
        try:
            # Decrypt
            decrypted = await self.decrypt(ciphertext)
        except Exception as e:
            if self._runtime is not None:
                self._runtime.record_srtp_packet(
                    session_id=self.observability_id,
                    protocol="rtp" if self.is_rtp else "rtcp", error=True,
                    error_detail=str(e),
                    sequence=(int.from_bytes(ciphertext[2:4], "big")
                              if len(ciphertext) >= 4 else None),
                    log_errors=config.log_srtp_decrypt_errors,
                    log_counts=config.log_packet_counts,
                )
            raise  # Re-raise so caller can handle
        finally:
            self._inflight_operations -= 1
            self._admission = replace(
                self._admission, inflight_operations=self._inflight_operations,
            )
            if self._inflight_operations == 0 and self._inflight_zero is not None:
                if not self._inflight_zero.done():
                    self._inflight_zero.set_result(None)
                self._inflight_zero = None

        # Get SSRC from decrypted packet
        if self.is_rtp:
            ssrc = parse_rtp_ssrc(decrypted)
        else:
            ssrc = parse_rtcp_ssrc(decrypted)

        if self._runtime is not None:
            self._runtime.record_srtp_packet(
                session_id=self.observability_id,
                protocol="rtp" if self.is_rtp else "rtcp", ssrc=ssrc,
                log_errors=config.log_srtp_decrypt_errors,
                log_counts=config.log_packet_counts,
            )

        # Route to stream
        stream, is_new = await self._get_or_create_stream(ssrc)

        if is_new and config.log_srtp_new_streams:
            while self._accept_waiters:
                waiter = self._accept_waiters.pop(0)
                if not waiter.done():
                    waiter.set_result((stream, ssrc))
                    break
            else:
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
        if self._runtime is None:
            return await self._new_stream_queue.get()
        admission = self._admission
        if not admission.accepting_streams:
            raise RuntimeError(
                f"SRTP stream admission rejected while {admission.state}"
            )
        if not self._new_stream_queue.empty():
            return self._new_stream_queue.get_nowait()
        waiter = asyncio.get_running_loop().create_future()
        self._accept_waiters.append(waiter)
        try:
            return await asyncio.shield(waiter)
        finally:
            if waiter in self._accept_waiters:
                self._accept_waiters.remove(waiter)

    async def open_stream(self, ssrc: int) -> Stream:
        """
        Open or get an existing stream for an SSRC.

        Unlike accept_stream(), this doesn't wait - it creates immediately.

        Args:
            ssrc: SSRC to open stream for

        Returns:
            Stream for the SSRC
        """
        admission = self._admission
        if admission.state not in {"new", "initializing", "ready"}:
            raise RuntimeError(
                f"SRTP stream admission rejected while {admission.state}"
            )
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
        if self._admission.state == "closed":
            return
        if self._machine_handle is None:
            await self._reconcile_terminal()
            return
        if self._admission.state in {"new", "initializing"}:
            await self.wait_ready()
        if self._admission.state == "ready":
            reply = ReplyPort[TransitionCommit]()
            await self._runner.submit(self._command(_LifecycleCommand.DRAIN, reply))
            await reply.wait()
        while self._admission.state != "closed":
            await self._wait_admission_change()
        await self._join_lifecycle()
