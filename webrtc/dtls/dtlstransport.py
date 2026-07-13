import asyncio
import logging
import uuid
from enum import Enum
from typing import Protocol

import webrtc_rs

from webrtc import ice
from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtls_cipher_suite import Keypair
from webrtc.dtls.dtls_record import (
    RecordLayer,
    RecordLayerBatch,
    is_dtls_record_layer,
)
from webrtc.dtls.flight_state import Flight
from webrtc.dtls.fsm import DTLSConn
from webrtc.dtls.handshake_reconstructor import HandshakeReconstructor
from webrtc.dtls.prf import SRTPKeyingMaterial
from webrtc.srtp import Session as SrtpSession, Stream as SrtpStream
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.performance import ObservedComponent, event_loop, task
from webrtc.runtime_services import FailurePolicy
from webrtc.lifecycle import (
    TransportCondition,
    require_timeout,
    wait_for_all,
    wait_for_event,
    wait_until,
)
from webrtc.tracing import measure_perf, perf_mark, perf_measured_async
from webrtc.domain_events import SrtpKeysReady, SrtpSessionReady, emit_domain_event

logger = logging.getLogger("webrtc.dtls.transport")


class DTLSRole(Enum):
    Auto = "auto"
    Server = "server"
    Client = "client"


class ICETransportDTLS(Protocol):
    async def get_ice_pair_transport(self) -> ice.CandidatePairTransport | None: ...


class RTPReaderProtocol(Protocol):
    async def recv_rtp_bytes(self) -> bytes: ...


class DTLSLocal:
    """Adapter to send DTLS packets via ICE transport."""

    def __init__(self, transport: ice.CandidatePairTransport) -> None:
        self._t = transport

    async def sendto(self, data: bytes):
        _mark_dtls_records("tx", data)
        self._t.sendto(data)


def _mark_dtls_records(direction: str, data: bytes) -> None:
    try:
        records = list(RecordLayerBatch(data))
    except Exception:
        perf_mark(
            "dtls",
            "record",
            direction,
            metadata={
                "size_bytes": len(data),
                f"counter.dtls.records_{direction}": 1,
            },
        )
        return

    for record, raw in records:
        perf_mark(
            "dtls",
            "record",
            direction,
            metadata={
                "content_type": getattr(record.header.content_type, "name", str(record.header.content_type)),
                "epoch": record.header.epoch,
                "sequence_number": record.header.sequence_number,
                "size_bytes": len(raw),
                f"counter.dtls.records_{direction}": 1,
            },
        )


class DTLSTransport(ObservedComponent):
    """
    DTLS Transport using Python flight-based FSM.

    Uses Python PRF for key derivation and Rust for:
    - ECDH key exchange (ECDHKeyPair)
    - AES-GCM encryption (AesGcmCipher)
    - SRTP encryption (after handshake)
    """

    def __init__(
        self,
        certificate: webrtc_rs.Certificate,
    ) -> None:
        self.__rust_cert = certificate
        # Wrap Rust certificate for Python FSM
        self.__cert = Certificate(certificate)

        # Python FSM state
        self.__dtls_conn: DTLSConn | None = None
        self.__role: DTLSRole = DTLSRole.Auto
        self.__transport: ice.CandidatePairTransport | None = None

        # Record layer channel for incoming DTLS packets
        self.record_layer_chan: asyncio.Queue[tuple[RecordLayer, bytes]] = asyncio.Queue()
        self.__handshake_reconstructor = HandshakeReconstructor()

        # SRTP state - Python Session with Rust SrtpContext for crypto
        self.__srtp_rtp_lock = asyncio.Event()
        self.__srtp_rtcp_lock = asyncio.Event()
        self._srtp_rtp: SrtpSession | None = None
        self._srtp_rtcp: SrtpSession | None = None

        # Handshake completion
        self.__handshake_complete = asyncio.Event()
        self.__handshake_failed: BaseException | None = None
        self._srtp_keying_material: SRTPKeyingMaterial | None = None
        self._closed = False
        self._handshake_task: asyncio.Task[Any] | None = None
        self._rtp_task: asyncio.Task[Any] | None = None
        self._rtcp_task: asyncio.Task[Any] | None = None

    @property
    def handshake_complete(self) -> asyncio.Event:
        """Event signaling handshake completion."""
        return self.__handshake_complete

    @event_loop
    def get_srtp_keying_material(self) -> SRTPKeyingMaterial | None:
        """Get SRTP keying material after handshake completion."""
        return self._srtp_keying_material

    async def bind(self, transport: ice.CandidatePairTransport):
        """Bind to ICE transport for sending/receiving DTLS packets."""
        self.__transport = transport

    @event_loop
    def start(self, role: DTLSRole, transport: "ice.CandidatePairTransport | None" = None):
        """
        Start DTLS handshake using Python flight-based FSM.

        Args:
            role: DTLSRole.Server or DTLSRole.Client
            transport: Optional ICE transport (if not already bound)
        """
        wlogger = get_logger()
        wlogger.debug(Component.DTLS, "Starting DTLS handshake",
                     role=role.value, transport_provided=transport is not None)
        perf_mark(
            "dtls",
            "start",
            "started",
            metadata={"role": role.value, "transport_provided": transport is not None},
        )

        # If handshake already completed, skip
        if self.__handshake_complete.is_set():
            wlogger.info(Component.DTLS, "Handshake already complete, skipping")
            perf_mark("dtls", "start", "completed", metadata={"already_complete": True})
            return

        # If there's already a DTLS connection in progress, skip (don't restart mid-handshake)
        if self.__dtls_conn is not None:
            wlogger.info(Component.DTLS, "DTLS connection already in progress, skipping duplicate start")
            perf_mark("dtls", "start", "completed", metadata={"already_started": True})
            return

        self.__role = role
        is_client = role == DTLSRole.Client
        perf_mark("dtls", "role", "selected", metadata={"role": role.value})

        # Bind transport if provided
        if transport:
            self.__transport = transport

        if not self.__transport:
            wlogger.error(Component.DTLS, "No transport bound - cannot start DTLS handshake")
            perf_mark(
                "dtls",
                "start",
                "failed",
                metadata={"role": role.value, "exception_class": "RuntimeError"},
            )
            raise RuntimeError("No transport bound - cannot start DTLS handshake")

        # Determine initial flight based on role
        if is_client:
            flight = Flight.FLIGHT1
        else:
            flight = Flight.FLIGHT0

        wlogger.debug(Component.DTLS, "Creating DTLSConn", flight=flight.name)
        # Create Python DTLS connection with FSM
        self.__dtls_conn = DTLSConn(
            remote=DTLSLocal(self.__transport),
            certificate=self.__cert,
            layer_chan=self.record_layer_chan,
            flight=flight,
        )

        wlogger.info(Component.DTLS, f"Starting DTLS handshake as {'client' if is_client else 'server'}")

        # Start handshake processing
        self._handshake_task = self._run_handshake(is_client)
        wlogger.debug(Component.DTLS, "Handshake task created")
        perf_mark("dtls", "start", "completed", metadata={"role": role.value})

    @task(name="dtls:handshake", kind="dtls", failure=FailurePolicy.FAIL_CONNECTION)
    @perf_measured_async("dtls", "handshake")
    async def _run_handshake(self, is_client: bool):
        """Run the DTLS handshake using Python FSM."""
        wlogger = get_logger()
        wlogger.info(Component.DTLS, "Running handshake", is_client=is_client)

        if not self.__dtls_conn:
            wlogger.error(Component.DTLS, "DTLS connection not initialized")
            exc = RuntimeError("DTLS connection not initialized")
            self.__handshake_failed = exc
            self.__handshake_complete.set()
            raise exc

        try:
            # Start FSM processing
            wlogger.debug(Component.DTLS, "Creating handle_inbound_record_layers task")
            self.__dtls_conn.handle_inbound_record_layers()

            # Dispatch initial state
            wlogger.debug(Component.DTLS, "Dispatching initial FSM state")
            await self.__dtls_conn.fsm.dispatch()
            wlogger.debug(Component.DTLS, "FSM dispatch complete, waiting for handshake")

            # Wait for handshake completion
            success = await self.__dtls_conn.wait_handshake_complete(timeout=30.0)

            if success:
                wlogger.info(Component.DTLS, "Handshake completed successfully")

                # Get SRTP keying material from Python FSM
                self._srtp_keying_material = self.__dtls_conn.get_srtp_keying_material()

                if self._srtp_keying_material:
                    emit_domain_event(SrtpKeysReady)
                    # Initialize Rust SRTP with Python-derived keys
                    await self._init_srtp(is_client)

                self.__handshake_complete.set()
            else:
                wlogger.error(Component.DTLS, "Handshake timed out")
                raise TimeoutError("DTLS handshake timed out")

        except Exception as e:
            wlogger.error(Component.DTLS, "Handshake error", error=str(e))
            self.__handshake_failed = e
            self.__handshake_complete.set()
            raise

    @perf_measured_async("srtp", "ready")
    async def _init_srtp(self, is_client: bool):
        """
        Initialize Python SRTP sessions with Rust cipher backend.

        The SRTP keys are derived by Python PRF, crypto is done by Rust SrtpContext.
        Stream demuxing is handled by Python.
        """
        wlogger = get_logger()
        config = get_config()

        if not self._srtp_keying_material:
            wlogger.error(Component.DTLS, "No SRTP keying material available")
            raise RuntimeError("No SRTP keying material available")

        keys = self._srtp_keying_material

        try:
            # Create SRTP with Python-derived keys
            # The SRTP master key format is: key (16 bytes) + salt (14 bytes) = 30 bytes
            if is_client:
                # Client sends with client key, receives with server key
                tx_master_key = keys.client_write_key + keys.client_write_salt
                rx_master_key = keys.server_write_key + keys.server_write_salt
            else:
                # Server sends with server key, receives with client key
                tx_master_key = keys.server_write_key + keys.server_write_salt
                rx_master_key = keys.client_write_key + keys.client_write_salt

            wlogger.debug(Component.DTLS, "Initializing SRTP", is_client=is_client)
            if config.dtls_log_level.value >= config.dtls_log_level.TRACE.value:
                wlogger.trace(Component.DTLS, "SRTP keys derived",
                            tx_key=tx_master_key.hex(), rx_key=rx_master_key.hex())

            # Initialize Python SRTP sessions (uses Rust SrtpContext internally)
            self._srtp_rtp = SrtpSession.from_keying_material(
                tx_key=tx_master_key,
                rx_key=rx_master_key,
                is_rtp=True,
            )
            self.__srtp_rtp_lock.set()
            emit_domain_event(
                SrtpSessionReady, protocol="rtp",
                session_id=getattr(self._srtp_rtp, "observability_id", None),
            )
            wlogger.debug(Component.DTLS, "RTP SRTP session created")

            self._srtp_rtcp = SrtpSession.from_keying_material(
                tx_key=tx_master_key,
                rx_key=rx_master_key,
                is_rtp=False,
            )
            self.__srtp_rtcp_lock.set()
            emit_domain_event(
                SrtpSessionReady, protocol="rtcp",
                session_id=getattr(self._srtp_rtcp, "observability_id", None),
            )
            wlogger.debug(Component.DTLS, "RTCP SRTP session created")

            wlogger.info(Component.DTLS, "SRTP sessions initialized")

            # Start internal receive loops to route incoming packets to streams
            self._rtp_task = self._rtp_receive_loop()
            self._rtcp_task = self._rtcp_receive_loop()

        except Exception as e:
            wlogger.error(Component.DTLS, "Failed to initialize SRTP", error=str(e))
            raise

    async def enqueue_record(self, record_layer_bytes: bytes):
        """
        Enqueue incoming DTLS record for processing by Python FSM.

        Called when ICE transport receives a DTLS packet.
        A single UDP packet may contain multiple DTLS records (e.g., Flight 5).
        """
        wlogger = get_logger()
        config = get_config()

        wlogger.trace(Component.DTLS, "Received DTLS record", size=len(record_layer_bytes))

        parse_metadata = {
            "flow_direction": "rx",
            "packet_kind": "dtls",
            "input_size_bytes": len(record_layer_bytes),
            "operation_id": uuid.uuid4().hex,
        }
        try:
            with measure_perf("dtls", "record.parse", metadata=parse_metadata):
                try:
                    if not is_dtls_record_layer(record_layer_bytes):
                        raise ValueError("received non-DTLS record")
                    records = list(RecordLayerBatch(record_layer_bytes))
                except Exception:
                    parse_metadata.update(
                        error_stage="record_batch_parse",
                        **{"counter.dtls.record_parse_failed": 1},
                    )
                    raise
                parse_metadata["record_count"] = len(records)
        except Exception as e:
            wlogger.error(Component.DTLS, "Failed to parse DTLS record", error=str(e))
            return

        try:
            for record_count, (record, raw) in enumerate(records, start=1):
                record_metadata = {
                    "flow_direction": "rx",
                    "packet_kind": "dtls",
                    "content_type": getattr(record.header.content_type, "name", str(record.header.content_type)),
                    "record_type": getattr(record.header.content_type, "name", str(record.header.content_type)),
                    "epoch": record.header.epoch,
                    "sequence_number": record.header.sequence_number,
                    "size_bytes": len(raw),
                    "counter.dtls.records_rx": 1,
                }
                perf_mark("dtls", "record", "rx", metadata=record_metadata)
                if config.log_packet_details and record_count <= 10:
                    wlogger.debug(Component.DTLS, f"Parsed DTLS record #{record_count}",
                                content_type=record.header.content_type,
                                epoch=record.header.epoch,
                                seq=record.header.sequence_number)
                reconstruct_metadata = {
                    key: value for key, value in record_metadata.items()
                    if not key.startswith("counter.")
                }
                reconstruct_metadata.update(operation_id=uuid.uuid4().hex)
                with measure_perf(
                    "dtls", "record.reconstruct", metadata=reconstruct_metadata
                ):
                    try:
                        complete_records = self.__handshake_reconstructor.complete(record, raw)
                    except Exception:
                        reconstruct_metadata.update(
                            error_stage="handshake_reconstruction",
                            **{"counter.dtls.record_reconstruct_failed": 1},
                        )
                        raise
                    reconstruct_metadata["reconstructed_size_bytes"] = sum(
                        len(complete_raw) for _, complete_raw in complete_records
                    )
                    reconstruct_metadata["counter.dtls.records_reconstructed"] = 1
                for complete_record, complete_raw in complete_records:
                    enqueue_metadata = {
                        key: value for key, value in reconstruct_metadata.items()
                        if not key.startswith("counter.")
                    }
                    enqueue_metadata.update(
                        operation_id=uuid.uuid4().hex,
                        reconstructed_size_bytes=len(complete_raw),
                    )
                    with measure_perf(
                        "dtls", "record.enqueue", metadata=enqueue_metadata
                    ):
                        try:
                            await self.record_layer_chan.put((complete_record, complete_raw))
                        except Exception:
                            enqueue_metadata["error_stage"] = "record_queue_enqueue"
                            raise

            wlogger.log_queue_size(Component.DTLS, "record_layer",
                                  self.record_layer_chan.qsize(),
                                  getattr(self.record_layer_chan, 'maxsize', 'unlimited'))
        except Exception as e:
            wlogger.error(Component.DTLS, "Failed to reconstruct or enqueue DTLS record", error=str(e))

    async def dequeue_record(self) -> bytes:
        """
        Dequeue outgoing DTLS record from Python FSM.

        Note: With Python FSM, records are sent directly via DTLSLocal.sendto().
        This method blocks forever since the Python FSM handles sending internally.
        The caller should not rely on this method for sending.
        """
        # Python FSM sends directly via DTLSLocal.sendto(), so this blocks forever
        # to prevent the caller from spinning in a tight loop.
        await asyncio.Event().wait()  # Never returns
        return bytes()

    @event_loop
    def _srtp_ready(self) -> bool:
        return (
            self.__srtp_rtp_lock.is_set()
            and self.__srtp_rtcp_lock.is_set()
            and self._srtp_rtp is not None
            and self._srtp_rtcp is not None
        )

    async def wait(self, condition: TransportCondition, timeout: float) -> None:
        timeout = require_timeout(timeout)
        match condition:
            case TransportCondition.HANDSHAKE_COMPLETE:
                await wait_for_event(self.__handshake_complete, timeout=timeout)
                if self.__handshake_failed is not None:
                    raise self.__handshake_failed
            case TransportCondition.SRTP_READY:
                await wait_for_all(
                    [
                        self.__srtp_rtp_lock.wait(),
                        self.__srtp_rtcp_lock.wait(),
                    ],
                    timeout=timeout,
                )
                await wait_until(self._srtp_ready, timeout=timeout)
            case _:
                raise ValueError(f"unsupported transport condition: {condition}")

    async def wait_handshake(self, timeout: float) -> bool:
        """
        Wait for DTLS handshake to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if handshake completed, False on timeout
        """
        try:
            await self.wait(TransportCondition.HANDSHAKE_COMPLETE, timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def wait_srtp_ready(self, timeout: float) -> bool:
        try:
            await self.wait(TransportCondition.SRTP_READY, timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def encrypt_rtp_bytes(self, data: bytes) -> bytes:
        """Encrypt RTP packet using SRTP (synchronous)."""
        if srtp := self._srtp_rtp:
            return await srtp.encrypt(data)
        raise ValueError("SRTP not initialized")

    async def encrypt_rtcp_bytes(self, data: bytes) -> bytes:
        """Encrypt RTCP packet using SRTP (synchronous)."""
        if srtp := self._srtp_rtcp:
            return await srtp.encrypt(data)
        raise ValueError("SRTP not initialized")

    async def write_rtcp_bytes(self, data: bytes) -> int:
        """Write RTCP packet (encrypted via SRTP) and send to network."""
        await self.__srtp_rtcp_lock.wait()
        if not self._srtp_rtcp or not self.__transport:
            return 0
        try:
            # Encrypt synchronously (Rust crypto is fast)
            encrypted = await self._srtp_rtcp.encrypt(data)
            # Send via ICE transport
            self.__transport.sendto(encrypted)
            return len(encrypted)
        except Exception as e:
            get_logger().error(Component.DTLS, "Failed to send RTCP", error=str(e))
            return 0

    async def write_rtp_bytes(self, data: bytes) -> int:
        """Write RTP packet (encrypted via SRTP) and send to network."""
        await self.__srtp_rtp_lock.wait()
        if not self._srtp_rtp or not self.__transport:
            wlogger = get_logger()
            wlogger.trace(Component.DTLS, "write_rtp_bytes skipped",
                        srtp_ready=self._srtp_rtp is not None,
                        transport_ready=self.__transport is not None)
            return 0
        try:
            # Encrypt synchronously (Rust crypto is fast)
            encrypted = await self._srtp_rtp.encrypt(data)
            # Send via ICE transport
            self.__transport.sendto(encrypted)
            return len(encrypted)
        except Exception as e:
            wlogger = get_logger()
            wlogger.error(Component.DTLS, "Failed to send RTP", error=str(e))
            return 0

    async def srtp_rtp_stream(self, ssrc: int) -> SrtpStream:
        """Get or create SRTP stream for given SSRC."""
        await self.__srtp_rtp_lock.wait()
        if not self._srtp_rtp:
            raise ValueError("SRTP must be started to get the stream")
        return await self._srtp_rtp.open_stream(ssrc)

    async def srtp_rtcp_stream(self, ssrc: int) -> SrtpStream:
        """Get or create SRTCP stream for given SSRC."""
        await self.__srtp_rtcp_lock.wait()
        if not self._srtp_rtcp:
            raise ValueError("SRTP must be started to get the stream")
        return await self._srtp_rtcp.open_stream(ssrc)

    @task(
        name="dtls:rtp-receive-loop",
        kind="dtls",
        metadata={"expected_long_running": True, "loop_role": "receive"},
        failure=FailurePolicy.FAIL_CONNECTION,
    )
    async def _rtp_receive_loop(self):
        """Internal loop that reads RTP from ICE and routes to SRTP streams."""
        wlogger = get_logger()
        config = get_config()

        if not self.__transport:
            wlogger.error(Component.DTLS, "No transport for RTP receive loop")
            return

        wlogger.info(Component.DTLS, "RTP receive loop started")
        rtp_packet_count = 0
        srtp_error_count = 0
        srtp_write_count = 0

        while True:
            try:
                packet = await self.__transport.recv_rtp()
                rtp_packet_count += 1

                # Parse packet info for logging
                if len(packet.data) >= 12:
                    seq = int.from_bytes(packet.data[2:4], 'big')
                    ssrc = int.from_bytes(packet.data[8:12], 'big')
                else:
                    seq = -1
                    ssrc = -1

                # Log packet details with smart throttling
                if config.log_packet_details and (rtp_packet_count <= config.log_first_n_packets or
                                                 rtp_packet_count % config.log_every_n_packets == 0):
                    wlogger.log_packet(Component.DTLS, "RX", rtp_packet_count,
                                     seq=seq, ssrc=ssrc, size=len(packet.data))

                if self._srtp_rtp:
                    try:
                        await self._srtp_rtp.write_incoming(packet.data)
                        srtp_write_count += 1
                        if config.log_packet_details and (rtp_packet_count <= config.log_first_n_packets or
                                                         rtp_packet_count % config.log_every_n_packets == 0):
                            wlogger.trace(Component.DTLS, f"Wrote packet #{rtp_packet_count} to SRTP")
                    except Exception as srtp_err:
                        srtp_error_count += 1
                        if srtp_error_count <= 10 or srtp_error_count % 100 == 0:
                            wlogger.error(Component.DTLS, f"SRTP decrypt error ({srtp_error_count}/{rtp_packet_count})",
                                        error=str(srtp_err))
                else:
                    if rtp_packet_count <= 10:
                        wlogger.warn(Component.DTLS, f"No SRTP session yet for packet #{rtp_packet_count}")

                # Log statistics
                if config.log_packet_counts and rtp_packet_count % 100 == 0:
                    success_rate = ((rtp_packet_count - srtp_error_count) / rtp_packet_count * 100)
                    wlogger.log_stats(Component.DTLS,
                                    received=rtp_packet_count,
                                    wrote_to_srtp=srtp_write_count,
                                    srtp_errors=srtp_error_count,
                                    success_rate=f"{success_rate:.1f}%")

            except Exception as e:
                wlogger.error(Component.DTLS, "RTP receive loop error", error=str(e))
                await asyncio.sleep(0.1)

    @task(
        name="dtls:rtcp-receive-loop",
        kind="dtls",
        metadata={"expected_long_running": True, "loop_role": "receive"},
        failure=FailurePolicy.FAIL_CONNECTION,
    )
    async def _rtcp_receive_loop(self):
        """Internal loop that reads RTCP from ICE and routes to SRTP streams."""
        wlogger = get_logger()
        if not self.__transport:
            wlogger.error(Component.DTLS, "No transport for RTCP receive loop")
            return

        wlogger.info(Component.DTLS, "RTCP receive loop started")
        while True:
            try:
                packet = await self.__transport.recv_rtcp()
                if self._srtp_rtcp:
                    await self._srtp_rtcp.write_incoming(packet.data)
            except Exception as e:
                wlogger.error(Component.DTLS, "RTCP receive loop error", error=str(e))
                await asyncio.sleep(0.1)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        tasks = tuple(
            task for task in (self._rtcp_task, self._rtp_task, self._handshake_task)
            if task is not None and task is not asyncio.current_task()
        )
        for running in tasks:
            if not running.done():
                running.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # SRTP is above DTLS in the dependency stack and therefore closes first.
        if self._srtp_rtcp is not None:
            await self._srtp_rtcp.close()
            self._srtp_rtcp = None
        if self._srtp_rtp is not None:
            await self._srtp_rtp.close()
            self._srtp_rtp = None
        self.__dtls_conn = None
        self.__transport = None
