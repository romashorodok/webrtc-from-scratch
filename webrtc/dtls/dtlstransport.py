import asyncio
import logging
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

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
from webrtc.dtls.handshake_reconstructor import (
    HandshakeReconstructor, HandshakeReconstructionOverflow,
)
from webrtc.dtls.prf import SRTPKeyingMaterial
from webrtc.srtp import Session as SrtpSession, Stream as SrtpStream
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.performance import ObservedComponent, event_loop
from webrtc.runtime_services import (
    FailurePolicy, OwnedTaskHandle, current_execution_scope,
)
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.queue_machine import RuntimeOwnedQueue
from webrtc.state_machine import (
    InlineStateMachineRunner, MachineCommand, PreparedTransition, ReplyPort,
    TransitionCommit,
)
from webrtc.lifecycle import (
    TransportCondition,
    require_timeout,
    wait_until,
)
from webrtc.tracing import measure_perf, perf_mark, perf_measured_async

logger = logging.getLogger("webrtc.dtls.transport")

RECORD_INGRESS_CAPACITY = 64


class _TransportCommandKind(Enum):
    BIND = "bind"
    START = "start"
    HANDSHAKE_READY = "handshake-ready"
    HANDSHAKE_FAILED = "handshake-failed"
    CLOSE = "close"


class DTLSRole(Enum):
    Auto = "auto"
    Server = "server"
    Client = "client"


@dataclass(frozen=True, slots=True)
class _StartPayload:
    role: "DTLSRole"
    transport: "ice.CandidatePairTransport"
    completion: ReplyPort[TransitionCommit]


@dataclass(frozen=True, slots=True)
class DTLSTransportSnapshot:
    """Authoritative DTLS binding and media-admission readiness."""

    revision: int = 0
    state: str = "new"
    role: DTLSRole = DTLSRole.Auto
    transport: "ice.CandidatePairTransport | None" = None
    selected_pair_id: str | None = None
    handshake_ready: bool = False
    srtp_rtp_revision: int | None = None
    srtp_rtcp_revision: int | None = None

    @property
    def media_ready(self) -> bool:
        return (
            self.state == "connected"
            and self.handshake_ready
            and self.transport is not None
            and self.srtp_rtp_revision is not None
            and self.srtp_rtcp_revision is not None
        )


class _DTLSTransportRunner(InlineStateMachineRunner):
    def __init__(self, owner: "DTLSTransport", **kwargs: Any) -> None:
        self.owner = owner
        super().__init__(MACHINE_SPECS["dtls-transport"], **kwargs)

    async def step(self, command: MachineCommand[Any, Any]) -> PreparedTransition[Any]:
        kind = command.kind
        if kind is _TransportCommandKind.BIND:
            proposed = "binding"
        elif kind is _TransportCommandKind.START:
            proposed = "connecting"
        elif kind is _TransportCommandKind.HANDSHAKE_READY:
            self.owner._require_connected_readiness()
            proposed = "connected"
        elif kind is _TransportCommandKind.HANDSHAKE_FAILED:
            proposed = "failed"
        elif kind is _TransportCommandKind.CLOSE:
            proposed = (
                "closed" if self._state == "new"
                else "closing" if self._state != "closing" else "closed"
            )
        else:
            raise ValueError(f"unsupported DTLS transport command: {kind!r}")
        return PreparedTransition(
            self._state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    async def after_commit(self, commit: TransitionCommit, effects: Any) -> None:
        if commit.to_state == "binding":
            self.owner._set_bound_transport(effects)
        elif commit.to_state == "connecting":
            payload: _StartPayload = effects
            self.owner._begin_start(payload.role, payload.transport)
            self.owner._launch_handshake(payload)
        elif commit.to_state == "connected":
            # This edge is impossible until key extraction and both child
            # SRTP sessions have committed readiness.
            self.owner._mark_handshake_connected()
        elif commit.to_state == "failed":
            self.owner._mark_handshake_failed(effects)
        elif commit.to_state == "closing":
            self.owner._request_stop(
                preserve_handshake=self.owner._srtp_rtcp is not None
                or self.owner._srtp_rtp is not None
            )
        self.owner._commit_authority(commit, effects)
        if commit.to_state == "connected":
            self.owner._launch_media_receive_pumps()

    async def reconcile_terminal(self, prepared: PreparedTransition[Any]) -> None:
        await self.owner._reconcile_terminal()


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
        *, observability_id: str | None = None,
    ) -> None:
        self.__rust_cert = certificate
        # Wrap Rust certificate for Python FSM
        self.__cert = Certificate(certificate)

        # Python FSM state
        self.__dtls_conn: DTLSConn | None = None
        self.__role: DTLSRole = DTLSRole.Auto
        self.__transport: ice.CandidatePairTransport | None = None
        self._authority = DTLSTransportSnapshot(role=DTLSRole.Auto)

        self.__handshake_reconstructor = HandshakeReconstructor()

        # SRTP state - Python Session with Rust SrtpContext for crypto
        self._srtp_rtp: SrtpSession | None = None
        self._srtp_rtcp: SrtpSession | None = None

        # Handshake completion
        self.__handshake_failed: BaseException | None = None
        self._srtp_keying_material: SRTPKeyingMaterial | None = None
        self._command_id = 0
        self._start_completion: ReplyPort[TransitionCommit] | None = None
        self._handshake_handle: OwnedTaskHandle[Any] | None = None
        self._record_ingress_handle: OwnedTaskHandle[Any] | None = None
        self._record_pump_handle: OwnedTaskHandle[Any] | None = None
        self._rtp_handle: OwnedTaskHandle[Any] | None = None
        self._rtcp_handle: OwnedTaskHandle[Any] | None = None
        scope = current_execution_scope()
        root = getattr(scope, "root_context", None)
        identity = (
            observability_id
            or getattr(scope, "scope_id", None)
            or getattr(root, "trace_id", None)
        )
        self.entity_id = f"dtls-transport:{identity or id(self)}"
        self.record_layer_chan: RuntimeOwnedQueue[tuple[RecordLayer, bytes]] = RuntimeOwnedQueue(
            RECORD_INGRESS_CAPACITY,
            entity_id=f"{self.entity_id}:record-ingress",
            queue_kind="dtls-record-ingress",
        )
        self._runtime = scope if hasattr(scope, "start_machine") else None
        self._machine_handle: OwnedTaskHandle[None] | None = None
        self._runner = _DTLSTransportRunner(
            self, entity_id=self.entity_id, mailbox_capacity=16,
            controller=getattr(scope, "transition_controller", None),
            transition_sink=(self._runtime.observe_transition
                             if self._runtime is not None else None),
        )
        projection = getattr(scope, "projection", None)
        if projection is not None:
            projection.machines.register(
                self.entity_id, MACHINE_SPECS["dtls-transport"]
            )
        if self._runtime is not None:
            self._runtime.register_owner(self.entity_id, epoch=self._runner.epoch)
            self._machine_handle = self._runner.activate(
                self._runtime, owner_entity_id=self.entity_id,
                owner_epoch=self._runner.epoch,
            )
            self.__bind_worker_owner__(
                self._runtime, self.entity_id, self._runner.epoch
            )

    @event_loop
    def _command(
        self, kind: _TransportCommandKind, payload: Any = None, *,
        reply: ReplyPort[Any] | None = None,
    ) -> MachineCommand[Any, Any]:
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, self._runner.epoch, payload, reply,
        )

    @event_loop
    def _set_bound_transport(self, transport: ice.CandidatePairTransport) -> None:
        self.__transport = transport

    @event_loop
    def authoritative_snapshot(self) -> DTLSTransportSnapshot:
        return self._authority

    @event_loop
    def _commit_authority(self, commit: TransitionCommit, effects: Any) -> None:
        current = self._authority
        role = current.role
        transport = current.transport
        if commit.to_state == "binding":
            transport = effects
        elif commit.to_state == "connecting":
            role = effects.role
            transport = effects.transport
        if commit.to_state in {"failed", "closed"}:
            transport = None
        rtp = self._srtp_rtp.lifecycle_snapshot() if self._srtp_rtp else None
        rtcp = self._srtp_rtcp.lifecycle_snapshot() if self._srtp_rtcp else None
        self._authority = DTLSTransportSnapshot(
            revision=commit.revision,
            state=commit.to_state,
            role=role,
            transport=transport,
            selected_pair_id=(
                getattr(transport, "entity_id", f"candidate-pair:{id(transport)}")
                if transport is not None else None
            ),
            handshake_ready=commit.to_state == "connected",
            srtp_rtp_revision=(rtp.revision if rtp and rtp.state == "ready" else None),
            srtp_rtcp_revision=(rtcp.revision if rtcp and rtcp.state == "ready" else None),
        )

    @event_loop
    def _begin_start(
        self, role: DTLSRole, transport: ice.CandidatePairTransport
    ) -> None:
        self.__role = role
        self.__transport = transport
        flight = Flight.FLIGHT1 if role is DTLSRole.Client else Flight.FLIGHT0
        self.__dtls_conn = DTLSConn(
            remote=DTLSLocal(transport), certificate=self.__cert,
            layer_chan=self.record_layer_chan, flight=flight,
        )

    @event_loop
    def _launch_handshake(self, payload: _StartPayload) -> None:
        if self._runtime is None:
            raise RuntimeError("DTLS handshake requires an active Runtime")
        self._record_ingress_handle = self._runtime.start_pump(
            lambda: self._record_ingress_loop(payload.transport),
            owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
            name="dtls:ice-record-ingress", kind="dtls",
            failure=FailurePolicy.FAIL_CONNECTION,
        )
        assert self.__dtls_conn is not None
        self._record_pump_handle = self._runtime.start_pump(
            self.__dtls_conn.handle_inbound_record_layers,
            owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
            name="dtls:record-pump", kind="dtls",
            failure=FailurePolicy.FAIL_CONNECTION,
        )
        self._handshake_handle = self._runtime.start_pump(
            lambda: self._handshake_workflow(payload),
            owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
            name="dtls:handshake", kind="dtls",
            failure=FailurePolicy.FAIL_CONNECTION,
        )

    async def _handshake_workflow(self, payload: _StartPayload) -> None:
        try:
            await self._run_handshake(payload.role is DTLSRole.Client)
        except asyncio.CancelledError:
            return
        except BaseException as error:
            command = self._command(
                _TransportCommandKind.HANDSHAKE_FAILED, error,
                reply=payload.completion,
            )
        else:
            command = self._command(
                _TransportCommandKind.HANDSHAKE_READY, None,
                reply=payload.completion,
            )
        try:
            await self._runner.submit(command)
        except Exception as error:
            payload.completion.reject(error)

    async def _record_ingress_loop(
        self, transport: "ice.CandidatePairTransport"
    ) -> None:
        while True:
            packet = await transport.recv_dtls()
            await self.enqueue_record(packet.data)

    @event_loop
    def _require_connected_readiness(self) -> None:
        if self._srtp_keying_material is None:
            raise RuntimeError("DTLS handshake finished without SRTP keying material")
        for protocol, session in (("RTP", self._srtp_rtp), ("RTCP", self._srtp_rtcp)):
            if session is None or session.lifecycle_snapshot().state != "ready":
                raise RuntimeError(f"{protocol} SRTP session is not ready")

    @event_loop
    def _mark_handshake_connected(self) -> None:
        self._require_connected_readiness()
        scope = current_execution_scope()
        if scope is not None and getattr(scope, "tracing_enabled", True):
            scope.observe_facets(
                self._runner.snapshot(), {
                    "srtp_keys_ready": True,
                    "srtp_rtp_ready": True,
                    "srtp_rtcp_ready": True,
                },
                observer_meta="exact",
            )

    @event_loop
    def _launch_media_receive_pumps(self) -> None:
        """Start media ingress only after connected authority is published."""
        if self._runtime is None:
            raise RuntimeError("SRTP receive pumps require an active Runtime")
        if self._rtp_handle is None:
            self._rtp_handle = self._runtime.start_pump(
                self._rtp_receive_loop,
                owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
                name="dtls:rtp-receive-loop", kind="dtls",
                failure=FailurePolicy.FAIL_CONNECTION,
            )
        if self._rtcp_handle is None:
            self._rtcp_handle = self._runtime.start_pump(
                self._rtcp_receive_loop,
                owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
                name="dtls:rtcp-receive-loop", kind="dtls",
                failure=FailurePolicy.FAIL_CONNECTION,
            )

    @event_loop
    def _mark_handshake_failed(self, error: BaseException) -> None:
        self.__handshake_failed = error

    @event_loop
    def get_srtp_keying_material(self) -> SRTPKeyingMaterial | None:
        """Get SRTP keying material after handshake completion."""
        return self._srtp_keying_material

    async def bind(self, transport: ice.CandidatePairTransport):
        """Bind to ICE transport for sending/receiving DTLS packets."""
        reply: ReplyPort[TransitionCommit] = ReplyPort()
        await self._runner.submit(self._command(
            _TransportCommandKind.BIND, transport, reply=reply,
        ))
        await reply.wait()

    async def start(
        self, role: DTLSRole,
        transport: "ice.CandidatePairTransport | None" = None,
    ) -> None:
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

        snapshot = self._runner.snapshot()
        if snapshot.state == "connected":
            wlogger.info(Component.DTLS, "Handshake already complete, skipping")
            perf_mark("dtls", "start", "completed", metadata={"already_complete": True})
            return

        # If there's already a DTLS connection in progress, skip (don't restart mid-handshake)
        if self._start_completion is not None:
            wlogger.info(Component.DTLS, "DTLS connection already in progress, skipping duplicate start")
            committed = await self._start_completion.wait()
            if committed.to_state == "failed":
                assert self.__handshake_failed is not None
                raise self.__handshake_failed
            perf_mark("dtls", "start", "completed", metadata={"already_started": True})
            return

        is_client = role == DTLSRole.Client
        perf_mark("dtls", "role", "selected", metadata={"role": role.value})

        # Bind transport if provided
        selected_transport = transport or self._authority.transport
        if not selected_transport:
            wlogger.error(Component.DTLS, "No transport bound - cannot start DTLS handshake")
            perf_mark(
                "dtls",
                "start",
                "failed",
                metadata={"role": role.value, "exception_class": "RuntimeError"},
            )
            raise RuntimeError("No transport bound - cannot start DTLS handshake")

        completion: ReplyPort[TransitionCommit] = ReplyPort()
        self._start_completion = completion
        try:
            await self._runner.submit(self._command(
                _TransportCommandKind.START,
                _StartPayload(role, selected_transport, completion),
            ))
        except BaseException as error:
            completion.reject(error)
            self._start_completion = None
            raise
        committed = await completion.wait()
        if committed.to_state == "failed":
            assert self.__handshake_failed is not None
            raise self.__handshake_failed
        perf_mark("dtls", "start", "completed", metadata={"role": role.value})

    @perf_measured_async("dtls", "handshake")
    async def _run_handshake(self, is_client: bool):
        """Run the DTLS handshake using Python FSM."""
        wlogger = get_logger()
        wlogger.info(Component.DTLS, "Running handshake", is_client=is_client)

        if not self.__dtls_conn:
            wlogger.error(Component.DTLS, "DTLS connection not initialized")
            exc = RuntimeError("DTLS connection not initialized")
            self.__handshake_failed = exc
            raise exc

        try:
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

                if self._srtp_keying_material is None:
                    raise RuntimeError(
                        "DTLS handshake finished without SRTP keying material"
                    )
                await self._init_srtp(is_client)
                self._require_connected_readiness()

            else:
                wlogger.error(Component.DTLS, "Handshake timed out")
                raise TimeoutError("DTLS handshake timed out")

        except Exception as e:
            wlogger.error(Component.DTLS, "Handshake error", error=str(e))
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

            # Initialize Python SRTP sessions (uses Rust SrtpContext internally)
            self._srtp_rtp = SrtpSession.from_keying_material(
                tx_key=tx_master_key,
                rx_key=rx_master_key,
                is_rtp=True,
            )
            wlogger.debug(Component.DTLS, "RTP SRTP session created")

            self._srtp_rtcp = SrtpSession.from_keying_material(
                tx_key=tx_master_key,
                rx_key=rx_master_key,
                is_rtp=False,
            )
            await self._srtp_rtp.wait_ready()
            await self._srtp_rtcp.wait_ready()
            wlogger.debug(Component.DTLS, "RTCP SRTP session created")

            wlogger.info(Component.DTLS, "SRTP sessions initialized")

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
                    except Exception as error:
                        reconstruct_metadata.update(
                            error_stage="handshake_reconstruction",
                            **{"counter.dtls.record_reconstruct_failed": 1},
                        )
                        if isinstance(error, HandshakeReconstructionOverflow):
                            scope = current_execution_scope()
                            diagnostics = getattr(scope, "diagnostics", None)
                            if diagnostics is not None:
                                diagnostics["dtls_handshake_fragment_overflow"] += 1
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
        await asyncio.Future()  # Never returns
        return bytes()

    @event_loop
    def _srtp_ready(self) -> bool:
        authority = getattr(self, "_authority", None)
        if authority is None:  # lightweight protocol test doubles
            return self._srtp_rtp is not None and self._srtp_rtcp is not None
        if not authority.media_ready or self._srtp_rtp is None or self._srtp_rtcp is None:
            return False
        rtp = self._srtp_rtp.admission_snapshot()
        rtcp = self._srtp_rtcp.admission_snapshot()
        return (
            rtp.accepting_packets
            and rtcp.accepting_packets
            and rtp.revision == authority.srtp_rtp_revision
            and rtcp.revision == authority.srtp_rtcp_revision
        )

    async def wait(self, condition: TransportCondition, timeout: float) -> None:
        timeout = require_timeout(timeout)
        match condition:
            case TransportCondition.HANDSHAKE_COMPLETE:
                await wait_until(
                    lambda: self._runner.snapshot().state
                    in {"connected", "failed", "closing", "closed"},
                    timeout=timeout,
                )
                if self.__handshake_failed is not None:
                    raise self.__handshake_failed
            case TransportCondition.SRTP_READY:
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
        if self._srtp_ready() and (srtp := self._srtp_rtp):
            return await srtp.encrypt(data)
        raise RuntimeError("DTLS media admission is not ready")

    async def encrypt_rtcp_bytes(self, data: bytes) -> bytes:
        """Encrypt RTCP packet using SRTP (synchronous)."""
        if self._srtp_ready() and (srtp := self._srtp_rtcp):
            return await srtp.encrypt(data)
        raise RuntimeError("DTLS media admission is not ready")

    async def write_rtcp_bytes(self, data: bytes) -> int:
        """Write RTCP packet (encrypted via SRTP) and send to network."""
        await self.wait(TransportCondition.SRTP_READY, 30.0)
        authority = self._authority
        if not self._srtp_ready() or not self._srtp_rtcp:
            return 0
        try:
            # Encrypt synchronously (Rust crypto is fast)
            encrypted = await self._srtp_rtcp.encrypt(data)
            # Send via ICE transport
            assert authority.transport is not None
            authority.transport.sendto(encrypted)
            return len(encrypted)
        except Exception as e:
            get_logger().error(Component.DTLS, "Failed to send RTCP", error=str(e))
            return 0

    async def write_rtp_bytes(self, data: bytes) -> int:
        """Write RTP packet (encrypted via SRTP) and send to network."""
        await self.wait(TransportCondition.SRTP_READY, 30.0)
        authority = self._authority
        if not self._srtp_ready() or not self._srtp_rtp:
            wlogger = get_logger()
            wlogger.trace(Component.DTLS, "write_rtp_bytes skipped",
                        srtp_ready=self._srtp_rtp is not None,
                        transport_ready=authority.transport is not None)
            return 0
        try:
            # Encrypt synchronously (Rust crypto is fast)
            encrypted = await self._srtp_rtp.encrypt(data)
            # Send via ICE transport
            assert authority.transport is not None
            authority.transport.sendto(encrypted)
            return len(encrypted)
        except Exception as e:
            wlogger = get_logger()
            wlogger.error(Component.DTLS, "Failed to send RTP", error=str(e))
            return 0

    async def srtp_rtp_stream(self, ssrc: int) -> SrtpStream:
        """Get or create SRTP stream for given SSRC."""
        await self.wait(TransportCondition.SRTP_READY, 30.0)
        if not self._srtp_rtp:
            raise ValueError("SRTP must be started to get the stream")
        return await self._srtp_rtp.open_stream(ssrc)

    async def srtp_rtcp_stream(self, ssrc: int) -> SrtpStream:
        """Get or create SRTCP stream for given SSRC."""
        await self.wait(TransportCondition.SRTP_READY, 30.0)
        if not self._srtp_rtcp:
            raise ValueError("SRTP must be started to get the stream")
        return await self._srtp_rtcp.open_stream(ssrc)

    async def _rtp_receive_loop(self):
        """Internal loop that reads RTP from ICE and routes to SRTP streams."""
        wlogger = get_logger()
        config = get_config()

        transport = self._authority.transport
        if transport is None or not self._srtp_ready():
            wlogger.error(Component.DTLS, "No transport for RTP receive loop")
            return

        wlogger.info(Component.DTLS, "RTP receive loop started")
        rtp_packet_count = 0
        srtp_error_count = 0
        srtp_write_count = 0

        while True:
            try:
                packet = await transport.recv_rtp()
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

    async def _rtcp_receive_loop(self):
        """Internal loop that reads RTCP from ICE and routes to SRTP streams."""
        wlogger = get_logger()
        transport = self._authority.transport
        if transport is None or not self._srtp_ready():
            wlogger.error(Component.DTLS, "No transport for RTCP receive loop")
            return

        wlogger.info(Component.DTLS, "RTCP receive loop started")
        while True:
            try:
                packet = await transport.recv_rtcp()
                if self._srtp_rtcp:
                    await self._srtp_rtcp.write_incoming(packet.data)
            except Exception as e:
                wlogger.error(Component.DTLS, "RTCP receive loop error", error=str(e))
                await asyncio.sleep(0.1)

    async def aclose(self) -> None:
        if self._runner.snapshot().state == "closed":
            await self._finalize_owner()
            return
        reply: ReplyPort[TransitionCommit] = ReplyPort()
        await self._runner.submit(self._command(
            _TransportCommandKind.CLOSE, reply=reply,
        ))
        await reply.wait()
        if self._runner.snapshot().state == "closed":
            self.__dtls_conn = None
            self.__transport = None
            await self._finalize_owner()
            return
        reply = ReplyPort()
        await self._runner.submit(self._command(
            _TransportCommandKind.CLOSE, reply=reply,
        ))
        await reply.wait()
        await self._finalize_owner()

    async def _finalize_owner(self) -> None:
        if self._machine_handle is None:
            return
        await self._machine_handle.wait()
        self._runtime.remove_owner(self.entity_id, self._runner.epoch)
        self._machine_handle = None

    @event_loop
    def _request_stop(self, *, preserve_handshake: bool = False) -> None:
        error = RuntimeError("DTLS transport closed during handshake")
        if self._start_completion is not None:
            self._start_completion.reject(error)
        self.__handshake_failed = error
        for handle in self._child_handles():
            if preserve_handshake and handle is self._handshake_handle:
                continue
            handle.cancel()

    @event_loop
    def _child_handles(self) -> tuple[OwnedTaskHandle[Any], ...]:
        return tuple(
            handle for handle in (
                self._rtcp_handle, self._rtp_handle, self._record_pump_handle,
                self._record_ingress_handle, self._handshake_handle,
            ) if handle is not None
        )

    async def _reconcile_terminal(self) -> None:
        # SRTP machine runners are created by the handshake workflow and are
        # therefore descendants of its Runtime-owned task.  Once key setup has
        # completed, let those children reconcile before cancelling the
        # handshake handle; cancelling the parent first would close their
        # mailboxes while they still reported ``ready``.
        preserve_handshake = (
            self._handshake_handle is not None
            and (self._srtp_rtcp is not None or self._srtp_rtp is not None)
        )
        self._request_stop(preserve_handshake=preserve_handshake)
        handles = tuple(
            handle for handle in self._child_handles()
            if not handle.done()
            and (not preserve_handshake or handle is not self._handshake_handle)
        )
        if handles:
            await asyncio.gather(
                *(handle.wait() for handle in handles), return_exceptions=True
            )
        if self._srtp_rtcp is not None:
            await self._srtp_rtcp.close()
            self._srtp_rtcp = None
        if self._srtp_rtp is not None:
            await self._srtp_rtp.close()
            self._srtp_rtp = None
        if preserve_handshake and self._handshake_handle is not None:
            await self._handshake_handle.wait()
        self._request_stop()
        if self.__dtls_conn is not None:
            await self.__dtls_conn.aclose()
        await self.record_layer_chan.close()
        self.__dtls_conn = None
        self.__transport = None
