import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import wraps
import secrets
import string
import uuid

import webrtc_rs

from webrtc.media.av1_payloader import AV1_PAYLOAD_TYPE
from webrtc.media.rtcp import (
    RecvDelta,
    RtcpPacket,
    RunLengthChunk,
    TransportLayerCC,
    TypeTCCPacketReceivedSmallDelta,
)

from . import ice
from .ice import net
from . import dtls

import socket
from .utils import impl_protocol, current_ntp_time
from .performance import ObservedComponent, event_loop, task
from .runtime_services import (
    FailurePolicy,
    OwnedTaskHandle,
    ScopeState,
    StaleOwnerEpoch,
    TaskFailureEvent,
    current_execution_scope,
)
from .machine_specs import MACHINE_SPECS
from .observability import MachineTransitionOp
from .state_machine import (
    AsyncStateMachineRunner, BoundedMailbox, MachineCommand, MailboxClosed,
    PreparedTransition, ReplyPort, StaleMachineAccess, TransitionCommit,
)
from .peer_components import (
    AsyncLogDrain,
    MediaSourceController,
    PeerConnectionLogInbox,
    PeerEventInbox,
    SignalingController,
)
from .logger import Component, get_logger
from .tracing import (
    get_current_performance_recorder, measure_perf_async, perf_mark,
    perf_measured_async, use_performance_recorder,
)

from .session_description import (
    Origin,
    SessionDescription,
    SessionDescriptionType,
    SessionDescriptionAttr,
    SessionDescriptionAttrKey,
)
from .session_description_populate import (
    flatten_media_section_transceivers,
    populate_session_descriptor,
    MediaSection,
)
from .transceiver import (
    MediaCaps,
    RTPCodecParameters,
    RTPCodecKind,
    RTCPFeedback,
    RTPDecodingParameters,
    RTPRtxParameters,
    RTPTransceiver,
    RTPTransceiverDirection,
    RTPReceiver,
    RTPSender,
    TrackLocal,
    find_transceiver_by_mid,
)
from .signaling import (
    SignalingChangeOperation,
    SignalingState,
    ensure_next_signaling_state,
    SignalingStateTransitionError,
)
from .peer_connection_types import (
    ICEParameters,
    ConnectionRole,
)
from .lifecycle import (
    ICECondition,
    PeerCondition,
    TransportCondition,
    require_timeout,
    wait_until,
)

nic_interfaces = net.interface_factory(
    net.InterfaceProvider.PSUTIL, [socket.AF_INET], False
)
if len(nic_interfaces) <= 0:
    nic_interfaces = net.interface_factory(
        net.InterfaceProvider.PSUTIL, [socket.AF_INET], True
    )


def random_string(length: int) -> str:
    allchar = string.ascii_letters + string.digits
    return "".join(secrets.choice(allchar) for _ in range(length))


def _sdp_description_measured(operation: str):
    def decorate(fn):
        @wraps(fn)
        async def wrapper(
            self,
            desc_type: SessionDescriptionType,
            desc: SessionDescription,
        ):
            async with measure_perf_async(
                "sdp",
                f"{operation}_{desc_type.value}",
                metadata={"description_type": desc_type.value},
            ):
                return await fn(self, desc_type, desc)

        return wrapper

    return decorate


class ICEGathererEvent(StrEnum):
    CANDIDATE_PAIR_CONTROLLER = "candidate-pair-controller"


class _GathererCommand(StrEnum):
    GATHER = "gather"
    COMPLETE = "complete"
    FAIL = "fail"
    CLOSE = "close"


class _GathererRunner(AsyncStateMachineRunner[MachineCommand[object, TransitionCommit]]):
    def __init__(self, owner: "ICEGatherer", **kwargs) -> None:
        super().__init__(MACHINE_SPECS["ice-gatherer"], **kwargs)
        self.owner = owner

    async def step(self, command):
        state = self.snapshot().state
        proposed = {
            _GathererCommand.GATHER: "gathering",
            _GathererCommand.COMPLETE: "complete",
            _GathererCommand.FAIL: "failed",
            _GathererCommand.CLOSE: "closed",
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported gatherer command: {command.kind}")
        return PreparedTransition(
            state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    async def reconcile_terminal(self, prepared):
        await self.owner._reconcile_gatherer()

    async def after_commit(self, commit, effects):
        if commit.to_state == "gathering":
            self.owner._launch_gather()


class ICEGatherer:
    def __init__(
        self, *, owner=None,
    ) -> None:

        self._loop = asyncio.get_running_loop()
        self.__agent: ice.Agent | None = None
        self._owner = owner
        self._gather_handle: OwnedTaskHandle[None] | None = None
        self._child_handles: set[OwnedTaskHandle] = set()
        self._gather_completion: ReplyPort[TransitionCommit] | None = None
        self._gather_submitted = False
        self._command_id = 0
        scope = current_execution_scope()
        root = getattr(scope, "root_context", None)
        identity = (
            getattr(owner, "_observability_id", None)
            or getattr(scope, "scope_id", None)
            or getattr(root, "trace_id", None)
        )
        self._runtime = scope if hasattr(scope, "start_machine") else None
        self.entity_id = f"ice-gatherer:{identity or id(self)}"
        common = {"controller": getattr(scope, "transition_controller", None)}
        self._runner = _GathererRunner(
            self, entity_id=self.entity_id, mailbox_capacity=8,
            transition_sink=self._project_transition, **common,
        )
        projection = getattr(scope, "projection", None)
        if projection is not None:
            projection.machines.register(self.entity_id, MACHINE_SPECS["ice-gatherer"])
        if self._runtime is not None:
            self._machine_handles = []
            for runner in (self._runner,):
                self._runtime.register_owner(runner.entity_id, epoch=runner.epoch)
                self._machine_handles.append(self._runtime.start_machine(
                    runner, owner_entity_id=runner.entity_id,
                    owner_epoch=runner.epoch,
                ))
        else:
            self._machine_handles = []

    def _command(self, runner, kind, payload=None, reply=None):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, runner.epoch, payload, reply,
            expected_revision=runner.revision,
            cause_id=f"{runner.entity_id}:{self._command_id}",
        )

    def _project_transition(self, commit: TransitionCommit) -> None:
        if self._runtime is None or not getattr(self._runtime, "tracing_enabled", True):
            return
        self._runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state, commit.to_state,
            commit.epoch, commit.revision, self._runtime.new_producer_dot(),
            commit.cause, commit.monotonic_ns,
        ))

    def _launch_gather(self) -> None:
        if self._runtime is None:
            raise RuntimeError("ICE gathering requires an active Runtime")
        self._gather_handle = self._runtime.start_pump(
            self._perform_gather, owner_entity_id=self.entity_id,
            owner_epoch=self._runner.epoch, name="ice:gather", kind="ice",
            failure=FailurePolicy.FAIL_CONNECTION,
        )

    async def _perform_gather(self) -> None:
        try:
            if self.__agent is None:
                self.__agent = await self.__create_agent()
            await self.__agent.gather_candidates()
            completion = self._gather_completion
            self._runner.try_submit(self._command(
                self._runner, _GathererCommand.COMPLETE, reply=completion,
            ))
        except asyncio.CancelledError:
            if self._gather_completion is not None:
                self._gather_completion.reject(asyncio.CancelledError())
            raise
        except BaseException as error:
            cause = f"{self.entity_id}:gather-failure"
            if not self._runner.snapshot().terminal:
                failed = ReplyPort[TransitionCommit]()
                self._runner.try_submit(self._command(
                    self._runner, _GathererCommand.FAIL, error, failed,
                ))
                await failed.wait()
            agent = self.__agent
            if agent is not None:
                await agent.fail(error, cause_id=cause)
            if self._gather_completion is not None:
                self._gather_completion.reject(error)

    async def _on_agent_failure(
        self, error: BaseException, agent_commit: TransitionCommit,
    ) -> None:
        if self._owner is not None:
            await self._owner._ice_failed(error, agent_commit)

    def _on_controller(self, controller: ice.CandidatePairController) -> None:
        if self._owner is None:
            return
        if self._runtime is None:
            raise RuntimeError("ICE controller callback requires an active Runtime")
        handle = self._runtime.start_pump(
            lambda: self._owner._ice_controller_created(controller), owner_entity_id=self.entity_id,
            owner_epoch=self._runner.epoch, name="ice:controller-created",
            kind="ice", failure=FailurePolicy.FAIL_CONNECTION,
        )
        self._child_handles.add(handle)

    async def _on_nominated(
        self, transport: ice.CandidatePairTransport, commit: TransitionCommit,
    ) -> None:
        if (
            commit.machine_type != "candidate-pair"
            or commit.to_state != "nominated"
            or transport.entity_id != commit.entity_id
        ):
            raise RuntimeError("public ICE requires the exact candidate-pair nomination")
        if self._owner is not None:
            await self._owner._ice_nominated(transport, commit)

    async def _reconcile_gatherer(self) -> None:
        for handle in tuple(self._child_handles):
            if not handle.done():
                handle.cancel()
            try:
                await handle.wait()
            except (asyncio.CancelledError, Exception):
                pass
        self._child_handles.clear()
        if self._gather_handle is not None and not self._gather_handle.done():
            self._gather_handle.cancel()
            try:
                await self._gather_handle.wait()
            except (asyncio.CancelledError, Exception):
                pass
        self._gather_handle = None
        agent, self.__agent = self.__agent, None
        if agent is not None:
            await agent.aclose()

        # self._policy: ICEGatherPolicy = ICEGatherPolicy.All
        # self._state: ICEGatherState = ICEGatherState.NEW
        # TODO: Add support for dedicated stun server
        # self._stun_servers = []

    # @property
    # def agent(self) -> ice.Agent:
    #     if self.__agent:
    #         return self.__agent
    #     raise ValueError("Agent is None, start it firstly")
    async def start(self):
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            return

        return None

    async def get_local_parameters(self) -> ICEParameters | None:
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            return

        ufrag, pwd = self.__agent.get_local_credentials()
        return ICEParameters(ufrag, pwd)

    def get_role(self) -> ice.AgentRole | None:
        if not self.__agent:
            return
        return self.__agent.get_role()

    async def get_local_candidates(self) -> list[ice.CandidateProtocol] | None:
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            return

        candidates = await self.__agent.get_local_candidates()
        return list(map(lambda c: c.unwrap, candidates))

    async def set_remote_credentials(self, ufrag: str, pwd: str):
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            raise RuntimeError("ICE agent is not available")

        self.__agent.set_remote_credentials(ufrag, pwd)

    async def add_remote_candidate(self, candidate_str: str):
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            raise RuntimeError("ICE agent is not available")

        await self.__agent.add_remote_candidate(candidate_str)

    async def __create_agent(
        self, port: int = 0, interfaces: list[net.Interface] = nic_interfaces
    ) -> ice.Agent:
        udp_mux = net.MultiUDPMux(interfaces, self._loop)
        await udp_mux.accept(port)

        options = ice.AgentOptions([ice.CandidateType.Host], udp_mux, interfaces)
        return ice.Agent(
            options, owner=self,
        )

    async def dial(self):
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            raise RuntimeError("ICE agent is not available")

        self.__agent.dial()

    async def accept(self):
        """Start ICE as Controlled agent (answerer role)."""
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            raise RuntimeError("ICE agent is not available")

        self.__agent.accept()

    async def gather(self):
        if self._runtime is None:
            raise RuntimeError("ICE gathering requires an active Runtime")
        state = self._runner.snapshot().state
        if state == "complete":
            return
        if state == "new" and not self._gather_submitted:
            self._gather_submitted = True
            self._gather_completion = ReplyPort[TransitionCommit]()
            self._runner.try_submit(self._command(
                self._runner, _GathererCommand.GATHER,
            ))
        if self._gather_completion is None:
            raise RuntimeError(f"ICE gathering cannot start from {state}")
        await self._gather_completion.wait()

        # agent = self.__agent
        # if agent is None:
        #     self.__agent = await self.__create_agent()
        #     agent = self.__agent

        # self._set_state(ICEGatherState.Gathering)

        # agent.set_on_candidate(self._on_candidate)
        # await agent.gather_candidates()

    async def wait(self, condition: ICECondition, timeout: float) -> None:
        timeout = require_timeout(timeout)
        if condition is ICECondition.GATHERING_COMPLETE:
            await wait_until(
                lambda: self._runner.snapshot().state == "complete",
                timeout=timeout,
            )
            return
        if not self.__agent:
            raise RuntimeError("ICE agent is not started")

        if not self.__agent:
            raise RuntimeError("ICE agent is not available")

        await self.__agent.wait(condition, timeout)

    async def aclose(self) -> None:
        if self._runtime is None:
            agent, self.__agent = self.__agent, None
            if agent is not None:
                await agent.aclose()
            return
        if not self._runner.snapshot().terminal:
            reply = ReplyPort[TransitionCommit]()
            self._runner.try_submit(self._command(
                self._runner, _GathererCommand.CLOSE, reply=reply,
            ))
            await reply.wait()
        if self._runtime is not None:
            for handle in self._machine_handles:
                await handle.wait()
            self._runtime.remove_owner(self._runner.entity_id, self._runner.epoch)

    async def aclose_controllers(self) -> None:
        if self.__agent is not None:
            await self.__agent.aclose_controllers()

    # def _set_state(self, state: ICEGatherState):
    #     # TODO: Make it reactive
    #     self._state = state


class _SelectedTransportCommand(StrEnum):
    SELECT = "select"
    READY = "ready"
    DRAIN = "drain"
    CLOSE = "close"
    FAIL = "fail"


class _SelectedTransportRunner(AsyncStateMachineRunner):
    async def step(self, command):
        proposed = {
            _SelectedTransportCommand.SELECT: "selecting",
            _SelectedTransportCommand.READY: "ready",
            _SelectedTransportCommand.DRAIN: "draining",
            _SelectedTransportCommand.CLOSE: "closed",
            _SelectedTransportCommand.FAIL: "failed",
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported selected-transport command: {command.kind}")
        return PreparedTransition(
            self.snapshot().state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )


@impl_protocol(dtls.ICETransportDTLS)
class ICETransport:
    def __init__(
        self,
        gatherer: ICEGatherer,
    ) -> None:
        self.__gatherer = gatherer
        self.__transport: ice.CandidatePairTransport | None = None
        self.__nomination: TransitionCommit | None = None
        self.__transport_revision = 0
        scope = current_execution_scope()
        root = getattr(scope, "root_context", None)
        identity = (
            getattr(gatherer, "entity_id", None)
            or getattr(scope, "scope_id", None)
            or getattr(root, "trace_id", None)
        )
        self.entity_id = f"selected-transport:{identity or id(self)}"
        self._runtime = scope if hasattr(scope, "start_machine") else None
        self._command_id = 0
        self._runner = _SelectedTransportRunner(
            MACHINE_SPECS["transport"], entity_id=self.entity_id,
            mailbox_capacity=8,
            controller=getattr(scope, "transition_controller", None),
            transition_sink=self._project_transition,
        )
        projection = getattr(scope, "projection", None)
        if projection is not None:
            projection.machines.register(self.entity_id, MACHINE_SPECS["transport"])
        if self._runtime is not None:
            self._runtime.register_owner(self.entity_id, epoch=self._runner.epoch)
            self._machine_handle = self._runtime.start_machine(
                self._runner, owner_entity_id=self.entity_id,
                owner_epoch=self._runner.epoch,
            )
        else:
            self._machine_handle = None
        # self.__running_transport = running_transport

        # self.__gatherer = gatherer
        # self._state: ICETransportState = ICETransportState.NEW

    def _project_transition(self, commit: TransitionCommit) -> None:
        if self._runtime is None:
            return
        self._runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state, commit.to_state,
            commit.epoch, commit.revision, self._runtime.new_producer_dot(),
            commit.cause, commit.monotonic_ns,
        ))
        values = {}
        if commit.to_state == "ready" and self.__transport is not None:
            pair_id = self.__transport.entity_id
            nomination = self.__nomination
            if nomination is None:
                raise RuntimeError("ready transport has no nomination provenance")
            values.update({
                "selected": True,
                "selected_pair_id": pair_id,
                "nomination_entity_id": nomination.entity_id,
                "nomination_revision": nomination.revision,
            })
        self._runtime.projection.merge_values(
            self.entity_id, self._runtime.new_producer_dot(), values,
            observer_meta="exact", source_entity_id=commit.entity_id,
            source_epoch=commit.epoch, source_revision=commit.revision,
            source_order=self._runtime.projection.new_facet_source_order(),
        )

    def _command(self, kind, *, cause_id=None, reply=None):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            expected_revision=None,
            cause_id=cause_id or f"{self.entity_id}:{self._command_id}",
        )

    async def bind(
        self, transport: ice.CandidatePairTransport,
        nomination: TransitionCommit,
    ):
        if self.__transport is not None and self.__transport is not transport:
            raise RuntimeError("selected ICE transport is already bound")
        pair_entity = transport.entity_id
        if (
            nomination.to_state != "nominated"
            or nomination.machine_type != "candidate-pair"
            or nomination.entity_id != pair_entity
        ):
            raise RuntimeError("selected transport requires a nomination commit")
        if self.__transport is None:
            cause = nomination.cause
            if self._machine_handle is not None:
                selected = ReplyPort[TransitionCommit]()
                self._runner.try_submit(self._command(
                    _SelectedTransportCommand.SELECT, cause_id=cause, reply=selected,
                ))
                await selected.wait()
            self.__transport = transport
            self.__nomination = nomination
            self.__transport_revision += 1
            if self._machine_handle is not None:
                ready = ReplyPort[TransitionCommit]()
                self._runner.try_submit(self._command(
                    _SelectedTransportCommand.READY, cause_id=cause, reply=ready,
                ))
                await ready.wait()

    async def get_ice_pair_transport(self) -> ice.CandidatePairTransport | None:
        return self.__transport

    def selected_snapshot(self) -> tuple[int, ice.CandidatePairTransport | None]:
        return self.__transport_revision, self.__transport

    async def aclose(self) -> None:
        if self._machine_handle is None or self._runner.snapshot().terminal:
            return
        cause = f"{self.entity_id}:close"
        draining = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(
            _SelectedTransportCommand.DRAIN, cause_id=cause, reply=draining,
        ))
        await draining.wait()
        transport, self.__transport = self.__transport, None
        self.__nomination = None
        if transport is not None:
            async_closer = getattr(transport, "aclose", None)
            if async_closer is not None:
                await async_closer()
            elif (closer := getattr(transport, "close", None)) is not None:
                closer()
        closed = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(
            _SelectedTransportCommand.CLOSE, cause_id=cause, reply=closed,
        ))
        await closed.wait()
        await self._machine_handle.wait()
        self._runtime.remove_owner(self.entity_id, self._runner.epoch)

    def get_ice_role(self) -> ice.AgentRole:
        role = self.__gatherer.get_role()
        if not role or role == ice.AgentRole.Unknown:
            return ice.AgentRole.Controlling
        return role

    # def get_ice_pair_transports(self) -> list[ice.CandidatePairTransport]:
    #     agent = self.__gatherer.agent
    #     return agent._candidate_pair_transports

    # def get_ice_role(self) -> ice.AgentRole:
    #     if
    #     return self._gatherer.agent.get_role()

    # Same as iceTransport.internalOnConnectionStateChangeHandler
    # def _on_connection_state_changed(self):
    #     # pc.onICEConnectionStateChange(cs)
    #     # pc.updateConnectionState(cs, pc.dtlsTransport.State())
    #     pass

    # def restart(self):
    #     raise ValueError("Implement agent restart")


@dataclass
class OfferOption:
    # VoiceActivityDetection allows the application to provide information
    # about whether it wishes voice detection feature to be enabled or disabled.
    voice_activity_detection: bool = False
    ice_restart: bool = False


def set_default_caps(caps: MediaCaps):
    caps.register_codec(
        RTPCodecParameters(
            mime_type="audio/opus",
            clock_rate=48000,
            refresh_rate=0.020,  # 20ms per packet (50 Hz) - standard for Opus
            channels=2,
            # https://datatracker.ietf.org/doc/html/rfc7587#section-6.1
            # https://datatracker.ietf.org/doc/html/draft-ietf-payload-rtp-opus-04
            sdp_fmtp_line="minptime=10;useinbandfec=1",
            payload_type=111,
            stats_id=f"RTPCodec-{current_ntp_time() >> 32}",
        ),
        RTPCodecKind.Audio,
    )

    av1 = RTPCodecParameters(
        mime_type="video/AV1",
        clock_rate=90000,
        refresh_rate=1 / 30,
        channels=0,
        sdp_fmtp_line="level-idx=5;profile=0;tier=0",
        payload_type=AV1_PAYLOAD_TYPE,
        stats_id=f"RTPCodec-{current_ntp_time() >> 32}",
    )
    # Match Chrome's expected RTCP feedback types
    # av1.rtcp_feedbacks.append(RTCPFeedback(rtcp_type="goog-remb", parameter=""))
    av1.rtcp_feedbacks.append(RTCPFeedback(rtcp_type="transport-cc", parameter=""))
    # av1.rtcp_feedbacks.append(RTCPFeedback(rtcp_type="ccm", parameter="fir"))
    # av1.rtcp_feedbacks.append(RTCPFeedback(rtcp_type="nack", parameter="pli"))
    caps.register_codec(av1, RTPCodecKind.Video)

    # vp8 = RTPCodecParameters(
    #     mime_type="video/VP8",
    #     clock_rate=90000,
    #     refresh_rate=1 / 30,
    #     channels=0,
    #     sdp_fmtp_line="",
    #     payload_type=96,
    #     stats_id=f"RTPCodec-{current_ntp_time() >> 32}",
    # )

    # receiver_report = RTCPFeedback(rtcp_type="rrtr", parameter="")
    # twcc = RTCPFeedback(rtcp_type="transport-cc", parameter="")
    # extended_reports_round_trip_time = RTCPFeedback(rtcp_type="ccm", parameter="fir")
    # vp8.rtcp_feedbacks.append(twcc)
    # vp8.rtcp_feedbacks.append(receiver_report)
    # vp8.rtcp_feedbacks.append(extended_reports_round_trip_time)
    # caps.register_codec(vp8, RTPCodecKind.Video)


@dataclass(frozen=True, slots=True)
class PeerConnectionTaskFailed:
    component: str
    task_name: str
    error: BaseException
    generation: int


class _PeerCommand(StrEnum):
    START = "start"
    NEGOTIATING = "negotiating"
    TRANSPORT_SELECTED = "transport-selected"
    CHILDREN_READY = "children-ready"
    FAIL = "fail"
    CLOSE = "close"
    FINISH_CLOSE = "finish-close"
    DIAL = "dial"
    ACCEPT = "accept"


class _SignalingCommand(StrEnum):
    SET_LOCAL = "set-local"
    SET_REMOTE = "set-remote"
    FAIL = "fail"
    CLOSE = "close"


@dataclass(frozen=True, slots=True)
class _ChildReadiness:
    entity_id: str
    epoch: int
    revision: int
    required_state: str


@dataclass(frozen=True, slots=True)
class _PeerReadiness:
    selected_transport: _ChildReadiness
    dtls: _ChildReadiness
    srtp_rtp: _ChildReadiness
    srtp_rtcp: _ChildReadiness


@dataclass(frozen=True, slots=True)
class _PeerCommandPayload:
    completion: ReplyPort[TransitionCommit] | None = None
    reason: str = ""
    error: BaseException | None = None
    readiness: _PeerReadiness | None = None
    role: str | None = None


@dataclass(frozen=True, slots=True)
class _CanonicalSDP:
    value: bytes

    @classmethod
    def capture(cls, desc: SessionDescription) -> "_CanonicalSDP":
        return cls(bytes(desc.marshal()))

    def materialize(self) -> SessionDescription:
        return SessionDescription.parse(self.value.decode("utf-8"))


@dataclass(frozen=True, slots=True)
class _SignalingSnapshot:
    state: SignalingState = SignalingState.Stable
    revision: int = 0
    negotiation_generation: int = 0
    current_local: _CanonicalSDP | None = None
    pending_local: _CanonicalSDP | None = None
    current_remote: _CanonicalSDP | None = None
    pending_remote: _CanonicalSDP | None = None


@dataclass(frozen=True, slots=True)
class _SignalingEffect:
    snapshot: _SignalingSnapshot
    description_type: SessionDescriptionType | None
    media_section_count: int = 0


class _PeerRunner(AsyncStateMachineRunner[MachineCommand[object, TransitionCommit]]):
    def __init__(self, owner: "PeerConnection", **kwargs) -> None:
        super().__init__(MACHINE_SPECS["peer"], **kwargs)
        self.owner = owner
        self.role: str | None = None

    async def step(self, command):
        state = self.snapshot().state
        proposed = {
            _PeerCommand.START: "starting",
            _PeerCommand.NEGOTIATING: "negotiating",
            _PeerCommand.TRANSPORT_SELECTED: "connecting",
            _PeerCommand.CHILDREN_READY: "connected",
            _PeerCommand.FAIL: "failed",
            _PeerCommand.CLOSE: "closing",
            _PeerCommand.FINISH_CLOSE: "closed",
            _PeerCommand.DIAL: state,
            _PeerCommand.ACCEPT: state,
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported peer command: {command.kind}")
        if command.kind is _PeerCommand.TRANSPORT_SELECTED and state == "connecting":
            raise StaleMachineAccess("selected transport was already committed")
        if command.kind is _PeerCommand.CHILDREN_READY:
            self.owner._validate_peer_readiness(command.payload.readiness)
        return PreparedTransition(
            state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    def commit(self, proposed, cause=None):
        # Child predicates are deliberately rechecked synchronously at the
        # commit boundary.  A before-commit checkpoint may allow a child epoch,
        # revision, or required state to change after step() prepared the edge.
        if isinstance(proposed, PreparedTransition):
            payload = proposed.effects
            if (
                proposed.proposed_state == "connected"
                and isinstance(payload, _PeerCommandPayload)
            ):
                self.owner._validate_peer_readiness(payload.readiness)
        if isinstance(proposed, PreparedTransition):
            payload = proposed.effects
            if isinstance(payload, _PeerCommandPayload) and payload.role is not None:
                if self.role is not None and self.role != payload.role:
                    raise StaleMachineAccess(
                        f"peer role is already {self.role}; cannot become {payload.role}"
                    )
        committed = super().commit(proposed, cause)
        if isinstance(proposed, PreparedTransition):
            payload = proposed.effects
            if isinstance(payload, _PeerCommandPayload) and payload.role is not None:
                self.role = payload.role
        return committed

    async def reconcile_terminal(self, prepared):
        await self.owner._reconcile_peer_terminal(prepared.effects)
        self.owner._assert_peer_reconciled()

    async def after_commit(self, commit, effects):
        try:
            await self.owner._after_peer_commit(commit, effects)
        except BaseException as error:
            # Some public peer operations use a completion carried by the
            # immutable effect rather than MachineCommand.reply.  Once the
            # transition has committed, AsyncStateMachineRunner can only
            # resolve the command reply; reject the public completion here so
            # callers observe the original post-commit failure instead of
            # waiting forever.
            if effects.completion is not None:
                effects.completion.reject(error)
            raise


class _SignalingRunner(AsyncStateMachineRunner[MachineCommand[object, TransitionCommit]]):
    def __init__(self, owner: "PeerConnection", **kwargs) -> None:
        super().__init__(MACHINE_SPECS["signaling"], **kwargs)
        self.owner = owner
        self.signaling = _SignalingSnapshot()

    async def step(self, command):
        if command.expected_revision not in (None, self.revision):
            raise StaleMachineAccess("signaling command prepared from a stale revision")
        if command.kind is _SignalingCommand.CLOSE:
            effect = _SignalingEffect(self.signaling, None)
            proposed = "closed"
        elif command.kind is _SignalingCommand.FAIL:
            effect = _SignalingEffect(self.signaling, None)
            proposed = "failed"
        else:
            desc_type, desc = command.payload
            if isinstance(desc, SessionDescription):
                desc = _CanonicalSDP.capture(desc)
            operation = (
                SignalingChangeOperation.SetLocal
                if command.kind is _SignalingCommand.SET_LOCAL
                else SignalingChangeOperation.SetRemote
            )
            target = (
                SignalingState.Stable
                if desc_type is SessionDescriptionType.Answer
                else SignalingState.HaveLocalOffer
                if command.kind is _SignalingCommand.SET_LOCAL
                else SignalingState.HaveRemoteOffer
            )
            next_state = ensure_next_signaling_state(
                self.signaling.state, target, operation, desc_type,
            )
            current = self.signaling
            generation = current.negotiation_generation + (
                1 if desc_type is SessionDescriptionType.Offer else 0
            )
            if command.kind is _SignalingCommand.SET_LOCAL:
                if desc_type is SessionDescriptionType.Offer:
                    updated = _SignalingSnapshot(
                        next_state, current.revision + 1, generation,
                        current.current_local, desc, current.current_remote,
                        current.pending_remote,
                    )
                elif desc_type is SessionDescriptionType.Answer:
                    updated = _SignalingSnapshot(
                        next_state, current.revision + 1, generation,
                        desc, None, current.pending_remote, None,
                    )
                else:
                    raise ValueError(f"unsupported local description type: {desc_type}")
            else:
                if desc_type is SessionDescriptionType.Offer:
                    updated = _SignalingSnapshot(
                        next_state, current.revision + 1, generation,
                        current.current_local, current.pending_local,
                        current.current_remote, desc,
                    )
                elif desc_type is SessionDescriptionType.Answer:
                    updated = _SignalingSnapshot(
                        next_state, current.revision + 1, generation,
                        current.pending_local, None, desc, None,
                    )
                else:
                    raise ValueError(f"unsupported remote description type: {desc_type}")
            media_section_count = len(desc.materialize().media_descriptions)
            effect = _SignalingEffect(updated, desc_type, media_section_count)
            proposed = next_state.value
        return PreparedTransition(
            self.snapshot().state, proposed, effect, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    def commit(self, proposed, cause=None):
        commit = super().commit(proposed, cause)
        if isinstance(proposed, PreparedTransition):
            effect = proposed.effects
            if isinstance(effect, _SignalingEffect):
                snapshot = effect.snapshot
                self.signaling = _SignalingSnapshot(
                    SignalingState.Closed
                    if commit.to_state == "closed"
                    else snapshot.state
                    if commit.to_state == "failed"
                    else SignalingState(commit.to_state),
                    commit.revision,
                    snapshot.negotiation_generation,
                    snapshot.current_local, snapshot.pending_local,
                    snapshot.current_remote, snapshot.pending_remote,
                )
        return commit

    async def after_commit(self, commit, effects):
        self.owner._after_signaling_commit(commit, effects)


class _MediaSendCommand(StrEnum):
    ACTIVATE = "activate"
    FAIL = "fail"
    DRAIN = "drain"
    CLOSE = "close"


class _MediaSendRunner(AsyncStateMachineRunner[MachineCommand[object, TransitionCommit]]):
    async def step(self, command):
        proposed = {
            _MediaSendCommand.ACTIVATE: "active",
            _MediaSendCommand.FAIL: "failed",
            _MediaSendCommand.DRAIN: "draining",
            _MediaSendCommand.CLOSE: "closed",
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported media-send command: {command.kind}")
        return PreparedTransition(
            self.snapshot().state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )


@dataclass(frozen=True, slots=True)
class _MediaSendRequest:
    submission_id: int
    packets: tuple[bytes, ...]
    rtcp: bool
    cause_id: str
    reply: ReplyPort[int]
    performance_recorder: object | None


@dataclass(frozen=True, slots=True)
class _MediaSendResult:
    submission_id: int
    value: int | None = None
    error: BaseException | None = None


async def dtls_ice_pair_queue_handshake_routine(
    pair_transport: ice.CandidatePairTransport, dtls_transport: dtls.DTLSTransport
):
    logger = get_logger()
    logger.debug(Component.DTLS, "DTLS ICE queue routine started")
    while True:
        try:
            pkt = await pair_transport.recv_dtls()
            logger.trace(Component.DTLS, "Received DTLS packet from ICE", size=len(pkt.data))
            await dtls_transport.enqueue_record(pkt.data)
        except Exception as e:
            logger.error(Component.DTLS, "DTLS ICE queue routine failed", error=str(e))
            raise


# TODO: Watch into ORTC API
class PeerConnection(ObservedComponent):
    def __init__(self, *, peer_id: str | None = None) -> None:
        self.__loop = asyncio.get_running_loop()
        self.id = peer_id or uuid.uuid4().hex
        self._observability_id = f"peer-{self.id[:12]}"
        self.gatherer = ICEGatherer(owner=self)
        self._ice_transport = ICETransport(self.gatherer)

        self.__certificate = webrtc_rs.Certificate()
        self._dtls_transport = dtls.DTLSTransport(
            self.__certificate, observability_id=self._observability_id,
        )
        self.__media_fingerprints = list[dtls.Fingerprint]()

        # self._certificates = [self.__certificate]
        # self.dtls_transports = list[dtls.DTLSTransport]()

        self._caps = MediaCaps()
        set_default_caps(self._caps)
        self.origin = Origin()

        self._greater_mid: int = 0
        # self._sdp_semantic: SDPSemantic = SDPSemantic.UnifiedPlan

        self._transceivers = list[RTPTransceiver]()
        self._transceiver_observability_sequence = 0

        self._cleanup_completed: set[str] = set()
        self.event_inbox = PeerEventInbox(maxsize=1024)
        self.log_drain = AsyncLogDrain()
        self.log_inbox: PeerConnectionLogInbox = self.log_drain.inbox
        self.signaling = SignalingController()
        self.media_sources = MediaSourceController()
        self._execution_scope = None
        self._transport: ice.CandidatePairTransport | None = None
        self._command_id = 0
        self._close_completion: ReplyPort[TransitionCommit] | None = None
        self._close_error: BaseException | None = None
        self._machine_handles: list[OwnedTaskHandle] = []
        self._runtime = None
        self.entity_id = self._observability_id
        self.signaling_entity_id = f"{self._observability_id}:signaling"
        self.media_send_entity_id = f"{self._observability_id}:media-send"
        common = {"controller": None, "transition_sink": self._project_transition}
        self._peer_runner = _PeerRunner(
            self, entity_id=self.entity_id, mailbox_capacity=16, **common,
        )
        self._signaling_runner = _SignalingRunner(
            self, entity_id=self.signaling_entity_id, mailbox_capacity=16, **common,
        )
        self._media_send_runner = _MediaSendRunner(
            MACHINE_SPECS["media-send"], entity_id=self.media_send_entity_id,
            mailbox_capacity=8, **common,
        )
        self._media_send_mailbox = BoundedMailbox[_MediaSendRequest](32)
        self._media_send_credits = asyncio.Queue[None](4)
        for _ in range(4):
            self._media_send_credits.put_nowait(None)
        self._media_send_submission_id = 0
        self._media_send_running = 0
        self._media_send_high_water = 0
        self._media_send_pump: OwnedTaskHandle[None] | None = None
        self._media_send_jobs: dict[int, OwnedTaskHandle[None]] = {}
        self._media_send_requests: dict[int, _MediaSendRequest] = {}
        self._media_send_results: dict[int, _MediaSendResult] = {}
        self._media_send_next_commit = 1
        self._media_send_failure: BaseException | None = None
        self._media_send_dispatch_stopped = False
        self._media_send_active: ReplyPort[TransitionCommit] | None = None

    @event_loop
    def _next_transceiver_observability_id(self) -> str:
        self._transceiver_observability_sequence += 1
        return (
            f"{self._observability_id}:transceiver-"
            f"{self._transceiver_observability_sequence}"
        )

    @property
    def closed(self) -> bool:
        return self._peer_runner.snapshot().state == "closed"

    @property
    def state(self) -> str:
        state = self._peer_runner.snapshot().state
        return "error" if state == "failed" else state

    @property
    def _closed(self) -> bool:
        return self.closed

    @property
    def _closing(self) -> bool:
        return self._peer_runner.snapshot().state in {"closing", "closed"}

    @property
    def _started(self) -> bool:
        return self._peer_runner.snapshot().state != "new"

    @property
    def _signaling_state(self) -> SignalingState:
        return self._signaling_runner.signaling.state

    @property
    def _current_local_description(self) -> SessionDescription | None:
        value = self._signaling_runner.signaling.current_local
        return value.materialize() if value is not None else None

    @property
    def _pending_local_description(self) -> SessionDescription | None:
        value = self._signaling_runner.signaling.pending_local
        return value.materialize() if value is not None else None

    @property
    def _current_remote_description(self) -> SessionDescription | None:
        value = self._signaling_runner.signaling.current_remote
        return value.materialize() if value is not None else None

    @property
    def _pending_remote_description(self) -> SessionDescription | None:
        value = self._signaling_runner.signaling.pending_remote
        return value.materialize() if value is not None else None

    @property
    def generation(self) -> int:
        return self._signaling_runner.signaling.negotiation_generation

    @event_loop
    def _ensure_machine_owners(self, scope) -> None:
        if self._machine_handles:
            return
        self._runtime = scope
        controller = getattr(scope, "transition_controller", None)
        for runner in (
            self._peer_runner, self._signaling_runner, self._media_send_runner,
        ):
            runner.controller = controller or runner.controller
            scope.projection.machines.register(runner.entity_id, runner.spec)
            scope.register_owner(runner.entity_id, epoch=runner.epoch)
            self._machine_handles.append(scope.start_machine(
                runner, owner_entity_id=runner.entity_id,
                owner_epoch=runner.epoch,
            ))
        self._media_send_pump = scope.start_pump(
            self._run_media_send_pump,
            owner_entity_id=self.media_send_entity_id,
            owner_epoch=self._media_send_runner.epoch,
            name=f"media-send:pump:{self.media_send_entity_id}",
            kind="media",
            failure=FailurePolicy.FAIL_CONNECTION,
            metadata={
                "observerMeta": "aggregate",
                "mailbox_capacity": self._media_send_mailbox.capacity,
                "max_concurrency": self._media_send_credits.maxsize,
            },
        )
        self._media_send_active = ReplyPort[TransitionCommit]()
        self._media_send_runner.try_submit(self._command(
            self._media_send_runner, _MediaSendCommand.ACTIVATE,
            cause_id=f"{self.media_send_entity_id}:activate",
            reply=self._media_send_active,
        ))

    @event_loop
    def _require_runtime_bound_children(self, scope) -> None:
        # Test/application peers may replace the complete ICE facade with an
        # injected implementation that does not use these concrete children.
        if not isinstance(self.gatherer, ICEGatherer):
            return
        unbound = [
            name
            for name, component in (
                ("ICE gatherer", self.gatherer),
                ("selected ICE transport", self._ice_transport),
                ("DTLS transport", self._dtls_transport),
            )
            if hasattr(component, "_runtime")
            and getattr(component, "_runtime") is not scope
        ]
        if unbound:
            raise RuntimeError(
                "PeerConnection must be constructed inside its active Runtime; "
                f"unbound components: {', '.join(unbound)}"
            )

    @event_loop
    def _command(self, runner, kind, payload=None, *, cause_id=None, reply=None):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, runner.epoch, payload, reply,
            expected_revision=runner.revision,
            cause_id=cause_id or f"{runner.entity_id}:{self._command_id}",
        )

    @event_loop
    def _project_transition(self, commit: TransitionCommit) -> None:
        runtime = self._runtime
        if runtime is None or not getattr(runtime, "tracing_enabled", True):
            return
        runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state, commit.to_state,
            commit.epoch, commit.revision, runtime.new_producer_dot(),
            commit.cause, commit.monotonic_ns,
        ))
        if commit.machine_type == "media-send":
            runtime.projection.merge_values(
                commit.entity_id, runtime.new_producer_dot(), {
                    "queued": self._media_send_mailbox.depth,
                    "running": self._media_send_running,
                    "high_water": self._media_send_high_water,
                },
                observer_meta="aggregate", source_entity_id=commit.entity_id,
                source_epoch=commit.epoch, source_revision=commit.revision,
                source_order=runtime.projection.new_facet_source_order(),
            )

    @event_loop
    def _publish_peer(
        self, commit: TransitionCommit, readiness: _PeerReadiness | None = None,
    ) -> None:
        runtime = self._runtime
        if runtime is not None and getattr(runtime, "tracing_enabled", True):
            values = {
                "negotiation_generation": self.generation,
            }
            if commit.to_state == "connected":
                if readiness is None:
                    raise RuntimeError("connected commit omitted its readiness effect")
                values.update({
                    "selected_transport_revision": readiness.selected_transport.revision,
                    "dtls_revision": readiness.dtls.revision,
                    "srtp_rtp_revision": readiness.srtp_rtp.revision,
                    "srtp_rtcp_revision": readiness.srtp_rtcp.revision,
                })
            runtime.projection.merge_values(
                self.entity_id, runtime.new_producer_dot(), values,
                observer_meta="exact", source_entity_id=commit.entity_id,
                source_epoch=commit.epoch, source_revision=commit.revision,
                source_order=runtime.projection.new_facet_source_order(),
            )

    @event_loop
    def _after_signaling_commit(
        self, commit: TransitionCommit, effect: _SignalingEffect,
    ) -> None:
        runtime = self._runtime
        snapshot = effect.snapshot
        if runtime is not None and getattr(runtime, "tracing_enabled", True):
            values = {
                "description_type": (
                    effect.description_type.value
                    if effect.description_type is not None else None
                ),
                "negotiation_generation": snapshot.negotiation_generation,
                "media_section_count": effect.media_section_count,
                "outcome": "failed" if commit.to_state == "failed" else "committed",
            }
            runtime.projection.merge_values(
                self.signaling_entity_id, runtime.new_producer_dot(), values,
                observer_meta="exact", source_entity_id=commit.entity_id,
                source_epoch=commit.epoch, source_revision=commit.revision,
                source_order=runtime.projection.new_facet_source_order(),
            )

    async def _after_peer_commit(
        self, commit: TransitionCommit, payload: _PeerCommandPayload,
    ) -> None:
        self._publish_peer(commit, payload.readiness)
        if commit.to_state == "starting":
            await self.gatherer.start()
            self._peer_runner.try_submit(self._command(
                self._peer_runner, _PeerCommand.NEGOTIATING, payload,
                cause_id=commit.cause,
            ))
        elif payload.role == "dial":
            await self.gatherer.dial()
            if payload.completion is not None:
                payload.completion.resolve(commit)
        elif payload.role == "accept":
            await self.gatherer.accept()
            if payload.completion is not None:
                payload.completion.resolve(commit)
        elif commit.to_state == "negotiating":
            if payload.completion is not None:
                payload.completion.resolve(commit)
        elif commit.to_state == "failed":
            if payload.error is not None:
                component = payload.reason or "protocol"
                self._offer_event(PeerConnectionTaskFailed(
                    component, f"{component}:failure", payload.error, self.generation,
                ))
            terminal = self._terminal_completion()
            failed_payload = _PeerCommandPayload(
                terminal, payload.reason, payload.error, payload.readiness,
                payload.role,
            )
            self._peer_runner.try_submit(self._command(
                self._peer_runner, _PeerCommand.CLOSE, failed_payload,
                cause_id=commit.cause,
            ))
        elif commit.to_state == "closing":
            self._peer_runner.try_submit(self._command(
                self._peer_runner, _PeerCommand.FINISH_CLOSE, payload,
                cause_id=commit.cause, reply=payload.completion,
            ))
        elif commit.to_state == "closed":
            if self.event_inbox._runner is not None:
                self._offer_event({
                    "type": "closed", "reason": payload.reason or "closed",
                    "generation": self.generation, "error": payload.error,
                })
                self.event_inbox.close()
            if payload.completion is not None:
                if self._close_error is not None:
                    payload.completion.reject(self._close_error)
                else:
                    payload.completion.resolve(commit)
            scope = self._execution_scope
            if scope is not None:
                try:
                    scope.task_scheduler.failure_observers.remove(
                        self.observe_task_failure
                    )
                except ValueError:
                    pass

    @event_loop
    def _peer_readiness_snapshot(self) -> _PeerReadiness:
        selected = self._ice_transport._runner.snapshot()
        dtls_snapshot = self._dtls_transport._runner.snapshot()
        rtp = self._dtls_transport._srtp_rtp
        rtcp = self._dtls_transport._srtp_rtcp
        if rtp is None or rtcp is None:
            raise RuntimeError("peer readiness requires both SRTP sessions")
        rtp_snapshot = rtp.lifecycle_snapshot()
        rtcp_snapshot = rtcp.lifecycle_snapshot()
        return _PeerReadiness(
            _ChildReadiness(selected.entity_id, selected.epoch, selected.revision, "ready"),
            _ChildReadiness(
                dtls_snapshot.entity_id, dtls_snapshot.epoch,
                dtls_snapshot.revision, "connected",
            ),
            _ChildReadiness(
                rtp_snapshot.entity_id, rtp_snapshot.epoch,
                rtp_snapshot.revision, "ready",
            ),
            _ChildReadiness(
                rtcp_snapshot.entity_id, rtcp_snapshot.epoch,
                rtcp_snapshot.revision, "ready",
            ),
        )

    @event_loop
    def _validate_peer_readiness(self, readiness: _PeerReadiness | None) -> None:
        if readiness is None or readiness != self._peer_readiness_snapshot():
            raise StaleMachineAccess("peer child readiness revisions are stale")

    @event_loop
    def _assert_peer_reconciled(self) -> None:
        if not self._cleanup_completed.issuperset({
            "signaling", "media-sources", "dtls", "selected-transport",
            "gatherer", "media-send", "transceivers", "log-drain",
        }):
            raise RuntimeError("peer terminal commit preceded child reconciliation")

    async def __aenter__(self) -> "PeerConnection":
        if self._closed or self._closing:
            raise RuntimeError("peer connection is closing")
        scope = current_execution_scope()
        if scope is None or scope.state is not ScopeState.ACTIVE:
            raise RuntimeError("PeerConnection requires an active Runtime")
        self._require_runtime_bound_children(scope)
        self._execution_scope = scope
        self._ensure_machine_owners(scope)
        self.signaling.bind(scope, f"{self.entity_id}:attachment-registry:signaling")
        self.media_sources.bind(scope, f"{self.entity_id}:attachment-registry:media")
        self.log_drain.bind(scope, f"{self.entity_id}:log-drain")
        self.event_inbox.bind(scope, f"{self.entity_id}:event-inbox")
        if self.observe_task_failure not in scope.task_scheduler.failure_observers:
            scope.task_scheduler.failure_observers.append(self.observe_task_failure)
        await self.start()
        self.signaling.start()
        self.media_sources.start()
        self.log_drain.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose("error" if exc is not None else "closed", error=exc)

    @event_loop
    def _offer_event(self, event: object) -> None:
        try:
            self.event_inbox.offer_nowait(event)
        except asyncio.QueueFull:
            pass

    def __aiter__(self):
        return self.event_inbox.__aiter__()

    async def wait_closed(self) -> None:
        await wait_until(lambda: self.closed, timeout=30.0)
        await self._join_peer_runner()

    @event_loop
    def attach_signaling(self, signaling: object) -> object:
        attached = self.signaling.attach(signaling)
        if self._started and not self._closing:
            self.signaling.start()
        return attached

    @event_loop
    def attach_media_source(self, source: object, *, kind: str | None = None) -> object:
        attached = self.media_sources.attach(source)
        if self._started and not self._closing:
            self.media_sources.start()
        return attached

    async def dial(self) -> None:
        if self._closing or self._closed:
            raise RuntimeError("peer connection is closing")
        if self._peer_runner.role == "dial":
            return
        if self._peer_runner.role is not None:
            raise StaleMachineAccess(
                f"peer role is already {self._peer_runner.role}; cannot dial"
            )
        completion = ReplyPort[TransitionCommit]()
        await self._peer_runner.submit(self._command(
            self._peer_runner, _PeerCommand.DIAL,
            _PeerCommandPayload(completion=completion, role="dial"),
            reply=completion,
        ))
        await completion.wait()

    async def accept(self) -> None:
        if self._closing or self._closed:
            raise RuntimeError("peer connection is closing")
        if self._peer_runner.role == "accept":
            return
        if self._peer_runner.role is not None:
            raise StaleMachineAccess(
                f"peer role is already {self._peer_runner.role}; cannot accept"
            )
        completion = ReplyPort[TransitionCommit]()
        await self._peer_runner.submit(self._command(
            self._peer_runner, _PeerCommand.ACCEPT,
            _PeerCommandPayload(completion=completion, role="accept"),
            reply=completion,
        ))
        await completion.wait()

    @event_loop
    def observe_task_failure(self, event: TaskFailureEvent) -> None:
        if event.spec.failure is not FailurePolicy.FAIL_CONNECTION:
            return
        if self._closing or self._closed:
            return
        component = str(event.spec.metadata.get("component", event.spec.kind))
        payload = _PeerCommandPayload(
            completion=self._terminal_completion(),
            reason=component, error=event.exception,
        )
        try:
            self._peer_runner.try_submit(self._command(
                self._peer_runner, _PeerCommand.FAIL, payload,
                cause_id=f"task-failure:{event.spec.name}",
            ))
        except (RuntimeError, asyncio.QueueFull):
            return

    async def aclose(
        self, reason: str = "closed", error: BaseException | None = None
    ) -> None:
        if not self._machine_handles:
            scope = current_execution_scope()
            if scope is None or scope.state is not ScopeState.ACTIVE:
                raise RuntimeError("PeerConnection close requires an active Runtime")
            self._execution_scope = scope
            self._ensure_machine_owners(scope)
        completion = self._terminal_completion()
        if not self.closed and self._peer_runner.snapshot().state not in {"closing"}:
            payload = _PeerCommandPayload(completion, reason, error)
            kind = (
                _PeerCommand.FAIL if error is not None else _PeerCommand.CLOSE
            )
            try:
                await self._peer_runner.submit(self._command(
                    self._peer_runner, kind, payload,
                    cause_id=f"peer-close:{reason}",
                ))
            except (StaleMachineAccess, RuntimeError):
                # Another close/failure intent owns the retained terminal reply.
                pass
        try:
            await completion.wait()
        finally:
            await self._join_peer_runner()

    @event_loop
    def _terminal_completion(self) -> ReplyPort[TransitionCommit]:
        if self._close_completion is None:
            self._close_completion = ReplyPort[TransitionCommit]()
        return self._close_completion

    async def _join_peer_runner(self) -> None:
        if not self.closed or not self._machine_handles:
            return
        handle = self._machine_handles[0]
        if not handle.done():
            await handle.wait()
        runtime = self._runtime
        if runtime is not None:
            try:
                runtime.remove_owner(self._peer_runner.entity_id, self._peer_runner.epoch)
            except (KeyError, StaleOwnerEpoch):
                pass

    async def _reconcile_peer_terminal(self, payload: _PeerCommandPayload) -> None:
        cleanup_errors: list[BaseException] = []

        async def attempt(key: str, operation) -> None:
            if key in self._cleanup_completed:
                return
            try:
                await operation()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            finally:
                # Reconciliation records a completed close attempt. Cleanup
                # failures are terminal evidence, not permission to strand the
                # peer in closing and retry side effects under a second reply.
                self._cleanup_completed.add(key)

        async def attempt_if_bound(key: str, component: object) -> None:
            if getattr(component, "_runner", None) is None:
                self._cleanup_completed.add(key)
                return
            await attempt(key, component.aclose)

        await attempt_if_bound("signaling-attachment", self.signaling)
        await attempt_if_bound("media-sources", self.media_sources)
        if not self._signaling_runner.snapshot().terminal:
            reply = ReplyPort[TransitionCommit]()
            await self._signaling_runner.submit(self._command(
                self._signaling_runner, _SignalingCommand.CLOSE,
                reply=reply, cause_id=f"{self.signaling_entity_id}:peer-close",
            ))
            await reply.wait()
        self._cleanup_completed.add("signaling")

        async def close_media_send() -> None:
            rejected = self._media_send_mailbox.close()
            closing_error = self._media_send_failure or RuntimeError(
                "peer media-send lane is closing"
            )
            for request in rejected:
                self._media_send_results[request.submission_id] = _MediaSendResult(
                    request.submission_id, error=closing_error,
                )
            self._commit_media_send_results()
            if self._media_send_pump is not None and not self._media_send_pump.done():
                await self._media_send_pump.wait()
            jobs = tuple(
                handle for handle in self._media_send_jobs.values() if not handle.done()
            )
            if jobs:
                await asyncio.gather(
                    *(handle.wait() for handle in jobs), return_exceptions=True,
                )
            state = self._media_send_runner.snapshot().state
            if state in {"active", "failed"}:
                reply = ReplyPort[TransitionCommit]()
                await self._media_send_runner.submit(self._command(
                    self._media_send_runner, _MediaSendCommand.DRAIN,
                    cause_id=f"{self.media_send_entity_id}:peer-close", reply=reply,
                ))
                await reply.wait()
            if self._media_send_runner.snapshot().state == "draining":
                reply = ReplyPort[TransitionCommit]()
                await self._media_send_runner.submit(self._command(
                    self._media_send_runner, _MediaSendCommand.CLOSE,
                    cause_id=f"{self.media_send_entity_id}:peer-close", reply=reply,
                ))
                await reply.wait()

        await attempt("media-send", close_media_send)

        # Stage 5 will move these stop operations behind transceiver machines.
        for transceiver in reversed(self._transceivers):
            receiver = transceiver.receiver
            if receiver is not None:
                async def stop_receiver(receiver=receiver) -> None:
                    await receiver.stop()
                await attempt(f"receiver:{id(receiver)}", stop_receiver)
            async def stop_transceiver(transceiver=transceiver) -> None:
                await transceiver.aclose()
            await attempt(f"transceiver:{id(transceiver)}", stop_transceiver)
        self._cleanup_completed.add("transceivers")

        controller_closer = getattr(self.gatherer, "aclose_controllers", None)
        if controller_closer is not None:
            await attempt("ice-controllers", controller_closer)
        await attempt("dtls", lambda: self._close_resource(self._dtls_transport))
        await attempt("selected-transport", self._ice_transport.aclose)
        await attempt("gatherer", lambda: self._close_resource(self.gatherer))
        await attempt_if_bound("log-drain", self.log_drain)
        if len(self._machine_handles) > 1:
            for runner, handle in zip(
                (self._signaling_runner, self._media_send_runner),
                self._machine_handles[1:3],
            ):
                if not handle.done():
                    await handle.wait()
                if self._runtime is not None:
                    self._runtime.remove_owner(runner.entity_id, runner.epoch)
        if cleanup_errors:
            errors = ([payload.error] if payload.error is not None else []) + cleanup_errors
            self._close_error = BaseExceptionGroup(
                "peer connection body and cleanup failures", errors,
            )

    @staticmethod
    async def _close_resource(resource: object) -> None:
        async_closer = getattr(resource, "aclose", None)
        if async_closer is not None:
            await async_closer()
            return
        closer = getattr(resource, "close", None) or getattr(resource, "stop", None)
        if closer is not None:
            closer()

    async def _wait_for_media_send_ready(self) -> None:
        """Wait until the selected ICE transport and both SRTP sessions exist."""
        # Lifecycle waits are deliberately bounded so a failed negotiation cannot
        # leave a public send call (and its send lock) blocked forever.
        await wait_until(
            lambda: self._ice_transport.selected_snapshot()[1] is not None,
            timeout=30.0,
        )
        # DTLSTransport owns the SRTP readiness state.  Its write methods also
        # wait on the individual RTP/RTCP session, while this wait makes the
        # public PeerConnection contract explicit before a send begins.
        await self._dtls_transport.wait(TransportCondition.SRTP_READY, timeout=30.0)

    @event_loop
    def _publish_media_send_load(self) -> None:
        runtime = self._runtime
        if runtime is None or not getattr(runtime, "tracing_enabled", True):
            return
        snapshot = self._media_send_runner.snapshot()
        runtime.projection.merge_values(
            self.media_send_entity_id, runtime.new_producer_dot(), {
                "queued": self._media_send_mailbox.depth,
                "running": self._media_send_running,
                "high_water": self._media_send_high_water,
            },
            observer_meta="aggregate", source_entity_id=snapshot.entity_id,
            source_epoch=snapshot.epoch, source_revision=snapshot.revision,
            source_order=runtime.projection.new_facet_source_order(),
        )

    async def _run_media_send_pump(self) -> None:
        """Dispatch bounded public sends without serializing independent callers."""
        while True:
            try:
                request = await self._media_send_mailbox.receive()
            except MailboxClosed:
                return
            await self._media_send_credits.get()
            if self._media_send_dispatch_stopped:
                error = self._media_send_failure or RuntimeError(
                    "media-send dispatch is stopped"
                )
                self._media_send_results[request.submission_id] = _MediaSendResult(
                    request.submission_id, error=error,
                )
                self._media_send_credits.put_nowait(None)
                self._commit_media_send_results()
                continue
            self._media_send_running += 1
            self._publish_media_send_load()
            scope = self._runtime
            if scope is None:
                self._media_send_results[request.submission_id] = _MediaSendResult(
                    request.submission_id,
                    error=RuntimeError("media-send lane has no Runtime owner"),
                )
                self._commit_media_send_results()
                self._media_send_running -= 1
                self._media_send_credits.put_nowait(None)
                continue
            handle = scope.start_pump(
                lambda request=request: self._execute_media_send(request),
                owner_entity_id=self.media_send_entity_id,
                owner_epoch=self._media_send_runner.epoch,
                name=f"media-send:{request.submission_id}",
                kind="media",
                failure=FailurePolicy.REPORT,
                metadata={
                    "observerMeta": "aggregate",
                    "submission_id": request.submission_id,
                    "packet_count": len(request.packets),
                },
            )
            self._media_send_jobs[request.submission_id] = handle

    async def _execute_media_send(self, request: _MediaSendRequest) -> None:
        try:
            with use_performance_recorder(request.performance_recorder):
                total = 0
                for index, packet in enumerate(request.packets):
                    total += await self._send_media_packet(
                        packet, rtcp=request.rtcp, wait_ready=index == 0,
                    )
        except BaseException as error:
            causal = self._media_send_failure or error
            if self._media_send_failure is None:
                self._media_send_failure = error
                self._media_send_dispatch_stopped = True
                rejected = self._media_send_mailbox.close()
                for queued in rejected:
                    self._media_send_results[queued.submission_id] = _MediaSendResult(
                        queued.submission_id, error=error,
                    )
                for submission_id, handle in tuple(self._media_send_jobs.items()):
                    if submission_id != request.submission_id and not handle.done():
                        handle.cancel()
            if self._media_send_runner.snapshot().state == "active":
                try:
                    self._media_send_runner.try_submit(self._command(
                        self._media_send_runner, _MediaSendCommand.FAIL,
                        payload=error, cause_id=request.cause_id,
                    ))
                except RuntimeError:
                    # A concurrent peer close already owns terminal reconciliation.
                    pass
            self._media_send_results[request.submission_id] = _MediaSendResult(
                request.submission_id, error=causal,
            )
        else:
            self._media_send_results[request.submission_id] = _MediaSendResult(
                request.submission_id, value=total,
            )
        finally:
            self._media_send_running -= 1
            self._media_send_credits.put_nowait(None)
            self._media_send_jobs.pop(request.submission_id, None)
            self._commit_media_send_results()
            self._publish_media_send_load()

    @event_loop
    def _commit_media_send_results(self) -> None:
        """Resolve tagged results strictly in admission order on the owner loop."""
        while result := self._media_send_results.pop(
            self._media_send_next_commit, None
        ):
            request = self._media_send_requests.pop(result.submission_id, None)
            if request is not None:
                if result.error is not None:
                    request.reply.reject(result.error)
                else:
                    request.reply.resolve(result.value or 0)
            self._media_send_next_commit += 1

    async def _submit_media_send(
        self, packets: tuple[bytes, ...], *, rtcp: bool,
    ) -> int:
        if not self._machine_handles:
            raise RuntimeError("media send requires an active PeerConnection")
        if self._media_send_active is not None:
            await self._media_send_active.wait()
        if self._media_send_runner.snapshot().state != "active":
            raise RuntimeError("media-send lane is not active")
        self._media_send_submission_id += 1
        reply = ReplyPort[int]()
        request = _MediaSendRequest(
            self._media_send_submission_id, packets, rtcp,
            f"{self.media_send_entity_id}:{self._media_send_submission_id}", reply,
            get_current_performance_recorder(),
        )
        self._media_send_requests[request.submission_id] = request
        await self._media_send_mailbox.submit(request)
        self._media_send_high_water = max(
            self._media_send_high_water, self._media_send_mailbox.depth,
        )
        self._publish_media_send_load()
        return await reply.wait()

    @staticmethod
    @event_loop
    def _media_packet_bytes(packet: bytes | bytearray) -> bytes:
        if not isinstance(packet, (bytes, bytearray)):
            raise TypeError("media packet must be bytes or bytearray")
        # Public helpers must not retain caller-owned mutable packet buffers.
        return bytes(packet)

    async def _send_media_packet(
        self, packet: bytes, *, rtcp: bool, wait_ready: bool = True
    ) -> int:
        component = "rtcp" if rtcp else "rtp"
        phase = "packet.send" if not rtcp else "feedback.send"
        metadata: dict[str, object] = {
            "flow_direction": "tx",
            "packet_kind": "rtcp" if rtcp else "rtp",
            "plaintext_size_bytes": len(packet),
        }
        if self._transport is not None:
            metadata["pair_id"] = self._transport.entity_id
        if rtcp:
            metadata["packet_count"] = 1
            if len(packet) >= 2:
                metadata["feedback_type"] = f"{packet[0] & 0x1f}/{packet[1]}"
            completed_metadata = {"counter.rtcp.feedback_sent": 1}
            failed_metadata = {"counter.rtcp.feedback_send_failed": 1}
        else:
            if len(packet) >= 12:
                metadata["sequence_number"] = int.from_bytes(packet[2:4], "big")
                metadata["ssrc"] = int.from_bytes(packet[8:12], "big")
            completed_metadata = {"counter.rtp.packets_sent": 1}
            failed_metadata = {"counter.rtp.packets_send_failed": 1}
        async with measure_perf_async(
            component,
            phase,
            metadata=metadata,
            completed_metadata=completed_metadata,
            failed_metadata=failed_metadata,
        ):
            if wait_ready:
                await self._wait_for_media_send_ready()
            sent = (
                await self._dtls_transport.write_rtcp_bytes(packet)
                if rtcp
                else await self._dtls_transport.write_rtp_bytes(packet)
            )
            if sent <= 0:
                raise RuntimeError(f"failed to send {'RTCP' if rtcp else 'RTP'} packet")
            return sent

    async def send_rtp_packet(self, packet: bytes | bytearray) -> int:
        """Encrypt and send one serialized RTP packet through the selected peer transport."""
        packet_bytes = self._media_packet_bytes(packet)
        return await self._submit_media_send((packet_bytes,), rtcp=False)

    async def send_rtp_packets(self, packets: Iterable[bytes | bytearray]) -> int:
        """Encrypt and send an ordered RTP burst without spawning per-packet tasks."""
        packet_batch = tuple(self._media_packet_bytes(packet) for packet in packets)
        if not packet_batch:
            return 0

        return await self._submit_media_send(packet_batch, rtcp=False)

    async def send_rtcp_packet(self, packet: bytes | bytearray) -> int:
        """Encrypt and send one serialized RTCP packet through the selected peer transport."""
        packet_bytes = self._media_packet_bytes(packet)
        return await self._submit_media_send((packet_bytes,), rtcp=True)

    async def recv_rtcp_feedback(self, ssrc: int) -> list[RtcpPacket]:
        """Read and accept one SRTP-delivered RTCP feedback packet by SSRC.

        The DTLS/SRTP transport owns secure delivery; this public peer boundary
        owns parsing the feedback that is visible to the sending application.
        """
        stream = await self._dtls_transport.srtp_rtcp_stream(ssrc)
        packet = await stream.read()
        metadata: dict[str, object] = {
            "flow_direction": "rx",
            "packet_kind": "rtcp",
            "plaintext_size_bytes": len(packet),
            "packet_count": 1,
        }
        try:
            feedback = RtcpPacket.parse(packet)
            if len(feedback) != 1:
                raise ValueError("expected exactly one RTCP feedback packet")
            parsed = feedback[0]
            metadata["feedback_type"] = "twcc" if isinstance(parsed, TransportLayerCC) else type(parsed).__name__
        except BaseException as exc:
            perf_mark(
                "rtcp", "feedback.receive", "failed",
                metadata={
                    **metadata,
                    "error_stage": "rtcp_feedback_parse",
                    "exception_class": exc.__class__.__name__,
                    "counter.rtcp.feedback_receive_failed": 1,
                },
            )
            raise

        perf_mark(
            "rtcp", "feedback.receive", "completed",
            metadata={**metadata, "counter.rtcp.feedback_received": 1},
        )
        if isinstance(parsed, TransportLayerCC):
            perf_mark(
                "rtcp", "twcc", "confirmed",
                metadata={
                    "flow_direction": "rx",
                    "feedback_type": "twcc",
                    "base_sequence_number": parsed.base_sequence_number,
                    "confirmed_packet_count": parsed.packet_status_count,
                    "packet_count": 1,
                    "counter.rtcp.confirmed_packets": parsed.packet_status_count,
                },
            )
        return feedback

    @event_loop
    def build_twcc_feedback(self, media_ssrc: int, transport_sequences: Iterable[int]) -> bytes:
        """Build receiver-owned TWCC feedback for received transport sequences."""
        sequences = tuple(transport_sequences)
        if not sequences:
            raise ValueError("TWCC feedback requires at least one transport sequence")
        if any(not 0 <= sequence <= 0xFFFF for sequence in sequences):
            raise ValueError("TWCC transport sequences must be unsigned 16-bit values")
        if any(sequence != ((sequences[0] + index) & 0xFFFF) for index, sequence in enumerate(sequences)):
            raise ValueError("TWCC feedback currently requires contiguous transport sequences")

        feedback = TransportLayerCC(
            sender_ssrc=media_ssrc,
            media_ssrc=media_ssrc,
            base_sequence_number=sequences[0],
            packet_status_count=len(sequences),
            reference_time=12345,
            fb_pkt_count=1,
            packet_chunks=[RunLengthChunk(TypeTCCPacketReceivedSmallDelta, len(sequences))],
            recv_deltas=[
                RecvDelta(delta=250 * (index + 1), delta_type=TypeTCCPacketReceivedSmallDelta)
                for index in range(len(sequences))
            ],
        ).marshal()
        perf_mark(
            "rtcp",
            "twcc",
            "generated",
            metadata={
                "flow_direction": "tx",
                "packet_kind": "rtcp",
                "feedback_type": "twcc",
                "base_sequence_number": sequences[0],
                "packet_count": 1,
                "confirmed_packet_count": len(sequences),
                "counter.rtcp.feedback_generated": 1,
            },
        )
        return feedback

    async def _ice_controller_created(self, pair_ctrl: ice.CandidatePairController):
        await pair_ctrl.start_managed()

    async def _ice_nominated(
        self, transport: ice.CandidatePairTransport, commit: TransitionCommit,
    ) -> None:
        # The ICE connected commit is the only cause allowed to select a
        # transport. Duplicate/lower-priority nominations never reach here.
        if self._transport is not None:
            return
        if commit.machine_type != "candidate-pair" or commit.to_state != "nominated":
            raise RuntimeError("selected transport requires the exact pair nomination")
        if not hasattr(self, "_ice_transport"):
            self._ice_transport = ICETransport(self.gatherer)
        await self._ice_transport.bind(transport, commit)
        selected_revision, selected_transport = self._ice_transport.selected_snapshot()
        if selected_transport is not transport or selected_revision < 1:
            raise RuntimeError("selected transport did not commit the nominated pair")
        dtls_role = self.__get_dtls_role()
        self._transport = selected_transport
        connecting = ReplyPort[TransitionCommit]()
        await self._peer_runner.submit(self._command(
            self._peer_runner, _PeerCommand.TRANSPORT_SELECTED,
            _PeerCommandPayload(), cause_id=commit.cause, reply=connecting,
        ))
        await connecting.wait()
        perf_mark("ice", "transport", "nominated")
        await self._dtls_transport.start(dtls_role, transport)
        readiness = self._peer_readiness_snapshot()
        dtls_snapshot = self._dtls_transport._runner.snapshot()
        connected = ReplyPort[TransitionCommit]()
        await self._peer_runner.submit(self._command(
            self._peer_runner, _PeerCommand.CHILDREN_READY,
            _PeerCommandPayload(readiness=readiness),
            cause_id=f"{dtls_snapshot.entity_id}:{dtls_snapshot.revision}",
            reply=connected,
        ))
        await connected.wait()

    async def _ice_failed(
        self, error: BaseException, commit: TransitionCommit,
    ) -> None:
        if commit.machine_type != "ice-agent" or commit.to_state != "failed":
            raise RuntimeError("peer ICE failure requires the public ICE failed commit")
        self._offer_event(PeerConnectionTaskFailed(
            "ice", "ice:public-failure", error, self.generation,
        ))
        self._peer_runner.try_submit(self._command(
            self._peer_runner, _PeerCommand.FAIL,
            _PeerCommandPayload(reason="ice", error=error),
            cause_id=commit.cause,
        ))

    async def start(self):
        if self._closing or self._closed:
            raise RuntimeError("peer connection is closing")
        if self._started:
            return
        if not self._machine_handles:
            scope = current_execution_scope()
            if scope is None or scope.state is not ScopeState.ACTIVE:
                raise RuntimeError("PeerConnection start requires an active Runtime")
            self._require_runtime_bound_children(scope)
            self._execution_scope = scope
            self._ensure_machine_owners(scope)
        completion = ReplyPort[TransitionCommit]()
        await self._peer_runner.submit(self._command(
            self._peer_runner, _PeerCommand.START,
            _PeerCommandPayload(completion=completion), reply=None,
        ))
        await completion.wait()

    @task(
        name="dtls:ice-pair-queue-handshake",
        kind="dtls",
        metadata={"expected_long_running": True, "loop_role": "receive"},
        failure=FailurePolicy.FAIL_CONNECTION,
    )
    async def _dtls_ice_pair_queue_handshake(
        self, transport: ice.CandidatePairTransport
    ) -> None:
        await dtls_ice_pair_queue_handshake_routine(transport, self._dtls_transport)

    async def wait(self, condition: PeerCondition, timeout: float) -> None:
        timeout = require_timeout(timeout)
        match condition:
            case PeerCondition.ICE_GATHERING_COMPLETE:
                await self.gatherer.wait(ICECondition.GATHERING_COMPLETE, timeout)
            case PeerCondition.ICE_CANDIDATE_PAIR_SUCCEEDED:
                await self.gatherer.wait(
                    ICECondition.CANDIDATE_PAIR_SUCCEEDED,
                    timeout,
                )
            case PeerCondition.ICE_NOMINATED:
                await self.gatherer.wait(ICECondition.NOMINATED, timeout)
            case PeerCondition.NOMINATED_TRANSPORT_READY:
                await wait_until(
                    lambda: self._ice_transport.selected_snapshot()[1] is not None,
                    timeout=timeout,
                )
            case PeerCondition.DTLS_HANDSHAKE_COMPLETE:
                await self._dtls_transport.wait(
                    TransportCondition.HANDSHAKE_COMPLETE,
                    timeout,
                )
            case PeerCondition.SRTP_READY:
                await self._dtls_transport.wait(TransportCondition.SRTP_READY, timeout)
            case _:
                raise ValueError(f"unsupported peer condition: {condition}")

    async def wait_nominated_transport(self, timeout: float) -> ice.CandidatePairTransport:
        await self.wait(PeerCondition.NOMINATED_TRANSPORT_READY, timeout)
        if self._transport is None:
            raise RuntimeError("nominated transport is not available")
        return self._transport

    async def wait_transport_ready(self, timeout: float) -> ice.CandidatePairTransport:
        return await self.wait_nominated_transport(timeout)

    async def wait_dtls_handshake(self, timeout: float) -> None:
        await self.wait(PeerCondition.DTLS_HANDSHAKE_COMPLETE, timeout)

    async def wait_srtp_ready(self, timeout: float) -> None:
        await self.wait(PeerCondition.SRTP_READY, timeout)

    async def add_transceiver_from_track(
        self, track: TrackLocal, direction: RTPTransceiverDirection
    ) -> RTPTransceiver:
        # TODO: this may contain directly transport creation
        # gathering process may take that list/set of transports
        # transport = ICETransport(self.__gatherer)
        # dtls_transport = dtls.DTLSTransport(transport, self.__certificate)
        # self.__dtls_transports.append(dtls_transport)

        receiver: RTPReceiver | None = None
        sender: RTPSender | None = None

        codec = track._rtp_codec_params
        kind = track.kind

        match direction:
            case RTPTransceiverDirection.Sendonly:
                sender = RTPSender(self._caps)
            case RTPTransceiverDirection.Sendrecv:
                sender = RTPSender(self._caps)
                receiver = RTPReceiver(self._caps, kind)
                receiver.receive(
                    RTPDecodingParameters(
                        rid=random_string(12),
                        ssrc=secrets.randbits(32),
                        payload_type=codec.payload_type,
                        rtx=RTPRtxParameters(ssrc=secrets.randbits(32)),
                    )
                )

            case RTPTransceiverDirection.Recvonly:
                receiver = RTPReceiver(self._caps, kind)
                receiver.receive(
                    RTPDecodingParameters(
                        rid=random_string(12),
                        ssrc=secrets.randbits(32),
                        payload_type=codec.payload_type,
                        rtx=RTPRtxParameters(ssrc=secrets.randbits(32)),
                    )
                )

        transceiver = RTPTransceiver(
            self._dtls_transport, caps=self._caps, kind=kind, direction=direction,
            observability_id=self._next_transceiver_observability_id(),
        )
        await transceiver.wait_active()
        await transceiver.set_prefered_codec(codec)

        if sender:
            await sender.add_encoding(track)
            await transceiver.set_sender(sender)

            encoding = sender._track_encodings[0]
            get_logger().debug(
                Component.PEER_CONNECTION,
                "Configured local sender stream",
                ssrc=encoding.ssrc,
                stream_id=track.stream_id,
            )
        if receiver:
            if not receiver._track:
                raise ValueError("Receiver stream must bedefined")

            # NOTE: It may have different SSRC after negotiation
            get_logger().debug(
                Component.PEER_CONNECTION,
                "Configured remote receiver stream",
                ssrc=receiver._track.ssrc,
                stream_id=track.stream_id,
            )

            await transceiver.set_receiver(receiver)

        self._transceivers.append(transceiver)

        return transceiver

    async def add_transceiver_from_kind(
        self, kind: RTPCodecKind, direction: RTPTransceiverDirection
    ) -> RTPTransceiver:
        if (
            direction is RTPTransceiverDirection.Sendrecv
            or direction is RTPTransceiverDirection.Sendonly
        ):
            codecs = self._caps.get_codecs_by_kind(kind)
            if not codecs:
                raise ValueError(f"Not found codecs for {kind.value}")

            track = TrackLocal(random_string(16), random_string(16), kind, codecs[0])
            return await self.add_transceiver_from_track(track, direction)
        elif direction is RTPTransceiverDirection.Recvonly:
            codecs = self._caps.get_codecs_by_kind(kind)
            if not codecs:
                raise ValueError(f"Not found codecs for {kind.value}")

            # transport = ICETransport(self.gatherer)
            # dtls_transport = dtls.DTLSTransport(transport, self.__certificate)
            # self.dtls_transports.append(dtls_transport)

            receiver = RTPReceiver(self._caps, kind)
            receiver.receive(
                RTPDecodingParameters(
                    rid=random_string(12),
                    ssrc=secrets.randbits(32),
                    payload_type=codecs[0].payload_type,
                    rtx=RTPRtxParameters(ssrc=secrets.randbits(32)),
                )
            )

            transceiver = RTPTransceiver(
                self._dtls_transport, caps=self._caps, kind=kind,
                direction=direction,
                observability_id=self._next_transceiver_observability_id(),
            )
            await transceiver.wait_active()
            await transceiver.set_receiver(receiver)
            await transceiver.set_prefered_codec(codecs[0])
            self._transceivers.append(transceiver)
            return transceiver
        else:
            raise ValueError("Unknown direction")

    @_sdp_description_measured("set_local")
    async def set_local_description(
        self, desc_type: SessionDescriptionType, desc: SessionDescription
    ):
        try:
            if not self._machine_handles:
                target = (
                    SignalingState.Stable
                    if desc_type is SessionDescriptionType.Answer
                    else SignalingState.HaveLocalOffer
                )
                ensure_next_signaling_state(
                    self._signaling_state, target,
                    SignalingChangeOperation.SetLocal, desc_type,
                )
                raise RuntimeError(
                    "set_local_description requires an active PeerConnection"
                )
            reply = ReplyPort[TransitionCommit]()
            canonical = _CanonicalSDP.capture(desc)
            await self._signaling_runner.submit(self._command(
                self._signaling_runner, _SignalingCommand.SET_LOCAL,
                (desc_type, canonical), reply=reply,
            ))
            await reply.wait()
        except SignalingStateTransitionError as e:
            get_logger().error(
                Component.SDP,
                "Invalid local description state transition",
                error=str(e),
            )
            raise

    async def _match_transceivers_with_offer(self, offer: SessionDescription):
        """
        Match local transceivers with remote offer media sections.

        When receiving an offer, we need to:
        1. Match our transceivers by kind (video/audio) with the offer's media sections
        2. Assign the MIDs from the offer to our transceivers
        """
        unassigned_transceivers = [t for t in self._transceivers if t.mid is None]

        for media in offer.media_descriptions:
            mid = media.get_attribute_value(SessionDescriptionAttrKey.MID.value)
            if not mid:
                continue

            kind = RTPCodecKind(media.kind)
            if kind != RTPCodecKind.Audio and kind != RTPCodecKind.Video:
                continue

            # Find an unassigned transceiver with matching kind
            for i, transceiver in enumerate(unassigned_transceivers):
                if transceiver.kind == kind:
                    # Assign the MID from the offer
                    await transceiver.set_mid(int(mid) if mid.isdigit() else 0)
                    get_logger().debug(
                        Component.SDP,
                        "Assigned MID from remote offer",
                        mid=mid,
                        kind=kind.value,
                    )

                    # Track greater mid for future use
                    if mid.isdigit() and int(mid) > self._greater_mid:
                        self._greater_mid = int(mid)

                    # Remove from unassigned list
                    unassigned_transceivers.pop(i)
                    break

    @_sdp_description_measured("set_remote")
    async def set_remote_description(
        self, desc_type: SessionDescriptionType, desc: SessionDescription
    ):
        get_logger().debug(
            Component.SDP,
            "Setting remote description",
            desc_type=desc_type.value,
            transceiver_count=len(self._transceivers),
        )
        try:
            if not self._machine_handles:
                target = (
                    SignalingState.Stable
                    if desc_type is SessionDescriptionType.Answer
                    else SignalingState.HaveRemoteOffer
                )
                ensure_next_signaling_state(
                    self._signaling_state, target,
                    SignalingChangeOperation.SetRemote, desc_type,
                )
                raise RuntimeError(
                    "set_remote_description requires an active PeerConnection"
                )
            reply = ReplyPort[TransitionCommit]()
            canonical = _CanonicalSDP.capture(desc)
            await self._signaling_runner.submit(self._command(
                self._signaling_runner, _SignalingCommand.SET_REMOTE,
                (desc_type, canonical), reply=reply,
            ))
            await reply.wait()
            committed_desc = canonical.materialize()
            if desc_type is SessionDescriptionType.Offer:
                # Stage 5 migrates transceiver negotiation itself; for now this
                # legacy side effect is causally after the signaling commit.
                await self._match_transceivers_with_offer(committed_desc)

        except SignalingStateTransitionError as e:
            get_logger().error(
                Component.SDP,
                "Invalid remote description state transition",
                error=str(e),
            )
            raise


        transceivers = self._transceivers.copy()

        if desc_type == SessionDescriptionType.Answer:
            get_logger().debug(Component.SDP, "Applying remote answer state")
            for media in committed_desc.media_descriptions:
                mid = media.get_attribute_value(SessionDescriptionAttrKey.MID.value)
                if not mid:
                    get_logger().debug(Component.SDP, "Skipping media without MID")
                    continue

                kind = RTPCodecKind(media.kind)
                if kind != RTPCodecKind.Audio and kind != RTPCodecKind.Video:
                    get_logger().debug(
                        Component.SDP,
                        "Skipping unsupported media kind",
                        kind=media.kind,
                    )
                    continue

                transceiver = find_transceiver_by_mid(mid, transceivers)
                if (
                    transceiver
                    and transceiver.direction == RTPTransceiverDirection.Inactive
                ):
                    transceiver.stop()

                # TODO: Need ensure that media transceiver same. Right now it check only kind or it None
                if transceiver is None or not (transceiver.kind == kind):
                    if len(media.codecs) == 0:
                        track = TrackLocal(
                            random_string(16),
                            random_string(16),
                            kind,
                            media.codecs[0],
                        )
                        await self.add_transceiver_from_track(track, media.direction)
                        get_logger().debug(
                            Component.SDP,
                            "Created transceiver from track",
                            kind=kind.value,
                        )
                    else:
                        get_logger().debug(
                            Component.SDP,
                            "Created transceiver from kind",
                            kind=kind.value,
                            direction=media.direction.value,
                        )
                        await self.add_transceiver_from_kind(kind, media.direction)
                elif transceiver:
                    # TODO: It may change direction too

                    if ssrc := media.get_attribute_value(
                        SessionDescriptionAttrKey.SSRC.value
                    ):
                        # TODO: Work around msid-semantic:WMS*
                        if recv := transceiver.receiver:
                            if track := recv.track:
                                track.ssrc = int(ssrc.split(" ")[0])

        get_logger().debug(
            Component.SDP,
            "Remote description applied",
            transceiver_count=len(self._transceivers),
        )
        # NOTE: Here may be also restart and updating candidates
        # TODO: May also start transports
        # TODO: This also may remote all unmatched transceivers

        self.__media_fingerprints.extend(committed_desc.get_media_fingerprints())

        for transceiver in self._transceivers:
            transceiver.start_srtp_streams()

    @event_loop
    def __get_sdp_role(self) -> ConnectionRole:
        role = self.gatherer.get_role()

        get_logger().debug(
            Component.SDP,
            "Selecting SDP setup role",
            ice_role=role.value if role else None,
        )
        if self._pending_remote_description is not None:
            return ConnectionRole.Passive

        return ConnectionRole.Actpass

    @event_loop
    def __get_dtls_role(self) -> dtls.DTLSRole:
        remote_description = (
            self._current_remote_description or self._pending_remote_description
        )
        remote_setup: str | None = None
        if remote_description is not None:
            for media in remote_description.media_descriptions:
                remote_setup = media.get_attribute_value(
                    SessionDescriptionAttrKey.ConnectionSetup.value
                )
                if remote_setup:
                    break

        match remote_setup:
            case ConnectionRole.Active.value:
                return dtls.DTLSRole.Server
            case ConnectionRole.Passive.value:
                return dtls.DTLSRole.Client
            case ConnectionRole.Actpass.value:
                return dtls.DTLSRole.Server
            case ConnectionRole.Holdconn.value:
                raise RuntimeError("remote SDP requested DTLS holdconn")

        role = self._ice_transport.get_ice_role() if hasattr(
            self, "_ice_transport"
        ) else self.gatherer.get_role()
        if role == ice.AgentRole.Controlled:
            return dtls.DTLSRole.Server
        return dtls.DTLSRole.Client

    # Generates an SDP that doesn't take remote state into account
    # This is used for the initial call for create_offer
    async def _generate_unmatched_sdp(
        self, transceivers: list[RTPTransceiver]
    ) -> SessionDescription | None:
        desc = SessionDescription()
        desc.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.MsidSemantic, "WMS*")
        )

        ice_params = await self.gatherer.get_local_parameters()
        if ice_params is None:
            raise RuntimeError("ICE local parameters are not available")

        if not self._transceivers:
            get_logger().debug(Component.SDP, "Generating SDP with no transceivers")

        ice_candidates = await self.gatherer.get_local_candidates()

        media_sections = list[MediaSection]()

        for t in transceivers:
            if sender := t.sender:
                sender.negotiate()

            if t.mid and t.mid.value:
                media_sections.append(
                    MediaSection(
                        mid=t.mid.value, transceivers=list[RTPTransceiver]([t])
                    )
                )
            else:
                get_logger().debug(
                    Component.SDP,
                    "Skipping transceiver without MID",
                    kind=t.kind.value,
                )

        fingerprints = [
            dtls.Fingerprint(
                algorithm="sha-256",
                value=self.__certificate.certificate_fingerprint(),
            ),
        ]

        get_logger().debug(
            Component.SDP,
            "Generated unmatched SDP media sections",
            media_section_count=len(media_sections),
        )

        return populate_session_descriptor(
            desc=desc,
            fingerprints=fingerprints,
            is_extmap_allow_mixed=True,
            role=self.__get_sdp_role(),
            candidates=ice_candidates,
            ice_params=ice_params,
            media_sections=media_sections,
            match_bundle_group=None,
            caps=self._caps,
        )

    # Generates a SDP and takes the remote state into account
    # this is used everytime we have a remote_description
    async def _generate_matched_sdp(
        self,
        transceivers: list[RTPTransceiver],
        remote_description: SessionDescription | None = None,
    ) -> SessionDescription | None:
        # Use provided remote description or fall back to current
        remote_desc = remote_description or self._current_remote_description
        if not remote_desc:
            raise ValueError(
                "Unable generate stateful desc. Set _current_remote_description"
            )

        if len(remote_desc.media_descriptions) == 0:
            raise ValueError(
                "Unable generate stateful desc. Not found media to generate"
            )

        group = remote_desc.get_attribute_value(SessionDescriptionAttrKey.Group.value)
        if not group:
            raise ValueError(
                "Unable generate stateful desc. Desc must contain BUNDLE attr"
            )

        group = group.removeprefix("BUNDLE")
        if len(group.split(" ")) == 0:
            raise ValueError(
                "Unable generate stateful desc. Desc bundle must contain at least one partition"
            )

        ice_params = await self.gatherer.get_local_parameters()
        if ice_params is None:
            raise RuntimeError("ICE local parameters are not available")

        if not self._transceivers:
            get_logger().debug(Component.SDP, "Generating SDP with no transceivers")

        ice_candidates = await self.gatherer.get_local_candidates()

        remote_desc.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.MsidSemantic, "WMS*")
        )

        media_sections = list[MediaSection]()

        for media in remote_desc.media_descriptions:
            mid = media.get_attribute_value(SessionDescriptionAttrKey.MID.value)
            if not mid:
                get_logger().debug(Component.SDP, "Skipping media without MID")
                continue

            kind = RTPCodecKind(media.kind)
            if kind != RTPCodecKind.Audio and kind != RTPCodecKind.Video:
                get_logger().debug(
                    Component.SDP,
                    "Skipping unsupported media kind",
                    kind=media.kind,
                )
                continue

            transceiver = find_transceiver_by_mid(mid, transceivers)
            if not transceiver or not transceiver.mid:
                continue

            if transceiver.sender:
                transceiver.sender.negotiate()

            media_sections.append(
                MediaSection(
                    mid=transceiver.mid.value,
                    transceivers=list[RTPTransceiver]([transceiver]),
                )
            )

        if len(media_sections) == 0:
            raise ValueError(
                "Unable generate stateful desc. Not found correct media_section"
            )

        get_logger().debug(
            Component.SDP,
            "Generated matched SDP media sections",
            media_section_count=len(media_sections),
        )

        # That approach will add flexability to decide client to assign it by own.
        matched_transiceivers = flatten_media_section_transceivers(media_sections)
        for t in transceivers:
            if t in matched_transiceivers:
                continue
            if not t.mid:
                continue
            media_sections.append(MediaSection(mid=t.mid.value, transceivers=[t]))

        fingerprints = [
            dtls.Fingerprint(
                algorithm="sha-256",
                value=self.__certificate.certificate_fingerprint(),
            ),
        ]

        return populate_session_descriptor(
            desc=SessionDescription(),
            fingerprints=fingerprints,
            is_extmap_allow_mixed=True,
            role=self.__get_sdp_role(),
            candidates=ice_candidates,
            ice_params=ice_params,
            media_sections=media_sections,
            match_bundle_group=group,
            caps=self._caps,
            remote_description=remote_desc,  # Pass remote for codec negotiation
        )

    @perf_measured_async("sdp", "create_offer")
    async def create_offer(self, options: OfferOption | None = None):
        # if self._closed:
        #     raise ValueError("connection closed")

        try:
            signaling = self._signaling_runner.signaling
            signaling_revision = self._signaling_runner.snapshot().revision
            remote = (
                signaling.current_remote.materialize()
                if signaling.current_remote is not None else None
            )
            # if options and options.ice_restart:
            #     self._transport.restart()

            current_transceivers = self._transceivers.copy()

            for transceiver in current_transceivers:
                if transceiver.mid and (mid := transceiver.mid.numeric_mid):
                    if mid > self._greater_mid:
                        self._greater_mid = mid
                    continue

                self._greater_mid += 1
                await transceiver.set_mid(self._greater_mid)

            if remote is None:
                desc = await self._generate_unmatched_sdp(current_transceivers)
            else:
                desc = await self._generate_matched_sdp(
                    current_transceivers, remote_description=remote,
                )

            if self._signaling_runner.snapshot().revision != signaling_revision:
                raise StaleMachineAccess(
                    "create_offer signaling snapshot changed during generation"
                )

            if desc:
                desc.origin.session_version = self.origin.session_version
                self.origin.session_version += 1

            return desc

        except RuntimeError as e:
            get_logger().error(Component.SDP, "Create offer failed", error=str(e))
            raise

    @perf_measured_async("sdp", "create_answer")
    async def create_answer(self):
        """
        Create an SDP answer in response to an offer from a remote peer.

        Must be called after set_remote_description with an offer.
        """
        # When creating an answer, the remote offer is in _pending_remote_description
        # (set by set_remote_description with Offer type)
        remote_offer = (
            self._pending_remote_description or self._current_remote_description
        )
        if remote_offer is None:
            raise ValueError("Cannot create answer without remote offer")

        try:
            current_transceivers = self._transceivers.copy()

            # Match transceivers with remote offer
            for transceiver in current_transceivers:
                if transceiver.mid and (mid := transceiver.mid.numeric_mid):
                    if mid > self._greater_mid:
                        self._greater_mid = mid

            # Generate answer based on the remote offer
            desc = await self._generate_matched_sdp(current_transceivers, remote_offer)

            if desc:
                desc.origin.session_version = self.origin.session_version
                self.origin.session_version += 1

            return desc

        except RuntimeError as e:
            get_logger().error(Component.SDP, "Create answer failed", error=str(e))
            raise
