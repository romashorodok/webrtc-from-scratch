import asyncio
from dataclasses import dataclass
from enum import StrEnum
import secrets
import string

from . import ice
from .ice import net
from . import dtls

import socket
from .utils import AsyncEventEmitter, impl_protocol, current_ntp_time

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


class ICEGathererEvent(StrEnum):
    CANDIDATE_PAIR_CONTROLLER = "candidate-pair-controller"


class ICEGatherer(AsyncEventEmitter):
    def __init__(self) -> None:
        super().__init__()

        self._loop = asyncio.get_running_loop()
        self.__agent: ice.Agent | None = None

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

        self.__agent.on(
            ice.AgentEvent.CANDIDATE_PAIR_CONTROLLER,
            lambda x: self.emit(ICEGathererEvent.CANDIDATE_PAIR_CONTROLLER, x),
        )

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
            return

        self.__agent.set_remote_credentials(ufrag, pwd)

    async def add_remote_candidate(self, candidate_str: str):
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            return

        self.__agent.add_remote_candidate(candidate_str)

    async def __create_agent(
        self, port: int = 0, interfaces: list[net.Interface] = nic_interfaces
    ) -> ice.Agent:
        udp_mux = net.MultiUDPMux(interfaces, self._loop)
        await udp_mux.accept(port)

        options = ice.AgentOptions([ice.CandidateType.Host], udp_mux, interfaces)
        return ice.Agent(options)

    # def _on_candidate(self, candidate: ice.CandidateBase):
    #     print("ICEGatherer on candidate", candidate)
    async def dial(self):
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            return

        self.__agent.dial()

    async def gather(self):
        try:
            if not self.__agent:
                self.__agent = await self.__create_agent()

            await self.__agent.gather_candidates()

            # agent = self.__agent
            # if agent is None:
            #     self.__agent = await self.__create_agent()
            #     agent = self.__agent

            # self._set_state(ICEGatherState.Gathering)

            # agent.set_on_candidate(self._on_candidate)
            # await agent.gather_candidates()
        except RuntimeError as e:
            print("ICE gather error. Err:", e)

    # def _set_state(self, state: ICEGatherState):
    #     # TODO: Make it reactive
    #     self._state = state


@impl_protocol(dtls.ICETransportDTLS)
class ICETransport:
    def __init__(
        self,
        gatherer: ICEGatherer,
    ) -> None:
        self.__gatherer = gatherer
        self.__transport: ice.CandidatePairTransport | None = None
        self.__transport_lock = asyncio.Lock()
        # self.__running_transport = running_transport

        # self.__gatherer = gatherer
        # self._state: ICETransportState = ICETransportState.NEW

    async def bind(self, transport: ice.CandidatePairTransport):
        async with self.__transport_lock:
            self.__transport = transport

    async def get_ice_pair_transport(self) -> ice.CandidatePairTransport | None:
        async with self.__transport_lock:
            return self.__transport

    def get_ice_role(self) -> ice.AgentRole:
        role = self.__gatherer.get_role()
        if not role or ice.AgentRole.Unknown:
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
            refresh_rate=0.020,
            channels=2,
            sdp_fmtp_line="minptime=10;useinbandfec=1",
            payload_type=111,
            stats_id=f"RTPCodec-{current_ntp_time() >> 32}",
        ),
        RTPCodecKind.Audio,
    )

    nack_pli = RTCPFeedback(rtcp_type="nack", parameter="pli")
    remb = RTCPFeedback(rtcp_type="goog-remb", parameter="")
    vp8 = RTPCodecParameters(
        mime_type="video/VP8",
        clock_rate=90000,
        refresh_rate=1 / 30,
        channels=0,
        sdp_fmtp_line="",
        payload_type=96,
        stats_id=f"RTPCodec-{current_ntp_time() >> 32}",
    )

    vp8.rtcp_feedbacks.append(nack_pli)
    vp8.rtcp_feedbacks.append(remb)

    caps.register_codec(vp8, RTPCodecKind.Video)


class PeerConnectionEvent(StrEnum):
    SignalingStateChange = "signaling-state-change"


# TODO: Watch into ORTC API
class PeerConnection(AsyncEventEmitter):
    def __init__(self) -> None:
        super().__init__()

        self.__loop = asyncio.get_running_loop()
        self.gatherer = ICEGatherer()

        self.__certificate = dtls.Certificate.generate_certificate()

        self._certificates = [self.__certificate]
        self.__media_fingerprints = list[dtls.Fingerprint]()

        self.dtls_transports = list[dtls.DTLSTransport]()

        self._caps = MediaCaps()
        set_default_caps(self._caps)
        self.origin = Origin()

        # Start Signaling related
        self._current_local_description: SessionDescription | None = None
        self._pending_local_description: SessionDescription | None = None

        self._current_remote_description: SessionDescription | None = None
        self._pending_remote_description: SessionDescription | None = None

        self._signaling_state: SignalingState = SignalingState.Stable
        self._signaling_lock = asyncio.Lock()
        # End Signaling related

        self._greater_mid: int = 0
        # self._sdp_semantic: SDPSemantic = SDPSemantic.UnifiedPlan

        self._transceivers = list[RTPTransceiver]()

        self._closed: bool = False
        self._peer_connection_lock = asyncio.Lock()

    async def __on_ice_pair_controller(self, pair_ctrl: ice.CandidatePairController):
        # TODO: check if this already started
        pair_ctrl.remove_all_listeners()

        ice_transport = ICETransport(self.gatherer)
        dtls_transport = dtls.DTLSTransport(ice_transport, self.__certificate)
        await dtls_transport.bind(pair_ctrl.get_transport())

        @pair_ctrl.on(ice.CandidatePairControllerEvent.NOMINATE_TRANSPORT)
        async def __bind_transport_on_nominated_to_transceivers(
            transport: ice.CandidatePairTransport,
        ):
            print("on __bind_transport_on_nominated_to_transceivers")

            for t in self.dtls_transports:
                await t.bind(transport)

            for t in self._transceivers:
                await t.bind(dtls_transport)

        self.__loop.create_task(dtls_transport.start(self.__media_fingerprints))
        self.__loop.create_task(pair_ctrl.start())
        self.dtls_transports.append(dtls_transport)

    def start(self):
        self.gatherer.on(
            ICEGathererEvent.CANDIDATE_PAIR_CONTROLLER, self.__on_ice_pair_controller
        )
        self.__loop.create_task(self.gatherer.start())

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

        transceiver = RTPTransceiver(caps=self._caps, kind=kind, direction=direction)
        transceiver.set_prefered_codec(codec)

        if sender:
            await sender.add_encoding(track)
            await transceiver.set_sender(sender)
        if receiver:
            transceiver.set_receiver(receiver)

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

            transport = ICETransport(self.gatherer)
            dtls_transport = dtls.DTLSTransport(transport, self.__certificate)
            self.dtls_transports.append(dtls_transport)

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
                caps=self._caps, kind=kind, direction=direction
            )
            transceiver.set_receiver(receiver)
            transceiver.set_prefered_codec(codecs[0])
            self._transceivers.append(transceiver)
            return transceiver
        else:
            raise ValueError("Unknown direction")

    async def set_local_description(
        self, desc_type: SessionDescriptionType, desc: SessionDescription
    ):
        try:
            match desc_type:
                case SessionDescriptionType.Answer:
                    # have-remote-offer->SetLocal(answer)->stable
                    # have-local-pranswer->SetLocal(answer)->stable
                    self._signaling_state = ensure_next_signaling_state(
                        self._signaling_state,
                        SignalingState.Stable,
                        SignalingChangeOperation.SetLocal,
                        desc_type,
                    )

                    self._current_local_description = desc
                    self._current_remote_description = self._pending_remote_description

                    self._pending_remote_description = None
                    self._pending_local_description = None

                    self.emit(
                        PeerConnectionEvent.SignalingStateChange,
                        self._signaling_state,
                    )

                case SessionDescriptionType.Offer:
                    # stable->SetLocal(offer)->have-local-offer
                    self._signaling_state = ensure_next_signaling_state(
                        self._signaling_state,
                        SignalingState.HaveLocalOffer,
                        SignalingChangeOperation.SetLocal,
                        desc_type,
                    )

                    self._pending_local_description = desc

                    self.emit(
                        PeerConnectionEvent.SignalingStateChange,
                        self._signaling_state,
                    )

                case SessionDescriptionType.Pranswer:
                    raise ValueError("unsupported pranswer desc type")
                case SessionDescriptionType.Rollback:
                    raise ValueError("unsupported rollback desc type")
        except SignalingStateTransitionError as e:
            print("Invalid local state transition", e)
            return

    async def set_remote_description(
        self, desc_type: SessionDescriptionType, desc: SessionDescription
    ):
        print("Old state", self._transceivers)
        try:
            match desc_type:
                case SessionDescriptionType.Answer:
                    # have-local-offer->SetRemote(answer)->stable
                    # have-remote-pranswer->SetRemote(answer)->stable
                    self._signaling_state = ensure_next_signaling_state(
                        self._signaling_state,
                        SignalingState.Stable,
                        SignalingChangeOperation.SetRemote,
                        desc_type,
                    )

                    self._current_remote_description = desc
                    self._current_local_description = self._pending_local_description

                    self._pending_remote_description = None
                    self._pending_local_description = None

                    self.emit(
                        PeerConnectionEvent.SignalingStateChange,
                        self._signaling_state,
                    )

                case SessionDescriptionType.Offer:
                    # stable->SetRemote(offer)->have-remote-offer
                    self._signaling_state = ensure_next_signaling_state(
                        self._signaling_state,
                        SignalingState.HaveRemoteOffer,
                        SignalingChangeOperation.SetRemote,
                        desc_type,
                    )
                    self._pending_remote_description = desc

                    self.emit(
                        PeerConnectionEvent.SignalingStateChange,
                        self._signaling_state,
                    )

                case SessionDescriptionType.Pranswer:
                    raise ValueError("unsupported pranswer desc type")
                case SessionDescriptionType.Rollback:
                    raise ValueError("unsupported rollback desc type")

        except SignalingStateTransitionError as e:
            print("Invalid remote state transition", e)
            return

        transceivers = self._transceivers.copy()

        if desc_type == SessionDescriptionType.Answer:
            print("Generate state by answer")
            for media in desc.media_descriptions:
                mid = media.get_attribute_value(SessionDescriptionAttrKey.MID.value)
                if not mid:
                    print("Not found mid")
                    continue

                kind = RTPCodecKind(media.kind)
                if kind != RTPCodecKind.Audio and kind != RTPCodecKind.Video:
                    print("Not found kind")
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
                        print("Create transciver from track", kind, media.codecs[0])
                    else:
                        print("Create transciver from kind", kind, media.direction)
                        await self.add_transceiver_from_kind(kind, media.direction)

        print("New state", self._transceivers)
        # NOTE: Here may be also restart and updating candidates
        # TODO: May also start transports
        # TODO: This also may remote all unmatched transceivers

        self.__media_fingerprints.extend(desc.get_media_fingerprints())

    def __get_sdp_role(self) -> ConnectionRole:
        role = self.gatherer.get_role()

        print(f"Set SDP from agent {role}")
        # The ICE controlling role acts as the server.
        if role == ice.AgentRole.Controlling or not role:
            return ConnectionRole.Passive

        return ConnectionRole.Active

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
            print("_generate_unmatched_sdp not found ice params")
            return

        if not self._transceivers:
            print("Empty transceivers")

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
                print("Not found transceiver mid. Must be already defined")

        fingerprints = self._certificates[0].get_fingerprints()

        print("media sections", media_sections)

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
    ) -> SessionDescription | None:
        if not self._current_remote_description:
            raise ValueError(
                "Unable generate stateful desc. Set _current_remote_description"
            )

        if len(self._current_remote_description.media_descriptions) == 0:
            raise ValueError(
                "Unable generate stateful desc. Not found media to generate"
            )

        group = self._current_remote_description.get_attribute_value(
            SessionDescriptionAttrKey.Group.value
        )
        if not group:
            raise ValueError(
                "Unable generate stateful desc. Desc must contain BUNDLE attr"
            )

        group = group.removeprefix("BUNDLE")
        if len(group.split(" ")) == 0:
            raise ValueError(
                "Unable generate stateful desc. Desc bundle must contain at least one partition"
            )

        ice_params = self.gatherer.get_local_parameters()
        if ice_params is None:
            return

        if not self._transceivers:
            print("Empty transceivers")

        ice_candidates = await self.gatherer.get_local_candidates()

        remote_desc = self._current_remote_description
        remote_desc.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.MsidSemantic, "WMS*")
        )

        media_sections = list[MediaSection]()

        for media in self._current_remote_description.media_descriptions:
            mid = media.get_attribute_value(SessionDescriptionAttrKey.MID.value)
            if not mid:
                print("Not found mid")
                continue

            kind = RTPCodecKind(media.kind)
            if kind != RTPCodecKind.Audio and kind != RTPCodecKind.Video:
                print("Not found kind")
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

        print(media_sections)

        # That approach will add flexability to decide client to assign it by own.
        matched_transiceivers = flatten_media_section_transceivers(media_sections)
        for t in transceivers:
            if t in matched_transiceivers:
                continue
            if not t.mid:
                continue
            media_sections.append(MediaSection(mid=t.mid.value, transceivers=[t]))

        fingerprints = self._certificates[0].get_fingerprints()

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
        )

    async def create_offer(self, options: OfferOption | None = None):
        # if self._closed:
        #     raise ValueError("connection closed")

        try:
            # if options and options.ice_restart:
            #     self._transport.restart()

            # async with self._peer_connection_lock:
            current_transceivers = self._transceivers.copy()

            for transceiver in current_transceivers:
                if transceiver.mid and (mid := transceiver.mid.numeric_mid):
                    if mid > self._greater_mid:
                        self._greater_mid = mid
                    continue

                self._greater_mid += 1
                transceiver.set_mid(self._greater_mid)

            if self._current_remote_description is None:
                desc = await self._generate_unmatched_sdp(current_transceivers)
            else:
                desc = await self._generate_matched_sdp(current_transceivers)

            if desc:
                desc.origin.session_version = self.origin.session_version
                self.origin.session_version += 1

            return desc

        except RuntimeError as e:
            print("Create offer error", e)
