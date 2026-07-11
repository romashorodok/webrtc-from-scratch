import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import wraps
import secrets
import string

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
from .utils import AsyncEventEmitter, impl_protocol, current_ntp_time
from .peer_context import get_active_peer_context, spawn_peer_task
from .logger import Component, get_logger
from .tracing import measure_perf_async, perf_mark, perf_measured_async

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
    wait_for_event,
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


class ICEGatherer(AsyncEventEmitter):
    def __init__(self) -> None:
        super().__init__()

        self._loop = asyncio.get_running_loop()
        self.__agent: ice.Agent | None = None
        self.__gather_lock = asyncio.Lock()

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
            raise RuntimeError("ICE agent is not available")

        self.__agent.set_remote_credentials(ufrag, pwd)

    async def add_remote_candidate(self, candidate_str: str):
        if not self.__agent:
            await self.gather()

        if not self.__agent:
            raise RuntimeError("ICE agent is not available")

        self.__agent.add_remote_candidate(candidate_str)

    async def __create_agent(
        self, port: int = 0, interfaces: list[net.Interface] = nic_interfaces
    ) -> ice.Agent:
        udp_mux = net.MultiUDPMux(interfaces, self._loop)
        await udp_mux.accept(port)

        options = ice.AgentOptions([ice.CandidateType.Host], udp_mux, interfaces)
        return ice.Agent(options)

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
        async with self.__gather_lock:
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

    async def wait(self, condition: ICECondition, timeout: float) -> None:
        timeout = require_timeout(timeout)
        if not self.__agent:
            if condition is ICECondition.GATHERING_COMPLETE:
                await self.gather()
            else:
                raise RuntimeError("ICE agent is not started")

        if not self.__agent:
            raise RuntimeError("ICE agent is not available")

        await self.__agent.wait(condition, timeout)

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


class PeerConnectionEvent(StrEnum):
    SignalingStateChange = "signaling-state-change"


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
class PeerConnection(AsyncEventEmitter):
    def __init__(self) -> None:
        super().__init__()

        self.__loop = asyncio.get_running_loop()
        self.gatherer = ICEGatherer()

        self.__certificate = webrtc_rs.Certificate()
        self._dtls_transport = dtls.DTLSTransport(self.__certificate)
        self.__media_fingerprints = list[dtls.Fingerprint]()

        # self._certificates = [self.__certificate]
        # self.dtls_transports = list[dtls.DTLSTransport]()

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
        self._transport: ice.CandidatePairTransport | None = None
        self._transport_ready = asyncio.Event()

        # Keep public raw-media sends ordered.  In particular, a burst must not
        # interleave with another caller halfway through its RTP sequence.
        self._media_send_lock = asyncio.Lock()

    async def _wait_for_media_send_ready(self) -> None:
        """Wait until the selected ICE transport and both SRTP sessions exist."""
        # Lifecycle waits are deliberately bounded so a failed negotiation cannot
        # leave a public send call (and its send lock) blocked forever.
        await wait_for_event(self._transport_ready, timeout=30.0)
        # DTLSTransport owns the SRTP readiness state.  Its write methods also
        # wait on the individual RTP/RTCP session, while this wait makes the
        # public PeerConnection contract explicit before a send begins.
        await self._dtls_transport.wait(TransportCondition.SRTP_READY, timeout=30.0)

    @staticmethod
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
        if self._transport is not None and self._transport._pair_id is not None:
            metadata["pair_id"] = self._transport._pair_id
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
        async with self._media_send_lock:
            return await self._send_media_packet(packet_bytes, rtcp=False)

    async def send_rtp_packets(self, packets: Iterable[bytes | bytearray]) -> int:
        """Encrypt and send an ordered RTP burst without spawning per-packet tasks."""
        packet_batch = tuple(self._media_packet_bytes(packet) for packet in packets)
        if not packet_batch:
            return 0

        async with self._media_send_lock:
            total = 0
            for index, packet in enumerate(packet_batch):
                total += await self._send_media_packet(
                    packet, rtcp=False, wait_ready=index == 0
                )
            return total

    async def send_rtcp_packet(self, packet: bytes | bytearray) -> int:
        """Encrypt and send one serialized RTCP packet through the selected peer transport."""
        packet_bytes = self._media_packet_bytes(packet)
        async with self._media_send_lock:
            return await self._send_media_packet(packet_bytes, rtcp=True)

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

    async def __on_ice_pair_controller(self, pair_ctrl: ice.CandidatePairController):
        # TODO: check if this already started
        pair_ctrl.remove_all_listeners()

        @pair_ctrl.on(ice.CandidatePairControllerEvent.NOMINATE_TRANSPORT)
        async def _bind_transport_on_nominated_to_transceivers(
            transport: ice.CandidatePairTransport,
        ):
            # Guard against duplicate NOMINATE_TRANSPORT events
            if self._transport is not None:
                get_logger().debug(
                    Component.PEER_CONNECTION,
                    "Ignoring duplicate nominated transport",
                )
                return

            dtls_role = self.__get_dtls_role()
            get_logger().info(
                Component.PEER_CONNECTION,
                "Starting DTLS on nominated transport",
                role=dtls_role.value,
            )
            self._transport = transport
            self._transport_ready.set()
            perf_mark("ice", "transport", "nominated")
            if peer_context := get_active_peer_context():
                peer_context._set_selected_transport(transport)

            # Start DTLS with the nominated transport
            self._dtls_transport.start(dtls_role, transport)
            get_logger().debug(Component.DTLS, "Starting DTLS ICE queue routine")
            spawn_peer_task(
                dtls_ice_pair_queue_handshake_routine(transport, self._dtls_transport),
                name="dtls:ice-pair-queue-handshake",
                component="dtls",
                metadata={"expected_long_running": True, "loop_role": "receive"},
            )

            # OBSOLETE: This loop was stealing 50% of packets from DTLSTransport._rtp_receive_loop()
            # The DTLSTransport already has its own _rtp_receive_loop() that reads from
            # transport.recv_rtp() and routes to SRTP. Having two loops reading from the
            # same queue causes 50% packet loss as they compete for packets.
            #
            # async def run_rtp_recv_loop():
            #     while True:
            #         pkt = await transport.recv_rtp()
            #         await self._dtls_transport.write_rtp_bytes(pkt.data)
            #
            get_logger().debug(
                Component.PEER_CONNECTION,
                "Skipping obsolete RTP receive bridge",
            )

        spawn_peer_task(
            pair_ctrl.start(),
            name="ice:candidate-pair-controller",
            component="ice",
            metadata={"expected_long_running": True, "loop_role": "controller"},
        )

        # self.dtls_transports.append(dtls_transport)

    def start(self):
        self.gatherer.on(
            ICEGathererEvent.CANDIDATE_PAIR_CONTROLLER, self.__on_ice_pair_controller
        )
        spawn_peer_task(
            self.gatherer.start(),
            name="ice:gatherer-start",
            component="ice",
            kind="lifecycle",
        )

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
                await wait_for_event(self._transport_ready, timeout=timeout)
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
            self._dtls_transport, caps=self._caps, kind=kind, direction=direction
        )
        transceiver.set_prefered_codec(codec)

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
                self._dtls_transport, caps=self._caps, kind=kind, direction=direction
            )
            transceiver.set_receiver(receiver)
            transceiver.set_prefered_codec(codecs[0])
            self._transceivers.append(transceiver)
            return transceiver
        else:
            raise ValueError("Unknown direction")

    @_sdp_description_measured("set_local")
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
                    transceiver.set_mid(int(mid) if mid.isdigit() else 0)
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

                    # Match local transceivers with remote offer media sections
                    # Assign MIDs from the offer to our transceivers
                    await self._match_transceivers_with_offer(desc)

                    self.emit(
                        PeerConnectionEvent.SignalingStateChange,
                        self._signaling_state,
                    )

                case SessionDescriptionType.Pranswer:
                    raise ValueError("unsupported pranswer desc type")
                case SessionDescriptionType.Rollback:
                    raise ValueError("unsupported rollback desc type")

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
            for media in desc.media_descriptions:
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

        self.__media_fingerprints.extend(desc.get_media_fingerprints())

        for transceiver in self._transceivers:
            spawn_peer_task(
                transceiver.start_srtp_streams(),
                name="srtp:start-streams",
                component="srtp",
            )

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

        ice_transport = ICETransport(self.gatherer)
        if ice_transport.get_ice_role() == ice.AgentRole.Controlled:
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
