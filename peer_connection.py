from abc import abstractmethod
import asyncio
from dataclasses import dataclass
import datetime
from typing import Any, Callable, Generic, Self, TypeVar
import re

import secrets
import string

import ice
import ice.net

import dtls

import socket

from enum import Enum, IntEnum

import ice.stun.utils as byteops
from utils import AsyncEventEmitter, impl_protocol
import itertools


nic_interfaces = ice.net.interface_factory(
    ice.net.InterfaceProvider.PSUTIL, [socket.AF_INET], False
)
if len(nic_interfaces) <= 0:
    nic_interfaces = ice.net.interface_factory(
        ice.net.InterfaceProvider.PSUTIL, [socket.AF_INET], True
    )


def random_string(length: int) -> str:
    allchar = string.ascii_letters + string.digits
    return "".join(secrets.choice(allchar) for _ in range(length))


class ICEGatherPolicy(Enum):
    # Use any type of candidate
    All = "all"
    # Use only TURN based candidates
    Relay = "relay"


class ICEGatherState(Enum):
    UNKNOWN = "unknow"
    # Gatherer has been create but gather has not been called
    NEW = "new"
    # Gather has been called mean state which gathering in process
    Gathering = "gathering"
    # Gathered with candidate
    Complete = "completed"
    Closed = "closed"


@dataclass
class ICEParameters:
    local_ufrag: str
    local_pwd: str


class ICEGatherer:
    def __init__(self) -> None:
        self._loop = asyncio.get_event_loop()

        self._policy: ICEGatherPolicy = ICEGatherPolicy.All
        self._state: ICEGatherState = ICEGatherState.NEW

        # TODO: Add support for dedicated stun server
        self._stun_servers = []
        self._agent: ice.Agent | None = None

    @property
    def agent(self) -> ice.Agent:
        if self._agent:
            return self._agent
        raise ValueError("Agent is None, start it firstly")

    def get_local_parameters(self) -> ICEParameters:
        ufrag, pwd = self.agent.get_local_credentials()
        return ICEParameters(ufrag, pwd)

    def get_gather_state(self) -> ICEGatherState:
        return self._state

    async def get_local_candidates(self) -> list[ice.CandidateProtocol]:
        candidates = await self.agent.get_local_candidates()

        return list(map(lambda c: c.unwrap, candidates))

    async def _create_agent(
        self, port: int = 0, interfaces: list[ice.net.Interface] = nic_interfaces
    ) -> ice.Agent:
        udp_mux = ice.net.MultiUDPMux(interfaces, self._loop)
        await udp_mux.accept(port)

        options = ice.AgentOptions([ice.CandidateType.Host], udp_mux, interfaces)
        return ice.Agent(options)

    def _on_candidate(self, candidate: ice.CandidateBase):
        print("ICEGatherer on candidate", candidate)

    async def gather(self):
        try:
            agent = self._agent
            if agent is None:
                self._agent = await self._create_agent()
                agent = self._agent

            self._set_state(ICEGatherState.Gathering)

            agent.set_on_candidate(self._on_candidate)
            await agent.gather_candidates()
        except RuntimeError as e:
            print("ICE gather error. Err:", e)

    def _set_state(self, state: ICEGatherState):
        # TODO: Make it reactive
        self._state = state


class ICETransportState(Enum):
    UNKNOWN = "unknow"
    # Not allocated transports. Indicate that no one transports allocated.
    NEW = "new"
    # All transport must be in checking state, and no other.
    Checking = "checking"
    # At least one transport in connected state, there may be other transports in "connected", "completed" or "closed"
    Connected = "connected"
    # At least one transport in completed state, there may be other transports  in "completed" or "closed"
    Completed = "completed"
    # Any of transports in "disconnected" state and none  in "failed"
    Disconnected = "Disconnected"
    Failed = "failed"
    # PeerConnection is closed
    Closed = "closed"


@impl_protocol(dtls.ICETransportDTLS)
class ICETransport:
    def __init__(self, gatherer: ICEGatherer) -> None:
        self._gatherer = gatherer
        self._loop = asyncio.get_event_loop()
        self._state: ICETransportState = ICETransportState.NEW

    def get_ice_pair_transports(self) -> list[ice.CandidatePairTransport]:
        agent = self._gatherer.agent
        return agent._candidate_pair_transports

    def get_ice_role(self) -> ice.AgentRole:
        return self._gatherer.agent.get_role()

    # Same as iceTransport.internalOnConnectionStateChangeHandler
    def _on_connection_state_changed(self):
        # pc.onICEConnectionStateChange(cs)
        # pc.updateConnectionState(cs, pc.dtlsTransport.State())
        pass

    def restart(self):
        raise ValueError("Implement agent restart")


@dataclass
class OfferOption:
    # VoiceActivityDetection allows the application to provide information
    # about whether it wishes voice detection feature to be enabled or disabled.
    voice_activity_detection: bool = False
    ice_restart: bool = False


class ConnectionRole(Enum):
    # Endpoint will initiate an outgoing connection
    Active = "active"
    # Endpoint will accept an incoming connection
    Passive = "passive"
    # Endpoint is willing to accept an incoming connection or to initiate an outgoing connection
    Actpass = "actpass"
    # Endpoint does not want the connection to be established for the time being
    Holdconn = "holdconn"


class SDPSemantic(Enum):
    # SDPSemanticsUnifiedPlan uses unified-plan offers and answers
    # (the default in Chrome since M72)
    # https://tools.ietf.org/html/draft-roach-mmusic-unified-plan-00
    UnifiedPlan = "unified plan"
    # Uses plan-b offers and answers NB: This format should be considered deprecated
    # https://tools.ietf.org/html/draft-uberti-rtcweb-plan-00
    PlanB = "plan b"
    # Prefers unified-plan offers and answers, but will respond to a plan-b offer  with a plan-b answer
    UnifiedPlanWithFallback = "unified plan with fallback"


class MID:
    def __init__(self, mid: int | str) -> None:
        self._mid = mid

    @property
    def numeric_mid(self) -> int | None:
        if isinstance(self._mid, int):
            return self._mid
        elif isinstance(self._mid, str) and self._mid.isdigit():
            return int(self._mid)
        else:
            return None

    @property
    def value(self) -> str:
        return str(self._mid)


class RTPCodecKind(Enum):
    Unknown = "unknown"
    Audio = "audio"
    Video = "video"


# RTCPFeedback signals the connection to use additional RTCP packet types.
# https://draft.ortc.org/#dom-rtcrtcpfeedback
class RTCPFeedback:
    def __init__(self, rtcp_type: str, parameter: str) -> None:
        # Type is the type of feedback.
        # see: https://draft.ortc.org/#dom-rtcrtcpfeedback
        # valid: ack, ccm, nack, goog-remb, transport-cc
        self.rtcp_type = rtcp_type
        # The parameter value depends on the type.
        # For example, type="nack" parameter="pli" will send Picture Loss Indicator packets.
        self.parameter = parameter


# RTPCodecParameters is a sequence containing the media codecs that an RtpSender
# will choose from, as well as entries for RTX, RED and FEC mechanisms. This also
# includes the PayloadType that has been negotiated
# https://w3c.github.io/webrtc-pc/#rtcrtpcodecparameters
class RTPCodecParameters:
    def __init__(
        self,
        mime_type: str,
        clock_rate: int,
        channels: int,
        sdp_fmtp_line: str,
        payload_type: int,
        stats_id: str,
    ) -> None:
        self.mime_type = mime_type
        self.clock_rate = clock_rate
        self.channels = channels
        self.sdp_fmtp_line = sdp_fmtp_line
        self.payload_type = payload_type
        self.stats_id = stats_id
        self.rtcp_feedbacks = list[RTCPFeedback]()


class RTPTransceiverDirection(Enum):
    Unknown = "unknown"
    Sendrecv = "sendrecv"
    Sendonly = "sendonly"
    Recvonly = "recvonly"
    Inactive = "inactive"


RTPTransceiverDirectionList = [
    RTPTransceiverDirection.Sendrecv.value,
    RTPTransceiverDirection.Sendonly.value,
    RTPTransceiverDirection.Recvonly.value,
    RTPTransceiverDirection.Inactive.value,
]


# RTPHeaderExtensionParameter represents a negotiated RFC5285 RTP header extension.
# https://w3c.github.io/webrtc-pc/#dictionary-rtcrtpheaderextensionparameters-members
class RTPHeaderExtensionParameter:
    def __init__(self, uri: str, id: int) -> None:
        self.uri = uri
        self.id = id


# RTPParameters is a list of negotiated codecs and header extensions
# https://w3c.github.io/webrtc-pc/#dictionary-rtcrtpparameters-members
class RTPParameters:
    def __init__(
        self,
        header_extensions: list[RTPHeaderExtensionParameter],
        codecs: list[RTPCodecParameters],
    ) -> None:
        self.header_extensions = header_extensions
        self.codecs = codecs


class MediaCapsHeaderExtension:
    def __init__(
        self,
        uri: str,
        allowed_directions: list[RTPTransceiverDirection],
        is_audio: bool = False,
        is_video: bool = False,
    ) -> None:
        self.uri = uri
        self.allowed_directions = allowed_directions
        self.is_audio = is_audio
        self.is_video = is_video


def have_rtp_transceiver_direction_intersection(pool, target):
    for n in target:
        for h in pool:
            if n == h:
                return True
    return False


class MediaCaps:
    def __init__(self) -> None:
        self.video_caps = list[RTPCodecParameters]()
        self.audio_caps = list[RTPCodecParameters]()
        self.negotiated_video_caps = list[RTPCodecParameters]()
        self.negotiated_audio_caps = list[RTPCodecParameters]()
        self.header_extensions = list[MediaCapsHeaderExtension]()
        self.negotiated_header_extensions = dict[int, MediaCapsHeaderExtension]()
        self.negotiated_video: bool = False
        self.negotiated_audio: bool = False

    def register_codec(self, codec: RTPCodecParameters, codec_kind: RTPCodecKind):
        match codec_kind:
            case RTPCodecKind.Audio:
                self.audio_caps.append(codec)
            case RTPCodecKind.Video:
                self.video_caps.append(codec)

    def get_codecs_by_kind(self, kind: RTPCodecKind) -> list[RTPCodecParameters]:
        match kind:
            case RTPCodecKind.Video:
                if self.negotiated_video:
                    return self.negotiated_video_caps
                return self.video_caps
            case RTPCodecKind.Audio:
                if self.negotiated_audio:
                    return self.negotiated_audio_caps
                return self.audio_caps
            case _:
                return list[RTPCodecParameters]()

    def get_rtp_parameters_by_kind(
        self, kind: RTPCodecKind, directions: list[RTPTransceiverDirection]
    ) -> RTPParameters:
        header_extensions = list[RTPHeaderExtensionParameter]()
        codecs = self.get_codecs_by_kind(kind)

        if (
            self.negotiated_audio
            and kind == RTPCodecKind.Audio
            or self.negotiated_video
            and kind == RTPCodecKind.Video
        ):
            for id, ext in self.negotiated_header_extensions.items():
                if have_rtp_transceiver_direction_intersection(
                    ext.allowed_directions, directions
                ) and (
                    ext.is_audio
                    and kind == RTPCodecKind.Audio
                    or ext.is_video
                    and kind == RTPCodecKind.Video
                ):
                    header_extensions.append(RTPHeaderExtensionParameter(ext.uri, id))
        else:
            media_header_extensions = dict[int, MediaCapsHeaderExtension]()
            for ext in self.header_extensions:
                using_negotiated_id = False
                for id, negotiated_ext in self.negotiated_header_extensions.items():
                    if negotiated_ext.uri == ext:
                        using_negotiated_id = True
                        media_header_extensions[id] = ext
                        break
                if not using_negotiated_id:
                    for id in range(1, 15):
                        is_available = True
                        if media_header_extensions.get(id):
                            is_available = False
                        if is_available and not self.negotiated_header_extensions.get(
                            id
                        ):
                            media_header_extensions[id] = ext
                            break
            for id, ext in media_header_extensions.items():
                if have_rtp_transceiver_direction_intersection(
                    ext.allowed_directions, directions
                ) and (
                    ext.is_audio
                    and kind == RTPCodecKind.Audio
                    or ext.is_video
                    and kind == RTPCodecKind.Video
                ):
                    header_extensions.append(RTPHeaderExtensionParameter(ext.uri, id))

        return RTPParameters(header_extensions, codecs)


class FMTP:
    def __init__(self, mime_type: str, parameters: dict[str, str]):
        self.mime_type = mime_type
        self.parameters = parameters

    def __eq__(self, target: object) -> bool:
        if not isinstance(target, FMTP):
            return False

        if self.mime_type.lower() != target.mime_type.lower():
            return False

        for k, v in self.parameters.items():
            if k in target.parameters and target.parameters[k].lower() != v.lower():
                return False

        for k, v in target.parameters.items():
            if k in self.parameters and self.parameters[k].lower() != v.lower():
                return False

        return True

    def parameter(self, key: str):
        return self.parameters.get(key), key in self.parameters


def parse_fmtp(mime_type: str, line: str):
    parameters = dict[str, str]()

    for p in line.split(";"):
        pp = p.strip().split("=", 1)
        key = pp[0].lower()
        value = pp[1] if len(pp) > 1 else ""
        parameters[key] = value

    return FMTP(mime_type, parameters)


def codecs_params_fuzzy_search(
    target: RTPCodecParameters, pool: list[RTPCodecParameters]
) -> RTPCodecParameters | None:
    target_fmtp = parse_fmtp(target.mime_type, target.sdp_fmtp_line)

    # First attempt to match on MimeType + SDPFmtpLine
    for item in pool:
        item_fmtp = parse_fmtp(item.mime_type, item.sdp_fmtp_line)
        if target_fmtp == item_fmtp:
            return item

    # Fallback to match only by MimeType
    for item in pool:
        if target.mime_type.lower() == item.mime_type.lower():
            return item

    return


class TrackLocal:
    def __init__(
        self,
        id: str,
        stream_id: str,
        kind: RTPCodecKind,
        rtp_codec_params: RTPCodecParameters,
    ) -> None:
        self._id = id
        self._rid = stream_id
        self._stream_id = stream_id
        self._rtp_codec_params = rtp_codec_params
        self._kind = kind
        self._writer: dtls.RTPWriterProtocol | None = None

    async def write_rtp(self, pkt: ice.net.Packet) -> int:
        if not self._writer:
            return 0
        return await self._writer.write_rtp(pkt)

    def bind(self, writer: dtls.RTPWriterProtocol):
        self._writer = writer

    @property
    def kind(self) -> RTPCodecKind:
        return self._kind

    @property
    def id(self) -> str:
        return self._id

    @property
    def rid(self) -> str:
        return self._rid

    @property
    def stream_id(self) -> str:
        return self._stream_id


# RTPEncodingParameters provides information relating to both encoding and decoding.
# This is a subset of the RFC since Pion WebRTC doesn't implement encoding itself
# http://draft.ortc.org/#dom-rtcrtpencodingparameters
class RTPEncodingParameters:
    def __init__(
        self, rid: str, ssrc: int, payload_type: int, rtx: int | None = None
    ) -> None:
        self.rid = rid
        self.ssrc = ssrc
        self.payload_type = payload_type
        # https://draft.ortc.org/#dom-rtcrtprtxparameters
        self.rtx = rtx


class RTPSendParameters:
    def __init__(
        self, rtp_parameters: RTPParameters, encodings: list[RTPEncodingParameters]
    ) -> None:
        self.encodings = encodings
        self.rtp_parameters = rtp_parameters


@impl_protocol(dtls.RTPWriterProtocol)
class TrackEncoding:
    def __init__(
        self, ssrc: int, dtls: dtls.DTLSTransport, track: TrackLocal | None = None
    ) -> None:
        self.track = track
        self.ssrc = ssrc
        self._dtls = dtls
        self._lock = asyncio.Lock()

    async def write_rtp(self, pkt: ice.net.Packet) -> int:
        # print("Write in encoding")
        async with self._lock:
            return self._dtls.write_rtp(pkt)


class RTPSender:
    def __init__(self, caps: MediaCaps, dtls: dtls.DTLSTransport) -> None:
        self._track_encodings = list[TrackEncoding]()
        self._payload_type: int = 0
        self._caps = caps
        self._track: TrackLocal | None = None
        self._dtls = dtls

    async def add_encoding(self, track: TrackLocal):
        self._track_encodings.append(
            TrackEncoding(ssrc=secrets.randbits(32), dtls=self._dtls, track=track)
        )
        await self.replace_track(track)

    async def replace_track(self, track: TrackLocal):
        for encoding in self._track_encodings:
            async with encoding._lock:
                if enc_track := encoding.track:
                    enc_track._writer = None

                track.bind(encoding)
        self._track = track

    @property
    def kind(self) -> RTPCodecKind | None:
        if self._track:
            return self._track._kind
        return

    def get_parameters(self) -> RTPSendParameters | None:
        encodings = list[RTPEncodingParameters]()
        for track_encoding in self._track_encodings:
            rid = ""
            if track_encoding.track:
                rid = track_encoding.track.rid
            encodings.append(
                RTPEncodingParameters(rid, track_encoding.ssrc, self._payload_type)
            )

        kind = self.kind
        if not kind:
            return

        send_params = RTPSendParameters(
            rtp_parameters=self._caps.get_rtp_parameters_by_kind(
                kind, [RTPTransceiverDirection.Sendonly]
            ),
            encodings=encodings,
        )
        send_params.rtp_parameters.codecs = self._caps.get_codecs_by_kind(kind)
        return send_params

    @property
    def track(self) -> TrackLocal | None:
        return self._track

    def negotiate(self):
        print("TODO: Add negotiate in RTPSender")


class RTPReceiver:
    def __init__(self, caps: MediaCaps) -> None:
        self._caps = caps


class RTPTransceiver:
    def __init__(
        self,
        caps: MediaCaps,
        kind: RTPCodecKind,
        direction: RTPTransceiverDirection,
    ):
        self._mid: MID | None = None
        self._sender: RTPSender | None = None
        self._receiver: RTPReceiver | None = None
        self._caps: MediaCaps = caps
        self._kind: RTPCodecKind = kind
        self._prefered_codecs = list[RTPCodecParameters]()
        self._direction = direction

    def set_prefered_codec(self, codec: RTPCodecParameters):
        self._prefered_codecs.append(codec)

    def get_codecs(self) -> list[RTPCodecParameters] | None:
        codecs = self._caps.get_codecs_by_kind(self._kind)

        if not codecs:
            return None

        filtered_codecs = list[RTPCodecParameters]()
        for codec in self._prefered_codecs:
            if item := codecs_params_fuzzy_search(codec, codecs):
                filtered_codecs.append(item)

        return filtered_codecs

    def stop(self):
        print("TODO: stop transceiver")

    def track_local(self) -> TrackLocal | None:
        if not self.sender:
            return
        return self.sender.track

    @property
    def sender(self) -> RTPSender | None:
        return self._sender

    def set_sender(self, sender: RTPSender):
        self._sender = sender

    @property
    def receiver(self) -> RTPReceiver | None:
        return self._receiver

    def set_receiver(self, receiver: RTPReceiver):
        self._receiver = receiver

    @property
    def direction(self) -> RTPTransceiverDirection:
        return self._direction

    @property
    def kind(self) -> RTPCodecKind:
        return self._kind

    @property
    def mid(self) -> MID | None:
        return self._mid

    def set_mid(self, mid: int | str):
        self._mid = MID(mid)


NTP_EPOCH = datetime.datetime(1900, 1, 1, tzinfo=datetime.timezone.utc)


def current_datetime() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def current_ms() -> int:
    delta = current_datetime() - NTP_EPOCH
    return int(delta.total_seconds() * 1000)


def current_ntp_time() -> int:
    return datetime_to_ntp(current_datetime())


def datetime_from_ntp(ntp: int) -> datetime.datetime:
    seconds = ntp >> 32
    microseconds = ((ntp & 0xFFFFFFFF) * 1000000) / (1 << 32)
    return NTP_EPOCH + datetime.timedelta(seconds=seconds, microseconds=microseconds)


def datetime_to_ntp(dt: datetime.datetime) -> int:
    delta = dt - NTP_EPOCH
    high = int(delta.total_seconds())
    low = round((delta.microseconds * (1 << 32)) // 1000000)
    return (high << 32) | low


class Origin:
    def __init__(self):
        self.username = "-"
        self.session_id = self._new_session_id()
        self.session_version = current_ntp_time() >> 32
        self.network_type = "IN"
        self.address_type = "IP4"
        self.unicast_address = "0.0.0.0"

    def _new_session_id(self):
        # https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-26#section-5.2.1
        # Session ID is recommended to be constructed by generating a 64-bit
        # quantity with the highest bit set to zero and the remaining 63-bits
        # being cryptographically random.
        id = secrets.randbits(64)
        # Set the highest bit to zero
        # Set the highest bit to zero
        id &= ~(1 << 63)
        return id

    def marshal(self) -> bytes:
        m = bytearray()
        m.extend(byteops.pack_string(self.username + " "))
        m.extend(byteops.pack_string(str(self.session_id) + " "))
        m.extend(byteops.pack_string(str(self.session_version) + " "))
        m.extend(byteops.pack_string(self.network_type + " "))
        m.extend(byteops.pack_string(self.address_type + " "))
        m.extend(byteops.pack_string(self.unicast_address))
        return m


class SessionDescriptionAttrKey(Enum):
    Candidate = "candidate"
    EndOfCandidates = "end-of-candidates"
    Identity = "identity"
    Group = "group"
    SSRC = "ssrc"
    SSRCGroup = "ssrc-group"
    Msid = "msid"
    MsidSemantic = "msid-semantic"
    ConnectionSetup = "setup"
    MID = "mid"
    ICELite = "ice-lite"
    RTCPMux = "rtcp-mux"
    RTCPRsize = "rtcp-rsize"
    Inactive = "inactive"
    RecvOnly = "recvonly"
    SendOnly = "sendonly"
    SendRecv = "sendrecv"
    ExtMap = "extmap"
    ExtMapAllowMixed = "extmap-allow-mixed"
    Fingerprint = "fingerprint"
    RTPMap = "rtpmap"
    FMTP = "fmtp"
    RTCPfb = "rtcp-fb"
    RID = "rid"
    ICEUfrag = "ice-ufrag"
    ICEPwd = "ice-pwd"


class SessionDescriptionAttr:
    def __init__(
        self, key: SessionDescriptionAttrKey | str, value: str | None = None
    ) -> None:
        if isinstance(key, SessionDescriptionAttrKey):
            self.key: str = key.value
        else:
            self.key = key

        self.value = value

    def __repr__(self) -> str:
        return f"SessionDescriptionAttr(key={self.key}, value={self.value})"

    def marshal(self) -> bytes:
        m = bytearray()
        m.extend(byteops.pack_string(self.key))
        if self.value and len(self.value) > 0:
            m.extend(byteops.pack_string(":" + self.value))
        return m


class SimulcastRid:
    def __init__(self, value: str, paused: bool) -> None:
        self.value = value
        self.paused = paused


# DefExtMapValueABSSendTime     = 1
# DefExtMapValueTransportCC     = 2
# DefExtMapValueSDESMid         = 3
# DefExtMapValueSDESRTPStreamID = 4
# ABSSendTimeURI     = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
# TransportCCURI     = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
# SDESMidURI         = "urn:ietf:params:rtp-hdrext:sdes:mid"
# SDESRTPStreamIDURI = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
# AudioLevelURI      = "urn:ietf:params:rtp-hdrext:ssrc-audio-level"


class ExtMap:
    def __init__(
        self,
        value: int,
        direction: RTPTransceiverDirection | None = None,
        uri: str | None = None,
        ext_attr: str | None = None,
    ) -> None:
        self.value = value
        self.direction = direction
        self.uri = uri
        self.ext_attr = ext_attr

    def marshal(self) -> str:
        out = f"extmap:{self.value}"

        # direction = self.direction
        # if direction == RTPTransceiverDirection.Unknown or self.direction is None:
        #     out += "/ "

        if self.uri:
            out += f" {self.uri}"

        if self.ext_attr:
            out += f" {self.ext_attr}"

        return out


class MediaSection:
    def __init__(
        self,
        mid: str,
        transceivers: list[RTPTransceiver],
        # rid_map: dict[str, SimulcastRid] | None = None,
    ) -> None:
        self.id = mid
        self.rid = mid
        self.transceivers = transceivers

        # NOTE: i not will use sctp
        self.data = False
        # self.rid_map = rid_map


def _desc_marshal_key_value(data: bytearray, key: str, value: bytes):
    data.extend(byteops.pack_string(key))
    data.extend(value)
    data.extend(b"\r\n")


def _append_list(lst: list[str], sep: str) -> str:
    b = []
    for i, p in enumerate(lst):
        if i != 0:
            b.append(sep)
        b.append(p)
    return "".join(b)


class MediaDescription:
    def __init__(
        self,
        media: str,
        port: int,
        protocols: list[str],
        # formats: list[str],
        # network_type: str,
        # address_type: str,
        # address: str,
    ) -> None:
        self.kind = media
        self.port = port
        self.port_end: int | None = None
        self.protocols = protocols
        # Mean which codec payload formats may be used
        self.formats = list[str]()

        self.network_type = "IN"
        self.address_type = "IP4"
        self.address_host = "0.0.0.0"

        self.ice_ufrag: str | None = None
        self.ice_pwd: str | None = None

        # a=<attribute>
        # a=<attribute>:<value>
        # https://tools.ietf.org/html/rfc4566#section-5.13
        self._attributes = list[SessionDescriptionAttr]()

        self.direction: RTPTransceiverDirection = RTPTransceiverDirection.Unknown
        self.candidates = list[ice.CandidateProtocol]()
        self.codecs = list[RTPCodecParameters]()
        self.fingerprints = list[dtls.Fingerprint]()

    def __repr__(self) -> str:
        return f"MediaDescription(ice_ufrag={self.ice_ufrag}, ice_pwd={self.ice_pwd}, _attributes={self._attributes})"

    def add_codec(self, codec: RTPCodecParameters):
        self.formats.append(str(codec.payload_type))
        name = codec.mime_type.removeprefix("audio/")
        name = name.removeprefix("video/")
        rtpmap = f"{codec.payload_type} {name}/{codec.clock_rate}"
        if codec.channels > 0:
            rtpmap += f"/{codec.channels}"
        self.codecs.append(codec)
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.RTPMap, rtpmap)
        )
        if codec.sdp_fmtp_line:
            fmtp = f"{codec.payload_type} {codec.sdp_fmtp_line}"
            self.add_attribute(
                SessionDescriptionAttr(SessionDescriptionAttrKey.FMTP, fmtp)
            )

    def add_rtcp_feedback(self, codec: RTPCodecParameters, rtcp_feedback: RTCPFeedback):
        feedback = (
            f"{codec.payload_type} {rtcp_feedback.rtcp_type} {rtcp_feedback.parameter}"
        )
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.RTCPfb, feedback)
        )

    def add_media_source(self, ssrc: int, cname: str, stream_label: str, label: str):
        # value = f"{ssrc} cname:{cname}"
        # self.add_attribute(
        #     SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        # )
        # value = f"{ssrc} msid:{stream_label} {label}"
        # self.add_attribute(
        #     SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        # )
        # value = f"{ssrc} label:{label}"
        # self.add_attribute(
        #     SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        # )
        value = f"{ssrc} mslabel:{stream_label}"
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        )

    @property
    def attributes(self) -> list[SessionDescriptionAttr]:
        return self._attributes

    def add_attribute(self, attr: SessionDescriptionAttr):
        self._attributes.append(attr)

    def get_attribute_value(self, key: str) -> str | None:
        for attr in self.attributes:
            if key == attr.key:
                return attr.value
        return

    @classmethod
    def parse(cls, media_lines: list[str]) -> Self | None:
        # TODO: add port range matching
        m = re.match("^m=([^ ]+) ([0-9]+) ([A-Z/]+) (.+)$", media_lines[0])
        if not m:
            return

        media_kind = m.group(1)
        port = int(m.group(2))
        protocols = m.group(3).split("/")
        fmt = m.group(4).split()

        media = cls(
            media=media_kind,
            port=port,
            protocols=protocols,
        )

        media.formats.extend(fmt)

        for line in media_lines[1:]:
            if line.startswith("c="):
                address_type, address_host = ipaddress_from_sdp(line[2:])
                media.address_type = address_type
                media.address_host = address_host
            elif line.startswith("a="):
                attr, value = parse_attr(line)

                if attr in RTPTransceiverDirectionList:
                    print("Parse direction", attr)
                    media.direction = RTPTransceiverDirection(attr)
                elif attr == SessionDescriptionAttrKey.Candidate.value and value:
                    candidates = ice.parse_candidate_str(value)
                    media.candidates.append(candidates)
                elif attr == SessionDescriptionAttrKey.RTPMap.value and value:
                    payload_id, payload_desc = value.split(" ", 1)
                    bits = payload_desc.split("/")

                    if media_kind == RTPCodecKind.Audio.value:
                        if len(bits) > 2:
                            channels = int(bits[2])
                        else:
                            channels = 1
                    else:
                        channels = 0

                    payload_name = bits[0]
                    clock_rate = bits[1]

                    codec = RTPCodecParameters(
                        mime_type=f"{media_kind}/{payload_name}",
                        clock_rate=int(clock_rate),
                        channels=channels,
                        payload_type=int(payload_id),
                        sdp_fmtp_line="",
                        stats_id=f"RTPCodec-{current_ntp_time() >> 32}",
                    )
                    media.add_codec(codec)

                elif attr == SessionDescriptionAttrKey.ICEUfrag.value and value:
                    media.ice_ufrag = value
                elif attr == SessionDescriptionAttrKey.ICEPwd.value and value:
                    media.ice_pwd = value

                elif attr == SessionDescriptionAttrKey.Fingerprint.value and value:
                    algorithm, fingerprint = value.split()
                    media.fingerprints.append(dtls.Fingerprint(algorithm, fingerprint))

                else:
                    media.attributes.append(
                        SessionDescriptionAttr(key=attr, value=value)
                    )

        return media

    def _marshal_ports(self) -> bytes:
        m = bytearray()

        m.extend(byteops.pack_string(str(self.port)))
        if self.port_end:
            m.extend(byteops.pack_string("/"))
            m.extend(byteops.pack_string(str(self.port_end)))

        return m

    def _marshal_name(self) -> bytes:
        m = bytearray()
        m.extend(byteops.pack_string(self.kind + " "))
        m.extend(self._marshal_ports())
        m.extend(byteops.pack_string(" "))
        m.extend(byteops.pack_string(_append_list(self.protocols, "/")))
        m.extend(byteops.pack_string(" "))
        m.extend(byteops.pack_string(_append_list(self.formats, " ")))
        self.kind

        return m

    def marshal(self) -> bytes:
        m = bytearray()
        _desc_marshal_key_value(m, "m=", self._marshal_name())
        _desc_marshal_key_value(
            m,
            "c=",
            byteops.pack_string(
                f"{self.network_type} {self.address_type} {self.address_host}"
            ),
        )
        for attr in self.attributes:
            _desc_marshal_key_value(m, "a=", attr.marshal())
        return m


def grouplines(sdp: str) -> tuple[list[str], list[list[str]]]:
    # Ensure the SDP data is a string (decode if it's a bytestring)
    if isinstance(sdp, bytes):
        sdp = sdp.decode()

    session = []
    media = []
    for line in sdp.splitlines():
        if line.startswith("m="):
            media.append([line])
        elif len(media):
            media[-1].append(line)
        else:
            session.append(line)
    return session, media


def ipaddress_from_sdp(sdp: str) -> tuple[str, str]:
    m = re.match("^IN (IP4|IP6) ([^ ]+)$", sdp)
    assert m
    return (m.group(1), m.group(2))


def parse_attr(line: str) -> tuple[str, str | None]:
    if ":" in line:
        bits = line[2:].split(":", 1)
        return bits[0], bits[1]
    else:
        return line[2:], None


@dataclass
class GroupDescription:
    semantic: str
    items: list[int | str]

    def __str__(self) -> str:
        return f"{self.semantic} {' '.join(map(str, self.items))}"


def parse_group(dest: list[GroupDescription], value: str, type=str) -> None:
    bits = value.split()
    if bits:
        dest.append(GroupDescription(semantic=bits[0], items=list(map(type, bits[1:]))))


FMTP_INT_PARAMETERS = [
    "apt",
    "max-fr",
    "max-fs",
    "maxplaybackrate",
    "minptime",
    "stereo",
    "useinbandfec",
]


def parameters_from_sdp(sdp: str):
    parameters = {}
    for param in sdp.split(";"):
        if "=" in param:
            k, v = param.split("=", 1)
            if k in FMTP_INT_PARAMETERS:
                parameters[k] = int(v)
            else:
                parameters[k] = v
        else:
            parameters[param] = None
    return parameters


# API to match draft-ietf-rtcweb-jsep.
# Some settings that are required by the JSEP spec.
class SessionDescription:
    def __init__(self) -> None:
        # o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
        # https://tools.ietf.org/html/rfc4566#section-5.2
        self.origin = Origin()
        # v=0
        # https://tools.ietf.org/html/rfc4566#section-5.1
        self.version = 0
        # s=<session name>
        # https://tools.ietf.org/html/rfc4566#section-5.3
        self.session_name = "-"
        # https://tools.ietf.org/html/rfc4566#section-5.9
        # https://tools.ietf.org/html/rfc4566#section-5.10
        # self.time_descriptions = list[TimeDescription]([TimeDescription()])
        # a=<attribute>
        # a=<attribute>:<value>
        # https://tools.ietf.org/html/rfc4566#section-5.13
        self.attributes = list[SessionDescriptionAttr]()
        self.media_descriptions = list[MediaDescription]()

    def add_attribute(self, attr: SessionDescriptionAttr):
        self.attributes.append(attr)

    def get_attribute_value(self, key: str) -> str | None:
        for attr in self.attributes:
            if key == attr.key:
                return attr.value
        return

    def add_media_description(self, desc: MediaDescription):
        self.media_descriptions.append(desc)

    @classmethod
    def parse(cls, sdp: str):
        current_media: MediaDescription | None = None
        dtls_fingerprints = []
        dtls_role = None
        ice_lite = False
        ice_options = None
        ice_password = None
        ice_usernameFragment = None

        session_lines, media_groups = grouplines(sdp)

        print("media_groups", media_groups)
        print("session_lines", session_lines)

        name: str | None = None
        host: str | None = None
        time: str | None = None

        sdp_attrs = []
        groups = list[GroupDescription]()

        session = cls()

        for line in session_lines:
            if line.startswith("v="):
                session.version = int(line.strip()[2:])
            elif line.startswith("o="):
                session.origin = Origin()
                # int(line.strip()[2:])
            elif line.startswith("s="):
                name = line.strip()[2:]
            elif line.startswith("c="):
                pass
                # host = ipaddress_from_sdp(line[2:])
            elif line.startswith("t="):
                time = line.strip()[2:]
            elif line.startswith("a="):
                attr, value = parse_attr(line)
                sdp_attrs.append((attr, value))

                if attr == "fingerprint" and value:
                    algorithm, fingerprint = value.split()
                    dtls_fingerprints.append((algorithm, fingerprint))
                elif attr == "ice-lite":
                    ice_lite = True
                elif attr == "ice-options":
                    ice_options = value
                elif attr == "ice-pwd":
                    ice_password = value
                elif attr == "ice-ufrag":
                    ice_usernameFragment = value
                elif attr == "group" and value:
                    session.add_attribute(
                        SessionDescriptionAttr(SessionDescriptionAttrKey.Group, value)
                    )
                    # parse_group(groups, value)
                elif attr == "msid-semantic" and value:
                    pass
                    # parse_group(groups, value)
                elif attr == "setup":
                    dtls_role = value

        print("groups", groups)

        # print("media groups", len(media_groups))
        # parse media
        for media_lines in media_groups:
            # m = re.match("^m=([^ ]+) ([0-9]+) ([A-Z/]+) (.+)$", media_lines[0])
            media = MediaDescription.parse(media_lines)
            if media is None:
                continue
            session.add_media_description(media)

            #
            # print("media line matched", m)
            # print("media line", media_lines[0])
            # if not m:
            #     continue
            #
            # # check payload types are valid
            # # kind = m.group(1)
            # fmt = m.group(4).split()
            # fmt_int: list[int] | None = None
            # #
            # # if kind in ["audio", "video"]:
            # #     fmt_int = [int(x) for x in fmt]
            # #     for pt in fmt_int:
            # #         assert pt >= 0 and pt < 256
            # #         # assert pt not in rtp.FORBIDDEN_PAYLOAD_TYPES
            # #
            # print(
            #     f"media = port:{int(m.group(2))} profile:{m.group(3)} fmt:{fmt_int or fmt}"
            # )
            #
            # print(f"media_dtls fingerprint:{dtls_fingerprints[:]} role:{dtls_role}")
            #
            # # current_media = MediaDescription(
            # # kind, port=int(m.group(2)), profile=m.group(3), fmt=fmt_int or fmt
            # # )
            # # current_media.dtls = RTCDtlsParameters(
            # #     fingerprints=dtls_fingerprints[:], role=dtls_role
            # # )
            #
            # print(
            #     f"media_ice ice_lite:{ice_lite} ufrag:{ice_usernameFragment} pwd:{ice_password}"
            # )
            #
            # print(f"ice_optionsa {ice_options}")
            # # current_media.ice = RTCIceParameters(
            # #     iceLite=ice_lite,
            # #     usernameFragment=ice_usernameFragment,
            # #     password=ice_password,
            # # )
            # # current_media.ice_options = ice_options
            # # session.media.append(current_media)
            #
            # for line in media_lines[1:]:
            #     if line.startswith("c="):
            #         # host = ipaddress_from_sdp(line[2:])
            #         print(f"media host {host}")
            #     elif line.startswith("a="):
            #         attr, value = parse_attr(line)
            #         if attr == "candidate" and value:
            #             print(f"media candidate {candidate_from_sdp(value)}")
            #         elif attr == "end-of-candidates":
            #             print("media candidate end")
            #         elif attr == "extmap" and value:
            #             ext_id, ext_uri = value.split()
            #             if "/" in ext_id:
            #                 ext_id, ext_direction = ext_id.split("/")
            #
            #             print(f"ext_id:{ext_id} ext_uri:{ext_uri}")
            #
            #             # extension = RTCRtpHeaderExtensionParameters(
            #             # id=int(ext_id), uri=ext_uri
            #             # )
            #             # current_media.rtp.headerExtensions.append(extension)
            #         elif attr == "fingerprint" and value:
            #             algorithm, fingerprint = value.split()
            #             print(f"algo:{algorithm} finger:{fingerprint}")
            #             # current_media.dtls.fingerprints.append(
            #             # RTCDtlsFingerprint(algorithm=algorithm, value=fingerprint)
            #             # )
            #         elif attr == "ice-options" and value:
            #             print("ice-options")
            #             # current_media.ice_options = value
            #         elif attr == "ice-pwd" and value:
            #             print("ice-pwd" + value)
            #             # current_media.ice.password = value
            #         elif attr == "ice-ufrag" and value:
            #             print("ice-ufrag" + value)
            #             # current_media.ice.usernameFragment = value
            #         elif attr == "max-message-size":
            #             print("max-message-size", value)
            #             # current_media.sctpCapabilities = RTCSctpCapabilities(
            #             # maxMessageSize=int(value)
            #             # )
            #         elif attr == "mid" and value:
            #             print("mid" + value)
            #             # current_media.rtp.muxId = value
            #         elif attr == "msid" and value:
            #             print("msid", value)
            #             # current_media.msid = value
            #         elif attr == "rtcp" and value:
            #             port, rest = value.split(" ", 1)
            #             print(f"rtcp {int(port)} {ipaddress_from_sdp(rest)}")
            #             # current_media.rtcp_port = int(port)
            #             # current_media.rtcp_host = ipaddress_from_sdp(rest)
            #         elif attr == "rtcp-mux":
            #             # current_media.rtcp_mux = True
            #             print("rtcp-mux")
            #         elif attr == "setup" and value:
            #             print("DTLS role", value)
            #             # current_media.dtls.role = DTLS_SETUP_ROLE[value]
            #         # elif attr in DIRECTIONS:
            #         #     current_media.direction = attr
            #         elif attr == "rtpmap" and value:
            #             format_id, format_desc = value.split(" ", 1)
            #             bits = format_desc.split("/")
            #
            #             # print(f"channels {int(bits[2])}")
            #             print("TODO: channels check if audio or video", bits)
            #
            #             # if current_media.kind == "audio":
            #             #     if len(bits) > 2:
            #             #         channels = int(bits[2])
            #             #     else:
            #             #         channels = 1
            #             # else:
            #             # channels = None
            #
            #             print(f"kind:{bits[0]} clock-rate:{bits[1]}")
            #             # codec = RTCRtpCodecParameters(
            #             #     mimeType=current_media.kind + "/" + bits[0],
            #             #     channels=channels,
            #             #     clockRate=int(bits[1]),
            #             #     payloadType=int(format_id),
            #             # )
            #             # current_media.rtp.codecs.append(codec)
            #         # elif attr == "sctpmap":
            #         #     format_id, format_desc = value.split(" ", 1)
            #         #     getattr(current_media, attr)[int(format_id)] = format_desc
            #         # elif attr == "sctp-port":
            #         #     current_media.sctp_port = int(value)
            #         elif attr == "ssrc-group" and value:
            #             print(f"ssrc-group {value}")
            #             # parse_group(current_media.ssrc_group, value, type=int)
            #         elif attr == "ssrc" and value:
            #             ssrc_str, ssrc_desc = value.split(" ", 1)
            #             ssrc = int(ssrc_str)
            #             ssrc_attr, ssrc_value = ssrc_desc.split(":", 1)
            #
            #             print(f"ssrc: {ssrc}, {ssrc_attr} {ssrc_value}")
            #
            #             # try:
            #             #     ssrc_info = next(
            #             #         (x for x in current_media.ssrc if x.ssrc == ssrc)
            #             #     )
            #             # except StopIteration:
            #             #     ssrc_info = SsrcDescription(ssrc=ssrc)
            #             #     current_media.ssrc.append(ssrc_info)
            #             # if ssrc_attr in SSRC_INFO_ATTRS:
            #             #     setattr(ssrc_info, ssrc_attr, ssrc_value)

            # if current_media.dtls.role is None:
            #     current_media.dtls = None

            # requires codecs to have been parsed
            # for line in media_lines[1:]:
            #     if line.startswith("a="):
            #         attr, value = parse_attr(line)
            #         if attr == "fmtp" and value:
            #             format_id, format_desc = value.split(" ", 1)
            #             print(f"{format_id} {format_desc}")
            #             # codec = find_codec(int(format_id))
            #             codec = parameters_from_sdp(format_desc)
            #             print(f"{codec}")
            #         elif attr == "rtcp-fb" and value:
            #             bits = value.split(" ", 2)
            #             print(f"rtcp-fb {bits[0]} {bits[1]} {bits[2]}")
            #             # for codec in current_media.rtp.codecs:
            #             # if bits[0] in ["*", str(codec.payloadType)]:
            #             # codec.rtcpFeedback.append(
            #             #     RTCRtcpFeedback(
            #             #         type=bits[1],
            #             #         parameter=bits[2] if len(bits) > 2 else None,
            #             #     )
            #             # )
            #             #
        return session

    def __repr__(self) -> str:
        return f"SessionDescription(media={self.media_descriptions})"

    def marshal(self) -> bytes:
        # https://tools.ietf.org/html/rfc4566#section-5
        # session description
        #
        # v=  (protocol version)
        # o=  (originator and session identifier)
        # s=  (session name)
        # i=* (session information)
        # u=* (uri of description)
        # e=* (email address)
        # p=* (phone number)
        # c=* (connection information -- not required if included in
        # all media)
        # b=* (zero or more bandwidth information lines)
        # one or more time descriptions ("t=" and "r=" lines; see below)
        # z=* (time zone adjustments)
        # k=* (encryption key)
        # a=* (zero or more session attribute lines)
        # zero or more media descriptions
        #
        # time description
        #
        # t=  (time the session is active)
        # r=* (zero or more repeat times)
        #
        # media description, if present
        #
        # m=  (media name and transport address)
        # i=* (media title)
        # c=* (connection information -- optional if included at
        # session level)
        # b=* (zero or more bandwidth information lines)
        # k=* (encryption key)
        # a=* (zero or more media attribute lines)

        m = bytearray()
        _desc_marshal_key_value(m, "v=", byteops.pack_string(str(self.version)))
        _desc_marshal_key_value(m, "o=", self.origin.marshal())
        _desc_marshal_key_value(m, "s=", byteops.pack_string(self.session_name))
        _desc_marshal_key_value(m, "t=", byteops.pack_string("0 0"))

        for attr in self.attributes:
            _desc_marshal_key_value(m, "a=", attr.marshal())

        for media in self.media_descriptions:
            m.extend(media.marshal())

        return bytes(m)


def bundle_match_from_remote(bundle_group: str | None) -> Callable[[str], bool]:
    if bundle_group is None:
        return lambda _: True

    bundle_tags = bundle_group.split(" ")
    return lambda mid: mid in bundle_tags


class RTPComponent(IntEnum):
    RTP = 1
    RTCP = 2


def find_transceiver_by_mid(
    mid: str, transceivers: list[RTPTransceiver]
) -> RTPTransceiver | None:
    for t in transceivers:
        if t.mid and t.mid.value == mid:
            return t
    return


def flatten_media_section_transceivers(media_sections: list[MediaSection]):
    transivers = map(lambda t: t.transceivers, media_sections)
    return list(itertools.chain(*transivers))


def add_candidate_to_media_descriptions(
    media: MediaDescription,
    candidates: list[ice.CandidateProtocol],
    gathering_state: ICEGatherState,
):
    def append_candidate_if_new(
        candidate: ice.CandidateProtocol, attributes: list[SessionDescriptionAttr]
    ):
        nonlocal media

        for attr in attributes:
            if attr.value and attr.value == candidate.to_ice_str():
                return

        media.add_attribute(
            SessionDescriptionAttr(
                SessionDescriptionAttrKey.Candidate, candidate.to_ice_str()
            )
        )

    for candidate in candidates:
        candidate.set_component(RTPComponent.RTP)
        append_candidate_if_new(candidate, media.attributes)

        candidate.set_component(RTPComponent.RTCP)
        append_candidate_if_new(candidate, media.attributes)

        candidate.set_component(RTPComponent.RTP)

    for attr in media.attributes:
        if attr.key == SessionDescriptionAttrKey.EndOfCandidates.value:
            return

    media.add_attribute(
        SessionDescriptionAttr(SessionDescriptionAttrKey.EndOfCandidates)
    )


def add_sender_sdp(desc: MediaDescription, media_section: MediaSection):
    for t in media_section.transceivers:
        sender = t.sender
        if sender is None:
            continue

        track = sender.track
        if track is None:
            continue

        send_params = sender.get_parameters()
        if not send_params:
            print("empty sender encodings. Possible empty track")
            continue

        for encoding in send_params.encodings:
            desc.add_media_source(
                encoding.ssrc, track.stream_id, track.stream_id, track.id
            )
            desc.add_attribute(
                SessionDescriptionAttr(f"msid:{track.stream_id} {track.id}")
            )

        if send_params.encodings:
            for encoding in send_params.encodings:
                desc.add_attribute(
                    SessionDescriptionAttr(
                        SessionDescriptionAttrKey.RID, f"{encoding.rid} send"
                    )
                )

        break


def add_transceiver_media_description(
    desc: SessionDescription,
    media_section: MediaSection,
    should_add_candidates: bool,
    fingerprints: list[dtls.Fingerprint],
    mid: str,
    ice_params: ICEParameters,
    candidates: list[ice.CandidateProtocol],
    role: ConnectionRole,
    gathering_state: ICEGatherState,
    caps: MediaCaps,
) -> bool:
    transceivers = media_section.transceivers
    if len(transceivers) < 1:
        return False

    t = transceivers[0]

    if t.mid is None:
        return False

    codecs = t.get_codecs()
    if codecs is None:
        return False

    media = MediaDescription(
        media=t.kind.value,
        port=9,
        protocols=["UDP", "TLS", "RTP", "SAVPF"],
    )

    media.add_attribute(
        SessionDescriptionAttr(
            SessionDescriptionAttrKey.ConnectionSetup,
            role.value,
        )
    )
    media.add_attribute(SessionDescriptionAttr(SessionDescriptionAttrKey.MID, mid))
    media.add_attribute(SessionDescriptionAttr("ice-ufrag", ice_params.local_ufrag))
    media.add_attribute(SessionDescriptionAttr("ice-pwd", ice_params.local_pwd))

    media.add_attribute(SessionDescriptionAttr(SessionDescriptionAttrKey.RTCPMux))
    media.add_attribute(SessionDescriptionAttr(SessionDescriptionAttrKey.RTCPRsize))

    for codec in codecs:
        media.add_codec(codec)
        for feedback in codec.rtcp_feedbacks:
            media.add_rtcp_feedback(codec, feedback)

    directions = list[RTPTransceiverDirection]()

    if t.sender:
        directions.append(RTPTransceiverDirection.Sendonly)
    if t.receiver:
        directions.append(RTPTransceiverDirection.Recvonly)

    media.direction = t.direction

    # ext_map_stub = [
    #     ExtMap(value=1, uri="urn:ietf:params:rtp-hdrext:sdes:mid"),
    #     ExtMap(
    #         value=3, uri="http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
    #     ),
    # ]
    # negotiated_parameters = caps.get_rtp_parameters_by_kind(t.kind, directions)
    # for rtp_ext in negotiated_parameters.header_extensions:
    # for rtp_ext in ext_map_stub:
    #     media.add_attribute(SessionDescriptionAttr(rtp_ext.marshal()))

    if RTPTransceiverDirection.Recvonly in directions:
        media.add_attribute(
            SessionDescriptionAttr(
                SessionDescriptionAttrKey.RID, f"{media_section.rid} recv"
            )
        )

    # if media_section.rid_map:
    #     for rid in media_section.rid_map.items():
    #         media.add_attribute(
    #             SessionDescriptionAttr(SessionDescriptionAttrKey.RID, f"{rid} recv")
    #         )

    add_sender_sdp(media, media_section)

    print("Current direction ", t.direction.value)
    media.add_attribute(SessionDescriptionAttr(t.direction.value))

    for fingerprint in fingerprints:
        media.add_attribute(
            SessionDescriptionAttr(
                "fingerprint", fingerprint.algorithm + " " + fingerprint.value.upper()
            )
        )

    if should_add_candidates:
        add_candidate_to_media_descriptions(media, candidates, gathering_state)

    desc.add_media_description(media)

    return True


def populate_session_descriptor(
    desc: SessionDescription,
    # is_plan_b: bool,
    fingerprints: list[dtls.Fingerprint],
    is_extmap_allow_mixed: bool,
    role: ConnectionRole,
    candidates: list[ice.CandidateProtocol],
    ice_params: ICEParameters,
    media_sections: list[MediaSection],
    gathering_state: ICEGatherState,
    match_bundle_group: str | None,
    caps: MediaCaps,
):
    bundle_value: str = "BUNDLE"
    bundle_count: int = 0

    bundle_matcher = bundle_match_from_remote(match_bundle_group)

    def bundle_appender(mid: str):
        nonlocal bundle_value, bundle_count
        bundle_value += " " + mid
        bundle_count += 1

    for idx, media in enumerate(media_sections):
        # should_add_candidates = idx == 0
        should_add_candidates = False

        if media.data:
            print("media session desc contain SCTP. Not supported")
            continue

        should_add_id = add_transceiver_media_description(
            desc,
            media,
            should_add_candidates,
            fingerprints,
            media.id,
            ice_params,
            candidates,
            role,
            gathering_state,
            caps,
        )

        if should_add_id:
            if bundle_matcher(media.id):
                bundle_appender(media.id)

    if fingerprints:
        for fingerprint in fingerprints:
            desc.add_attribute(
                SessionDescriptionAttr(
                    SessionDescriptionAttrKey.Fingerprint,
                    fingerprint.algorithm + " " + fingerprint.value.upper(),
                )
            )

    if is_extmap_allow_mixed:
        desc.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.ExtMapAllowMixed)
        )

    if bundle_count > 0:
        desc.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.Group, bundle_value)
        )

    return desc


def set_default_caps(caps: MediaCaps):
    caps.register_codec(
        RTPCodecParameters(
            mime_type="audio/opus",
            clock_rate=48000,
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
        channels=0,
        sdp_fmtp_line="",
        payload_type=96,
        stats_id=f"RTPCodec-{current_ntp_time() >> 32}",
    )

    # vp8.rtcp_feedbacks.append(nack_pli)
    # vp8.rtcp_feedbacks.append(remb)

    caps.register_codec(vp8, RTPCodecKind.Video)


class SignalingState(Enum):
    Unknown = "unknown"
    # Stable indicates there is no offer/answer exchange in
    # progress. This is also the initial state, in which case the local and
    # remote descriptions are nil.
    Stable = "stable"
    # HaveLocalOffer indicates that a local description, of
    # type "offer", has been successfully applied.
    HaveLocalOffer = "have-local-offer"
    # HaveRemoteOffer indicates that a remote description, of
    # type "offer", has been successfully applied.
    HaveRemoteOffer = "have-remote-offer"
    # HaveLocalPranswer indicates that a remote description
    # of type "offer" has been successfully applied and a local description
    # of type "pranswer" has been successfully applied.
    HaveLocalPranswer = "have-local-pranswer"
    # HaveRemotePranswer indicates that a local description
    # of type "offer" has been successfully applied and a remote description
    # of type "pranswer" has been successfully applied.
    HaveRemotePranswer = "have-remote-pranswer"
    # Closed indicates The PeerConnection has been closed.
    Closed = "closed"


class SignalingChangeOperation(Enum):
    SetLocal = "set-local"
    SetRemote = "set-remote"


class SessionDescriptionType(Enum):
    Offer = "offer"
    Answer = "answer"
    Rollback = "rollback"
    Pranswer = "pranswer"


class SignalingStateTransitionError(Exception):
    def __init__(self, message):
        super().__init__(message)


# https://www.w3.org/TR/webrtc/#rtcsignalingstate-enum
def ensure_next_signaling_state(
    curr_state: SignalingState,
    next_state: SignalingState,
    operation: SignalingChangeOperation,
    desc_type: SessionDescriptionType,
):
    if (
        desc_type == SessionDescriptionType.Rollback
        and curr_state == SignalingState.Stable
    ):
        raise SignalingStateTransitionError("Cannot rollback stable state")

    if curr_state == SignalingState.Stable:
        if operation == SignalingChangeOperation.SetLocal:
            if (
                desc_type == SessionDescriptionType.Offer
                and next_state == SignalingState.HaveLocalOffer
            ):
                return next_state
        elif operation == SignalingChangeOperation.SetRemote:
            if (
                desc_type == SessionDescriptionType.Offer
                and next_state == SignalingState.HaveRemoteOffer
            ):
                return next_state
    elif curr_state == SignalingState.HaveLocalOffer:
        if operation == SignalingChangeOperation.SetRemote:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state
            elif (
                desc_type == SessionDescriptionType.Pranswer
                and next_state == SignalingState.HaveRemotePranswer
            ):
                return next_state
    elif curr_state == SignalingState.HaveRemotePranswer:
        if operation == SignalingChangeOperation.SetRemote:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state
    elif curr_state == SignalingState.HaveRemoteOffer:
        if operation == SignalingChangeOperation.SetLocal:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state
            elif (
                desc_type == SessionDescriptionType.Pranswer
                and next_state == SignalingState.HaveLocalPranswer
            ):
                return next_state
    elif curr_state == SignalingState.HaveLocalPranswer:
        if operation == SignalingChangeOperation.SetLocal:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state

    raise SignalingStateTransitionError(
        f"Invalid state transition: {curr_state}->{operation}({desc_type})->{next_state}"
    )


class PeerConnectionEvent:
    SignalingStateChange = "signaling-state-change"


# TODO: Watch into ORTC API
class PeerConnection(AsyncEventEmitter):
    def __init__(self) -> None:
        super().__init__()

        self.gatherer = ICEGatherer()

        self._certificate = dtls.Certificate.generate_certificate()
        self._certificates: list[dtls.Certificate] = [self._certificate]

        self._dtls_transports = list[dtls.DTLSTransport]()

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
        self._sdp_semantic: SDPSemantic = SDPSemantic.UnifiedPlan

        self._transceivers = list[RTPTransceiver]()

        self._closed: bool = False
        self._peer_connection_lock = asyncio.Lock()

    async def add_transceiver_from_track(
        self, track: TrackLocal, direction: RTPTransceiverDirection
    ) -> RTPTransceiver:
        # TODO: this may contain directly transport creation
        # gathering process may take that list/set of transports
        transport = ICETransport(self.gatherer)
        dtls_transport = dtls.DTLSTransport(transport, self._certificate)
        self._dtls_transports.append(dtls_transport)

        receiver: RTPReceiver | None = None
        sender: RTPSender | None = None

        match direction:
            case RTPTransceiverDirection.Sendrecv:
                # TODO: add logic
                receiver = RTPReceiver(self._caps)
                sender = RTPSender(self._caps, dtls_transport)
            case RTPTransceiverDirection.Sendonly:
                sender = RTPSender(self._caps, dtls_transport)
            case RTPTransceiverDirection.Recvonly:
                receiver = RTPReceiver(self._caps)

        if sender:
            await sender.add_encoding(track)

        transceiver = RTPTransceiver(
            caps=self._caps, kind=track.kind, direction=direction
        )
        transceiver.set_prefered_codec(track._rtp_codec_params)

        if sender:
            transceiver.set_sender(sender)
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
            print("TODO: make recv only")
            codecs = self._caps.get_codecs_by_kind(kind)
            track = TrackLocal(random_string(16), random_string(16), kind, codecs[0])
            return await self.add_transceiver_from_track(track, direction)
        else:
            raise ValueError("Unknown direction")

    async def set_local_description(
        self, desc_type: SessionDescriptionType, desc: SessionDescription
    ):
        async with self._signaling_lock:
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
                        self._current_remote_description = (
                            self._pending_remote_description
                        )

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
        async with self._signaling_lock:
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
                        self._current_local_description = (
                            self._pending_local_description
                        )

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
                            await self.add_transceiver_from_track(
                                track, media.direction
                            )
                            print("Create transciver from track", kind, media.codecs[0])
                        else:
                            print("Create transciver from kind", kind, media.direction)
                            await self.add_transceiver_from_kind(kind, media.direction)

            # NOTE: Here may be also restart and updating candidates
            # TODO: May also start transports
            # TODO: This also may remote all unmatched transceivers

    def _get_sdp_role(self) -> ConnectionRole:
        role = self.gatherer.agent.get_role()
        print(f"Set SDP from agent {role}")
        # The ICE controlling role acts as the server.
        if role == ice.AgentRole.Controlling:
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

        ice_params = self.gatherer.get_local_parameters()
        if ice_params is None:
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

        return populate_session_descriptor(
            desc=desc,
            fingerprints=fingerprints,
            is_extmap_allow_mixed=True,
            role=self._get_sdp_role(),
            candidates=ice_candidates,
            ice_params=ice_params,
            media_sections=media_sections,
            gathering_state=self.gatherer.get_gather_state(),
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
            role=self._get_sdp_role(),
            candidates=ice_candidates,
            ice_params=ice_params,
            media_sections=media_sections,
            gathering_state=self.gatherer.get_gather_state(),
            match_bundle_group=group,
            caps=self._caps,
        )

    async def create_offer(self, options: OfferOption | None = None):
        # if self._closed:
        #     raise ValueError("connection closed")

        try:
            # if options and options.ice_restart:
            #     self._transport.restart()

            async with self._peer_connection_lock:
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
