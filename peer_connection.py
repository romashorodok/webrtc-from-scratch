from abc import abstractmethod
import asyncio
from dataclasses import dataclass
import datetime
from typing import Any, Callable, Generic, TypeVar

import secrets
import string

from OpenSSL.SSL import Session
import ice
import ice.net
import dtls

import socket

from enum import Enum, IntEnum

import ice.stun.utils as byteops


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
            agent = await self._create_agent()
            self._set_state(ICEGatherState.Gathering)
            self._agent = agent

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


class ICETransport:
    def __init__(self, gatherer: ICEGatherer) -> None:
        self._gatherer = gatherer
        self._loop = asyncio.get_event_loop()
        self._state: ICETransportState = ICETransportState.NEW

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


class RTPCodecKind(IntEnum):
    Unknown = 0
    Audio = 1
    Video = 2


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


class TrackEncoding:
    def __init__(self, ssrc: int, track: TrackLocal | None = None) -> None:
        self.track = track
        self.ssrc = ssrc


class RTPSender:
    def __init__(self, caps: MediaCaps) -> None:
        self._track_encodings = list[TrackEncoding]()
        self._payload_type: int = 0
        self._caps = caps
        self._track: TrackLocal | None = None

    def add_encoding(self, track: TrackLocal):
        self._track_encodings.append(
            TrackEncoding(ssrc=secrets.randbits(32), track=track)
        )
        self.replace_track(track)

    def replace_track(self, track: TrackLocal):
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
    def __init__(self) -> None:
        pass


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

        print("filtered", filtered_codecs)

        return filtered_codecs

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


# TimeDescription describes "t=", "r=" fields of the session description
# which are used to specify the start and stop times for a session as well as
# repeat intervals and durations for the scheduled session.
# class TimeDescription:
#     def __init__(self) -> None:
#         # t=<start-time> <stop-time>
#         # https://tools.ietf.org/html/rfc4566#section-5.9
#         self.start_time: int = 0  # int64
#         self.stop_time: int = 0  # int64
#
#         # r=<repeat interval> <active duration> <offsets from start-time>
#         # https://tools.ietf.org/html/rfc4566#section-5.10
#         self.interval: int = 0  # int64
#         self.duration: int = 0  # int64
#         self.offsets: list[int] | None = None  # list[int64]
#


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

        direction = self.direction
        if direction == RTPTransceiverDirection.Unknown or self.direction is None:
            out += "/ "

        if self.uri:
            out += f" {self.uri}"

        if self.ext_attr:
            out += f" {self.ext_attr}"

        return out


class MediaSection:
    def __init__(
        self,
        id: str,
        transceivers: list[RTPTransceiver],
        rid_map: dict[str, SimulcastRid] | None = None,
    ) -> None:
        self.id = id
        self.transceivers = transceivers

        # NOTE: i not will use sctp
        self.data = False
        self.rid_map = rid_map


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
        formats: list[str],
        network_type: str,
        address_type: str,
        address: str,
    ) -> None:
        self.media = media
        self.port = port
        self.port_end: int | None = port
        self.protocols = protocols
        self.formats = formats
        self.network_type = network_type
        self.address_type = address_type
        self.address = address

        # a=<attribute>
        # a=<attribute>:<value>
        # https://tools.ietf.org/html/rfc4566#section-5.13
        self._attributes = list[SessionDescriptionAttr]()

    def __repr__(self) -> str:
        return f"MediaDescription(_attributes={self._attributes})"

    def add_codec(self, codec: RTPCodecParameters):
        self.formats.append(str(codec.payload_type))
        name = codec.mime_type.removeprefix("audio/")
        name = name.removeprefix("video/")
        rtpmap = f"{codec.payload_type} {name}/{codec.clock_rate}"
        if codec.channels > 0:
            rtpmap += f"/{codec.channels}"
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
        # Also may looks like this, but this formats deprecated
        # "%d cname:%s", ssrc, cname
        # "%d mslabel:%s", ssrc, stream_label
        # "%d label:%s", ssrc, label
        value = f"{ssrc} msid:{stream_label} {label}"
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        )

    @property
    def attributes(self) -> list[SessionDescriptionAttr]:
        return self._attributes

    def add_attribute(self, attr: SessionDescriptionAttr):
        self._attributes.append(attr)

    def _marshal_ports(self) -> bytes:
        m = bytearray()

        m.extend(byteops.pack_unsigned(self.port))
        if self.port_end:
            m.extend(byteops.pack_string("/"))
            m.extend(byteops.pack_unsigned(self.port_end))

        return m

    def _marshal_name(self) -> bytes:
        m = bytearray()
        m.extend(byteops.pack_string(self.media + " "))
        m.extend(self._marshal_ports())
        m.extend(byteops.pack_string(" "))
        m.extend(byteops.pack_string(_append_list(self.protocols, "/")))
        m.extend(byteops.pack_string(" "))
        m.extend(byteops.pack_string(_append_list(self.formats, " ")))
        self.media

        return m

    def marshal(self) -> bytes:
        m = bytearray()
        _desc_marshal_key_value(m, "m=", self._marshal_name())
        for attr in self.attributes:
            _desc_marshal_key_value(m, "a=", attr.marshal())
        return m


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

    def add_media_description(self, desc: MediaDescription):
        self.media_descriptions.append(desc)

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
        _desc_marshal_key_value(m, "v=", byteops.pack_unsigned_64(self.version))
        _desc_marshal_key_value(m, "o=", self.origin.marshal())
        _desc_marshal_key_value(m, "s=", byteops.pack_string(self.session_name))

        for attr in self.attributes:
            _desc_marshal_key_value(m, "a=", attr.marshal())

        for media in self.media_descriptions:
            m.extend(media.marshal())

        return m


def bundle_match_from_remote(bundle_group: str | None) -> Callable[[str], bool]:
    if bundle_group is None:
        return lambda _: True

    bundle_tags = bundle_group.split(" ")
    return lambda mid: mid in bundle_tags


MEDIA_DESCRIPTION_SECTION_APPLICATION = "application"


class RTPComponent(IntEnum):
    RTP = 1
    RTCP = 2


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

    # if gathering_state != ICEGatherState.Complete:
    #     return

    for attr in media.attributes:
        if attr.key == SessionDescriptionAttrKey.EndOfCandidates.value:
            return

    media.add_attribute(
        SessionDescriptionAttr(SessionDescriptionAttrKey.EndOfCandidates)
    )


def add_sender_sdp(
    desc: MediaDescription, media_section: MediaSection, is_plan_b: bool
):
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
            if not is_plan_b:
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

        if not is_plan_b:
            break


def add_transceiver_media_description(
    desc: SessionDescription,
    media_section: MediaSection,
    is_plan_b: bool,
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
    print("sdp", t)
    if codecs is None:
        return False

    media = MediaDescription(
        media=t.mid.value,
        port=9,
        protocols=["UDP", "TLS", "RTP", "SAVPF"],
        formats=["0"],
        network_type="IN",
        address_type="IP4",
        address="0.0.0.0",
    )

    media.add_attribute(
        SessionDescriptionAttr(
            SessionDescriptionAttrKey.ConnectionSetup,
            role.value,
        )
    )
    media.add_attribute(SessionDescriptionAttr(SessionDescriptionAttrKey.MID, mid))
    media.add_attribute(SessionDescriptionAttr(RTPTransceiverDirection.Sendrecv.value))
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

    negotiated_parameters = caps.get_rtp_parameters_by_kind(t.kind, directions)
    for rtp_ext in negotiated_parameters.header_extensions:
        ext_uri = ExtMap(value=rtp_ext.id, uri=rtp_ext.uri)
        media.add_attribute(SessionDescriptionAttr(ext_uri.marshal()))

    if media_section.rid_map:
        for rid in media_section.rid_map.items():
            media.add_attribute(
                SessionDescriptionAttr(SessionDescriptionAttrKey.RID, f"{rid} recv")
            )
        # TODO: add attr for simulcast

    add_sender_sdp(media, media_section, is_plan_b)

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
    is_plan_b: bool,
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
        if not is_plan_b and len(media.transceivers) > 1:
            raise ValueError("media section multiple track invalid")

        should_add_candidates = idx == 0

        if media.data:
            print("media session desc contain SCTP. Not supported")
            continue

        should_add_id = add_transceiver_media_description(
            desc,
            media,
            is_plan_b,
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


# SessionDescription contains a MediaSection with name `audio`, `video` or `data`
# If only one SSRC is set we can't know if it is Plan-B or Unified. If users have
# set fallback mode assume it is Plan-B
def description_possibly_plan_b(desc: SessionDescription) -> bool:
    print("Implement plan b check. In description_possibly_plan_b")
    return False


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

    vp8.rtcp_feedbacks.append(nack_pli)
    vp8.rtcp_feedbacks.append(remb)

    caps.register_codec(vp8, RTPCodecKind.Video)


# TODO: Watch into ORTC API
class PeerConnection:
    def __init__(self) -> None:
        self.gatherer = ICEGatherer()
        self._transport = ICETransport(self.gatherer)
        self._certificates: list[dtls.Certificate] = [
            dtls.Certificate.generate_certificate()
        ]
        self._caps = MediaCaps()
        set_default_caps(self._caps)
        self.origin = Origin()

        self._greater_mid: int = 0
        self._sdp_semantic: SDPSemantic = SDPSemantic.UnifiedPlan
        self._current_remote_description: SessionDescription | None = None

        self._transceivers = list[RTPTransceiver]()

        self._controlling: bool = True

        self._closed: bool = False
        self._lock = asyncio.Lock()

    def add_transceiver_from_track(
        self, track: TrackLocal, direction: RTPTransceiverDirection
    ) -> RTPTransceiver:
        receiver: RTPReceiver | None = None
        sender: RTPSender | None = None

        match direction:
            case RTPTransceiverDirection.Sendrecv:
                # TODO: add logic
                receiver = RTPReceiver()
                sender = RTPSender(self._caps)
            case RTPTransceiverDirection.Sendonly:
                sender = RTPSender(self._caps)

        if sender:
            sender.add_encoding(track)

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

    def add_transceiver_from_kind(
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

            return self.add_transceiver_from_track(track, direction)
        elif direction is RTPTransceiverDirection.Recvonly:
            print("TODO: make recv only")
            codecs = self._caps.get_codecs_by_kind(kind)
            track = TrackLocal(random_string(16), random_string(16), kind, codecs[0])
            return self.add_transceiver_from_track(track, direction)
        else:
            raise ValueError("Unknown direction")

    def _get_sdp_role(self) -> ConnectionRole:
        # The ICE controlling role acts as the server.
        if self._controlling:
            return ConnectionRole.Passive

        # The ICE controlled role acts as client which connect to the server
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

        is_plan_b = self._sdp_semantic == SDPSemantic.PlanB
        if is_plan_b and (remote_desc := self._current_remote_description):
            is_plan_b = description_possibly_plan_b(remote_desc)

        media_sections = list[MediaSection]()

        if is_plan_b:
            video = list[RTPTransceiver]()
            audio = list[RTPTransceiver]()

            for t in transceivers:
                match t.kind:
                    case RTPCodecKind.Video:
                        video.append(t)
                    case RTPCodecKind.Audio:
                        audio.append(t)
                if sender := t.sender:
                    sender.negotiate()

            if len(video) > 0:
                media_sections.append(MediaSection(id="video", transceivers=video))
            if len(audio) > 0:
                media_sections.append(MediaSection(id="audio", transceivers=audio))
        else:
            for t in transceivers:
                if sender := t.sender:
                    sender.negotiate()

                if t.mid and t.mid.value:
                    media_sections.append(
                        MediaSection(
                            id=t.mid.value, transceivers=list[RTPTransceiver]([t])
                        )
                    )
                else:
                    print("Not found transceiver mid. Must be already defined")

        fingerprints = self._certificates[0].get_fingerprints()

        return populate_session_descriptor(
            desc=desc,
            is_plan_b=is_plan_b,
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
    def _generate_matched_sdp(
        self,
        transceivers: list[RTPTransceiver],
        use_identity: bool,
        include_unmatched: bool,
        connection_role: ConnectionRole,
    ) -> SessionDescription | None: ...

    async def create_offer(self, options: OfferOption | None = None):
        # TODO: what is idpLoginURL identity
        use_identity = False

        # if not self._closed:
        #     raise ValueError("connection closed")

        try:
            if options and options.ice_restart:
                self._transport.restart()

            # This may be necessary to recompute if, for example, createOffer was called when only an
            # audio RTCRtpTransceiver was added to connection, but while performing the in-parallel
            # steps to create an offer, a video RTCRtpTransceiver was added, requiring additional
            # inspection of video system resources.
            async with self._lock:
                count = 0
                # Cache current transceivers to ensure they aren't mutated during offer
                # generation. Later will check if they have been mutated and recompute if necessary
                current_transceivers = self._transceivers.copy()

                plan_b = self._sdp_semantic == SDPSemantic.PlanB
                if plan_b and (remote_desc := self._current_remote_description):
                    plan_b = description_possibly_plan_b(remote_desc)

                if not plan_b:
                    # update the greater mid if the remote description provides a greater one
                    if remote_desc := self._current_remote_description:
                        print("TODO: update mid if remote description provided")
                        pass

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
                    desc = self._generate_matched_sdp(
                        current_transceivers, use_identity, True, self._get_sdp_role()
                    )

                if desc:
                    desc.origin.session_version = self.origin.session_version
                    self.origin.session_version += 1

                return desc

        except RuntimeError as e:
            print("Create offer error", e)
