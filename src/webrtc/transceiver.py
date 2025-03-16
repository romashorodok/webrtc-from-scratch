import asyncio
from dataclasses import dataclass
import fractions
import queue
import secrets
from enum import Enum
import threading
from typing import Any, Callable, Coroutine, Protocol

from . import media
from .utils import impl_protocol
from .media.packetizer import Packetizer, get_payloader_by_payload_type
from . import dtls


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
        refresh_rate: float,
        channels: int,
        sdp_fmtp_line: str,
        payload_type: int,
        stats_id: str,
    ) -> None:
        self.mime_type = mime_type
        self.clock_rate = clock_rate
        self.refresh_rate = refresh_rate
        self.channels = channels
        self.sdp_fmtp_line = sdp_fmtp_line
        self.payload_type = payload_type
        self.stats_id = stats_id
        self.rtcp_feedbacks = list[RTCPFeedback]()


class RTPWriterProtocol(Protocol):
    async def write_frame(self, frame: bytes) -> int: ...
    async def write_rtp_bytes(self, rtp_packet: media.RtpPacket) -> int: ...


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
        self._writer: RTPWriterProtocol | None = None

    async def write_frame(self, frame: bytes) -> int:
        if not self._writer:
            return 0
        return await self._writer.write_frame(frame)

    async def write_rtp_packet(self, pkt: media.RtpPacket) -> int:
        if not self._writer:
            return 0
        return await self._writer.write_rtp_bytes(pkt)

    def bind(self, writer: RTPWriterProtocol):
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


@impl_protocol(RTPWriterProtocol)
class TrackEncoding:
    def __init__(self, ssrc: int, track: TrackLocal) -> None:
        # TODO: remove track from this place
        self.track = track
        self.codec = track._rtp_codec_params
        self.ssrc = ssrc
        self._dtls: dtls.DTLSTransport | None = None

        payloader = get_payloader_by_payload_type(self.codec.payload_type)
        if not payloader:
            raise ValueError("Unknown payloader type")

        self._packetizer = Packetizer(
            mtu=1200,
            pt=self.codec.payload_type,
            ssrc=self.ssrc,
            payloader=payloader,
            clock_rate=self.codec.clock_rate,
            refresh_rate=self.codec.refresh_rate,
        )

    def bind(self, transport: dtls.DTLSTransport):
        self._dtls = transport

    def convert_timebase(
        self, pts: int, from_base: fractions.Fraction, to_base: fractions.Fraction
    ) -> int:
        if from_base != to_base:
            pts = int(pts * from_base / to_base)
        return pts

    async def write_rtp_bytes(self, rtp_packet: media.RtpPacket) -> int:
        if not self._dtls:
            print("write_rtp | Not found transport")
            return 0

        rtp_packet.ssrc = self.ssrc

        return await self._dtls.write_rtp_bytes(rtp_packet.serialize())

    async def write_frame(self, frame: bytes) -> int:
        if not self._dtls:
            print("write_frame | Not found transport")
            return 0

        pts, time_base = await self._packetizer.next_timestamp()

        pkts = self._packetizer.packetize(
            frame, self.convert_timebase(pts, time_base, time_base)
        )

        n = 0
        for pkt in pkts:
            n += await self._dtls.write_rtp_bytes(pkt.serialize())
        return n


# RTPRtxParameters dictionary contains information relating to retransmission (RTX) settings.
# https://draft.ortc.org/#dom-rtcrtprtxparameters
@dataclass
class RTPRtxParameters:
    ssrc: int


# RTPEncodingParameters provides information relating to both encoding and decoding.
# This is a subset of the RFC since Pion WebRTC doesn't implement encoding itself
# http://draft.ortc.org/#dom-rtcrtpencodingparameters
class RTPEncodingParameters:
    def __init__(
        self,
        rid: str,
        ssrc: int,
        payload_type: int,
        rtx: RTPRtxParameters | None = None,
    ) -> None:
        self.rid = rid
        self.ssrc = ssrc
        self.payload_type = payload_type
        # https://draft.ortc.org/#dom-rtcrtprtxparameters
        self.rtx = rtx


@dataclass
class RTPDecodingParameters:
    rid: str
    ssrc: int
    payload_type: int
    rtx: RTPRtxParameters


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


class RTPSendParameters:
    def __init__(
        self, rtp_parameters: RTPParameters, encodings: list[RTPEncodingParameters]
    ) -> None:
        self.encodings = encodings
        self.rtp_parameters = rtp_parameters


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


class RTPSender:
    def __init__(self, caps: MediaCaps) -> None:
        self._track_encodings = list[TrackEncoding]()
        self._payload_type: int = 0
        self._caps = caps
        self._track: TrackLocal | None = None
        self.__transport: dtls.DTLSTransport | None = None
        self.__transport_lock = asyncio.Lock()

    async def bind(self, transport: dtls.DTLSTransport):
        async with self.__transport_lock:
            self.__transport = transport
            for enc in self._track_encodings:
                enc.bind(transport)

    async def add_encoding(self, track: TrackLocal):
        async with self.__transport_lock:
            enc = TrackEncoding(ssrc=secrets.randbits(32), track=track)
            if self.__transport:
                enc.bind(self.__transport)
            self._track_encodings.append(enc)

        await self.replace_track(track)

    async def replace_track(self, track: TrackLocal):
        for encoding in self._track_encodings:
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


class TrackRemote:
    def __init__(
        self,
        kind: RTPCodecKind,
        ssrc: int,  # uint32
        rtx_ssrc: int,  # uint32
        rid: str,
    ) -> None:
        self.kind = kind
        self.ssrc = ssrc
        self.rtx_ssrc = rtx_ssrc
        self.rid = rid

        self._rtp_packet_queue = queue.Queue[media.RtpPacket]()

    def write_rtp_bytes_sync(self, data: bytes):
        self._rtp_packet_queue.put(media.RtpPacket.parse(data))

    def recv_rtp_pkt_sync(self) -> media.RtpPacket:
        return self._rtp_packet_queue.get()


def _receive_worker(
    done_signal: threading.Event,
    reader: Callable[[], Coroutine[Any, Any, tuple[bytes, int]]],
    track: TrackRemote,
):
    loop = asyncio.new_event_loop()

    while True:
        try:
            if done_signal.is_set():
                return

            future = reader()
            if not asyncio.iscoroutine(future):
                raise TypeError(
                    f"Reader expected to be a coroutine, got {type(future)}"
                )

            data, n = loop.run_until_complete(future)
            if n == 0:
                print("__rtp_reader EOF")
                loop.run_until_complete(asyncio.sleep(1))
                continue

            print("Recv rtp??", data)
            track.write_rtp_bytes_sync(data)

        except ValueError:
            pass


class RTPReceiver:
    def __init__(self, caps: MediaCaps, kind: RTPCodecKind) -> None:
        self._caps = caps
        self._kind = kind
        self._dtls: dtls.DTLSTransport | None = None
        self._track: TrackRemote | None = None
        self._receive_thread: threading.Thread | None = None
        self._done_signal = threading.Event()

    def bind(self, transport: dtls.DTLSTransport):
        self._dtls = transport

    def __rtp_reader(self) -> Callable[[], Coroutine[Any, Any, tuple[bytes, int]]]:
        async def read() -> tuple[bytes, int]:
            reader = self._dtls
            if not reader:
                print("Not found dtls transport for __rtp_reader")
                return (bytes(), 0)
            return await reader.read_rtp_bytes()

        return read

    def receive(self, params: RTPDecodingParameters):
        if self._receive_thread:
            print("Receiver already started")
            return

        self._track = TrackRemote(self._kind, params.ssrc, params.rtx.ssrc, params.rid)
        self._done_signal.clear()
        self._receive_thread = threading.Thread(
            # TODO: pass into worker queue and send None if worker should stop
            target=_receive_worker,
            name=f"RTPReceiver-{self._track.ssrc}",
            args=(self._done_signal, self.__rtp_reader(), self._track),
        )
        self._receive_thread.start()

    def stop(self):
        if self._receive_thread:
            self._receive_thread.join()
            self._done_signal.set()

    @property
    def track(self) -> TrackRemote | None:
        return self._track


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
        self.__dtls: dtls.DTLSTransport | None = None

    async def bind(self, transport: dtls.DTLSTransport):
        if self._sender:
            await self._sender.bind(transport)
        if self._receiver:
            self._receiver.bind(transport)

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

    async def set_sender(self, sender: RTPSender):
        if self.__dtls:
            await sender.bind(self.__dtls)
        self._sender = sender

    @property
    def receiver(self) -> RTPReceiver | None:
        return self._receiver

    def set_receiver(self, receiver: RTPReceiver):
        if self.__dtls:
            receiver.bind(self.__dtls)

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


def find_transceiver_by_mid(
    mid: str, transceivers: list[RTPTransceiver]
) -> RTPTransceiver | None:
    for t in transceivers:
        if t.mid and t.mid.value == mid:
            return t
    return
