import asyncio
from dataclasses import dataclass
import fractions
import secrets
from enum import Enum
from typing import Any, Callable, Coroutine, Protocol

import webrtc_rs

from webrtc.media.av1_payloader import AV1_PAYLOAD_TYPE, Av1Packetizer
from webrtc.media.opus_payloader import OPUS_PAYLOAD_TYPE, OpusPacketizer
from webrtc.media.vp8_payloader import VP8Payloader
from webrtc.performance import ObservedComponent, event_loop, task
from webrtc.runtime_services import FailurePolicy
from webrtc.srtp import Stream as SrtpStream
from webrtc.tracing import measure_perf_async, perf_mark

from . import media
from .utils import impl_protocol
from .media.packetizer import Packetizer, PacketizerBase, get_payloader_by_payload_type
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

        if 96 == self.codec.payload_type:
            payloader = VP8Payloader()
            self._packetizer: PacketizerBase = Packetizer(
                mtu=1200,
                pt=self.codec.payload_type,
                ssrc=self.ssrc,
                payloader=payloader,
                clock_rate=self.codec.clock_rate,
                refresh_rate=self.codec.refresh_rate,
            )
        elif self.codec.payload_type == AV1_PAYLOAD_TYPE:
            self._packetizer: PacketizerBase = Av1Packetizer(
                mtu=1200,
                pt=self.codec.payload_type,
                ssrc=self.ssrc,
                clock_rate=self.codec.clock_rate,
                refresh_rate=self.codec.refresh_rate,
            )
        elif self.codec.payload_type == OPUS_PAYLOAD_TYPE:
            # Opus audio - always use 20ms packet time (standard for Opus)
            self._packetizer: PacketizerBase = OpusPacketizer(
                mtu=1200,
                pt=self.codec.payload_type,
                ssrc=self.ssrc,
                clock_rate=self.codec.clock_rate,
                ptime=0.020,  # Fixed 20ms for Opus, not codec.refresh_rate
            )

    def bind(self, transport: dtls.DTLSTransport):
        self._dtls = transport

    def convert_timebase(
        self, pts: int, from_base: fractions.Fraction, to_base: fractions.Fraction
    ) -> int:
        if from_base != to_base:
            scale = from_base / to_base  # Fraction
            pts = int(pts * scale)
        return pts

    async def write_rtp_bytes(self, rtp_packet: media.RtpPacket) -> int:
        raise ValueError("Not implemented")

        if not self._dtls:
            print("write_rtp | Not found transport")
            return 0

        rtp_packet.ssrc = self.ssrc

        return await self._dtls.write_rtp_bytes(rtp_packet.serialize())

    async def write_rtp_raw_bytes(self, rtp_packet_raw: bytes):
        if not self._dtls:
            print(f"write_rtp_bytes_raw {self.ssrc} | not found dtls")
            return 0
        pkt = media.RtpPacket.parse(rtp_packet_raw)
        pkt.ssrc = self.ssrc

        await self._dtls.encrypt_rtp_bytes(pkt.serialize())

    async def write_frame(self, frame: bytes) -> int:
        if not self._dtls:
            print("write_frame | Not found transport")
            return 0

        pts, time_base = await self._packetizer.next_timestamp()
        timestamp = self.convert_timebase(pts, time_base, time_base)
        metadata: dict[str, int | str] = {
            "flow_direction": "tx",
            "codec": self.codec.mime_type,
            "frame_bytes": len(frame),
            "mtu": self._packetizer.mtu,
        }
        async with measure_perf_async("rtp", "frame.packetize", metadata=metadata):
            pkts = self._packetizer.packetize(frame, timestamp)
            metadata.update(
                {
                    "packet_count": len(pkts),
                    "ssrc": self.ssrc,
                    "timestamp": timestamp,
                    "counter.rtp.frames_packetized": 1,
                    "counter.rtp.packets_packetized": len(pkts),
                }
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
        self._rtcp_stream: SrtpStream | None = None

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

        self.__stream: SrtpStream | None = None
        self.__queue = asyncio.Queue[bytes](maxsize=1000)

    async def recv(self) -> bytes:
        """
        Read decrypted RTP packet from stream.

        WARNING: This method reads directly from SRTP stream and will compete
        with _receive_task if both are used. Use recv_rtp_pkt_sync() instead
        to read from the queue.
        """
        import traceback
        print(f"[TrackRemote.recv] CALLED for SSRC={self.ssrc} - THIS STEALS PACKETS FROM _receive_task!")
        print(f"[TrackRemote.recv] Call stack:\n{''.join(traceback.format_stack())}")
        return await self.stream.read()

    @property
    def stream(self) -> SrtpStream:
        if not self.__stream:
            raise ValueError("Unable get stream")

        return self.__stream

    @stream.setter
    def stream(self, value: SrtpStream):
        self.__stream = value

    async def write_rtp_bytes(self, data: bytes) -> bool:
        """Make a decrypted RTP packet visible to the application queue."""
        try:
            self.__queue.put_nowait(data)
            metadata: dict[str, int | str] = {
                "flow_direction": "rx",
                "packet_kind": "rtp",
                "ssrc": self.ssrc,
                "plaintext_size_bytes": len(data),
                "counter.rtp.packets_received": 1,
            }
            if len(data) >= 4:
                metadata["sequence_number"] = int.from_bytes(data[2:4], "big")
            perf_mark("rtp", "packet.receive", "completed", metadata=metadata)
            return True
        except asyncio.QueueFull:
            perf_mark(
                "rtp",
                "packet.receive",
                "failed",
                metadata={
                    "flow_direction": "rx",
                    "packet_kind": "rtp",
                    "ssrc": self.ssrc,
                    "plaintext_size_bytes": len(data),
                    "error_stage": "track_queue_delivery",
                    "drop_reason": "track_queue_full",
                    "counter.rtp.packets_receive_failed": 1,
                },
            )
            return False

    async def recv_rtp_pkt_sync(self):
        """Read RTP bytes from queue (async)."""
        return await self.__queue.get()


async def _receive_task(
    reader: Callable[[], Coroutine[Any, Any, tuple[bytes, int]]],
    track: TrackRemote,
):
    """
    Async task that reads from SRTP stream and writes to TrackRemote queue.

    This runs as an asyncio task in the main event loop.
    """
    packet_count = 0
    print(f"[_receive_task] STARTED for track SSRC={track.ssrc}")

    while True:
        try:
            data, n = await reader()

            if n == 0:
                # EOF or no data
                await asyncio.sleep(1)
                continue

            # Write to async queue
            await track.write_rtp_bytes(data)
            packet_count += 1

            if packet_count <= 20 or packet_count % 100 == 0:
                print(f"[_receive_task] SSRC={track.ssrc}: received {packet_count} packets")

        except ValueError:
            pass
        except Exception as e:
            # Log unexpected errors but continue
            print(f"_receive_task error: {e}")
            await asyncio.sleep(0.1)


class RTPReceiver(ObservedComponent):
    def __init__(self, caps: MediaCaps, kind: RTPCodecKind) -> None:
        self._caps = caps
        self._kind = kind
        self._dtls: dtls.DTLSTransport | None = None
        self._track: TrackRemote | None = None
        self._receive_task: asyncio.Task | None = None

    @event_loop
    def bind(self, transport: dtls.DTLSTransport):
        self._dtls = transport

    @event_loop
    def __rtp_reader(self) -> Callable[[], Coroutine[Any, Any, tuple[bytes, int]]]:
        async def read() -> tuple[bytes, int]:
            # Read from track's SRTP stream
            if not self._track:
                print("Not found track for __rtp_reader")
                return (bytes(), 0)
            try:
                # Read decrypted RTP bytes from SRTP stream
                data = await self._track.stream.read()
                return (data, len(data))
            except Exception as e:
                print(f"__rtp_reader error: {e}")
                return (bytes(), 0)

        return read

    @event_loop
    def receive(self, params: RTPDecodingParameters):
        """
        Start receiving RTP packets.

        Args:
            params: RTP decoding parameters
        """
        print(f"[RTPReceiver.receive] CALLED for SSRC={params.ssrc}, existing_task={self._receive_task is not None}")
        if self._receive_task:
            print(f"[RTPReceiver.receive] Receiver already started for SSRC={params.ssrc}, SKIPPING")
            return

        self._track = TrackRemote(self._kind, params.ssrc, params.rtx.ssrc, params.rid)

        # Create async task to read from SRTP stream
        self._receive_task = self._run_receive_loop(self.__rtp_reader(), self._track)
        print(f"[RTPReceiver.receive] Started _receive_task for SSRC={params.ssrc}")

    @task(
        name="rtp:receiver",
        kind="rtp",
        metadata={"expected_long_running": True, "loop_role": "receive"},
        failure=FailurePolicy.FAIL_CONNECTION,
    )
    async def _run_receive_loop(
        self,
        reader: Callable[[], Coroutine[Any, Any, tuple[bytes, int]]],
        track: TrackRemote,
    ) -> None:
        await _receive_task(reader, track)

    @event_loop
    def stop(self):
        if self._receive_task:
            self._receive_task.cancel()

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


class RTPTransceiver(ObservedComponent):
    def __init__(
        self,
        dtls: dtls.DTLSTransport,
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
        self.__dtls = dtls

    @task(
        name="srtp:start-streams",
        kind="srtp",
        failure=FailurePolicy.FAIL_CONNECTION,
    )
    async def start_srtp_streams(self):
        if self._sender:
            encoding = self._sender._track_encodings[0]
            print(f"SSRC {encoding.ssrc} Local Sender | Start srtp stream")
            # TODO: actual rust impl of srtp don't have the write api, encryption the Session
            stream = await self.__dtls.srtp_rtp_stream(encoding.ssrc)
            print(f"SSRC {encoding.ssrc} Local Sender | Done stream", stream)

            stream = await self.__dtls.srtp_rtcp_stream(encoding.ssrc)
            print(f"SSRC {encoding.ssrc} Local Sender | Done srtcp stream", stream)
            self._sender._rtcp_stream = stream
            # encoding.stream = stream

        if self._receiver and self._receiver.track:
            track = self._receiver.track
            print(f"SSRC {track.ssrc} Remote Receiver | Start srtp stream")
            stream = await self.__dtls.srtp_rtp_stream(track.ssrc)
            track.stream = stream
            print(f"SSRC {track.ssrc} Remote Receiver | Done stream", stream)

    async def bind(self, transport: dtls.DTLSTransport):
        if self._sender:
            await self._sender.bind(transport)
        if self._receiver:
            self._receiver.bind(transport)

    @event_loop
    def set_prefered_codec(self, codec: RTPCodecParameters):
        self._prefered_codecs.append(codec)

    @event_loop
    def get_codecs(self) -> list[RTPCodecParameters] | None:
        codecs = self._caps.get_codecs_by_kind(self._kind)

        if not codecs:
            return None

        filtered_codecs = list[RTPCodecParameters]()
        for codec in self._prefered_codecs:
            if item := codecs_params_fuzzy_search(codec, codecs):
                filtered_codecs.append(item)

        return filtered_codecs

    @event_loop
    def stop(self):
        print("TODO: stop transceiver")

    @event_loop
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

    @event_loop
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

    @event_loop
    def set_mid(self, mid: int | str):
        self._mid = MID(mid)


def find_transceiver_by_mid(
    mid: str, transceivers: list[RTPTransceiver]
) -> RTPTransceiver | None:
    for t in transceivers:
        if t.mid and t.mid.value == mid:
            return t
    return
