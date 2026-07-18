import asyncio
from dataclasses import dataclass, replace
import fractions
import secrets
from enum import Enum, StrEnum
from typing import Any, Callable, Coroutine, Protocol

import webrtc_rs

from webrtc.media.av1_payloader import AV1_PAYLOAD_TYPE, Av1Packetizer
from webrtc.media.opus_payloader import OPUS_PAYLOAD_TYPE, OpusPacketizer
from webrtc.media.vp8_payloader import VP8Payloader
from webrtc.performance import ObservedComponent, event_loop, task
from webrtc.runtime_services import FailurePolicy, OwnedTaskHandle, StaleOwnerEpoch, current_execution_scope
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.observability import MachineTransitionOp
from webrtc.state_machine import (
    AsyncStateMachineRunner, BoundedMailbox, MachineCommand, MailboxClosed,
    MailboxFull, PreparedTransition, ReplyPort, TransitionCommit,
)
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


class _LifecycleCommand(StrEnum):
    BIND = "bind"
    ACTIVATE = "activate"
    PAUSE = "pause"
    RESUME = "resume"
    LIVE = "live"
    MUTE = "mute"
    FAIL = "fail"
    STOP = "stop"
    FINISH = "finish"


class _ComponentRunner(AsyncStateMachineRunner[MachineCommand[object, TransitionCommit]]):
    def __init__(self, owner: "_MachineComponent", machine_type: str) -> None:
        self.owner = owner
        super().__init__(
            MACHINE_SPECS[machine_type], entity_id=owner.entity_id,
            mailbox_capacity=16,
            controller=getattr(owner._runtime, "transition_controller", None),
            transition_sink=owner._project_transition,
        )

    async def step(self, command):
        state = self.snapshot().state
        if self.spec.machine_type == "media-track":
            proposed = {
                _LifecycleCommand.LIVE: "live", _LifecycleCommand.RESUME: "live",
                _LifecycleCommand.MUTE: "muted", _LifecycleCommand.FAIL: "failed",
                _LifecycleCommand.STOP: "ended",
            }.get(command.kind)
        else:
            proposed = {
                _LifecycleCommand.BIND: "bound", _LifecycleCommand.ACTIVATE: "active",
                _LifecycleCommand.PAUSE: "paused", _LifecycleCommand.RESUME: "active",
                _LifecycleCommand.FAIL: "failed", _LifecycleCommand.STOP: "stopping",
                _LifecycleCommand.FINISH: "stopped",
            }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported {self.spec.machine_type} command: {command.kind}")
        return PreparedTransition(
            state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    async def reconcile_terminal(self, prepared):
        await self.owner._reconcile_terminal()

    async def after_commit(self, commit, effects):
        self.owner._after_lifecycle_commit(commit)


class _MachineComponent:
    """Small Runtime-owned lifecycle used by Stage-5 media entities."""

    def _init_machine(self, machine_type: str, entity_id: str) -> None:
        self.entity_id = entity_id
        self._runtime = current_execution_scope()
        self._command_id = 0
        self._machine_handle: OwnedTaskHandle[None] | None = None
        self._terminal_reply: ReplyPort[TransitionCommit] | None = None
        self._runner = _ComponentRunner(self, machine_type)
        if self._runtime is None:
            return
        self._runtime.projection.machines.register(self.entity_id, self._runner.spec)
        self._runtime.register_owner(self.entity_id, epoch=self._runner.epoch)
        self._machine_handle = self._runtime.start_machine(
            self._runner, owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
        )

    def _command(self, kind, payload=None, *, reply=None, expected_revision=None):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, self._runner.epoch, payload, reply,
            expected_revision=expected_revision,
            cause_id=f"{self.entity_id}:{self._command_id}",
        )

    async def _transition(self, kind, payload=None, *, expected_revision=None):
        if self._machine_handle is None:
            raise RuntimeError(f"{self.entity_id} requires an active Runtime")
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(
            kind, payload, reply=reply, expected_revision=expected_revision,
        ))
        return await reply.wait()

    def _try_transition(self, kind, payload=None) -> None:
        if self._machine_handle is not None:
            self._runner.try_submit(self._command(kind, payload))

    def _project_transition(self, commit: TransitionCommit) -> None:
        runtime = self._runtime
        if runtime is None or not getattr(runtime, "tracing_enabled", True):
            return
        runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state, commit.to_state,
            commit.epoch, commit.revision, runtime.new_producer_dot(), commit.cause,
            commit.monotonic_ns,
        ))

    def _after_lifecycle_commit(self, commit: TransitionCommit) -> None:
        if commit.to_state == "stopping":
            self._runner.try_submit(self._command(
                _LifecycleCommand.FINISH, reply=self._terminal_reply,
            ))

    async def _reconcile_terminal(self) -> None:
        return None

    async def pause(self) -> TransitionCommit:
        return await self._transition(_LifecycleCommand.PAUSE)

    async def resume(self) -> TransitionCommit:
        return await self._transition(_LifecycleCommand.RESUME)

    async def aclose(self) -> None:
        if self._machine_handle is None:
            await self._reconcile_terminal()
            return
        state = self._runner.snapshot().state
        if not self._runner.snapshot().terminal:
            if self._terminal_reply is None:
                self._terminal_reply = ReplyPort[TransitionCommit]()
            if state != "stopping":
                await self._runner.submit(self._command(
                    _LifecycleCommand.STOP,
                    reply=(self._terminal_reply
                           if self._runner.spec.machine_type == "media-track"
                           else None),
                ))
            await self._terminal_reply.wait()
        if not self._machine_handle.done():
            await self._machine_handle.wait()
        if self._runtime is not None:
            try:
                self._runtime.remove_owner(self.entity_id, self._runner.epoch)
            except (KeyError, StaleOwnerEpoch):
                pass


class TrackLocal(_MachineComponent):
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
        self._init_machine("media-track", f"track-local:{id}")

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
        if self._runner.snapshot().state == "new":
            self._try_transition(_LifecycleCommand.LIVE)

    async def mute(self) -> TransitionCommit:
        return await self._transition(_LifecycleCommand.MUTE)

    async def unmute(self) -> TransitionCommit:
        return await self._transition(_LifecycleCommand.RESUME)

    async def _reconcile_terminal(self) -> None:
        self._writer = None

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


class RTPSender(_MachineComponent):
    def __init__(self, caps: MediaCaps, *, observability_id: str | None = None) -> None:
        self._track_encodings = list[TrackEncoding]()
        self._payload_type: int = 0
        self._caps = caps
        self._track: TrackLocal | None = None
        self.__transport: dtls.DTLSTransport | None = None
        self._rtcp_stream: SrtpStream | None = None
        self._init_machine(
            "rtp-sender", observability_id or f"rtp-sender:{secrets.token_hex(6)}",
        )

    async def bind(self, transport: dtls.DTLSTransport):
        self.__transport = transport
        for enc in self._track_encodings:
            enc.bind(transport)
        state = self._runner.snapshot().state
        if state == "new":
            await self._transition(_LifecycleCommand.BIND)
        if self._track is not None and self._runner.snapshot().state == "bound":
            await self._transition(_LifecycleCommand.ACTIVATE)

    async def add_encoding(self, track: TrackLocal):
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
        if self._runner.snapshot().state == "bound":
            await self._transition(_LifecycleCommand.ACTIVATE)

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

    def negotiate(self) -> None:
        """Compatibility hook; RTPTransceiver owns negotiated state."""

    async def _reconcile_terminal(self) -> None:
        for encoding in self._track_encodings:
            encoding._dtls = None
        self.__transport = None
        self._rtcp_stream = None
        if self._track is not None:
            await self._track.aclose()


class TrackRemote(_MachineComponent):
    def __init__(
        self,
        kind: RTPCodecKind,
        ssrc: int,  # uint32
        rtx_ssrc: int,  # uint32
        rid: str, *, observability_id: str | None = None,
    ) -> None:
        self.kind = kind
        self.ssrc = ssrc
        self.rtx_ssrc = rtx_ssrc
        self.rid = rid

        self.__stream: SrtpStream | None = None
        self.__queue = BoundedMailbox[bytes](1000)
        self._init_machine(
            "media-track",
            observability_id or f"track-remote:{ssrc}:{secrets.token_hex(4)}",
        )

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
        if self._runner.snapshot().state == "new":
            self._try_transition(_LifecycleCommand.LIVE)

    async def write_rtp_bytes(self, data: bytes) -> bool:
        """Make a decrypted RTP packet visible to the application queue."""
        try:
            self.__queue.try_submit(bytes(data))
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
        except (MailboxFull, MailboxClosed):
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
        return await self.__queue.receive()

    async def mute(self) -> TransitionCommit:
        return await self._transition(_LifecycleCommand.MUTE)

    async def unmute(self) -> TransitionCommit:
        return await self._transition(_LifecycleCommand.RESUME)

    async def _reconcile_terminal(self) -> None:
        self.__stream = None
        self.__queue.close()


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


class RTPReceiver(ObservedComponent, _MachineComponent):
    def __init__(
        self, caps: MediaCaps, kind: RTPCodecKind, *, observability_id: str | None = None,
    ) -> None:
        self._caps = caps
        self._kind = kind
        self._dtls: dtls.DTLSTransport | None = None
        self._track: TrackRemote | None = None
        self._receive_handle: OwnedTaskHandle[None] | None = None
        self._pending_receive = False
        self._init_machine(
            "rtp-receiver", observability_id or f"rtp-receiver:{secrets.token_hex(6)}",
        )

    @event_loop
    def bind(self, transport: dtls.DTLSTransport):
        self._dtls = transport
        if self._runner.snapshot().state == "new":
            self._try_transition(_LifecycleCommand.BIND)
        if self._pending_receive:
            self._try_transition(_LifecycleCommand.ACTIVATE)

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
        print(f"[RTPReceiver.receive] CALLED for SSRC={params.ssrc}, existing_task={self._receive_handle is not None}")
        if self._receive_handle:
            print(f"[RTPReceiver.receive] Receiver already started for SSRC={params.ssrc}, SKIPPING")
            return

        self._track = TrackRemote(
            self._kind, params.ssrc, params.rtx.ssrc, params.rid,
            observability_id=f"{self.entity_id}:track",
        )
        self._pending_receive = True
        if self._runner.snapshot().state == "bound":
            self._try_transition(_LifecycleCommand.ACTIVATE)

        # Create async task to read from SRTP stream
        if self._runtime is None:
            raise RuntimeError("RTPReceiver requires an active Runtime")
        reader = self.__rtp_reader()
        track = self._track
        self._receive_handle = self._runtime.start_pump(
            lambda: _receive_task(reader, track),
            owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
            name="rtp:receiver", kind="rtp", failure=FailurePolicy.FAIL_CONNECTION,
            metadata={"expected_long_running": True, "loop_role": "receive"},
        )
        print(f"[RTPReceiver.receive] Started _receive_task for SSRC={params.ssrc}")

    @event_loop
    def stop(self):
        # Compatibility entry point: teardown is completed and joined by aclose().
        if self._machine_handle is not None and not self._runner.snapshot().terminal:
            if self._terminal_reply is None:
                self._terminal_reply = ReplyPort[TransitionCommit]()
                self._try_transition(_LifecycleCommand.STOP)

    async def _reconcile_terminal(self) -> None:
        if self._receive_handle is not None and not self._receive_handle.done():
            self._receive_handle.cancel()
            try:
                await self._receive_handle.wait()
            except asyncio.CancelledError:
                pass
        self._receive_handle = None
        if self._track is not None:
            await self._track.aclose()
        self._dtls = None

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


class _TransceiverCommand(Enum):
    NEGOTIATE = "negotiate"
    ACTIVATE = "activate"
    SET_MID = "set-mid"
    SET_CODEC = "set-codec"
    SET_SENDER = "set-sender"
    SET_RECEIVER = "set-receiver"
    SET_SNAPSHOT = "set-snapshot"
    STOP = "stop"
    FINISH = "finish"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class NegotiatedTransceiverSnapshot:
    direction: RTPTransceiverDirection
    mid: str | None
    codecs: tuple[RTPCodecParameters, ...]
    sender_id: str | None
    receiver_id: str | None
    sender_config: tuple[tuple[str, object], ...]
    receiver_config: tuple[tuple[str, object], ...]


class _TransceiverRunner(
    AsyncStateMachineRunner[MachineCommand[object, TransitionCommit]]
):
    def __init__(self, owner: "RTPTransceiver", **kwargs) -> None:
        super().__init__(MACHINE_SPECS["transceiver"], **kwargs)
        self.owner = owner

    async def step(self, command):
        state = self.snapshot().state
        proposed = {
            _TransceiverCommand.NEGOTIATE: "negotiating",
            _TransceiverCommand.ACTIVATE: "active",
            _TransceiverCommand.SET_MID: "active",
            _TransceiverCommand.SET_CODEC: "active",
            _TransceiverCommand.SET_SENDER: "active",
            _TransceiverCommand.SET_RECEIVER: "active",
            _TransceiverCommand.SET_SNAPSHOT: "active",
            _TransceiverCommand.STOP: "stopping",
            _TransceiverCommand.FINISH: "stopped",
            _TransceiverCommand.FAIL: "failed",
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported transceiver command: {command.kind}")
        if command.kind in {
            _TransceiverCommand.SET_MID, _TransceiverCommand.SET_CODEC,
            _TransceiverCommand.SET_SENDER, _TransceiverCommand.SET_RECEIVER,
        } and state != "negotiating":
            raise RuntimeError("transceiver configuration requires negotiating ownership")
        if command.kind is _TransceiverCommand.SET_SNAPSHOT and state != "active":
            raise RuntimeError("negotiated snapshot replacement requires active ownership")
        return PreparedTransition(
            state, proposed, (command.kind, command.payload), command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    def commit(self, proposed, cause=None):
        commit = super().commit(proposed, cause)
        if isinstance(proposed, PreparedTransition):
            kind, payload = proposed.effects
            self.owner._commit_configuration(kind, payload)
        return commit

    async def reconcile_terminal(self, prepared):
        await self.owner._reconcile_terminal()

    async def after_commit(self, commit, effects):
        self.owner._after_commit(commit)


class RTPTransceiver(ObservedComponent):
    def __init__(
        self,
        dtls: dtls.DTLSTransport,
        caps: MediaCaps,
        kind: RTPCodecKind,
        direction: RTPTransceiverDirection,
        *, observability_id: str | None = None,
    ):
        self._mid: MID | None = None
        self._sender: RTPSender | None = None
        self._receiver: RTPReceiver | None = None
        self._caps: MediaCaps = caps
        self._kind: RTPCodecKind = kind
        self._prefered_codecs = list[RTPCodecParameters]()
        self._direction = direction
        self._negotiated = NegotiatedTransceiverSnapshot(
            direction, None, (), None, None, (), (),
        )
        self.__dtls = dtls
        self._observability_id = (
            observability_id or f"transceiver-{secrets.token_hex(6)}"
        )
        self.entity_id = self._observability_id
        self._runtime = current_execution_scope()
        self._command_id = 0
        self._machine_handle: OwnedTaskHandle[None] | None = None
        self._activation: ReplyPort[TransitionCommit] | None = None
        self._terminal: ReplyPort[TransitionCommit] | None = None
        self._runner = _TransceiverRunner(
            self, entity_id=self.entity_id, mailbox_capacity=16,
            controller=getattr(self._runtime, "transition_controller", None),
            transition_sink=self._project_transition,
        )
        if self._runtime is not None and hasattr(self._runtime, "start_machine"):
            self._runtime.projection.machines.register(
                self.entity_id, MACHINE_SPECS["transceiver"],
            )
            self._runtime.register_owner(self.entity_id, epoch=self._runner.epoch)
            self._machine_handle = self._runtime.start_machine(
                self._runner, owner_entity_id=self.entity_id,
                owner_epoch=self._runner.epoch,
            )
            self._activation = ReplyPort[TransitionCommit]()
            self._runner.try_submit(self._command(
                _TransceiverCommand.NEGOTIATE,
                cause_id=f"{self.entity_id}:activate",
            ))
            self._runner.try_submit(self._command(
                _TransceiverCommand.ACTIVATE, reply=self._activation,
                cause_id=f"{self.entity_id}:activate",
            ))

    @event_loop
    def _command(
        self, kind, payload=None, *, reply=None, cause_id=None,
        expected_revision=None, expected_epoch=None,
    ):
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id,
            self._runner.epoch if expected_epoch is None else expected_epoch,
            payload, reply,
            expected_revision=expected_revision,
            cause_id=cause_id or f"{self.entity_id}:{self._command_id}",
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
        runtime.projection.merge_values(
            commit.entity_id, runtime.new_producer_dot(), {
                "direction": self._negotiated.direction.value,
                "kind": self._kind.value,
                "active": commit.to_state == "active",
                "mid": self._negotiated.mid,
                "codecs": ",".join(codec.mime_type for codec in self._negotiated.codecs),
                "sender_id": self._negotiated.sender_id,
                "receiver_id": self._negotiated.receiver_id,
            },
            observer_meta="exact", source_entity_id=commit.entity_id,
            source_epoch=commit.epoch, source_revision=commit.revision,
            source_order=runtime.projection.new_facet_source_order(),
        )

    @event_loop
    def _commit_configuration(self, kind, payload) -> None:
        if kind is _TransceiverCommand.SET_MID:
            self._mid = MID(payload)
            self._negotiated = replace(self._negotiated, mid=self._mid.value)
        elif kind is _TransceiverCommand.SET_CODEC:
            self._prefered_codecs.append(payload)
            self._negotiated = replace(
                self._negotiated, codecs=tuple(self._prefered_codecs),
            )
        elif kind is _TransceiverCommand.SET_SENDER:
            self._sender = payload
            parameters = payload.get_parameters()
            self._negotiated = replace(
                self._negotiated, sender_id=payload.entity_id,
                sender_config=(("encoding_count", len(payload._track_encodings)),
                               ("has_parameters", parameters is not None)),
            )
        elif kind is _TransceiverCommand.SET_RECEIVER:
            self._receiver = payload
            self._negotiated = replace(
                self._negotiated, receiver_id=payload.entity_id,
                receiver_config=(("kind", payload._kind.value),
                                 ("has_track", payload.track is not None)),
            )
        elif kind is _TransceiverCommand.SET_SNAPSHOT:
            self._negotiated = payload
            self._direction = payload.direction
            self._mid = MID(payload.mid) if payload.mid is not None else None
            self._prefered_codecs = list(payload.codecs)

    @event_loop
    def _after_commit(self, commit: TransitionCommit) -> None:
        if commit.to_state == "stopping":
            self._runner.try_submit(self._command(
                _TransceiverCommand.FINISH,
                cause_id=str(commit.cause) if commit.cause is not None else None,
                reply=self._terminal,
            ))

    async def _reconcile_terminal(self) -> None:
        if self._receiver is not None:
            await self._receiver.aclose()
        if self._sender is not None:
            await self._sender.aclose()

    async def wait_active(self) -> TransitionCommit:
        if self._activation is None:
            raise RuntimeError("transceiver requires an active Runtime")
        return await self._activation.wait()

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

    async def set_prefered_codec(self, codec: RTPCodecParameters):
        await self.wait_active()
        await self._begin_negotiation()
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(
            _TransceiverCommand.SET_CODEC, codec, reply=reply,
        ))
        await reply.wait()

    async def _begin_negotiation(self) -> TransitionCommit:
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(
            _TransceiverCommand.NEGOTIATE, reply=reply,
            expected_revision=self._runner.revision,
        ))
        return await reply.wait()

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
        if self._runner.snapshot().state in {"stopping", "stopped"}:
            return self._terminal
        self._terminal = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(
            _TransceiverCommand.STOP, reply=None,
            cause_id=f"{self.entity_id}:stop",
        ))
        return self._terminal

    async def aclose(self) -> None:
        terminal = self.stop()
        if terminal is not None:
            await terminal.wait()
        if self._machine_handle is not None and not self._machine_handle.done():
            await self._machine_handle.wait()
        if self._runtime is not None:
            try:
                self._runtime.remove_owner(self.entity_id, self._runner.epoch)
            except (KeyError, StaleOwnerEpoch):
                pass

    @event_loop
    def track_local(self) -> TrackLocal | None:
        if not self.sender:
            return
        return self.sender.track

    @property
    def sender(self) -> RTPSender | None:
        return self._sender

    async def set_sender(self, sender: RTPSender):
        await self.wait_active()
        if self.__dtls:
            await sender.bind(self.__dtls)
        await self._begin_negotiation()
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(
            _TransceiverCommand.SET_SENDER, sender, reply=reply,
        ))
        await reply.wait()

    @property
    def receiver(self) -> RTPReceiver | None:
        return self._receiver

    async def set_receiver(self, receiver: RTPReceiver):
        await self.wait_active()
        if self.__dtls:
            receiver.bind(self.__dtls)
        await self._begin_negotiation()
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(
            _TransceiverCommand.SET_RECEIVER, receiver, reply=reply,
        ))
        await reply.wait()

    @property
    def direction(self) -> RTPTransceiverDirection:
        return self._direction

    @property
    def observability_id(self) -> str:
        return self._observability_id

    @property
    def kind(self) -> RTPCodecKind:
        return self._kind

    @property
    def mid(self) -> MID | None:
        return self._mid

    async def set_mid(self, mid: int | str):
        await self.wait_active()
        await self._begin_negotiation()
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(
            _TransceiverCommand.SET_MID, mid, reply=reply,
        ))
        await reply.wait()

    @property
    def negotiated_snapshot(self) -> NegotiatedTransceiverSnapshot:
        return self._negotiated

    async def apply_negotiated_snapshot(
        self, snapshot: NegotiatedTransceiverSnapshot, *, expected_epoch: int,
        expected_revision: int,
    ) -> TransitionCommit:
        """Atomically replace the complete negotiation snapshot under CAS guards."""
        reply = ReplyPort[TransitionCommit]()
        await self._runner.submit(self._command(
            _TransceiverCommand.SET_SNAPSHOT, snapshot, reply=reply,
            expected_epoch=expected_epoch, expected_revision=expected_revision,
        ))
        return await reply.wait()


def find_transceiver_by_mid(
    mid: str, transceivers: list[RTPTransceiver]
) -> RTPTransceiver | None:
    for t in transceivers:
        if t.mid and t.mid.value == mid:
            return t
    return
