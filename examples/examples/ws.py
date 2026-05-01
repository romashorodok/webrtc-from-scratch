import asyncio
import json
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from webrtc.srtp import Session as SrtpSession

from webrtc import media
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import (
    RtcpPacket,
    RunLengthChunk,
    TransportLayerCC,
    AnyRtcpPacket
)
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.peer_connection import (
    PeerConnection,
)
from webrtc.peer_context import PeerContext
from webrtc.runtime import WebRTCRuntimeResources, get_default_runtime
from webrtc.session_description import (
    SessionDescription,
    SessionDescriptionType,
)
from .trace_pump import pump_trace_updates
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection

app = FastAPI()
VIDEO_FILE = Path(__file__).resolve().parents[1] / "output_av1.ivf"


async def on_recv(ws: WebSocket, on_close: Callable | None = None):
    try:
        while True:
            yield await ws.receive_text()
    except WebSocketDisconnect:
        if _on_close := on_close:
            _on_close()


def read_frames(file_path: str):
    frames: list[tuple[bytes, media.IVFFrameHeader]] = []
    with open(file_path, "rb") as file:
        reader = media.IVFReader(file)
        for frame, header in reader:
            frames.append((frame, header))
    return frames


class SendTimeCache:
    def __init__(self, max_age_seconds=5):
        self.cache = dict[int, float]()  # seq -> (send_time)
        self.queue = deque[tuple[int, float]]()
        self.max_age = max_age_seconds

    def add(self, sequence_number: int, send_time: float | None = None):
        if send_time is None:
            send_time = time.monotonic()
            # send_time = time.time()

        self.cache[sequence_number] = send_time
        self.queue.append((sequence_number, send_time))
        self._prune()

    def get(self, sequence_number: int):
        return self.cache.get(sequence_number)

    def _prune(self):
        """Drop old entries based on age."""
        # now = time.time()
        now = time.monotonic()
        while self.queue:
            seq, ts = self.queue[0]
            if now - ts > self.max_age:
                self.queue.popleft()
                self.cache.pop(seq, None)
            else:
                break


TARGET_FPS = 30
FRAME_PERIOD = 1 / TARGET_FPS


async def start_write_loop(pc: PeerConnection, peer: PeerContext):
    sender = pc._transceivers[0].sender
    if not sender:
        raise ValueError("Not found the sender")

    local_track = sender.track
    if not local_track:
        raise ValueError("Not found local track")

    encoding = sender._track_encodings[0]

    frames = await peer.to_thread(
        read_frames,
        str(VIDEO_FILE),
        name="ws:read-ivf-frames",
    )

    ptime = encoding.codec.refresh_rate
    ms = 1000

    # TWCC sequence numbers must be same across the session
    twcc_seq = Sequencer()

    send_time_cache = SendTimeCache()

    def print_rtcp(pkts: list[AnyRtcpPacket], smoothed_gradient: float):
        for feedback in pkts:
            if isinstance(feedback, TransportLayerCC):
                seq = feedback.base_sequence_number
                base_time_us = (
                    feedback.reference_time * 64_000
                )  # 64ms = 64,000µs

                # Build list of packet statuses from chunks
                # Status: 0=not received, 1=small delta, 2=large delta, 3=received without delta
                packet_statuses = []
                for chunk in feedback.packet_chunks:
                    if isinstance(chunk, RunLengthChunk):
                        # Same status repeated run_length times
                        packet_statuses.extend([chunk.packet_status_symbol] * chunk.run_length)
                    elif hasattr(chunk, 'symbol_list'):
                        # StatusVectorChunk - list of individual statuses
                        packet_statuses.extend(chunk.symbol_list)

                # Track previous packet within this feedback only
                # (arrival times are only comparable within same reference_time)
                prev_seq = None
                prev_send_time = None
                prev_arrival_time_us = None
                delta_idx = 0

                for status in packet_statuses:
                    if status == 0:  # TypeTCCPacketNotReceived
                        # Packet lost - reset tracking
                        prev_seq = None
                        prev_send_time = None
                        prev_arrival_time_us = None
                        seq += 1
                        continue

                    # Packet was received - get delta
                    if delta_idx >= len(feedback.recv_deltas):
                        seq += 1
                        continue

                    delta = feedback.recv_deltas[delta_idx]
                    delta_idx += 1

                    send_time = send_time_cache.get(seq)
                    if not send_time:
                        # Not in our cache - reset tracking
                        prev_seq = None
                        prev_send_time = None
                        prev_arrival_time_us = None
                        seq += 1
                        continue

                    # Accumulate arrival time from deltas
                    base_time_us += delta.delta  # microseconds
                    arrival_time_us = base_time_us

                    # Only calculate gradient for consecutive received packets
                    if (prev_seq is not None and
                        prev_send_time is not None and
                        prev_arrival_time_us is not None and
                        seq == prev_seq + 1):

                        # Inter-send time (time between sending packets)
                        send_delta = (send_time - prev_send_time) * 1_000_000  # to µs

                        # Inter-arrival time (time between receiving packets at browser)
                        arrival_delta = arrival_time_us - prev_arrival_time_us  # already in µs

                        # Delay gradient: positive = congestion building, negative = recovering
                        delay_gradient_us = arrival_delta - send_delta

                        # Clamp extreme values (likely measurement errors)
                        if abs(delay_gradient_us) < 100_000:  # < 100ms
                            # Apply EWMA smoothing
                            alpha = 0.1
                            smoothed_gradient = alpha * delay_gradient_us + (1 - alpha) * smoothed_gradient
                            print(f"Seq {seq}: delay_gradient = {smoothed_gradient / 1000:.3f} ms")

                    prev_seq = seq
                    prev_send_time = send_time
                    prev_arrival_time_us = arrival_time_us
                    seq += 1

    async def rtcp_handler():
        # Persistent state across TWCC feedback packets
        smoothed_gradient = 0.0

        while True:
            try:
                # DTLSTransport now handles incoming RTCP routing internally
                # Just read from the stream (already decrypted and routed)
                stream = sender._rtcp_stream
                assert stream, "No srtp strem in rtcp handler"

                # Read decrypted RTCP from stream
                rtcp = await stream.read()
                pkts = await peer.to_thread(
                    RtcpPacket.parse,
                    rtcp,
                    name="rtcp:parse",
                    aggregate=True,
                    group_name="rtcp:parse-feedback",
                    group_key="rtcp:parse-feedback",
                )
                await peer.to_thread(
                    print_rtcp,
                    pkts,
                    smoothed_gradient,
                    name="rtcp:print-feedback",
                    aggregate=True,
                    group_name="rtcp:feedback-processing",
                    group_key="rtcp:feedback-processing",
                )

            except Exception as e:
                print("rtcp error", e)
                await asyncio.sleep(1)


    async def encode():
        frame_index = 0

        srtp: SrtpSession | None = None

        async for _ in media.ticker(ptime / ms):
            if not srtp:
                if srtp_transport := pc._dtls_transport._srtp_rtp:
                    srtp = srtp_transport
                else:
                    continue

            if frame_index >= len(frames):
                frame_index = 0

            frame, _ = frames[frame_index]
            frame_index += 1
            pts, time_base = await encoding._packetizer.next_timestamp()

            pkts = encoding._packetizer.packetize(
                frame, encoding.convert_timebase(pts, time_base, time_base)
            )

            for pkt in pkts:
                pkt.extensions.transport_sequence_number = (
                    twcc_seq.next_sequence_number()
                )
                serialized = pkt.serialize(DEFAULT_EXT_MAP)
                # Offload encrypt to thread pool to avoid blocking event loop
                encoded = await peer.to_thread(
                    srtp.encrypt,
                    serialized,
                    name="srtp:encrypt-rtp",
                    aggregate=True,
                    group_name="srtp:encrypt-rtp-packets",
                    group_key="srtp:encrypt-rtp-packets",
                )
                if not pc._transport:
                    print(f"[WS] ERROR: pc._transport is None!")
                    continue
                send_time_cache.add(pkt.extensions.transport_sequence_number)
                await peer.to_thread(
                    pc._transport.sendto,
                    encoded,
                    name="ice:sendto-rtp",
                    aggregate=True,
                    group_name="ice:send-rtp-packets",
                    group_key="ice:send-rtp-packets",
                )

    peer.spawn_app(rtcp_handler(), name="ws:rtcp-handler", kind="rtcp")
    await encode()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    runtime = get_default_runtime()
    pc = PeerConnection()
    send_lock = asyncio.Lock()

    async def send_json(message: dict[str, Any]) -> None:
        async with send_lock:
            await ws.send_json(message)

    async with PeerContext(pc, runtime=runtime) as peer:
        trace_task = peer.spawn_app(
            pump_trace_updates(runtime, peer.peer_id, send_json),
            name=f"ws:trace-pump-{peer.peer_id}",
            kind="trace",
        )
        write_task: asyncio.Task[Any] | None = None

        peer.start()
        await pc.gatherer.dial()

        await pc.add_transceiver_from_kind(
            RTPCodecKind.Video, RTPTransceiverDirection.Sendonly
        )

        def on_close():
            trace_task.cancel()
            print("WebSocket disconnected")

        async def start_media() -> None:
            nonlocal write_task
            if write_task and not write_task.done():
                return
            write_task = peer.spawn_app(
                start_write_loop(pc, peer),
                name="ws:av1-write-loop",
                kind="media",
            )

        async for data in on_recv(ws, on_close):
            msg: dict[str, Any] = json.loads(data)

            match msg.get("event"):
                case "negotiate":
                    print("Start all webrtc")
                    await pc.gatherer.dial()
                    await start_media()

                case "offer":
                    print("recv offer")
                    if offer := await pc.create_offer():
                        print("offer offer")
                        await pc.set_local_description(SessionDescriptionType.Offer, offer)
                        print("set offer")
                        await send_json(
                            {"event": "offer", "data": offer.marshal().decode()}
                        )

                case "answer":
                    data = msg.get("data")
                    if not data:
                        continue

                    payload: dict[str, Any] = json.loads(data)
                    sdp = payload.get("sdp")
                    sdp_type = payload.get("type")

                    if not sdp or not sdp_type:
                        continue

                    if not isinstance(sdp, str):
                        continue

                    desc_type = SessionDescriptionType(sdp_type)
                    if not (
                        desc_type is SessionDescriptionType.Offer
                        or desc_type is SessionDescriptionType.Answer
                    ):
                        continue

                    desc = SessionDescription.parse(sdp)
                    print(f"Set remote description desc:{desc}")

                    for ufrag, pwd in desc.get_media_credentials():
                        await peer.set_remote_credentials(ufrag, pwd)

                    await peer.set_remote_description(desc_type, desc)

                case "trickle-ice":
                    # NOTE: In my current state I need know ufrag, pwd before adding the candidate, because all pair credentials is immutable
                    data = msg.get("data")
                    if not data:
                        continue
                    payload: dict[str, Any] = json.loads(data)

                    candidate_str = payload.get("candidate")
                    if not candidate_str:
                        continue

                    await peer.add_remote_candidate(candidate_str)

                case "trace:delete":
                    data = msg.get("data")
                    payload: dict[str, Any] = json.loads(data) if isinstance(data, str) else data or {}
                    trace_id = payload.get("trace_id")
                    scope = payload.get("scope")

                    if isinstance(trace_id, str):
                        runtime.delete_trace(trace_id)
                    elif scope == "failed":
                        runtime.delete_traces(peer_id=peer.peer_id, statuses={"failed"})
                    elif scope == "completed":
                        runtime.delete_traces(
                            peer_id=peer.peer_id,
                            statuses={"completed", "cancelled"},
                        )

                case _:
                    print("Unknown event")
