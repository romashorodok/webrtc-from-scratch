import numpy as np
import math

import os
import asyncio
import json
import threading
import time
from collections import deque
from typing import Any, Callable, Awaitable

import zmq
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from webrtc_rs import SRTP
from zmq.asyncio import Context, Socket

from webrtc import media
from webrtc.media.jitterbuffer import JitterBuffer, JitterFrame
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import (
    RtcpPacket,
    TransportLayerCC,
)
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.media.vp8_payloader import vp8_depayload
from webrtc.media.y4m import Y4mFrame
from webrtc.peer_connection import (
    PeerConnection,
)
from webrtc.session_description import (
    SessionDescription,
    SessionDescriptionType,
)
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection

app = FastAPI()


async def on_recv(ws: WebSocket, on_close: Callable | None = None):
    try:
        while True:
            yield await ws.receive_text()
    except WebSocketDisconnect:
        if _on_close := on_close:
            _on_close()


async def pre_read_frames(file_path: str):
    frames: list[tuple[bytes, media.IVFFrameHeader]] = []
    with open(file_path, "rb") as file:
        reader = media.IVFReader(file)
        for frame, header in reader:
            frames.append((frame, header))
    return frames


def pre_read_y4m(file_path: str):
    with open(file_path, "rb") as file:
        n_frames = 0
        reader = media.Y4mDecoder(file)
        frames: list[Y4mFrame] = []
        for frame in reader:
            n_frames += 1
            frames.append(frame)
        return frames, reader


frames, y4m_reader = pre_read_y4m("output.y4m")
video_details = y4m_reader.get_video_details()


loop = asyncio.new_event_loop()


# TWCC sequence numbers must be same across the session
twcc_seq = Sequencer()


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


yuv_channel = os.environ.get("YUV_CHANNEL", "ipc:///tmp/yuv.sock")
transport_channel = os.environ.get("TRANSPORT_CHANNEL", "ipc:///tmp/transport.sock")


class Encoder:
    def __init__(
        self,
    ) -> None:
        ctx = Context()

        self.__sock = ctx.socket(zmq.DEALER)
        self.__sock.setsockopt(zmq.IDENTITY, os.urandom(8))

        self.__yuv = ctx.socket(zmq.PUSH)
        self.nominated = asyncio.Event()
        self._running = True
        self.on_frame = asyncio.Queue[bytes](30 * 5)

        self._on_nominated: Callable[[Socket], Awaitable[None]] | None = None

    def on_nominated(
        self, cb: Callable[[Socket], Awaitable[None]] | Callable[[Socket], None]
    ):
        if asyncio.iscoroutinefunction(cb):
            self._on_nominated = cb
        else:

            async def wrapper(_sock: Socket):
                cb(self.__sock)

            self._on_nominated = wrapper

    async def recv_loop(self):
        self.__sock.connect(transport_channel)
        self.__yuv.connect(yuv_channel)
        await self.__sock.send_multipart([b"connect"])

        while self._running:
            try:
                payload = await asyncio.wait_for(
                    self.__sock.recv_multipart(), timeout=5
                )
                await self.__handler(payload)
            except asyncio.TimeoutError:
                print("[ZMQ] No data received in 5 seconds")
                asyncio.ensure_future(self.recv_loop())
                return
            except Exception as e:
                print(f"[Receiver] Error: {e}")
                await asyncio.sleep(0.5)

    async def __handler(self, payload: list[bytes]):
        match payload[0]:
            case b"nominated":
                self.nominated.set()
                if self._on_nominated:
                    await self._on_nominated(self.__sock)
            case b"connected":
                print("connected pair")
            case b"frame":
                await self.on_frame.put(payload[1])
            case _:
                pass

    async def send_frame(
        self,
        bytes_per_sample: int,
        width: int,
        chroma_width: int,
        y_plane: bytes,
        u_plane: bytes,
        v_plane: bytes,
    ):
        await self.__yuv.send_multipart(
            [
                bytes_per_sample.to_bytes(4, "big"),
                width.to_bytes(4, "big"),
                chroma_width.to_bytes(4, "big"),
                y_plane,
                u_plane,
                v_plane,
            ]
        )


def apply_brightness_wave(
    y_plane: bytes, width: int, height: int, frame_index: int
) -> bytes:
    """
    Applies a horizontal sine wave brightness modulation on the Y (luma) plane.

    Args:
        y_plane: Original Y plane bytes.
        width: Frame width.
        height: Frame height.
        frame_index: Current frame number for animation.

    Returns:
        Transformed Y plane as bytes.
    """
    y = np.frombuffer(y_plane, dtype=np.uint8).copy()
    y = y.reshape((height, width))

    # Create row indices array
    rows = np.arange(height).reshape(-1, 1)  # shape (height,1)

    # Precompute phase shift per row plus animation phase
    phase = 2 * np.pi * (rows / 40) + frame_index * 0.1

    # Calculate sine values for all rows, then broadcast over columns
    wave = 30 * np.sin(phase)

    # Add wave to each pixel in the row (broadcast wave shape: height x 1)
    y = y + wave

    # Clip to valid 8-bit range
    np.clip(y, 0, 255, out=y)

    return y.astype(np.uint8).tobytes()


def blend_chroma_with_rainbow(
    u, v, frame_index, chroma_width, chroma_height, strength=0.3
):
    """
    Blend original U,V with a cycling rainbow tint.
    strength controls how strong the color shift is (0=no shift, 1=full rainbow).
    """

    u_norm = u.astype(np.int16) - 128
    v_norm = v.astype(np.int16) - 128

    x = np.arange(chroma_width)
    phase = 2 * np.pi * (x / chroma_width) + frame_index * 0.1

    offset_u = (np.cos(phase) * 50 * strength).astype(np.int16)
    offset_v = (np.sin(phase) * 50 * strength).astype(np.int16)

    offset_u = np.tile(offset_u, (chroma_height, 1))
    offset_v = np.tile(offset_v, (chroma_height, 1))

    u_tinted = u_norm + offset_u
    v_tinted = v_norm + offset_v

    u_tinted = np.clip(u_tinted, -128, 127)
    v_tinted = np.clip(v_tinted, -128, 127)

    u_final = (u_tinted + 128).astype(np.uint8)
    v_final = (v_tinted + 128).astype(np.uint8)

    return u_final, v_final


def apply_rainbow_wave(
    y_plane: bytes,
    u_plane: bytes,
    v_plane: bytes,
    width: int,
    height: int,
    chroma_width: int,
    chroma_height: int,
    frame_index: int,
    strength=1,
):
    y = np.frombuffer(y_plane, dtype=np.uint8).copy()
    y = y.reshape((height, width))

    rows = np.arange(height).reshape(-1, 1)
    phase = 2 * np.pi * (rows / 40) + frame_index * 0.1
    wave = 30 * np.sin(phase)
    y = y + wave
    np.clip(y, 0, 255, out=y)

    u = np.frombuffer(u_plane, dtype=np.uint8).copy()
    v = np.frombuffer(v_plane, dtype=np.uint8).copy()

    u = u.reshape((chroma_height, chroma_width))
    v = v.reshape((chroma_height, chroma_width))

    u_tinted, v_tinted = blend_chroma_with_rainbow(
        u, v, frame_index, chroma_width, chroma_height, strength
    )

    return y.astype(np.uint8).tobytes(), u_tinted.tobytes(), v_tinted.tobytes()


def start_write_loop(pc: PeerConnection, loop: asyncio.AbstractEventLoop):
    rw_loop = asyncio.new_event_loop()

    sender = pc._transceivers[0].sender
    if not sender:
        raise ValueError("Not found the sender")

    local_track = sender.track
    if not local_track:
        raise ValueError("Not found local track")

    encoding = sender._track_encodings[0]

    # frames = rw_loop.run_until_complete(pre_read_frames("output_av1.ivf"))
    # frames = rw_loop.run_until_complete(pre_read_frames("output.ivf"))

    # ptime = encoding.codec.refresh_rate
    # ms = 10000
    # ssrc = encoding.ssrc

    send_time_cache = SendTimeCache()

    encoder = Encoder()
    rw_loop.create_task(encoder.recv_loop())

    @encoder.on_nominated
    async def on_nominated(sock: Socket):
        await sock.send_multipart(
            [
                b"config",
                json.dumps(
                    {
                        "width": video_details.width,
                        "height": video_details.height,
                        "sample_aspect_ratio_num": video_details.sample_aspect_ratio.denominator,
                        "sample_aspect_ratio_den": video_details.sample_aspect_ratio.numerator,
                        "bit_depth": video_details.bit_depth,
                        "chroma_sampling": video_details.chroma_sampling,
                        "time_base_num": video_details.time_base.numerator,
                        "time_base_dem": video_details.time_base.denominator,
                    }
                ).encode(),
            ]
        )
        print("encoder nominated as the sender")

    async def rtcp_handler():
        while True:
            try:
                transport = pc._transport
                assert transport
                srtp = pc._dtls_transport._srtp_rtcp
                assert srtp

                rtcp_packet = await transport.recv_rtcp()
                await srtp.write_pkt(rtcp_packet.data)

                stream = sender._rtcp_stream
                assert stream

                rtcp = await stream.recv_rtcp()
                pkts = RtcpPacket.parse(rtcp)
                for feedback in pkts:
                    if isinstance(feedback, TransportLayerCC):
                        seq = feedback.base_sequence_number
                        arrival_times = []
                        base_time_us = (
                            feedback.reference_time * 64_000
                        )  # 64ms = 64,000µs

                        for delta in feedback.recv_deltas:
                            send_time = send_time_cache.get(seq)
                            assert send_time
                            # print(
                            #     f"Seq {seq}: send_time={send_time}, delta={delta},"
                            #     f"cache={send_time_cache.cache}"
                            # )
                            base_time_us += delta.delta  # microseconds
                            arrival_time = (
                                base_time_us / 1_000_000
                            )  # convert to seconds (optional)

                            delay = max(0.0, arrival_time - send_time)

                            # For metrics, apply a moving average or EWMA filter to absorb jitter.
                            # EWMA with an alpha of 0.1 gives 90% weight to the previous value and 10% to the new value, making the delay more responsive.
                            alpha = 0.1
                            smoothed_delay = (
                                alpha * delay + (1 - alpha) * smoothed_delay
                                if "smoothed_delay" in locals()
                                else delay
                            )

                            # Print delay in milliseconds for debugging
                            print(f"Seq {seq}: delay = {smoothed_delay * 1000:.3f} ms")
                            # delay = arrival_time - send_time
                            # print("delay", delay)
                            # print(f"Seq {seq}: delay = {delay * 1000:.3f} ms")

                            arrival_times.append(arrival_time)
                            seq += 1

            except Exception as e:
                print("rtcp error", e)
                await asyncio.sleep(1)

    async def send_routine():
        frame_index = 0
        chroma_width, chroma_height = (
            video_details.chroma_sampling.get_chroma_dimensions(
                video_details.width,
                video_details.height,
            )
        )
        width = video_details.width
        height = video_details.height
        while True:
            await encoder.nominated.wait()

            if frame_index >= len(frames):
                frame_index = 0

            frame = frames[frame_index]

            # y_bytes = apply_brightness_wave(frame.planes.y, width, height, frame_index)

            y_bytes, u_bytes, v_bytes = apply_rainbow_wave(
                frame.planes.y,
                frame.planes.u,
                frame.planes.v,
                width=video_details.width,
                height=video_details.height,
                chroma_width=chroma_width,
                chroma_height=chroma_height,
                frame_index=frame_index,
            )

            await encoder.send_frame(
                bytes_per_sample=y4m_reader.bytes_per_sample,
                width=video_details.width,
                chroma_width=chroma_width,
                # y_plane=frame.planes.y,
                # u_plane=frame.planes.u,
                # v_plane=frame.planes.v,
                y_plane=y_bytes,
                u_plane=u_bytes,
                v_plane=v_bytes,
            )
            frame_index += 1

    async def encode():
        srtp: SRTP | None = None

        async for pts, time_base in encoding._packetizer.ticker():
            if not srtp:
                if srtp_transport := pc._dtls_transport._srtp_rtp:
                    srtp = srtp_transport
                else:
                    continue

            # print("try send data")
            # await enc.send_packet()
            # print("send dat")

            frame = await encoder.on_frame.get()
            # print("recv data", frame)

            # if frame_index >= len(frames):
            #     frame_index = 0

            # frame, _ = frames[frame_index]
            # frame_index += 1

            pkts = encoding._packetizer.packetize(
                frame, encoding.convert_timebase(pts, time_base, time_base)
            )

            for pkt in pkts:
                pkt.extensions.transport_sequence_number = (
                    twcc_seq.next_sequence_number()
                )
                encoded = await srtp.encrypt_nonblock(pkt.serialize(DEFAULT_EXT_MAP))
                assert pc._transport
                send_time_cache.add(pkt.extensions.transport_sequence_number)
                pc._transport.sendto(encoded)

    rw_loop.create_task(send_routine())
    rw_loop.create_task(rtcp_handler())
    rw_loop.run_until_complete(encode())


def start_read_write_loop(pc: PeerConnection, loop: asyncio.AbstractEventLoop):
    rw_loop = asyncio.new_event_loop()

    sender = pc._transceivers[0].sender
    receiver = pc._transceivers[0].receiver
    if not sender or not receiver:
        raise ValueError("Not found sender/receiver")

    remote_track = receiver.track
    local_track = sender.track
    encoding = sender._track_encodings[0]

    if not remote_track or not local_track:
        return

    jitter = JitterBuffer(capacity=128, is_video=True)

    frames_queue = asyncio.Queue[JitterFrame](100)

    async def encode():
        while True:
            frame = await frames_queue.get()

            try:
                pkts = encoding._packetizer.packetize(
                    frame.data,
                    frame.timestamp,
                )

                srtp = pc._dtls_transport._srtp_rtp

                if not srtp:
                    await asyncio.sleep(1)
                    continue

                assert pc._transport

                for pkt in pkts:
                    enc = await srtp.encrypt_nonblock(pkt.serialize(DEFAULT_EXT_MAP))
                    pc._transport.sendto(enc)

            except Exception as e:
                print("encode loop error:", e)
                pass

    asyncio.ensure_future(encode(), loop=loop)

    async def enqueue(frame: JitterFrame):
        await frames_queue.put(frame)

    while True:
        try:
            result = rw_loop.run_until_complete(remote_track.recv())

            pkt = media.RtpPacket.parse(result)
            pkt.ssrc = encoding.ssrc

            if not pc._dtls_transport._srtp_rtp:
                continue

            pkt._data = vp8_depayload(pkt.payload)

            # The frame packetized and may be restored via identical timestamp so frame splited into many rtp packets with the same timestamp but each part of it has own sequence number
            # The jitter return the sample frame that able to decode by decoder in my case it libvpx for vp8
            is_pli, encoded_frame = jitter.add(pkt)
            if is_pli:
                print("got pli")
                continue

            if encoded_frame:
                asyncio.ensure_future(enqueue(encoded_frame), loop=loop)

        except Exception as e:
            print("examples_ws | recv err", e)
            time.sleep(1)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    pc = PeerConnection()
    pc.start()
    await pc.gatherer.dial()

    # await pc.add_transceiver_from_kind(
    #     RTPCodecKind.Video, RTPTransceiverDirection.Sendrecv
    # )

    await pc.add_transceiver_from_kind(
        RTPCodecKind.Video, RTPTransceiverDirection.Sendonly
    )

    # await pc.add_transceiver_from_kind(
    #     RTPCodecKind.Video, RTPTransceiverDirection.Recvonly
    # )

    # def start():
    #     "send recive example"
    #     rw_thread = threading.Thread(
    #         target=start_read_write_loop, args=(pc, asyncio.get_running_loop())
    #     )
    #     rw_thread.start()

    def start():
        "send only example"
        rw_thread = threading.Thread(
            target=start_write_loop, args=(pc, asyncio.get_running_loop())
        )
        rw_thread.start()

    def on_close():
        # done.set()
        print("Done thread")

    async for data in on_recv(ws, on_close):
        msg: dict[str, Any] = json.loads(data)

        match msg.get("event"):
            case "negotiate":
                print("Start all webrtc")
                await pc.gatherer.dial()

                try:
                    start()
                except RuntimeError:
                    pass

            case "offer":
                print("recv offer")
                if offer := await pc.create_offer():
                    print("offer offer")
                    await pc.set_local_description(SessionDescriptionType.Offer, offer)
                    print("set offer")
                    await ws.send_json(
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
                    await pc.gatherer.set_remote_credentials(ufrag, pwd)

                await pc.set_remote_description(desc_type, desc)

            case "trickle-ice":
                # NOTE: In my current state I need know ufrag, pwd before adding the candidate, because all pair credentials is immutable
                data = msg.get("data")
                if not data:
                    continue
                payload: dict[str, Any] = json.loads(data)

                candidate_str = payload.get("candidate")
                if not candidate_str:
                    continue

                await pc.gatherer.add_remote_candidate(candidate_str)

            case _:
                print("Unknown event")
