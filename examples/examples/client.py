"""
WebRTC Client Example (Python as DTLS Client)

This example demonstrates Python WebRTC acting as the DTLS client:
- Browser sends offer, Python sends answer
- Python acts as ICE Controlled (accepts connection)
- Python acts as DTLS Client (sends ClientHello)
- Sends video stream to browser

The browser acts as the WebRTC server (creates offer, receives answer).

Usage:
    make client
    # or
    uv run serve.py examples.client:app
"""

import asyncio
import json
import threading
import time
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import shared_memory
from typing import Any, Callable

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from rav1e import Rav1e
from webrtc.srtp import Session as SrtpSession

from webrtc import media
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import RtcpPacket, TransportLayerCC
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.media.y4m import Y4mFrame
from webrtc.peer_connection import PeerConnection
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


# Video configuration
filename = "test.y4m"

with open(filename, "rb") as file:
    y4m_reader = media.Y4mDecoder(file)

video_details = y4m_reader.get_video_details()
enc = Rav1e(
    width=video_details.width,
    height=video_details.height,
    sample_aspect_ratio_num=video_details.sample_aspect_ratio.numerator,
    sample_aspect_ratio_den=video_details.sample_aspect_ratio.denominator,
    bit_depth=video_details.bit_depth,
    chroma_sampling=video_details.chroma_sampling.value,
    time_base_num=video_details.time_base.numerator,
    time_base_dem=video_details.time_base.denominator,
)

NUM_SLOTS = 2
TARGET_FPS = 30
FRAME_PERIOD = 1 / TARGET_FPS

# TWCC sequence numbers
twcc_seq = Sequencer()


def pre_read_y4m(file_path: str):
    with open(file_path, "rb") as file:
        n_frames = 0
        reader = media.Y4mDecoder(file)
        frames = list[Y4mFrame]()
        for frame in reader:
            n_frames += 1
            frames.append(frame)
        return frames, n_frames, reader


def stage_frame_worker(
    shm_name: str,
    width: int,
    height: int,
    chroma_width: int,
    chroma_height: int,
    frame_index: int,
):
    """Keep the shared-memory worker stage, but do no image processing."""
    _ = frame_index
    shm = shared_memory.SharedMemory(name=shm_name)

    y_size = width * height
    chroma_size = chroma_width * chroma_height

    # Explicit copy keeps the examples structured as ingest -> worker -> encode.
    staged = bytes(shm.buf[: y_size + 2 * chroma_size])
    shm.buf[: y_size + 2 * chroma_size] = staged

    shm.close()


class SendTimeCache:
    def __init__(self, max_age_seconds=5):
        self.cache = dict[int, float]()
        self.queue = deque[tuple[int, float]]()
        self.max_age = max_age_seconds

    def add(self, sequence_number: int, send_time: float | None = None):
        if send_time is None:
            send_time = time.monotonic()
        self.cache[sequence_number] = send_time
        self.queue.append((sequence_number, send_time))
        self._prune()

    def get(self, sequence_number: int):
        return self.cache.get(sequence_number)

    def _prune(self):
        now = time.monotonic()
        while self.queue:
            seq, ts = self.queue[0]
            if now - ts > self.max_age:
                self.queue.popleft()
                self.cache.pop(seq, None)
            else:
                break


executor = ProcessPoolExecutor(max_workers=NUM_SLOTS)
shm_slots = [
    shared_memory.SharedMemory(create=True, size=y4m_reader.buffer_bytes_size)
    for _ in range(NUM_SLOTS)
]


async def process_frame(
    slot_idx: int,
    shm_slots: list[shared_memory.SharedMemory],
    frame: Y4mFrame,
    executor: ProcessPoolExecutor,
    frame_index: int,
):
    shm = shm_slots[slot_idx]
    shm_buf = shm.buf

    shm_size = y4m_reader.buffer_bytes_size

    chroma_width, chroma_height = video_details.chroma_sampling.get_chroma_dimensions(
        video_details.width,
        video_details.height,
    )
    y_size = video_details.width * video_details.height
    chroma_size = chroma_width * chroma_height

    y, u, v = frame.planes.y, frame.planes.u, frame.planes.v
    shm_buf[0:y_size] = y
    shm_buf[y_size : y_size + chroma_size] = u
    shm_buf[y_size + chroma_size : shm_size] = v

    await asyncio.get_running_loop().run_in_executor(
        executor,
        stage_frame_worker,
        shm.name,
        video_details.width,
        video_details.height,
        chroma_width,
        chroma_height,
        frame_index,
    )

    await enc.send_packet(
        1,
        width=video_details.width,
        chroma_width=chroma_width,
        y_plane=bytes(shm_buf[0:y_size]),
        u_plane=bytes(shm_buf[y_size : y_size + chroma_size]),
        v_plane=bytes(shm_buf[y_size + chroma_size : shm_size]),
    )


def start_write_loop(pc: PeerConnection, loop: asyncio.AbstractEventLoop):
    """Video encoding and sending loop."""
    rw_loop = asyncio.new_event_loop()

    sender = pc._transceivers[0].sender
    if not sender:
        raise ValueError("Sender not found")

    local_track = sender.track
    if not local_track:
        raise ValueError("Local track not found")

    encoding = sender._track_encodings[0]
    frames, frame_count, _ = pre_read_y4m(filename)
    send_time_cache = SendTimeCache()

    async def rtcp_handler():
        while True:
            try:
                stream = sender._rtcp_stream
                if not stream:
                    await asyncio.sleep(0.1)
                    continue

                rtcp = await stream.read()
                pkts = RtcpPacket.parse(rtcp)
                for feedback in pkts:
                    if isinstance(feedback, TransportLayerCC):
                        seq = feedback.base_sequence_number
                        base_time_us = feedback.reference_time * 64_000

                        for delta in feedback.recv_deltas:
                            send_time = send_time_cache.get(seq)
                            if send_time:
                                base_time_us += delta.delta
                                arrival_time = base_time_us / 1_000_000
                                delay = max(0.0, arrival_time - send_time)
                                print(f"Seq {seq}: delay = {delay * 1000:.3f} ms")
                            seq += 1

            except Exception as e:
                print(f"RTCP error: {e}")
                await asyncio.sleep(1)

    async def send_routine():
        frame_index = 0
        max_inflight_tasks = len(shm_slots)
        inflight_tasks = set()

        async for pts, time_base in encoding._packetizer.ticker():
            start_time = asyncio.get_event_loop().time()

            if frame_index >= frame_count:
                frame_index = 0

            if len(inflight_tasks) >= max_inflight_tasks:
                _done, inflight_tasks = await asyncio.wait(
                    inflight_tasks, return_when=asyncio.FIRST_COMPLETED
                )

            slot_idx = frame_index % max_inflight_tasks
            frame = frames[frame_index]

            task = asyncio.create_task(
                process_frame(slot_idx, shm_slots, frame, executor, frame_index)
            )
            inflight_tasks.add(task)
            frame_index += 1

            elapsed = asyncio.get_event_loop().time() - start_time
            sleep_time = max(0, FRAME_PERIOD - elapsed)
            await asyncio.sleep(sleep_time)

    encoded_frames = asyncio.Queue[bytes]()

    async def encoded_result():
        while True:
            frame = await enc.receive_packet()
            await encoded_frames.put(frame)

    async def encode():
        srtp: SrtpSession | None = None

        async for pts, time_base in encoding._packetizer.ticker():
            if not srtp:
                if srtp_transport := pc._dtls_transport._srtp_rtp:
                    srtp = srtp_transport
                else:
                    continue

            frame = await encoded_frames.get()
            pkts = encoding._packetizer.packetize(
                frame, encoding.convert_timebase(pts, time_base, time_base)
            )

            for pkt in pkts:
                pkt.extensions.transport_sequence_number = twcc_seq.next_sequence_number()
                serialized = pkt.serialize(DEFAULT_EXT_MAP)
                encoded = await asyncio.to_thread(srtp.encrypt, serialized)
                if not pc._transport:
                    print("[CLIENT] ERROR: pc._transport is None!")
                    continue
                send_time_cache.add(pkt.extensions.transport_sequence_number)
                pc._transport.sendto(encoded)

    rw_loop.create_task(encoded_result())
    rw_loop.create_task(send_routine())
    rw_loop.create_task(rtcp_handler())
    rw_loop.run_until_complete(encode())


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    """
    WebSocket endpoint where Python acts as WebRTC client (DTLS Client).

    Flow:
    1. Browser sends offer
    2. Python creates answer and sends it back
    3. Python uses ICE Controlled role (accept)
    4. Python uses DTLS Client role
    5. Video is streamed to browser
    """
    await ws.accept()
    print("[CLIENT] WebSocket connected, waiting for browser offer...")

    pc = PeerConnection()
    pc.start()

    # Add video transceiver (send only)
    await pc.add_transceiver_from_kind(
        RTPCodecKind.Video, RTPTransceiverDirection.Sendonly
    )

    rw_thread: threading.Thread | None = None

    def start_video():
        nonlocal rw_thread
        if rw_thread is None:
            rw_thread = threading.Thread(
                target=start_write_loop,
                args=(pc, asyncio.get_running_loop())
            )
            rw_thread.start()
            print("[CLIENT] Video thread started")

    def on_close():
        print("[CLIENT] WebSocket closed")

    async for data in on_recv(ws, on_close):
        msg: dict[str, Any] = json.loads(data)

        match msg.get("event"):
            case "offer":
                # Browser sends offer, we create answer
                print("[CLIENT] Received offer from browser")
                data = msg.get("data")
                if not data:
                    continue

                payload: dict[str, Any] = json.loads(data) if isinstance(data, str) else data
                sdp = payload.get("sdp")
                sdp_type = payload.get("type")

                if not sdp or sdp_type != "offer":
                    print(f"[CLIENT] Invalid offer: sdp={bool(sdp)}, type={sdp_type}")
                    continue

                # Parse and set remote description (the offer)
                remote_desc = SessionDescription.parse(sdp)
                print("[CLIENT] Parsed remote offer")

                # Set remote credentials for ICE
                for ufrag, pwd in remote_desc.get_media_credentials():
                    await pc.gatherer.set_remote_credentials(ufrag, pwd)

                await pc.set_remote_description(SessionDescriptionType.Offer, remote_desc)
                print("[CLIENT] Remote description set")

                # Start ICE as Controlled (answerer) - this makes Python DTLS Client
                await pc.gatherer.accept()
                print("[CLIENT] ICE accept() called - acting as Controlled/DTLS Client")

                # Create and send answer
                answer = await pc.create_answer()
                if answer:
                    await pc.set_local_description(SessionDescriptionType.Answer, answer)
                    print("[CLIENT] Created answer, sending to browser")
                    await ws.send_json({
                        "event": "answer",
                        "data": json.dumps({
                            "type": "answer",
                            "sdp": answer.marshal().decode()
                        })
                    })

                    # Start video after answer is sent
                    try:
                        start_video()
                    except RuntimeError:
                        pass
                else:
                    print("[CLIENT] Failed to create answer")

            case "trickle-ice" | "candidate":
                data = msg.get("data")
                if not data:
                    continue

                payload: dict[str, Any] = json.loads(data) if isinstance(data, str) else data
                candidate_str = payload.get("candidate")

                if candidate_str:
                    print(f"[CLIENT] Adding remote ICE candidate")
                    await pc.gatherer.add_remote_candidate(candidate_str)

            case "negotiate":
                # If browser asks to negotiate, we wait for their offer
                print("[CLIENT] Negotiate requested, waiting for browser offer...")

            case _:
                print(f"[CLIENT] Unknown event: {msg.get('event')}")
