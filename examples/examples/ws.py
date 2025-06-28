import asyncio
import json
import threading
import time
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import shared_memory
from typing import Any, Callable

import numpy as np
import torch
import torch.nn.functional as F
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from rav1e import Rav1e
from webrtc_rs import SRTP

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
        frames = list[Y4mFrame]()
        for frame in reader:
            n_frames += 1
            frames.append(frame)
        return frames, n_frames, reader


# filename = "output.y4m"
filename = "test.y4m"
# frames, y4m_reader = pre_read_y4m("test.y4m")


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
# chroma_width, chroma_height = video_details.chroma_sampling.get_chroma_dimensions(
#     video_details.width,
#     video_details.height,
# )


NUM_SLOTS = 2


def transform_worker(
    shm_name: str,
    prev_shm_name: str,
    width: int,
    height: int,
    chroma_width: int,
    chroma_height: int,
    frame_index: int,
):
    import numpy as np

    shm = shared_memory.SharedMemory(name=shm_name)
    y_size = width * height
    u_size = chroma_width * chroma_height
    v_size = chroma_width * chroma_height

    buf = np.ndarray((y_size + u_size + v_size,), dtype=np.uint8, buffer=shm.buf)

    y = buf[0:y_size]
    # u = buf[y_size : y_size + u_size]
    # v = buf[y_size + u_size :]

    # apply_rainbow_wave_numpy(
    #     y, u, v, width, height, chroma_width, chroma_height, frame_index
    # )

    y_t = (
        torch.from_numpy(y).float().unsqueeze(0).unsqueeze(0) / 255.0
    )  # shape [1,1,H,W]

    # Apply conv2d with padding=1 to keep size
    grad_x = torch.nn.functional.conv2d(y_t, sobel_x, padding=1)
    grad_y = torch.nn.functional.conv2d(y_t, sobel_y, padding=1)

    # Compute gradient magnitude
    edges = torch.sqrt(grad_x**2 + grad_y**2).squeeze()

    # Normalize to 0-1
    edges = edges / edges.max()
    threshold = 0.1
    edges = torch.where(edges > threshold, edges, torch.zeros_like(edges))

    # Scale edges back to 0-255 uint8
    edges_uint8 = (edges * 255).clamp(0, 255).to(torch.uint8)

    # Blend with original y (uint8)
    alpha = 0.5
    blended = (
        ((1 - alpha) * y + alpha * edges_uint8.numpy()).clip(0, 255).astype(np.uint8)
    )

    y[:] = blended.flatten()

    shm.close()


sobel_x = torch.tensor([[[[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]]]], dtype=torch.float32)
sobel_y = torch.tensor([[[[-1, -2, -1], [0, 0, 0], [1, 2, 1]]]], dtype=torch.float32)


def gaussian_blur(y_tensor: torch.Tensor, kernel_size=5, sigma=1.0) -> torch.Tensor:
    def get_gaussian_kernel1d(size, sigma):
        coords = torch.arange(size).float() - size // 2
        kernel = torch.exp(-(coords**2) / (2 * sigma**2))
        kernel /= kernel.sum()
        return kernel

    k = get_gaussian_kernel1d(kernel_size, sigma).view(1, 1, -1)  # [1,1,K]

    y_blur = F.conv2d(y_tensor, k.unsqueeze(2), padding=(0, kernel_size // 2))
    y_blur = F.conv2d(y_blur, k.unsqueeze(3), padding=(kernel_size // 2, 0))
    return y_blur


def transform_motion_highlight_Edge_glow_worker(
    curr_shm_name: str,
    prev_shm_name: str,
    width: int,
    height: int,
    chroma_width: int,
    chroma_height: int,
    frame_index: int,
):
    shm = shared_memory.SharedMemory(name=curr_shm_name)
    y_size = width * height
    u_size = chroma_width * chroma_height
    v_size = chroma_width * chroma_height
    buf = np.ndarray((y_size + u_size + v_size,), dtype=np.uint8, buffer=shm.buf)
    y = buf[0:y_size].reshape(height, width)
    u = buf[y_size : y_size + u_size]
    v = buf[y_size + u_size :]

    # Previous frame shm
    prev_shm = shared_memory.SharedMemory(name=prev_shm_name)
    prev_buf = np.ndarray((y_size,), dtype=np.uint8, buffer=prev_shm.buf)
    y_prev = prev_buf.reshape(height, width)

    y_t = torch.from_numpy(y).float().unsqueeze(0).unsqueeze(0) / 255.0  # [1,1,H,W]
    y_prev_t = torch.from_numpy(y_prev).float().unsqueeze(0).unsqueeze(0) / 255.0

    y_t = gaussian_blur(y_t, kernel_size=3, sigma=0.5)
    y_prev_t = gaussian_blur(y_prev_t, kernel_size=3, sigma=0.5)

    # 1) Motion mask by frame difference
    motion = torch.abs(y_t - y_prev_t).squeeze()
    motion_threshold = 0.3
    motion_mask = (motion > motion_threshold).float()

    grad_x = F.conv2d(y_t, sobel_x, padding=1)
    grad_y = F.conv2d(y_t, sobel_y, padding=1)
    edges = torch.sqrt(grad_x**2 + grad_y**2).squeeze()
    edges = edges / edges.max()
    edge_threshold = 0.15
    edges_mask = (edges > edge_threshold).float()

    # 3) Create glow mask where motion AND edges are strong
    glow_mask = (motion_mask * edges_mask).clamp(0, 1)

    # 4) Increase Y luminance where glow is detected (boost brightness)
    glow_strength = 0.5
    y_t_new = y_t.squeeze() + glow_mask * glow_strength
    y_t_new = y_t_new.clamp(0, 1)

    # 5) Boost blue tint in U/V near glow (simple)
    # Normalize U/V
    u_t = torch.from_numpy(u).float().reshape(chroma_height, chroma_width) / 255.0
    v_t = torch.from_numpy(v).float().reshape(chroma_height, chroma_width) / 255.0

    glow_mask_resized = glow_mask.unsqueeze(0).unsqueeze(0)  # [1,1,H,W]
    glow_mask_resized = F.interpolate(
        glow_mask_resized,
        size=(chroma_height, chroma_width),
        mode="bilinear",
        align_corners=False,
    )
    glow_mask_resized = glow_mask_resized.squeeze(0).squeeze(
        0
    )  # [chroma_height, chroma_width]

    # Add blue tint: increase V (blue chroma) in glow areas, clip to [0,1]
    tint_strength = 0.3
    v_t = (v_t + glow_mask_resized * tint_strength).clamp(0, 1)

    y_float = y.astype(np.float32)
    u_float = u.astype(np.float32).reshape(chroma_height, chroma_width)
    v_float = v.astype(np.float32).reshape(chroma_height, chroma_width)

    # y_t_new is float [0..1], scale to 0..255
    y_t_new_255 = (y_t_new.numpy() * 255).astype(np.float32)

    # u_t and v_t are float [0..1], scale to 0..255
    u_t_255 = (u_t.numpy() * 255).astype(np.float32)
    v_t_255 = (v_t.numpy() * 255).astype(np.float32)

    alpha = 0.4

    # TODO: blend make the encoding soo fast
    # Blend each channel
    y_blended = (
        ((1 - alpha) * y_float + alpha * y_t_new_255).clip(0, 255).astype(np.uint8)
    )
    u_blended = ((1 - alpha) * u_float + alpha * u_t_255).clip(0, 255).astype(np.uint8)
    v_blended = ((1 - alpha) * v_float + alpha * v_t_255).clip(0, 255).astype(np.uint8)

    # Write back to buffers
    y[:] = y_blended
    u[:] = u_blended.flatten()
    v[:] = v_blended.flatten()

    # alpha = 0.4
    # blended = ((1 - alpha) * y + alpha * y_t_new.numpy()).clip(0, 255).astype(np.uint8)

    # y[:] = blended

    # # Write back Y,U,V
    # # y[:] = (y_t_new.squeeze().numpy() * 255).astype(np.uint8)
    # u[:] = (u_t.numpy() * 255).astype(np.uint8).flatten()
    # v[:] = (v_t.numpy() * 255).astype(np.uint8).flatten()

    shm.close()
    prev_shm.close()


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
    shm_np = np.ndarray((shm_size,), dtype=np.uint8, buffer=shm_buf)

    # Step 1: Write original frame into shared memory

    chroma_width, chroma_height = video_details.chroma_sampling.get_chroma_dimensions(
        video_details.width,
        video_details.height,
    )
    y_size = video_details.width * video_details.height
    chroma_size = chroma_width * chroma_height

    y, u, v = frame.planes.y, frame.planes.u, frame.planes.v
    shm_np[0:y_size] = np.frombuffer(y, dtype=np.uint8)
    shm_np[y_size : y_size + chroma_size] = np.frombuffer(u, dtype=np.uint8)
    shm_np[y_size + chroma_size :] = np.frombuffer(v, dtype=np.uint8)

    prev_slot_idx = (slot_idx - 1) % len(shm_slots)
    prev_shm = shm_slots[prev_slot_idx]

    await asyncio.get_running_loop().run_in_executor(
        executor,
        # transform_worker,
        transform_motion_highlight_Edge_glow_worker,
        shm.name,
        prev_shm.name,
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
        # y_plane=y,
        # u_plane=u,
        # v_plane=v,
        y_plane=shm_np[0:y_size].tobytes(),
        u_plane=shm_np[y_size : y_size + chroma_size].tobytes(),
        v_plane=shm_np[y_size + chroma_size :].tobytes(),
    )

    return ""


executor = ProcessPoolExecutor(max_workers=NUM_SLOTS)
shm_slots = [
    shared_memory.SharedMemory(create=True, size=y4m_reader.buffer_bytes_size)
    for _ in range(NUM_SLOTS)
]


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


TARGET_FPS = 30
FRAME_PERIOD = 1 / TARGET_FPS


def start_write_loop(pc: PeerConnection, loop: asyncio.AbstractEventLoop):
    rw_loop = asyncio.new_event_loop()

    sender = pc._transceivers[0].sender
    if not sender:
        raise ValueError("Not found the sender")

    local_track = sender.track
    if not local_track:
        raise ValueError("Not found local track")

    encoding = sender._track_encodings[0]

    frames, frame_count, y4m_reader = pre_read_y4m(filename)

    # frames = rw_loop.run_until_complete(pre_read_frames("output_av1.ivf"))
    # frames = rw_loop.run_until_complete(pre_read_frames("output.ivf"))

    # ptime = encoding.codec.refresh_rate
    # ms = 10000
    # ssrc = encoding.ssrc

    send_time_cache = SendTimeCache()

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
        max_inflight_tasks = len(shm_slots)
        inflight_tasks = set()

        async for pts, time_base in encoding._packetizer.ticker():
            start_time = asyncio.get_event_loop().time()

            if frame_index >= frame_count:
                frame_index = 0

                # Wait if all slots are busy
            if len(inflight_tasks) >= max_inflight_tasks:
                # Wait for any one task to finish before submitting another
                _done, inflight_tasks = await asyncio.wait(
                    inflight_tasks, return_when=asyncio.FIRST_COMPLETED
                )

            slot_idx = frame_index % max_inflight_tasks
            frame = frames[frame_index]

            # Launch a non-blocking task for this frame
            task = asyncio.create_task(
                process_frame(slot_idx, shm_slots, frame, executor, frame_index)
            )
            inflight_tasks.add(task)

            frame_index += 1

            # await asyncio.sleep(0)
            elapsed = asyncio.get_event_loop().time() - start_time
            sleep_time = max(0, FRAME_PERIOD - elapsed)
            await asyncio.sleep(sleep_time)

            # if frame_index >= len(frames):
            #     frame_index = 0

            # frame = frames[frame_index]

            # await process_frame(0, shm_slots, frame, executor, frame_index)

            # y_bytes, u_bytes, v_bytes = apply_rainbow_wave(
            #     frame.planes.y,
            #     frame.planes.u,
            #     frame.planes.v,
            #     width=video_details.width,
            #     height=video_details.height,
            #     chroma_width=chroma_width,
            #     chroma_height=chroma_height,
            #     frame_index=frame_index,
            # )

            # await enc.send_packet(
            #     bytes_per_sample=y4m_reader.buffer_bytes_size,
            #     width=video_details.width,
            #     chroma_width=chroma_width,
            #     y_plane=frame.planes.y,
            #     u_plane=frame.planes.u,
            #     v_plane=frame.planes.v,
            #     # y_plane=y_bytes,
            #     # u_plane=u_bytes,
            #     # v_plane=v_bytes,
            # )
            frame_index += 1

    encoded_frames = asyncio.Queue[bytes]()

    async def encoded_result():
        while True:
            # start_time = asyncio.get_event_loop().time()
            frame = await enc.receive_packet()
            await encoded_frames.put(frame)
            # elapsed = asyncio.get_event_loop().time() - start_time
            # sleep_time = max(0, FRAME_PERIOD - elapsed)
            # await asyncio.sleep(sleep_time)

    async def encode():
        frame_index = 0

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

            # frame = await enc.receive_packet()

            frame = await encoded_frames.get()
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

    rw_loop.create_task(encoded_result())
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
