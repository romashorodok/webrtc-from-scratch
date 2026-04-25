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
from webrtc.media.jitterbuffer import JitterBuffer, JitterFrame
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import (
    RtcpPacket,
    RunLengthChunk,
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
NUM_SLOTS = 2


def stage_frame_worker(
    shm_name: str,
    width: int,
    height: int,
    chroma_width: int,
    chroma_height: int,
    frame_index: int,
):
    """Keep a process boundary without mutating the frame.

    The examples still move bytes through shared memory and a worker process,
    but the image-processing step is now an explicit no-op.
    """
    shm = shared_memory.SharedMemory(name=shm_name)
    y_size = width * height
    u_size = chroma_width * chroma_height
    v_size = chroma_width * chroma_height
    _ = frame_index
    # Explicit copy keeps the example structured as ingest -> worker -> encode.
    staged = bytes(shm.buf[: y_size + u_size + v_size])
    shm.buf[: y_size + u_size + v_size] = staged

    shm.close()


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
        # y_plane=y,
        # u_plane=u,
        # v_plane=v,
        y_plane=bytes(shm_buf[0:y_size]),
        u_plane=bytes(shm_buf[y_size : y_size + chroma_size]),
        v_plane=bytes(shm_buf[y_size + chroma_size : shm_size]),
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
        # Persistent state across TWCC feedback packets
        smoothed_gradient = 0.0

        while True:
            try:
                # DTLSTransport now handles incoming RTCP routing internally
                # Just read from the stream (already decrypted and routed)
                stream = sender._rtcp_stream
                assert stream

                # Read decrypted RTCP from stream
                rtcp = await stream.read()
                pkts = RtcpPacket.parse(rtcp)
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
            # start_time = asyncio.get_event_loop().time()
            frame = await enc.receive_packet()
            await encoded_frames.put(frame)
            # elapsed = asyncio.get_event_loop().time() - start_time
            # sleep_time = max(0, FRAME_PERIOD - elapsed)
            # await asyncio.sleep(sleep_time)

    async def encode():
        frame_index = 0

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
                pkt.extensions.transport_sequence_number = (
                    twcc_seq.next_sequence_number()
                )
                serialized = pkt.serialize(DEFAULT_EXT_MAP)
                # Offload encrypt to thread pool to avoid blocking event loop
                encoded = await asyncio.to_thread(srtp.encrypt, serialized)
                if not pc._transport:
                    print(f"[WS] ERROR: pc._transport is None!")
                    continue
                send_time_cache.add(pkt.extensions.transport_sequence_number)
                pc._transport.sendto(encoded)

    rw_loop.create_task(encoded_result())
    rw_loop.create_task(send_routine())
    # Run rtcp_handler in the MAIN event loop since Stream._queue was created there
    asyncio.run_coroutine_threadsafe(rtcp_handler(), loop)
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
                    # Offload encrypt to thread pool to avoid blocking event loop
                    enc = await asyncio.to_thread(srtp.encrypt, pkt.serialize(DEFAULT_EXT_MAP))
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
