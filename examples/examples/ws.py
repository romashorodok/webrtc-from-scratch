import asyncio
import json
import threading
import time
from collections import deque
from typing import Any, Callable

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
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
        reader = media.Y4mDecoder(file)
        n_frames = 0
        for data in reader:
            n_frames += 1

        print("done frame", n_frames)


pre_read_y4m("output.y4m")

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


def start_write_loop(pc: PeerConnection, loop: asyncio.AbstractEventLoop):
    rw_loop = asyncio.new_event_loop()

    sender = pc._transceivers[0].sender
    if not sender:
        raise ValueError("Not found the sender")

    local_track = sender.track
    if not local_track:
        raise ValueError("Not found local track")

    encoding = sender._track_encodings[0]

    frames = rw_loop.run_until_complete(pre_read_frames("output.ivf"))

    ptime = encoding.codec.refresh_rate
    ms = 1000
    ssrc = encoding.ssrc

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

    async def encode():
        frame_index = 0

        srtp: SRTP | None = None

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
                enc = await srtp.encrypt_nonblock(pkt.serialize(DEFAULT_EXT_MAP))
                assert pc._transport
                send_time_cache.add(pkt.extensions.transport_sequence_number)
                pc._transport.sendto(enc)

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
