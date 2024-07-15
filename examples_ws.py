import asyncio
import json
from typing import Any, Callable
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from peer_connection import (
    PeerConnection,
    RTPCodecKind,
    RTPTransceiverDirection,
    SessionDescription,
    SessionDescriptionType,
)
import media
import fractions
import threading

app = FastAPI()


async def on_recv(ws: WebSocket, on_close: Callable | None = None):
    try:
        while True:
            yield await ws.receive_text()
    except WebSocketDisconnect:
        if _on_close := on_close:
            _on_close()


FRAME_RATE = 30  # frames per second
FRAME_DURATION = 1 / FRAME_RATE  # duration of each frame in seconds
CLOCK_RATE = 90000  # RTP clock rate for video
VIDEO_CLOCK_RATE = 90000
VIDEO_PTIME = 1 / 30  # 30fps
VIDEO_TIME_BASE = fractions.Fraction(1, VIDEO_CLOCK_RATE)


def convert_timebase(
    pts: int, from_base: fractions.Fraction, to_base: fractions.Fraction
) -> int:
    if from_base != to_base:
        pts = int(pts * from_base / to_base)
    return pts


async def write_routine(
    done: threading.Event,
    pc: PeerConnection,
    frames: list[tuple[bytes, media.IVFFrameHeader]],
):
    frame_index = 0

    async for _ in media.ticker(VIDEO_PTIME / 1000):
        if done.is_set():
            raise asyncio.CancelledError()

        if frame_index >= len(frames):
            print("All frames sent. Replay from beginning.")
            frame_index = 0

        frame, _ = frames[frame_index]
        frame_index += 1

        try:
            for t in pc._transceivers:
                track = t.track_local()
                if not track:
                    print("Not found sender")
                    continue
                await track.write_frame(frame)

        except RuntimeError:
            pass


async def pre_read_frames(file_path: str):
    frames: list[tuple[bytes, media.IVFFrameHeader]] = []
    with open(file_path, "rb") as file:
        reader = media.IVFReader(file)
        for frame, header in reader:
            frames.append((frame, header))
    return frames


def start_writer_loop(pc: PeerConnection, done: threading.Event):
    writer_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(writer_loop)
    frames = writer_loop.run_until_complete(pre_read_frames("output.ivf"))
    print("done reading frames")
    try:
        writer_loop.run_until_complete(write_routine(done, pc, frames))
    except asyncio.CancelledError:
        print("Stop of writer_loop")
    finally:
        writer_loop.run_until_complete(writer_loop.shutdown_asyncgens())
        writer_loop.close()
        print("Graceful shutdown of writer_loop")


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    pc = PeerConnection()
    await pc.add_transceiver_from_kind(
        RTPCodecKind.Video, RTPTransceiverDirection.Sendrecv
    )
    await pc.gatherer.gather()
    pc.gatherer.agent.dial()

    done = threading.Event()
    writer_thread = threading.Thread(
        target=start_writer_loop, daemon=False, args=(pc, done)
    )

    def on_close():
        done.set()
        print("Done thread")

    async for data in on_recv(ws, on_close):
        msg: dict[str, Any] = json.loads(data)

        match msg.get("event"):
            case "negotiate":
                print("Start all webrtc")
                await pc.gatherer.gather()
                pc.gatherer.agent.dial()
                for dtls in pc._dtls_transports:
                    await dtls.start()
                writer_thread.start()

            case "offer":
                if offer := await pc.create_offer():
                    await pc.set_local_description(SessionDescriptionType.Offer, offer)
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
                    pc.gatherer.agent.set_remote_credentials(ufrag, pwd)

                for dtls_t in pc._dtls_transports:
                    print("fingerprints", desc.get_media_fingerprints())
                    dtls_t._media_fingerprints.extend(desc.get_media_fingerprints())

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

                pc.gatherer.agent.add_remote_candidate(candidate_str)
            case _:
                print("Unknown event")
