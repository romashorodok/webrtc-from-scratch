import asyncio
import json
from typing import Any
from fastapi import FastAPI, WebSocket
from peer_connection import (
    PeerConnection,
    RTPCodecKind,
    RTPTransceiverDirection,
    SessionDescription,
    SessionDescriptionType,
)
from ice.net.types import Packet, Address
import media
import fractions
import threading

app = FastAPI()


async def on_recv(ws: WebSocket):
    while True:
        yield await ws.receive_text()


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
    pc: PeerConnection, frames: list[tuple[bytes, media.IVFFrameHeader]]
):
    packetizer = media.Packetizer(
        mtu=1200,
        pt=96,
        ssrc=0,
        payloader=media.VP8Payloader(),
        clock_rate=CLOCK_RATE,
    )

    frame_index = 0

    async for _ in media.ticker(VIDEO_PTIME / 1000):
        if frame_index >= len(frames):
            print("All frames sent. Replay from beginning.")
            frame_index = 0

        frame, _ = frames[frame_index]
        frame_index += 1

        try:
            for t in pc._transceivers:
                track = t.track_local()
                sender = t._sender

                if not sender or not track:
                    print("Not found sender")
                    continue

                encodings = sender._track_encodings
                if not encodings:
                    print("Not found encoding")
                    continue
                enc = encodings[0]

                packetizer.ssrc = enc.ssrc

                pts, time_base = await packetizer.next_timestamp()

                pkts = packetizer.packetize(
                    frame, convert_timebase(pts, time_base, VIDEO_TIME_BASE)
                )

                for pkt in pkts:
                    data = pkt.serialize()
                    await track.write_rtp(Packet(Address("0.0.0.0", 0), data))

        except RuntimeError:
            pass


async def pre_read_frames(file_path: str):
    frames: list[tuple[bytes, media.IVFFrameHeader]] = []
    with open(file_path, "rb") as file:
        reader = media.IVFReader(file)
        for frame, header in reader:
            frames.append((frame, header))
    return frames


def start_writer_loop(pc: PeerConnection):
    writer_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(writer_loop)
    frames = writer_loop.run_until_complete(pre_read_frames("output.ivf"))
    print("done reading frames")
    writer_loop.create_task(write_routine(pc, frames))
    writer_loop.run_forever()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    pc = PeerConnection()
    await pc.add_transceiver_from_kind(
        RTPCodecKind.Video, RTPTransceiverDirection.Sendrecv
    )
    await pc.gatherer.gather()
    pc.gatherer.agent.dial()
    writer_thread = threading.Thread(target=start_writer_loop, daemon=False, args=(pc,))

    async for data in on_recv(ws):
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
