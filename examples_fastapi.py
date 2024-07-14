import asyncio
from concurrent.futures import ThreadPoolExecutor

import json
import threading
from typing import Any
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import peer_connection
from ice.net.types import Packet, Address

import media
import fractions


app = FastAPI()

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


pc = peer_connection.PeerConnection()

lock = asyncio.Lock()


async def peer():
    yield pc


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


def next_read_frame(reader: media.IVFReader):
    try:
        return next(reader)
    except StopIteration:
        return None, None


async def read_frame(reader: media.IVFReader):
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        return await loop.run_in_executor(executor, next_read_frame, reader)


async def pre_read_frames(file_path: str):
    frames: list[tuple[bytes, media.IVFFrameHeader]] = []
    with open(file_path, "rb") as file:
        reader = media.IVFReader(file)
        for frame, header in reader:
            frames.append((frame, header))
    return frames


async def write_routine(frames: list[tuple[bytes, media.IVFFrameHeader]]):
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


@app.get("/offer")
async def offer(pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        await pc.add_transceiver_from_kind(
            peer_connection.RTPCodecKind.Video,
            peer_connection.RTPTransceiverDirection.Sendrecv,
        )
        pc.gatherer.agent.dial()

        desc = await pc.create_offer()
        if not desc:
            return "unable create offer"
        return {"type": "offer", "sdp": desc.marshal()}


@app.get("/candidates")
async def candidates(pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        print(pc)
        await pc.gatherer.gather()
        candidates = await pc.gatherer.agent.get_local_candidates()
        c = candidates[0]
        return c.unwrap.to_ice_str()


@app.post("/ice")
async def ice(req: Request, pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        body = await req.body()
        body_dict: dict[str, Any] = json.loads(body)
        candidate = body_dict.get("candidate")
        if not candidate:
            return
        pc.gatherer.agent.add_remote_candidate(candidate)
        await pc.gatherer.gather()
        pc.gatherer.agent.dial()

        for dtls in pc._dtls_transports:
            await dtls.start()


def start_writer_loop():
    writer_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(writer_loop)
    frames = writer_loop.run_until_complete(pre_read_frames("output.ivf"))
    print("Done reading frames")
    writer_loop.create_task(write_routine(frames))
    writer_loop.run_forever()


writer_thread = threading.Thread(target=start_writer_loop)
writer_thread.start()


@app.post("/answer")
async def answer(req: Request, pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        body = await req.body()
        body_dict = json.loads(body)
        _ = body_dict["type"]
        sdp = body_dict["sdp"]
        desc = peer_connection.SessionDescription.parse(sdp)
        media = desc.media_descriptions[0]

        for dtls in pc._dtls_transports:
            dtls._media_fingerprints.extend(media.fingerprints)

        candidate_str = media.candidates
        ufrag, pwd = media.ice_ufrag, media.ice_pwd
        if not ufrag or not pwd:
            return

        pc.gatherer.agent.set_remote_credentials(ufrag, pwd)

        pc.gatherer.agent.dial()
        await pc.gatherer.gather()

        for dtls in pc._dtls_transports:
            await dtls.start()

        print(candidate_str, ufrag, pwd)
