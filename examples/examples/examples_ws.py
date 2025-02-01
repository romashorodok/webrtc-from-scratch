import asyncio
import json
from typing import Any, Callable
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from webrtc.peer_connection import (
    PeerConnection,
)
from webrtc import media
from webrtc.session_description import SessionDescription, SessionDescriptionType
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection

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
    transceiver = pc._transceivers[0]
    sender = transceiver.sender
    track = transceiver.track_local()
    if not sender or not track:
        raise ValueError("Something goes wrong with track")

    encoding = sender._track_encodings[0]
    ptime = encoding.codec.refresh_rate
    ms = 1000

    async for _ in media.ticker(ptime / ms):
        if done.is_set():
            raise asyncio.CancelledError()

        if frame_index >= len(frames):
            print("All frames sent. Replay from beginning.")
            frame_index = 0

        frame, _ = frames[frame_index]
        frame_index += 1

        try:
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
    # asyncio.set_event_loop(writer_loop)
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


def start_reader_loop(pc: PeerConnection):
    receiver = pc._transceivers[0].receiver
    if not receiver:
        raise ValueError("Not found expected receiver")

    track = receiver._track
    if not track:
        raise ValueError("Not found expected track")

    while True:
        pkt = track.recv_rtp_pkt_sync()
        print("Recv pkt from reader loop", pkt)


def start_read_write_loop(pc: PeerConnection):
    rw_loop = asyncio.new_event_loop()

    sender = pc._transceivers[0].sender
    receiver = pc._transceivers[0].receiver
    if not sender or not receiver:
        raise ValueError("Not found sender/receiver")

    remote_track = receiver.track
    local_track = sender.track

    if not remote_track or not local_track:
        return

    while True:
        pkt = remote_track.recv_rtp_pkt_sync()
        result = rw_loop.run_until_complete(local_track.write_rtp_packet(pkt))
        print("Write result", result)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    pc = PeerConnection()
    pc.start()
    await pc.gatherer.dial()

    await pc.add_transceiver_from_kind(
        RTPCodecKind.Video, RTPTransceiverDirection.Sendrecv
    )

    # await pc.add_transceiver_from_kind(
    #     RTPCodecKind.Video, RTPTransceiverDirection.Sendonly
    # )

    # await pc.add_transceiver_from_kind(
    #     RTPCodecKind.Video, RTPTransceiverDirection.Recvonly
    # )

    # await pc.__gatherer.gather()
    # pc.__gatherer.agent.dial()

    # done = threading.Event()
    # writer_thread = threading.Thread(
    #     target=start_writer_loop, daemon=False, args=(pc, done)
    # )
    # reader_thread = threading.Thread(target=start_reader_loop, daemon=False, args=(pc,))
    rw_thread = threading.Thread(target=start_read_write_loop, args=(pc,))

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
                    # writer_thread.start()
                    # reader_thread.start()
                    rw_thread.start()
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
                    # pc.__gatherer.agent.set_remote_credentials(ufrag, pwd)

                # for dtls_t in pc.__dtls_transports:
                #     print("fingerprints", desc.get_media_fingerprints())
                #
                #     dtls_t.P_media_fingerprints.extend(desc.get_media_fingerprints())

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
