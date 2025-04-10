import asyncio
from struct import pack
import time
import json
from typing import Any, Callable
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from webrtc.media.jitterbuffer import JitterBuffer, JitterFrame
from webrtc.media.packetizer import Sequencer, SimplePacketizer
from webrtc.media.vp8_payloader import vp8_depayload
from webrtc.peer_connection import (
    PeerConnection,
)
from webrtc import media
from webrtc.session_description import SessionDescription, SessionDescriptionType
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection
from webrtc.media.jitterbuffer import JitterBuffer

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

    # while True:
    #     pkt = track.recv_rtp_pkt_sync()
    #     print("Recv pkt from reader loop", pkt)


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

    ptime = encoding.codec.refresh_rate
    ms = 1000

    async def encode():
        while True:
            # print("encode loop")
            frame = await frames_queue.get()
            # print("encoded frame recv", frame)

            try:
                # pts, time_base = await encoding._packetizer.next_timestamp()

                pkts = encoding._packetizer.packetize(
                    frame.data,
                    frame.timestamp,
                    # encoding.convert_timebase(pts, time_base, time_base)
                )

                srtp = pc._dtls_transport._srtp_rtp

                if not srtp:
                    await asyncio.sleep(1)
                    continue

                assert pc._transport

                for pkt in pkts:
                    # pkt.timestamp = frame.timestamp
                    enc = await srtp.encrypt_nonblock(pkt.serialize())
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

            # srtp = pc._dtls_transport._srtp_rtp

            # The frame packetized and may be restored via identical timestamp so frame splited into many rtp packets with the same timestamp but each part of it has own sequence number
            # The jitter return the sample frame that able to decode by decoder in my case it libvpx for vp8
            is_pli, encoded_frame = jitter.add(pkt)
            if is_pli:
                print("got pli")
                continue

            if encoded_frame:
                asyncio.ensure_future(enqueue(encoded_frame), loop=loop)

            # if not is_pli:
            #     print("got pli")
            #     continue

            # if encoded_frame:
            #     print("send frame")
            #     asyncio.ensure_future(enqueue(encoded_frame), loop=loop)

            # async def enc():
            # remote_track
            # encoded = await pc._dtls_transport._srtp_rtp.encrypt_nonblock(
            # pkt.serialize()
            # )
            # if not encoded:
            # return

            # print("encoded", encoded)
            # await local_track.write_frame(encoded)

            # async def send():
            # data = await remote_track.recv_rtp_pkt_sync()
            # _pkt = media.RtpPacket.parse(data)
            # _pkt.ssrc = encoding.ssrc
            # encoded = await pc._dtls_transport.encrypt_rtp_bytes(_pkt.serialize())
            # await local_track.write_rtp_packet(_pkt)

            # asyncio.ensure_future(enc(), loop=loop)
            # )

            # pkt = rw_loop.run_until_complete(
            #     pc._dtls_transport.encrypt_rtp_bytes(pkt.serialize()),
            # )

            # print("run", pkt.serialize())

            # n = rw_loop.run_until_complete(
            #     encoding.write_rtp_raw_bytes(result),
            # )
        # enc_pkt = rw_loop.run_until_complete(
        # pc._dtls_transport._srtp_rtp.encrypt_nonblock(pkt.serialize())
        except Exception as e:
            print("examples_ws | recv err", e)
            time.sleep(1)

    # while True:
    #     pkt = remote_track.recv_rtp_pkt_sync()
    #     result = rw_loop.run_until_complete(local_track.write_rtp_packet(pkt))
    #     print("Write result", result)


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
    rw_thread = threading.Thread(
        target=start_read_write_loop, args=(pc, asyncio.get_running_loop())
    )

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
