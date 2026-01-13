"""
Opus WebSocket Server - Separate Transceivers

Backend WebSocket server for bidirectional Opus audio.
Uses separate sendonly and recvonly transceivers.
Runs on port 9001.
"""

import asyncio
import json
from typing import Any, Callable

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from webrtc import media
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.media.rtcp import RtcpPacket
from webrtc.peer_connection import PeerConnection
from webrtc.session_description import (
    SessionDescription,
    SessionDescriptionType,
)
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection

app = FastAPI()

# TWCC (Transport Wide Congestion Control) sequence numbers
twcc_seq = Sequencer()


async def on_recv(ws: WebSocket, on_close: Callable | None = None):
    """Async generator for receiving WebSocket messages."""
    try:
        while True:
            yield await ws.receive_text()
    except WebSocketDisconnect:
        if _on_close := on_close:
            _on_close()


async def start_audio_loop(pc: PeerConnection):
    """
    Handle bidirectional audio with single sendrecv transceiver.

    Pure async implementation - all tasks run in the main event loop.
    """
    # Transceiver 0: Sendrecv (bidirectional)
    transceiver = pc._transceivers[0]

    sender = transceiver.sender
    if not sender:
        raise ValueError("Transceiver has no sender")

    local_track = sender.track
    if not local_track:
        raise ValueError("Sender has no track")

    encoding = sender._track_encodings[0]

    receiver = transceiver.receiver
    if not receiver:
        raise ValueError("Transceiver has no receiver")

    remote_track = receiver.track
    if not remote_track:
        raise ValueError("Receiver has no track")

    print(f"[Opus] Sender SSRC: {encoding.ssrc}, PT: {encoding.codec.payload_type}")
    print(f"[Opus] Receiver track SSRC: {remote_track.ssrc}")

    # Monitor ALL SSRCs in SRTP session to detect if multiple streams exist
    async def srtp_monitor():
        """Monitor SRTP session for new streams."""
        print(f"[Opus] SRTP monitor started")
        srtp_session = pc._dtls_transport._srtp_rtp
        if not srtp_session:
            print(f"[Opus] WARNING: No SRTP session found")
            return

        known_ssrcs = set()
        while True:
            try:
                # Check all active streams in SRTP session
                if hasattr(srtp_session, '_streams'):
                    current_ssrcs = set(srtp_session._streams.keys())
                    new_ssrcs = current_ssrcs - known_ssrcs
                    if new_ssrcs:
                        for ssrc in new_ssrcs:
                            print(f"[Opus] NEW SSRC DETECTED: {ssrc} (total SSRCs: {len(current_ssrcs)})")
                        known_ssrcs = current_ssrcs
                await asyncio.sleep(1)
            except Exception as e:
                print(f"[Opus] SRTP monitor error: {e}")
                await asyncio.sleep(1)

    # Start SRTP monitor as async task
    asyncio.create_task(srtp_monitor())

    # Buffer to store received Opus frames (payloads only)
    opus_frames_queue = asyncio.Queue(maxsize=100)

    async def receive_routine():
        """Receive audio from browser and buffer Opus frames (async)."""
        packet_count = 0
        last_seq = None
        seq_gaps = []
        timeout_count = 0
        print(f"[Opus receive_routine] STARTED")
        print(f"[Opus receive_routine] Receiver track SSRC: {remote_track.ssrc}")
        print(f"[Opus receive_routine] Receiver track kind: {remote_track.kind}")

        # Wait for receiver track to have a stream
        max_wait = 50  # 5 seconds
        for i in range(max_wait):
            try:
                # Try to access stream property to see if it's ready
                _ = remote_track.stream
                print(f"[Opus] Receiver stream is ready after {i*0.1}s")
                break
            except ValueError as e:
                # Stream not ready yet
                if i == 0:
                    print(f"[Opus] Waiting for stream... (error: {e})")
                pass
            await asyncio.sleep(0.1)
        else:
            print(f"[Opus] WARNING: Receiver stream not ready after {max_wait*0.1}s")
            return  # Exit if stream never becomes ready

        print(f"[Opus] Starting packet receive loop...")

        while True:
            try:
                # Read from async queue (populated by _receive_task)
                if packet_count == 0:
                    print(f"[Opus] Waiting for first RTP packet...")

                # Use recv_rtp_pkt_sync() which reads from asyncio.Queue
                try:
                    result = await asyncio.wait_for(remote_track.recv_rtp_pkt_sync(), timeout=5.0)
                except asyncio.TimeoutError:
                    timeout_count += 1
                    if timeout_count <= 10 or timeout_count % 50 == 0:
                        print(f"[Opus receive_routine] Timeout #{timeout_count} waiting for packet from queue")
                    await asyncio.sleep(0.01)
                    continue

                # Parse RTP packet
                pkt = media.RtpPacket.parse(result)

                # Track sequence number gaps
                if last_seq is not None:
                    expected_seq = (last_seq + 1) % 65536
                    if pkt.sequence_number != expected_seq:
                        gap = (pkt.sequence_number - expected_seq) % 65536
                        seq_gaps.append((last_seq, pkt.sequence_number, gap))
                        if packet_count < 50 or len(seq_gaps) % 10 == 1:
                            print(f"[Opus] SEQ GAP! last={last_seq}, current={pkt.sequence_number}, gap={gap} packets")

                last_seq = pkt.sequence_number

                if packet_count < 20:
                    print(f"[Opus] RX packet {packet_count}: seq={pkt.sequence_number}, "
                          f"ts={pkt.timestamp}, ssrc={pkt.ssrc}, size={len(pkt.payload)}, marker={pkt.marker}")

                packet_count += 1

                # Extract Opus payload and put in queue for sending
                # No depayloading - just forward the raw Opus frame
                try:
                    await asyncio.wait_for(opus_frames_queue.put(pkt.payload), timeout=0.5)
                except asyncio.TimeoutError:
                    # Queue full, drop packet
                    if packet_count % 100 == 0:
                        print(f"[Opus] Warning: Frame queue full, dropping packets")

                if packet_count % 100 == 0:
                    print(f"[Opus] Received {packet_count} packets, {len(seq_gaps)} seq gaps, queue: {opus_frames_queue.qsize()}")

            except Exception as e:
                if packet_count < 10 or str(e):
                    print(f"[Opus receive_routine] Receive error: {e}")
                await asyncio.sleep(0.1)

    async def send_routine():
        """Send audio to browser using ticker-based pacing."""
        send_count = 0
        timeout_count = 0
        print(f"[Opus] Send routine started")

        # Wait for SRTP to be ready
        srtp = None
        while not srtp:
            if srtp_transport := pc._dtls_transport._srtp_rtp:
                srtp = srtp_transport
                print(f"[Opus] SRTP ready")
            else:
                await asyncio.sleep(0.1)

        if not pc._transport:
            print(f"[Opus] ERROR: No transport!")
            return

        # Use ticker for proper 20ms pacing (like video example)
        async for pts, time_base in encoding._packetizer.ticker():
            try:
                # BLOCKING wait for frame with timeout (like video does)
                # Timeout should be longer than ptime (20ms) to account for network jitter
                try:
                    opus_frame = await asyncio.wait_for(
                        opus_frames_queue.get(),
                        timeout=0.1  # 100ms timeout (5x packet time)
                    )
                except asyncio.TimeoutError:
                    # Only hit if receive pipeline stalled for 100ms
                    timeout_count += 1
                    if timeout_count < 10 or timeout_count % 50 == 0:
                        print(f"[Opus] WARNING: Frame queue timeout - receive pipeline stalled? (count: {timeout_count}, queue: {opus_frames_queue.qsize()})")
                    continue  # Skip this ticker interval

                # Packetize with ticker timestamp
                pkts = encoding._packetizer.packetize(
                    opus_frame,
                    encoding.convert_timebase(pts, time_base, time_base)
                )

                for pkt in pkts:
                    # Add TWCC extension
                    pkt.extensions.transport_sequence_number = twcc_seq.next_sequence_number()

                    # Serialize and encrypt
                    serialized = pkt.serialize(DEFAULT_EXT_MAP)
                    encoded = await asyncio.to_thread(srtp.encrypt, serialized)

                    # Send
                    pc._transport.sendto(encoded)

                send_count += 1

                if send_count < 10:
                    print(f"[Opus] TX packet {send_count}: "
                          f"pts={encoding.convert_timebase(pts, time_base, time_base)}, "
                          f"size={len(opus_frame)}, queue={opus_frames_queue.qsize()}")

                if send_count % 100 == 0:
                    print(f"[Opus] Sent {send_count} packets (timeouts: {timeout_count}), queue size: {opus_frames_queue.qsize()}")

            except Exception as e:
                print(f"[Opus] Send error: {e}")
                await asyncio.sleep(0.1)

    async def rtcp_handler():
        """Handle incoming RTCP packets from browser."""
        rtcp_count = 0
        print(f"[Opus] RTCP handler started")

        while True:
            try:
                # Get the RTCP stream from sender
                stream = sender._rtcp_stream
                if not stream:
                    print(f"[Opus] Waiting for RTCP stream...")
                    await asyncio.sleep(0.1)
                    continue

                # Read decrypted RTCP from stream
                rtcp = await stream.read()
                pkts = RtcpPacket.parse(rtcp)

                rtcp_count += 1
                if rtcp_count < 10 or rtcp_count % 50 == 0:
                    print(f"[Opus] RTCP packet {rtcp_count}: {len(pkts)} compound packets")
                    for pkt in pkts:
                        print(f"  Type: {type(pkt).__name__}")

            except Exception as e:
                if rtcp_count < 10:
                    print(f"[Opus] RTCP error: {e}")
                await asyncio.sleep(0.1)

    # Start all async tasks in the main event loop
    asyncio.create_task(receive_routine(), name=f"OpusReceiver-{remote_track.ssrc}")
    asyncio.create_task(rtcp_handler(), name=f"OpusRTCP-{encoding.ssrc}")

    # Run send routine (this will run until cancelled)
    await send_routine()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    """WebSocket endpoint for Opus audio signaling."""
    await ws.accept()
    print("[Opus] WebSocket connection established")

    # Create PeerConnection
    pc = PeerConnection()
    pc.start()
    await pc.gatherer.dial()

    # Add SINGLE sendrecv transceiver for bidirectional audio
    await pc.add_transceiver_from_kind(
        RTPCodecKind.Audio, RTPTransceiverDirection.Sendrecv
    )
    print("[Opus] Added sendrecv audio transceiver (bidirectional)")

    def start():
        """Start audio processing as async task."""
        print(f"[Opus] Starting audio processing task")
        asyncio.create_task(start_audio_loop(pc), name="OpusAudioLoop")
        print("[Opus] Audio task started")

    def on_close():
        print("[Opus] WebSocket connection closed")

    # Handle WebSocket messages
    print("[Opus] Waiting for messages...")
    async for data in on_recv(ws, on_close):
        print(f"[Opus] Received message: {data[:100]}...")  # Log first 100 chars
        msg: dict[str, Any] = json.loads(data)
        print(f"[Opus] Event type: {msg.get('event')}")

        match msg.get("event"):
            case "negotiate":
                print("[Opus] Negotiate event received")
                await pc.gatherer.dial()
                try:
                    start()
                except RuntimeError as e:
                    print(f"[Opus] RuntimeError in start(): {e}")
                except Exception as e:
                    print(f"[Opus] Error in start(): {e}")

            case "offer":
                print("[Opus] Offer event received")
                if offer := await pc.create_offer():
                    await pc.set_local_description(SessionDescriptionType.Offer, offer)
                    await ws.send_json(
                        {"event": "offer", "data": offer.marshal().decode()}
                    )
                    print("[Opus] Offer sent")

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
                desc = SessionDescription.parse(sdp)

                print(f"[Opus] Setting remote description (type={sdp_type})")

                for ufrag, pwd in desc.get_media_credentials():
                    await pc.gatherer.set_remote_credentials(ufrag, pwd)

                await pc.set_remote_description(desc_type, desc)

                # Start audio processing automatically after answer
                if desc_type is SessionDescriptionType.Answer:
                    print("[Opus] Answer received, starting audio processing...")
                    try:
                        start()
                    except RuntimeError as e:
                        print(f"[Opus] RuntimeError in start(): {e}")
                    except Exception as e:
                        print(f"[Opus] Error in start(): {e}")

            case "trickle-ice":
                data = msg.get("data")
                if not data:
                    continue
                payload: dict[str, Any] = json.loads(data)

                candidate_str = payload.get("candidate")
                if not candidate_str:
                    continue

                await pc.gatherer.add_remote_candidate(candidate_str)
                print(f"[Opus] Added ICE candidate")

            case _:
                print(f"[Opus] Unknown event: {msg.get('event')}")
