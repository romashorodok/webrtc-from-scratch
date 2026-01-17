"""
Opus WebSocket Server - Separate Transceivers

Backend WebSocket server for bidirectional Opus audio.
Uses separate sendonly and recvonly transceivers.
Runs on port 9001.
"""

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from opus import OpusDecoder, OpusEncoder
from webrtc import media
from webrtc.logger import Component, get_logger
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import RtcpPacket
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.peer_connection import PeerConnection
from webrtc.session_description import (
    SessionDescription,
    SessionDescriptionType,
)
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection
from webrtc.audio import (
    AudioAnalyzer,
    ThresholdDetector,
    SpectrumAggregator,
    create_filter_chain,
    FILTER_PRESETS,
)

app = FastAPI()


@dataclass
class OpusConfig:
    """Opus codec configuration"""

    sample_rate: int = 48000
    channels: int = 1
    application: str = "voip"  # "voip", "audio", or "lowdelay"
    bitrate: int = 32000  # bits per second
    complexity: int = 5  # 0-10 (10 = best quality, slowest)
    dtx: bool = True  # Discontinuous Transmission (silence suppression)
    decode_fec: bool = False  # Forward Error Correction
    frame_size: int = 960  # Samples per frame (20ms @ 48kHz)

    @property
    def frame_bytes(self) -> int:
        """Calculate PCM frame size in bytes"""
        return self.frame_size * self.channels * 2  # 2 bytes per i16 sample


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


async def analyze_and_send(
    pcm_bytes: bytes,
    timestamp: int,
    analyzer: AudioAnalyzer,
    detector: ThresholdDetector,
    aggregator: SpectrumAggregator,
):
    """Analyze PCM frame and send results via WebSocket (non-blocking)"""
    try:
        # Compute spectrum and features (in thread pool to avoid blocking)
        result = await analyzer.analyze_frame(pcm_bytes, timestamp)

        # Check threshold
        threshold_result = detector.update(result["features"])

        # Add to aggregator (will batch and send at 10 Hz)
        await aggregator.add_frame(result, result["features"], threshold_result)

    except Exception as e:
        logger.error(Component.OPUS, "Analysis error", error=str(e))


async def start_audio_loop(
    pc: PeerConnection,
    config: OpusConfig | None = None,
    audio_analyzer: AudioAnalyzer | None = None,
    threshold_detector: ThresholdDetector | None = None,
    spectrum_aggregator: SpectrumAggregator | None = None,
):
    """
    Handle bidirectional audio with Opus encode/decode.

    Pure async implementation - all tasks run in the main event loop.
    """
    # Use default config if not provided
    if config is None:
        config = OpusConfig()

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

    # Initialize Opus codec

    logger = get_logger()

    try:
        opus_encoder = OpusEncoder(
            sample_rate=config.sample_rate,
            channels=config.channels,
            application=config.application,
        )
        opus_encoder.set_bitrate(config.bitrate)
        opus_encoder.set_complexity(config.complexity)
        opus_encoder.set_dtx(config.dtx)

        opus_decoder = OpusDecoder(
            sample_rate=config.sample_rate,
            channels=config.channels,
        )

        logger.info(
            Component.OPUS,
            "Codec initialized",
            bitrate=config.bitrate,
            complexity=config.complexity,
            dtx=config.dtx,
        )
    except Exception as e:
        logger.error(Component.OPUS, "Failed to initialize codec", error=str(e))
        raise

    # Monitor ALL SSRCs in SRTP session to detect if multiple streams exist
    async def srtp_monitor():
        """Monitor SRTP session for new streams."""
        print("[Opus] SRTP monitor started")
        srtp_session = pc._dtls_transport._srtp_rtp
        if not srtp_session:
            print("[Opus] WARNING: No SRTP session found")
            return

        known_ssrcs = set()
        while True:
            try:
                # Check all active streams in SRTP session
                if hasattr(srtp_session, "_streams"):
                    current_ssrcs = set(srtp_session._streams.keys())
                    new_ssrcs = current_ssrcs - known_ssrcs
                    if new_ssrcs:
                        for ssrc in new_ssrcs:
                            print(
                                f"[Opus] NEW SSRC DETECTED: {ssrc} (total SSRCs: {len(current_ssrcs)})"
                            )
                        known_ssrcs = current_ssrcs
                await asyncio.sleep(1)
            except Exception as e:
                print(f"[Opus] SRTP monitor error: {e}")
                await asyncio.sleep(1)

    # Start SRTP monitor as async task
    asyncio.create_task(srtp_monitor())

    # Buffer to store received Opus frames (payloads only)
    pcm_frames_queue = asyncio.Queue(maxsize=100)

    async def receive_routine():
        """Receive audio from browser, decode Opus → PCM."""
        packet_count = 0
        last_seq = None
        seq_gaps = []
        timeout_count = 0
        decode_errors = 0
        logger.info(Component.OPUS, "Receive routine started")
        print(f"[Opus receive_routine] Receiver track SSRC: {remote_track.ssrc}")
        print(f"[Opus receive_routine] Receiver track kind: {remote_track.kind}")

        # Wait for receiver track to have a stream
        max_wait = 50  # 5 seconds
        for i in range(max_wait):
            try:
                # Try to access stream property to see if it's ready
                _ = remote_track.stream
                print(f"[Opus] Receiver stream is ready after {i * 0.1}s")
                break
            except ValueError as e:
                # Stream not ready yet
                if i == 0:
                    print(f"[Opus] Waiting for stream... (error: {e})")
                pass
            await asyncio.sleep(0.1)
        else:
            print(f"[Opus] WARNING: Receiver stream not ready after {max_wait * 0.1}s")
            return  # Exit if stream never becomes ready

        while True:
            try:
                # Read from async queue (populated by _receive_task)
                if packet_count == 0:
                    print("[Opus] Waiting for first RTP packet...")

                # Use recv_rtp_pkt_sync() which reads from asyncio.Queue
                try:
                    result = await asyncio.wait_for(
                        remote_track.recv_rtp_pkt_sync(), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    timeout_count += 1
                    if timeout_count <= 10 or timeout_count % 50 == 0:
                        print(
                            f"[Opus receive_routine] Timeout #{timeout_count} waiting for packet from queue"
                        )
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
                            print(
                                f"[Opus] SEQ GAP! last={last_seq}, current={pkt.sequence_number}, gap={gap} packets"
                            )

                last_seq = pkt.sequence_number

                if packet_count < 20:
                    print(
                        f"[Opus] RX packet {packet_count}: seq={pkt.sequence_number}, "
                        f"ts={pkt.timestamp}, ssrc={pkt.ssrc}, size={len(pkt.payload)}, marker={pkt.marker}"
                    )

                packet_count += 1

                # DECODE: Opus payload → PCM bytes
                try:
                    pcm_bytes = opus_decoder.decode(
                        pkt.payload,
                        frame_size=config.frame_size,
                        decode_fec=config.decode_fec,
                    )

                    # Non-blocking audio analysis (fire and forget)
                    if audio_analyzer and threshold_detector and spectrum_aggregator:
                        asyncio.create_task(
                            analyze_and_send(
                                pcm_bytes,
                                pkt.timestamp,
                                audio_analyzer,
                                threshold_detector,
                                spectrum_aggregator,
                            )
                        )

                    if packet_count < 20:
                        logger.debug(
                            Component.OPUS,
                            "Decoded frame",
                            seq=pkt.sequence_number,
                            opus_bytes=len(pkt.payload),
                            pcm_bytes=len(pcm_bytes),
                        )

                    # Optionally apply filter to audio for playback (debugging)
                    pcm_to_play = pcm_bytes
                    if audio_analyzer.filter_chain and audio_analyzer.filter_chain.enabled:
                        # Convert PCM to float samples
                        import numpy as np
                        samples = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32) / 32768.0

                        # Apply filter chain
                        filtered_samples, _ = audio_analyzer.filter_chain.process(samples)

                        # Convert back to PCM bytes
                        filtered_i16 = (filtered_samples * 32768.0).astype(np.int16)
                        pcm_to_play = filtered_i16.tobytes()

                        if packet_count < 5:
                            logger.debug(Component.OPUS, "Playing filtered audio", filter_enabled=True)

                    # Put PCM into queue for encoding
                    try:
                        await asyncio.wait_for(
                            pcm_frames_queue.put(pcm_to_play), timeout=0.5
                        )
                    except asyncio.TimeoutError:
                        if packet_count % 100 == 0:
                            logger.info(
                                Component.OPUS, "PCM queue full, dropping frame"
                            )

                except Exception as e:
                    decode_errors += 1
                    if decode_errors < 10 or decode_errors % 100 == 0:
                        logger.error(
                            Component.OPUS,
                            "Decode error",
                            error=str(e),
                            count=decode_errors,
                        )

                if packet_count % 100 == 0:
                    print(
                        f"[Opus] Received {packet_count} packets, {len(seq_gaps)} seq gaps, queue: {pcm_frames_queue.qsize()}"
                    )

            except Exception as e:
                if packet_count < 10 or str(e):
                    print(f"[Opus receive_routine] Receive error: {e}")
                await asyncio.sleep(0.1)

    async def send_routine():
        """Get PCM, encode to Opus, send to browser."""
        send_count = 0
        timeout_count = 0
        encode_errors = 0
        logger.info(Component.OPUS, "Send routine started")

        # Wait for SRTP to be ready
        srtp = None
        while not srtp:
            if srtp_transport := pc._dtls_transport._srtp_rtp:
                srtp = srtp_transport
                print("[Opus] SRTP ready")
            else:
                await asyncio.sleep(0.1)

        if not pc._transport:
            print("[Opus] ERROR: No transport!")
            return

        # Use ticker for proper 20ms pacing (like video example)
        async for pts, time_base in encoding._packetizer.ticker():
            try:
                # Get PCM audio frame
                try:
                    pcm_frame = await asyncio.wait_for(
                        pcm_frames_queue.get(),
                        timeout=0.1,  # 100ms timeout (5x packet time)
                    )
                except asyncio.TimeoutError:
                    timeout_count += 1
                    if timeout_count < 10 or timeout_count % 50 == 0:
                        logger.info(
                            Component.OPUS,
                            "PCM queue timeout",
                            count=timeout_count,
                            queue_size=pcm_frames_queue.qsize(),
                        )
                    continue

                # Validate PCM frame size
                if len(pcm_frame) != config.frame_bytes:
                    logger.error(
                        Component.OPUS,
                        "Invalid PCM frame size",
                        expected=config.frame_bytes,
                        actual=len(pcm_frame),
                    )
                    continue

                # ENCODE: PCM bytes → Opus payload
                try:
                    opus_frame = opus_encoder.encode(pcm_frame)

                    if send_count < 10:
                        logger.debug(
                            Component.OPUS,
                            "Encoded frame",
                            pcm_bytes=len(pcm_frame),
                            opus_bytes=len(opus_frame),
                        )

                except Exception as e:
                    encode_errors += 1
                    if encode_errors < 10 or encode_errors % 100 == 0:
                        logger.error(
                            Component.OPUS,
                            "Encode error",
                            error=str(e),
                            count=encode_errors,
                        )
                    continue

                # Packetize and send
                pkts = encoding._packetizer.packetize(
                    opus_frame, encoding.convert_timebase(pts, time_base, time_base)
                )

                for pkt in pkts:
                    # Add TWCC extension
                    pkt.extensions.transport_sequence_number = (
                        twcc_seq.next_sequence_number()
                    )

                    # Serialize and encrypt
                    serialized = pkt.serialize(DEFAULT_EXT_MAP)
                    encoded = await asyncio.to_thread(srtp.encrypt, serialized)

                    # Send
                    pc._transport.sendto(encoded)

                send_count += 1

                if send_count < 10:
                    print(
                        f"[Opus] TX packet {send_count}: "
                        f"pts={encoding.convert_timebase(pts, time_base, time_base)}, "
                        f"size={len(opus_frame)}, queue={pcm_frames_queue.qsize()}"
                    )

                if send_count % 100 == 0:
                    print(
                        f"[Opus] Sent {send_count} packets (timeouts: {timeout_count}), queue size: {pcm_frames_queue.qsize()}"
                    )

            except Exception as e:
                print(f"[Opus] Send error: {e}")
                await asyncio.sleep(0.1)

    async def rtcp_handler():
        """Handle incoming RTCP packets from browser."""
        rtcp_count = 0
        print("[Opus] RTCP handler started")

        while True:
            try:
                # Get the RTCP stream from sender
                stream = sender._rtcp_stream
                if not stream:
                    print("[Opus] Waiting for RTCP stream...")
                    await asyncio.sleep(0.1)
                    continue

                # Read decrypted RTCP from stream
                rtcp = await stream.read()
                pkts = RtcpPacket.parse(rtcp)

                rtcp_count += 1
                if rtcp_count < 10 or rtcp_count % 50 == 0:
                    print(
                        f"[Opus] RTCP packet {rtcp_count}: {len(pkts)} compound packets"
                    )
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
    from webrtc.logger import Component, get_logger

    logger = get_logger()
    logger.info(Component.OPUS, "WebSocket connection established")

    # Create PeerConnection
    pc = PeerConnection()
    pc.start()
    await pc.gatherer.dial()

    # Add SINGLE sendrecv transceiver for bidirectional audio
    await pc.add_transceiver_from_kind(
        RTPCodecKind.Audio, RTPTransceiverDirection.Sendrecv
    )
    logger.info(Component.OPUS, "Added sendrecv audio transceiver")

    # Create Opus configuration
    config = OpusConfig(
        sample_rate=48000,
        channels=1,
        application="voip",
        bitrate=32000,
        complexity=5,
        dtx=True,
        decode_fec=False,
    )

    # Audio analysis setup
    # Create filter chain (default: "none" - no filtering)
    filter_chain = create_filter_chain("none", sample_rate=config.sample_rate)

    # Flag to enable/disable playing filtered audio (for debugging)
    play_filtered_audio = False

    audio_analyzer = AudioAnalyzer(
        sample_rate=config.sample_rate, fft_size=1024, filter_chain=filter_chain
    )
    threshold_detector = ThresholdDetector(
        {
            "rms_threshold": 0.1,
            "zcr_threshold": 0.05,
            "duration_ms": 500,
            "hysteresis": 0.8,
        }
    )
    spectrum_aggregator = SpectrumAggregator(target_rate_hz=10, ws=ws)

    # Flag to ensure start() is only called once
    audio_loop_started = False

    def start():
        """Start audio processing with configuration."""
        nonlocal audio_loop_started
        if audio_loop_started:
            logger.info(Component.OPUS, "Audio loop already started, skipping")
            return
        audio_loop_started = True
        logger.info(Component.OPUS, "Starting audio loop", config=config)
        asyncio.create_task(
            start_audio_loop(
                pc, config, audio_analyzer, threshold_detector, spectrum_aggregator
            ),
            name="OpusAudioLoop",
        )
        logger.info(Component.OPUS, "Audio loop task created")

    def on_close():
        print("[Opus] WebSocket connection closed")

    # Start audio loop proactively once DTLS is ready
    async def auto_start_when_ready():
        """Monitor DTLS/SRTP and auto-start audio loop when ready."""
        await asyncio.sleep(0.5)  # Give DTLS time to establish
        max_wait = 50  # 5 seconds
        for i in range(max_wait):
            if pc._dtls_transport and pc._dtls_transport._srtp_rtp:
                logger.info(Component.OPUS, "DTLS/SRTP ready, auto-starting audio loop")
                start()
                return
            await asyncio.sleep(0.1)
        logger.info(
            Component.OPUS, "DTLS/SRTP not ready after 5s, audio loop not started"
        )

    # Start monitor task
    asyncio.create_task(auto_start_when_ready(), name="OpusAutoStart")

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
                print("[Opus] Added ICE candidate")

            case "audio_config":
                data = msg.get("data")
                if not data:
                    continue

                # Parse JSON if it's a string
                if isinstance(data, str):
                    try:
                        payload = json.loads(data)
                    except json.JSONDecodeError:
                        print(f"[Opus] Failed to parse audio_config data: {data}")
                        continue
                else:
                    payload = data

                # Update threshold detector config
                if threshold_config := payload.get("threshold_config"):
                    threshold_detector.update_config(threshold_config)

                # Update aggregator rate
                if update_rate := payload.get("update_rate_hz"):
                    spectrum_aggregator.set_rate(update_rate)

                # Change filter preset
                if filter_preset := payload.get("filter_preset"):
                    print(f"[Opus] Changing filter preset to: {filter_preset}")
                    new_filter_chain = create_filter_chain(
                        filter_preset, sample_rate=config.sample_rate
                    )
                    audio_analyzer.filter_chain = new_filter_chain

                # Apply custom filter configuration
                if custom_filter_config := payload.get("custom_filter_config"):
                    print(f"[Opus] Applying custom filter config: {custom_filter_config}")
                    from webrtc.audio.filters import (
                        HighPassFilter,
                        BandPassFilter,
                        NoiseGate,
                        PreEmphasisFilter,
                        VoiceActivityDetector,
                        FilterChain,
                    )

                    # Create new filter chain from custom config
                    new_chain = FilterChain(sample_rate=config.sample_rate)

                    # Add filters based on config
                    for filter_def in custom_filter_config.get("filters", []):
                        filter_type = filter_def["type"]

                        if filter_type == "highpass":
                            filter = HighPassFilter(
                                config.sample_rate,
                                cutoff_hz=filter_def.get("cutoff_hz", 80)
                            )
                        elif filter_type == "bandpass":
                            filter = BandPassFilter(
                                config.sample_rate,
                                low_cutoff_hz=filter_def.get("low_cutoff_hz", 300),
                                high_cutoff_hz=filter_def.get("high_cutoff_hz", 3400)
                            )
                        elif filter_type == "noise_gate":
                            filter = NoiseGate(
                                config.sample_rate,
                                threshold_db=filter_def.get("threshold_db", -40),
                                attack_ms=filter_def.get("attack_ms", 5),
                                release_ms=filter_def.get("release_ms", 50)
                            )
                        elif filter_type == "preemphasis":
                            filter = PreEmphasisFilter(
                                config.sample_rate,
                                alpha=filter_def.get("alpha", 0.97)
                            )
                        else:
                            continue

                        new_chain.add_filter(filter)

                    # Add VAD if configured
                    if vad_config := custom_filter_config.get("vad"):
                        vad = VoiceActivityDetector(
                            config.sample_rate,
                            energy_threshold=vad_config.get("energy_threshold", 0.05),
                            zcr_threshold=vad_config.get("zcr_threshold", 0.1),
                            hangover_frames=vad_config.get("hangover_frames", 10)
                        )
                        new_chain.set_vad(vad)

                    audio_analyzer.filter_chain = new_chain
                    print("[Opus] Custom filter chain applied")

                # Enable/disable playing filtered audio
                if "play_filtered" in payload:
                    enabled = payload["play_filtered"]
                    if audio_analyzer.filter_chain:
                        audio_analyzer.filter_chain.set_enabled(enabled)
                        print(f"[Opus] Play filtered audio: {'enabled' if enabled else 'disabled'}")

                print(f"[Opus] Audio config updated: {payload}")

            case "get_filter_presets":
                # Send available filter presets to frontend
                presets_info = {
                    key: {
                        "name": val["name"],
                        "description": val["description"],
                    }
                    for key, val in FILTER_PRESETS.items()
                }
                await ws.send_json(
                    {"event": "filter_presets", "data": presets_info}
                )
                print("[Opus] Sent filter presets to client")

            case _:
                print(f"[Opus] Unknown event: {msg.get('event')}")
