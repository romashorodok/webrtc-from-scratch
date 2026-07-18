import asyncio
import json
import os
import time
import tracemalloc
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from webrtc.srtp import Session as SrtpSession

from webrtc import media
from webrtc.media.packetizer import Sequencer
from webrtc.media.rtcp import (
    RtcpPacket,
    RunLengthChunk,
    TransportLayerCC,
    AnyRtcpPacket
)
from webrtc.media.rtp_extensions import DEFAULT_EXT_MAP
from webrtc.peer_connection import (
    PeerConnection,
)
from webrtc import Runtime
from webrtc.runtime_services import OwnedTaskHandle
from webrtc.state_machine import BoundedMailbox, ReplyPort
from webrtc.session_description import (
    SessionDescription,
    SessionDescriptionType,
)
from .trace_pump import pump_trace_updates
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection

app = FastAPI()
VIDEO_FILE = Path(__file__).resolve().parents[1] / "output_av1.ivf"


class WebSocketMediaWorker:
    """Worker facade whose submissions and failures belong to the media lane."""

    def __init__(self, runtime: Runtime, owner_entity_id: str, owner_epoch: int) -> None:
        self._runtime = runtime
        self.entity_id = owner_entity_id
        self.epoch = owner_epoch

    async def invoke(self, function: Callable[..., Any], *args: Any) -> Any:
        handle = self._runtime.call_worker(
            function, *args, owner_entity_id=self.entity_id,
            owner_epoch=self.epoch, name="websocket-media-worker",
        )
        result = await handle.wait()
        if result.exception is not None:
            raise result.exception
        return result.value


async def on_recv(
    ws: WebSocket,
    on_close: Callable[[], Awaitable[None]] | None = None,
):
    try:
        while (
            ws.client_state is WebSocketState.CONNECTED
            and ws.application_state is WebSocketState.CONNECTED
        ):
            yield await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if on_close is not None:
            await on_close()


def loop_frames(file_path: str):
    """Yield IVF frames forever without retaining the complete video."""
    while True:
        yielded = False
        with open(file_path, "rb") as file:
            for frame, header in media.IVFReader(file):
                yielded = True
                yield frame, header
        if not yielded:
            raise RuntimeError(f"IVF video contains no frames: {file_path}")


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
_allocation_profiler_started = False


def _allocation_profiler_finished(error: BaseException | None = None) -> None:
    global _allocation_profiler_started
    _allocation_profiler_started = False
    if tracemalloc.is_tracing():
        tracemalloc.stop()
    if error is not None:
        print(
            "[allocation-profile] task failed: "
            f"{error.__class__.__name__}: {error}",
            flush=True,
        )


async def profile_allocations(
    pc: PeerConnection,
    runtime: Runtime,
) -> None:
    """Print retained Python allocations while the real WebRTC sender runs."""
    import psutil

    interval = float(os.getenv("WEBRTC_ALLOCATION_PROFILE_INTERVAL", "15"))
    print(
        "[allocation-profile] enabled; lightweight sampling started "
        f"(interval={interval:g}s)",
        flush=True,
    )
    process = psutil.Process()
    previous_rss = process.memory_info().rss
    previous = None
    previous_python = 0
    while True:
        await asyncio.sleep(interval)
        srtp_ready = pc._dtls_transport._srtp_rtp is not None
        if srtp_ready and not tracemalloc.is_tracing():
            tracemalloc.start(25)
            previous = tracemalloc.take_snapshot()
            previous_python = tracemalloc.get_traced_memory()[0]
            print(
                "[allocation-profile] SRTP ready; detailed Python sampling started",
                flush=True,
            )

        current = tracemalloc.take_snapshot() if tracemalloc.is_tracing() else None
        current_bytes, peak_bytes = (
            tracemalloc.get_traced_memory() if tracemalloc.is_tracing() else (0, 0)
        )
        transport = pc._transport
        queue_depths: dict[str, int] = {}
        for name in ("_rtp", "_rtcp", "_dtls"):
            interceptor = getattr(transport, name, None)
            queue = getattr(interceptor, "_queue", None)
            if queue is not None:
                queue_depths[name.removeprefix("_")] = queue.qsize()
        print(
            "[allocation-profile]",
            f"rss={process.memory_info().rss}",
            f"rss_delta={process.memory_info().rss - previous_rss:+d}",
            f"python_current={current_bytes if current is not None else 'disabled'}",
            f"python_delta={current_bytes - previous_python:+d}" if current is not None else "python_delta=disabled",
            f"python_peak={peak_bytes if current is not None else 'disabled'}",
            f"ice_ready={pc._transport is not None}",
            f"srtp_ready={srtp_ready}",
            f"ice_queues={queue_depths}",
            f"metric_groups={len(runtime.activity_groups.snapshots())}",
            f"trace_tasks={len(runtime.task_registry.task_ids())}",
            f"metric_keys={len(runtime.activity_groups.snapshots())}",
            flush=True,
        )
        if current is not None and previous is not None:
            for stat in current.compare_to(previous, "lineno")[:12]:
                if stat.size_diff > 0:
                    print(f"[allocation-profile] + {stat}", flush=True)
            previous = current
        previous_rss = process.memory_info().rss
        if current is not None:
            previous_python = current_bytes


async def start_write_loop(
    pc: PeerConnection,
    execution: Runtime,
):
    worker = WebSocketMediaWorker(
        execution, pc.media_send_entity_id, pc.media_send_epoch,
    )
    sender = pc._transceivers[0].sender
    if not sender:
        raise ValueError("Not found the sender")

    local_track = sender.track
    if not local_track:
        raise ValueError("Not found local track")

    encoding = sender._track_encodings[0]

    frames = loop_frames(str(VIDEO_FILE))

    ptime = encoding.codec.refresh_rate
    ms = 1000

    # TWCC sequence numbers must be same across the session
    twcc_seq = Sequencer()

    send_time_cache = SendTimeCache()

    async def wait_sender_rtcp_stream(timeout: float) -> None:
        async def poll() -> None:
            while sender._rtcp_stream is None:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(poll(), timeout)

    def print_rtcp(pkts: list[AnyRtcpPacket], smoothed_gradient: float):
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
                            if os.getenv("WEBRTC_ALLOCATION_PROFILE") != "1":
                                print(f"Seq {seq}: delay_gradient = {smoothed_gradient / 1000:.3f} ms")

                    prev_seq = seq
                    prev_send_time = send_time
                    prev_arrival_time_us = arrival_time_us
                    seq += 1

    async def rtcp_handler():
        # Persistent state across TWCC feedback packets
        smoothed_gradient = 0.0

        while True:
            try:
                # DTLSTransport now handles incoming RTCP routing internally
                # Just read from the stream (already decrypted and routed)
                stream = sender._rtcp_stream
                assert stream, "No srtp strem in rtcp handler"

                # Read decrypted RTCP from stream
                rtcp = await stream.read()
                pkts = await worker.invoke(RtcpPacket.parse, rtcp)
                await worker.invoke(print_rtcp, pkts, smoothed_gradient)

            except Exception:
                # Runtime observes the original exception and owns connection
                # failure propagation; this worker must not become a second
                # mutable retry/failure authority.
                raise


    async def encode():
        srtp: SrtpSession | None = None

        async for _ in media.ticker(ptime / ms):
            if not srtp:
                if srtp_transport := pc._dtls_transport._srtp_rtp:
                    srtp = srtp_transport
                else:
                    continue

            frame, _ = next(frames)
            pts, time_base = await encoding._packetizer.next_timestamp()

            pkts = encoding._packetizer.packetize(
                frame, encoding.convert_timebase(pts, time_base, time_base)
            )

            for pkt in pkts:
                pkt.extensions.transport_sequence_number = (
                    twcc_seq.next_sequence_number()
                )
                serialized = pkt.serialize(DEFAULT_EXT_MAP)
                # Offload encrypt to thread pool to avoid blocking event loop
                encoded = await srtp.encrypt(serialized)
                if not pc._transport:
                    print(f"[WS] ERROR: pc._transport is None!")
                    continue
                send_time_cache.add(pkt.extensions.transport_sequence_number)
                await worker.invoke(pc._transport.sendto, encoded)

    await pc.wait_transport_ready(timeout=30)
    await pc.wait_srtp_ready(timeout=30)
    await wait_sender_rtcp_stream(timeout=30)
    execution.start(lambda: rtcp_handler(), name="ws:rtcp-handler", kind="rtcp")
    await encode()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    peer_id = uuid.uuid4().hex
    runtime = Runtime(scope_id=peer_id)
    async with runtime as execution:
      # Runtime-bound components capture their execution scope while they are
      # constructed.  Creating the peer before entering Runtime leaves its
      # ICE/DTLS child machines unbound and makes peer startup wait forever.
      pc = PeerConnection(peer_id=peer_id)
      async with pc:
        send_mailbox = BoundedMailbox[
            tuple[dict[str, Any], ReplyPort[None]]
        ](64)

        async def send_pump() -> None:
            while True:
                message, reply = await send_mailbox.receive()
                try:
                    await ws.send_json(message)
                except BaseException as error:
                    reply.reject(error)
                    raise
                else:
                    reply.resolve(None)

        send_pump_task = execution.start_pump(
            send_pump, owner_entity_id=pc.entity_id,
            owner_epoch=pc._peer_runner.epoch, name="ws:send-mailbox",
        )

        async def send_json(message: dict[str, Any]) -> None:
            reply = ReplyPort[None]()
            await send_mailbox.submit((message, reply))
            await reply.wait()

        global _allocation_profiler_started
        if (
            os.getenv("WEBRTC_ALLOCATION_PROFILE") == "1"
            and not _allocation_profiler_started
        ):
            # tracemalloc is process-global. Keep a single sampler for this
            # explicitly profiled server process instead of competing peers.
            _allocation_profiler_started = True
            async def run_allocation_profiler() -> None:
                error = None
                try:
                    await profile_allocations(pc, runtime)
                except asyncio.CancelledError:
                    raise
                except BaseException as caught:
                    error = caught
                    raise
                finally:
                    _allocation_profiler_finished(error)

            execution.start(
                run_allocation_profiler,
                name="ws:allocation-profile",
                kind="diagnostic",
            )
            print("[allocation-profile] task scheduled", flush=True)
        elif os.getenv("WEBRTC_ALLOCATION_PROFILE") != "1":
            print("[allocation-profile] disabled in server process", flush=True)

        trace_task = execution.start(
            lambda: pump_trace_updates(
                execution,
                send_json,
                peer_id=pc.id,
                scope_trace_id=execution.root_context.trace_id if execution.root_context else None,
            ),
            name=f"ws:trace-pump-{pc.id}",
            kind="trace",
        )
        write_task: OwnedTaskHandle[Any] | None = None

        await pc.add_transceiver_from_kind(
            RTPCodecKind.Video, RTPTransceiverDirection.Sendonly
        )

        async def on_close() -> None:
            print("WebSocket disconnected")
            handles = [trace_task]
            if write_task is not None:
                handles.append(write_task)
            for handle in handles:
                handle.cancel()
            for handle in handles:
                try:
                    await handle.wait()
                except (asyncio.CancelledError, Exception):
                    pass

            closed_error = WebSocketDisconnect()
            for _message, reply in send_mailbox.close():
                reply.reject(closed_error)
            send_pump_task.cancel()
            try:
                await send_pump_task.wait()
            except (asyncio.CancelledError, Exception):
                pass

        async def start_media() -> None:
            nonlocal write_task
            if write_task and not write_task.done():
                return
            write_task = execution.start(
                lambda: start_write_loop(pc, execution),
                name="ws:av1-write-loop",
                kind="media",
            )

        async for data in on_recv(ws, on_close):
            msg: dict[str, Any] = json.loads(data)

            match msg.get("event"):
                case "negotiate":
                    print("Start all webrtc")
                    await pc.dial()
                    await start_media()

                case "offer":
                    print("recv offer")
                    if offer := await pc.create_offer():
                        print("offer offer")
                        await pc.set_local_description(SessionDescriptionType.Offer, offer)
                        print("set offer")
                        await send_json(
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
                    if desc_type is SessionDescriptionType.Answer:
                        await pc.dial()

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

                case "trace:delete":
                    data = msg.get("data")
                    payload: dict[str, Any] = json.loads(data) if isinstance(data, str) else data or {}
                    task_id = payload.get("task_id")
                    scope = payload.get("scope")

                    if isinstance(task_id, str):
                        execution.observability.cancel(task_id)

                case "trace:capture_request":
                    data = msg.get("data")
                    payload: dict[str, Any] = json.loads(data) if isinstance(data, str) else data or {}
                    try:
                        authorization = execution.authorize_trace_capture(
                            selector_kind=payload.get("selector_kind"),
                            selector_value=payload.get("selector_value"),
                            duration_seconds=payload.get("duration_seconds"),
                            call_budget=payload.get("call_budget"),
                        )
                    except (TypeError, ValueError, RuntimeError) as error:
                        await send_json({
                            "event": "trace:capture_result",
                            "data": {"success": False, "error": str(error)[:160]},
                        })
                    else:
                        await send_json({
                            "event": "trace:capture_result",
                            "data": {
                                "success": True,
                                "capture_id": authorization.capture_id,
                                "expires_ns": authorization.expires_ns,
                                "call_budget": authorization.call_budget,
                            },
                        })

                case "trace:resync_request":
                    await send_json(execution.trace_snapshot())

                case _:
                    print("Unknown event")
