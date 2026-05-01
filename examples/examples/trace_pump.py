import asyncio
from typing import Any, Awaitable, Callable

from webrtc.runtime import WebRTCRuntimeResources


async def pump_trace_updates(
    runtime: WebRTCRuntimeResources,
    peer_id: str,
    send_json: Callable[[dict[str, Any]], Awaitable[None]],
    *,
    heartbeat_interval: float = 0.25,
    heartbeat_keepalive_interval: float = 2.5,
    update_flush_interval: float = 0.25,
) -> None:
    subscription = runtime.trace_subscribe(peer_id=peer_id)
    loop = asyncio.get_running_loop()
    next_heartbeat = loop.time() + heartbeat_interval
    last_heartbeat_emit = 0.0
    last_heartbeat_signature: tuple[tuple[str, str | None, str], ...] = ()
    pending_events: list[dict[str, Any]] = []
    pending_updates: dict[str, dict[str, Any]] = {}
    pending_sequence = 0
    next_batch_flush: float | None = None

    def schedule_batch_flush() -> None:
        nonlocal next_batch_flush
        if next_batch_flush is None:
            next_batch_flush = loop.time() + update_flush_interval

    def update_batch_event() -> dict[str, Any] | None:
        nonlocal pending_sequence
        if not pending_updates:
            return None

        data: dict[str, Any] = {
            "peer_id": peer_id,
            "traces": list(pending_updates.values()),
        }
        if pending_sequence:
            data["sequence"] = pending_sequence
        pending_updates.clear()
        pending_sequence = 0
        return {"event": "trace:update", "data": data}

    def add_pending_event(event: dict[str, Any]) -> None:
        pending_events.append(event)
        schedule_batch_flush()

    async def flush_pending_batch() -> None:
        nonlocal next_batch_flush
        events = pending_events.copy()
        pending_events.clear()
        update = update_batch_event()
        if not events and update is None:
            next_batch_flush = None
            return
        next_batch_flush = None
        if events:
            await send_trace_batch(send_json, events, peer_id=peer_id)
        if update is not None:
            await send_trace_batch(send_json, [update], peer_id=peer_id)

    def add_pending_update_event(event: dict[str, Any]) -> None:
        nonlocal pending_sequence
        data = event.get("data")
        if not isinstance(data, dict):
            return

        sequence = data.get("sequence")
        if isinstance(sequence, int):
            pending_sequence = max(pending_sequence, sequence)

        traces = data.get("traces")
        if isinstance(traces, list):
            for trace in traces:
                add_pending_trace(trace)

        trace = data.get("trace")
        add_pending_trace(trace)
        if pending_updates:
            schedule_batch_flush()

    def add_pending_trace(trace: Any) -> None:
        if not isinstance(trace, dict):
            return
        trace_id = trace.get("trace_id")
        if not isinstance(trace_id, str):
            return
        pending_updates[trace_id] = compact_trace_update(trace)
        schedule_batch_flush()

    add_pending_event(
        {
            "event": "trace:init",
            "data": {
                "peer_id": peer_id,
                "traces": runtime.trace_live_tree(peer_id=peer_id),
            },
        }
    )

    try:
        while True:
            deadline = next_heartbeat
            if next_batch_flush is not None:
                deadline = min(deadline, next_batch_flush)
            timeout = max(0.0, deadline - loop.time())
            try:
                event = await asyncio.wait_for(subscription.get(), timeout=timeout)
            except asyncio.TimeoutError:
                now = loop.time()
                if next_batch_flush is not None and now >= next_batch_flush:
                    await flush_pending_batch()
                    continue
                if now < next_heartbeat:
                    continue

                heartbeat_due = now - last_heartbeat_emit >= heartbeat_keepalive_interval
                traces = runtime.trace_live_running(
                    include_duration=heartbeat_due,
                    peer_id=peer_id,
                )
                signature = tuple(
                    (trace["trace_id"], trace["parent_id"], trace["status"])
                    for trace in traces
                )
                should_emit = (
                    bool(traces)
                    and (
                        signature != last_heartbeat_signature
                        or heartbeat_due
                    )
                )
                if should_emit:
                    for trace in traces:
                        add_pending_trace(trace)
                    last_heartbeat_emit = now
                    last_heartbeat_signature = signature
                next_heartbeat = loop.time() + heartbeat_interval
            else:
                for item in trace_events_from_subscription_event(event):
                    if item.get("event") == "trace:update":
                        add_pending_update_event(item)
                    else:
                        if pending_updates:
                            await flush_pending_batch()
                        add_pending_event(item)
    finally:
        await flush_pending_batch()
        subscription.close()


def trace_events_from_subscription_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    if event.get("event") != "trace:batch":
        return [event]
    data = event.get("data")
    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list):
        return []
    return [item for item in events if isinstance(item, dict)]


async def send_trace_batch(
    send_json: Callable[[dict[str, Any]], Awaitable[None]],
    events: list[dict[str, Any]],
    *,
    peer_id: str,
) -> None:
    if not events:
        return

    if len(events) == 1 and events[0].get("event") == "trace:update":
        data = dict(events[0].get("data") or {})
        data["peer_id"] = peer_id
        await send_json(
            {
                "event": "trace:batch",
                "data": data,
            }
        )
        return

    await send_json(
        {
            "event": "trace:batch",
            "data": {
                "peer_id": peer_id,
                "events": events,
            },
        }
    )


def compact_trace_update(trace: dict[str, Any]) -> dict[str, Any]:
    compact = dict(trace)
    if compact.get("status") in {"created", "running"}:
        compact.pop("transitions", None)
        compact["duration_ms"] = trace.get("duration_ms")
    return compact
