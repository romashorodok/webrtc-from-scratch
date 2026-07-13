import asyncio
from typing import Any, Awaitable, Callable

from webrtc import Runtime


async def pump_trace_updates(
    runtime: Runtime,
    send_json: Callable[[dict[str, Any]], Awaitable[None]],
    *,
    peer_id: str | None = None,
    scope_trace_id: str | None = None,
    heartbeat_interval: float = 0.25,
    heartbeat_keepalive_interval: float = 2.5,
) -> None:
    subscription = runtime.trace_subscribe(peer_id=peer_id)
    loop = asyncio.get_running_loop()
    next_heartbeat = loop.time() + heartbeat_interval
    last_heartbeat_emit = 0.0
    last_heartbeat_signature: tuple[tuple[str, str | None, str], ...] = ()
    await send_trace_batch(
        send_json,
        [{
            "event": "trace:init",
            "data": {
                "trace_id": scope_trace_id,
                "tasks": runtime.trace_live_tree(scope_trace_id=scope_trace_id),
                "groups": runtime.trace_groups(scope_trace_id),
                "snapshot": True,
                **({"peer_id": peer_id} if peer_id is not None else {}),
            },
        }],
    )

    try:
        while True:
            timeout = max(0.0, next_heartbeat - loop.time())
            try:
                event = await asyncio.wait_for(subscription.get(), timeout=timeout)
            except asyncio.TimeoutError:
                now = loop.time()
                if now < next_heartbeat:
                    continue

                heartbeat_due = now - last_heartbeat_emit >= heartbeat_keepalive_interval
                signature = runtime.trace_running_signature(scope_trace_id=scope_trace_id)
                should_emit = (
                    bool(signature)
                    and (
                        signature != last_heartbeat_signature
                        or heartbeat_due
                    )
                )
                if should_emit:
                    traces = runtime.trace_live_running(
                        include_duration=heartbeat_due,
                        scope_trace_id=scope_trace_id,
                    )
                    update = {
                        "event": "trace:update",
                        "data": {
                            "tasks": [compact_trace_update(trace) for trace in traces],
                            "groups": runtime.trace_groups(scope_trace_id),
                        },
                    }
                    await send_trace_batch(send_json, [update])
                    last_heartbeat_emit = now
                    last_heartbeat_signature = signature
                next_heartbeat = loop.time() + heartbeat_interval
            else:
                events = trace_events_from_subscription_event(event)
                attach_groups_once(events, runtime.trace_groups(scope_trace_id))
                await send_trace_batch(send_json, events)
    finally:
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
) -> None:
    if not events:
        return

    await send_json(
        {
            "event": "trace:batch",
            "data": {"events": events},
        }
    )


def attach_groups_once(events: list[dict[str, Any]], groups: list[dict[str, Any]]) -> None:
    for event in reversed(events):
        if event.get("event") not in {"trace:init", "trace:update", "trace:complete"}:
            continue
        data = event.get("data")
        if isinstance(data, dict):
            event["data"] = {**data, "groups": groups}
        return


def compact_trace_update(trace: dict[str, Any]) -> dict[str, Any]:
    compact = dict(trace)
    if compact.get("status") in {"created", "running"}:
        compact.pop("transitions", None)
        compact["duration_ms"] = trace.get("duration_ms")
    return compact
