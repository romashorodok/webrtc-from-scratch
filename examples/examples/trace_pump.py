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
    del scope_trace_id, heartbeat_interval, heartbeat_keepalive_interval
    subscription = runtime.trace_patch_subscribe(peer_id=peer_id)
    try:
        while True:
            await send_json(await subscription.get())
    finally:
        subscription.close()
