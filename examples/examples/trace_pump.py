import asyncio
from typing import Any, Awaitable, Callable

from webrtc.runtime import WebRTCRuntimeResources


async def pump_trace_updates(
    runtime: WebRTCRuntimeResources,
    peer_id: str,
    send_json: Callable[[dict[str, Any]], Awaitable[None]],
    *,
    heartbeat_interval: float = 0.25,
) -> None:
    await send_json(
        {
            "event": "trace:init",
            "data": {
                "peer_id": peer_id,
                "traces": runtime.trace_snapshot(peer_id=peer_id),
                "summaries": runtime.trace_summaries(peer_id=peer_id),
                "success_retention_seconds": runtime.get_success_trace_retention(peer_id=peer_id),
            },
        }
    )

    subscription = runtime.subscribe_traces(peer_id=peer_id)
    loop = asyncio.get_running_loop()
    next_heartbeat = loop.time() + heartbeat_interval
    try:
        while True:
            timeout = max(0.0, next_heartbeat - loop.time())
            try:
                event = await asyncio.wait_for(subscription.get(), timeout=timeout)
            except asyncio.TimeoutError:
                for trace in runtime.running_trace_snapshot(peer_id=peer_id):
                    await send_json(
                        {
                            "event": "trace:update",
                            "data": {
                                "peer_id": peer_id,
                                "trace": trace,
                            },
                        }
                    )
                next_heartbeat = loop.time() + heartbeat_interval
            else:
                await send_json(event)
    finally:
        subscription.close()
