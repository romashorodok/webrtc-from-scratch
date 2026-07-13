import asyncio
from contextlib import suppress
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "examples"))

from examples.trace_pump import pump_trace_updates


class _Subscription:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.closed = False

    async def get(self):
        return await self.queue.get()

    def close(self):
        self.closed = True


class _Runtime:
    def __init__(self):
        self.subscription = _Subscription()

    def trace_patch_subscribe(self, *, peer_id=None):
        del peer_id
        self.subscription.queue.put_nowait({
            "event": "trace:snapshot",
            "data": {"schema": 2, "trace_id": "session", "snapshot_sequence": 0},
        })
        return self.subscription


def test_pump_forwards_only_canonical_schema2_messages_and_closes_subscription():
    async def scenario():
        runtime = _Runtime()
        sent = []

        async def send_json(message):
            sent.append(message)

        pump = asyncio.create_task(pump_trace_updates(runtime, send_json))
        try:
            await _wait_for_count(sent, 1)
            runtime.subscription.queue.put_nowait({
                "event": "trace:batch",
                "data": {"schema": 2, "trace_id": "session", "sequence": 1, "events": []},
            })
            await _wait_for_count(sent, 2)
        finally:
            pump.cancel()
            with suppress(asyncio.CancelledError):
                await pump
        assert [item["event"] for item in sent] == ["trace:snapshot", "trace:batch"]
        assert runtime.subscription.closed

    asyncio.run(scenario())


async def _wait_for_count(items, count):
    while len(items) < count:
        await asyncio.sleep(0)
