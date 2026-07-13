import asyncio
from contextlib import suppress
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "examples"))

from examples.trace_pump import pump_trace_updates, send_trace_batch
from webrtc.tracing.events import TraceEventBus


def update(task_id: str, duration: int, *, groups=None):
    data = {
        "trace_id": "session",
        "tasks": [{"trace_id": "session", "task_id": task_id, "duration_ms": duration}],
    }
    if groups is not None:
        data["groups"] = groups
    return data


def test_event_bus_coalesces_updates_and_duplicates_with_lifecycle_ordering():
    asyncio.run(_check_event_bus_coalescing())


async def _check_event_bus_coalescing():
    bus = TraceEventBus(batch_interval=0.01)
    subscriber = bus.subscribe()
    try:
        bus.publish("trace:init", {"tasks": [{"task_id": "one"}]})
        bus.publish("trace:update", update("one", 1, groups=[{"calls": 1}]))
        bus.publish("trace:update", update("one", 2, groups=[{"calls": 2}]))
        bus.publish("trace:performance", {"name": "tick"})
        bus.publish("trace:performance", {"name": "tick"})
        bus.publish("trace:complete", {"tasks": [{"task_id": "one", "status": "completed"}]})
        bus.publish("trace:update", update("one", 3))
        bus.publish("trace:delete", {"task_ids": ["one"]})

        batch = await asyncio.wait_for(subscriber.queue.get(), timeout=0.2)
    finally:
        bus.unsubscribe(subscriber)

    assert batch["event"] == "trace:batch"
    events = batch["data"]["events"]
    assert [event["event"] for event in events] == [
        "trace:init",
        "trace:update",
        "trace:performance",
        "trace:complete",
        "trace:update",
        "trace:delete",
    ]
    assert events[1]["data"]["tasks"][0]["duration_ms"] == 2
    assert events[1]["data"]["groups"] == [{"calls": 2}]
    assert events[1]["data"]["sequence"] > events[0]["data"]["sequence"]
    assert events[4]["data"]["tasks"][0]["duration_ms"] == 3


def test_send_trace_batch_always_uses_the_canonical_events_envelope():
    asyncio.run(_check_canonical_envelope())


async def _check_canonical_envelope():
    sent = []

    async def send_json(message):
        sent.append(message)

    event = {"event": "trace:update", "data": update("one", 1)}
    await send_trace_batch(send_json, [event])

    assert sent == [{"event": "trace:batch", "data": {"events": [event]}}]


class _Subscription:
    def __init__(self, bus, subscriber):
        self.bus = bus
        self.subscriber = subscriber

    async def get(self):
        return await self.subscriber.queue.get()

    def close(self):
        self.bus.unsubscribe(self.subscriber)


class _Runtime:
    def __init__(self):
        self.bus = TraceEventBus(batch_interval=0.01)

    def trace_subscribe(self, *, peer_id=None):
        return _Subscription(self.bus, self.bus.subscribe(peer_id=peer_id))

    def trace_live_tree(self, *, scope_trace_id=None):
        return [{"trace_id": "session", "task_id": "root", "parent_task_id": None}]

    def trace_groups(self, trace_id=None):
        return [{"trace_id": "session", "task_id": "root", "calls": 1}]

    def trace_running_signature(self, *, scope_trace_id=None):
        return ()

    def trace_live_running(self, *, include_duration=False, scope_trace_id=None):
        return []


def test_pump_sends_immediate_snapshot_then_forwards_one_bus_batch():
    asyncio.run(_check_pump_delivery())


async def _check_pump_delivery():
    runtime = _Runtime()
    sent = []

    async def send_json(message):
        sent.append(message)

    pump = asyncio.create_task(
        pump_trace_updates(runtime, send_json, scope_trace_id="session")
    )
    try:
        await asyncio.wait_for(_wait_for_count(sent, 1), timeout=0.2)
        snapshot = sent[0]
        assert snapshot["data"]["events"][0]["data"]["snapshot"] is True

        runtime.bus.publish("trace:update", update("root", 1))
        runtime.bus.publish("trace:update", update("root", 2))
        await asyncio.wait_for(_wait_for_count(sent, 2), timeout=0.2)
    finally:
        pump.cancel()
        with suppress(asyncio.CancelledError):
            await pump

    assert len(sent) == 2
    batch_events = sent[1]["data"]["events"]
    assert len(batch_events) == 1
    assert batch_events[0]["event"] == "trace:update"
    assert batch_events[0]["data"]["tasks"][0]["duration_ms"] == 2
    assert batch_events[0]["data"]["groups"] == runtime.trace_groups("session")


async def _wait_for_count(items, count):
    while len(items) < count:
        await asyncio.sleep(0)
