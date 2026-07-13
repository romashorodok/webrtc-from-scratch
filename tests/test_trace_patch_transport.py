import asyncio
import time
from types import SimpleNamespace

from webrtc import Runtime
from webrtc.performance import _intern_operation
from webrtc.observability import ControlHandle, FacetOp, MachineTransitionOp, ProducerDot
from webrtc.state_machine import MachineSpec


def _policy(name: str):
    return SimpleNamespace(operation_id=_intern_operation(name), operation=name, group="test")


def _record(runtime: Runtime, name: str):
    return runtime.activity_groups.resolve(
        _policy(name),
        trace_id=runtime.root_context.trace_id,
        owner_entity_id="owner",
        owner_epoch=1,
        parent_ref_id=None,
    )


def _group_records(message):
    return [
        record
        for event in message["data"].get("events", ())
        if event["type"] == "group:upsert"
        for record in event["records"]
    ]


def test_one_group_patch_is_absolute_and_source_coalesced():
    async def scenario():
        async with Runtime(trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe()
            snapshot = await subscription.get()
            assert snapshot["event"] == "trace:snapshot"
            record = _record(runtime, "stage4.coalesced")
            now = time.monotonic_ns()
            runtime.activity_groups.begin(record, now)
            runtime.activity_groups.end(record, "success", 10, now + 10)
            runtime.activity_groups.begin(record, now + 20)
            runtime.activity_groups.end(record, "success", 20, now + 40)

            batches = runtime.trace_patch_flush()
            assert len(batches) == 1
            delivered = await subscription.get()
            assert delivered is batches[0]
            records = _group_records(delivered)
            assert len(records) == 1
            assert records[0]["calls"] == 2
            assert records[0]["successes"] == 2
            assert records[0]["revision"] == 4
            assert delivered["data"]["operation_strings"][record.operation_id] == record.operation
            subscription.close()

    asyncio.run(scenario())


def test_serialized_batch_object_is_reused_for_all_subscribers():
    async def scenario():
        async with Runtime(trace_patch_cadence=60) as runtime:
            first = runtime.trace_patch_subscribe()
            second = runtime.trace_patch_subscribe()
            await first.get()
            await second.get()
            record = _record(runtime, "stage4.shared")
            runtime.activity_groups.begin(record, time.monotonic_ns())
            batch = runtime.trace_patch_flush()[0]
            assert await first.get() is batch
            assert await second.get() is batch
            first.close()
            second.close()

    asyncio.run(scenario())


def test_slow_subscriber_overflow_resyncs_then_snapshot_converges():
    async def scenario():
        async with Runtime(trace_patch_cadence=60, trace_journal_limit=2) as runtime:
            subscription = runtime.trace_patch_subscribe(maxsize=1)
            await subscription.get()
            record = _record(runtime, "stage4.slow")
            now = time.monotonic_ns()
            runtime.activity_groups.begin(record, now)
            runtime.trace_patch_flush()
            runtime.activity_groups.end(record, "success", 5, now + 5)
            runtime.trace_patch_flush()

            resync = await subscription.get()
            assert resync["event"] == "trace:resync_required"
            snapshot = await subscription.get()
            assert snapshot["event"] == "trace:snapshot"
            current = next(item for item in snapshot["data"]["groups"] if item["group_id"] == record.group_id)
            assert current["calls"] == 1
            assert current["in_flight"] == 0
            assert current["successes"] == 1
            assert runtime.diagnostics["trace_resync_required"] == 1
            subscription.close()

    asyncio.run(scenario())


def test_no_transport_serialization_without_viewers_and_snapshot_catches_up():
    async def scenario():
        async with Runtime(trace_patch_cadence=0) as runtime:
            record = _record(runtime, "stage4.closed")
            runtime.activity_groups.begin(record, time.monotonic_ns())
            assert runtime.trace_patch_flush() == ()
            assert runtime.trace_transport.journal_depth == 0

            subscription = runtime.trace_patch_subscribe()
            snapshot = await subscription.get()
            current = next(item for item in snapshot["data"]["groups"] if item["group_id"] == record.group_id)
            assert current["calls"] == 1
            subscription.close()

    asyncio.run(scenario())


def test_record_budget_preserves_stable_sequence_order():
    async def scenario():
        async with Runtime(trace_patch_cadence=60, trace_patch_record_budget=1) as runtime:
            subscription = runtime.trace_patch_subscribe(maxsize=4)
            await subscription.get()
            first = _record(runtime, "stage4.budget.first")
            second = _record(runtime, "stage4.budget.second")
            now = time.monotonic_ns()
            runtime.activity_groups.begin(first, now)
            runtime.activity_groups.begin(second, now)
            batches = runtime.trace_patch_flush()
            assert len(batches) == 2
            assert [item["data"]["sequence"] for item in batches] == [1, 2]
            assert [_group_records(item)[0]["group_id"] for item in batches] == [
                first.group_id, second.group_id
            ]
            subscription.close()

    asyncio.run(scenario())


def test_machine_control_and_state_records_share_the_schema2_drain():
    async def scenario():
        async with Runtime(trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe()
            await subscription.get()
            spec = MachineSpec(
                "peer", "new", {"new": frozenset({"active"}), "active": frozenset()},
                frozenset(),
            )
            runtime.projection.machines.register("peer", spec)
            runtime.projection.machines.apply(MachineTransitionOp(
                "peer", "peer", "new", "active", 1, 1,
                ProducerDot(runtime.runtime_epoch, 1, 1), monotonic_ns=time.monotonic_ns(),
            ))
            runtime.projection.controls.expose(ControlHandle(
                "stop", runtime.root_context.trace_id, "peer", 1, "Stop", True,
            ))
            runtime.projection.facets.apply(FacetOp(
                "peer.ready", "peer", 1, True, 1,
                ProducerDot(runtime.runtime_epoch, 2, 1),
            ))

            batch = runtime.trace_patch_flush()[0]
            events = {item["type"]: item for item in batch["data"]["events"]}
            assert events["machine:transition"]["records"][0]["revision"] == 1
            assert events["control:upsert"]["records"][0]["revision"] == 1
            assert events["state:upsert"]["records"][0]["revision"] == 1
            assert "diagnostics:patch" in events
            subscription.close()

    asyncio.run(scenario())


def test_projection_records_obey_the_same_record_budget_as_groups():
    async def scenario():
        async with Runtime(trace_patch_cadence=60, trace_patch_record_budget=1) as runtime:
            subscription = runtime.trace_patch_subscribe(maxsize=8)
            await subscription.get()
            runtime.projection.controls.expose(ControlHandle(
                "one", runtime.root_context.trace_id, "peer", 1, "One", True,
            ))
            runtime.projection.controls.expose(ControlHandle(
                "two", runtime.root_context.trace_id, "peer", 1, "Two", True,
            ))
            batches = runtime.trace_patch_flush()
            upserts = [
                event
                for batch in batches for event in batch["data"]["events"]
                if event["type"] == "control:upsert"
            ]
            assert len(upserts) == 2
            assert all(len(event["records"]) == 1 for event in upserts)
            subscription.close()

    asyncio.run(scenario())


def test_resync_waiter_does_not_retain_unbounded_removal_checkpoints():
    async def scenario():
        async with Runtime(trace_patch_cadence=60, trace_journal_limit=2) as runtime:
            subscription = runtime.trace_patch_subscribe(maxsize=1)
            await subscription.get()
            record = _record(runtime, "stage4.resync-bounds")
            for index in range(20):
                runtime.activity_groups.begin(record, time.monotonic_ns() + index)
                runtime.trace_patch_flush()
            assert subscription.subscriber.needs_snapshot
            assert len(runtime.trace_transport._removal_checkpoint_by_sequence) <= 1
            subscription.close()

    asyncio.run(scenario())


def test_owner_teardown_publishes_final_absolute_group_before_remove():
    async def scenario():
        async with Runtime(trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe(maxsize=4)
            await subscription.get()
            record = runtime.activity_groups.resolve(
                _policy("stage4.final"), trace_id=runtime.root_context.trace_id,
                owner_entity_id="closing", owner_epoch=1, parent_ref_id=None,
            )
            now = time.monotonic_ns()
            runtime.activity_groups.begin(record, now)
            runtime.activity_groups.end(record, "success", 5, now + 5)
            runtime.projection.terminate_entity_epoch("closing", 1)
            batch = runtime.trace_patch_flush()[0]
            events = batch["data"]["events"]
            upsert_index = next(i for i, event in enumerate(events) if event["type"] == "group:upsert")
            remove_index = next(i for i, event in enumerate(events) if event["type"] == "group:remove")
            assert upsert_index < remove_index
            assert events[upsert_index]["records"][0]["successes"] == 1
            assert events[remove_index]["ids"] == [record.group_id]
            subscription.close()

    asyncio.run(scenario())
