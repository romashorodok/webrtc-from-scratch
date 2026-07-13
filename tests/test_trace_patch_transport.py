import asyncio
import time
from types import SimpleNamespace

from webrtc import Runtime
from webrtc.domain_events import PeerStateChanged, get_domain_event_dispatcher
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


def test_diagnostic_only_changes_coalesce_and_do_not_emit_noop_patches():
    async def scenario():
        async with Runtime(trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe()
            await subscription.get()

            runtime.diagnostics["diagnostic_only"] += 1
            runtime.diagnostics["diagnostic_only"] += 2
            assert runtime.trace_transport._flush_handle is not None

            batches = runtime.trace_patch_flush()
            assert len(batches) == 1
            events = batches[0]["data"]["events"]
            assert [event["type"] for event in events] == ["diagnostics:patch"]
            assert events[0]["values"]["diagnostic_only"] == 3
            assert await subscription.get() is batches[0]
            assert runtime.trace_patch_flush() == ()

            del runtime.diagnostics["diagnostic_only"]
            reset = runtime.trace_patch_flush()[0]
            reset_event = next(
                event for event in reset["data"]["events"]
                if event["type"] == "diagnostics:patch"
            )
            assert reset_event["values"]["diagnostic_only"] == 0
            assert runtime.trace_patch_flush() == ()
            subscription.close()

    asyncio.run(scenario())


def test_domain_dispatcher_observer_failures_reach_patch_snapshot_and_health_facet():
    class BrokenObserver:
        def on_domain_event(self, event):
            raise RuntimeError("observer failed")

    async def scenario():
        dispatcher = get_domain_event_dispatcher()
        broken = BrokenObserver()
        async with Runtime(scope_id="diagnostic-peer", trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe()
            await subscription.get()
            dispatcher.add_observer(broken)
            try:
                assert dispatcher.publish(PeerStateChanged(
                    context=runtime.root_context,
                ))
            finally:
                dispatcher.remove_observer(broken)

            batch = runtime.trace_patch_flush()[0]
            diagnostic_event = next(
                event for event in batch["data"]["events"]
                if event["type"] == "diagnostics:patch"
            )
            assert diagnostic_event["values"]["domain_dispatcher_observer_failures"] == 1
            health = {
                item.facet_id.rsplit(":", 1)[-1]: item.value
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == "tracing:diagnostic-peer"
            }
            assert health["dispatcher_observer_failures"] == 1
            snapshot = runtime.trace_snapshot()
            assert snapshot["data"]["diagnostics"][
                "domain_dispatcher_observer_failures"
            ] == 1
            assert runtime.trace_patch_flush() == ()
            subscription.close()

    asyncio.run(scenario())


def test_trace_health_delivery_failure_is_reconciled_without_feedback_loop():
    class BrokenObserver:
        def on_domain_event(self, event):
            raise RuntimeError("observer failed")

    async def scenario():
        dispatcher = get_domain_event_dispatcher()
        broken = BrokenObserver()
        async with Runtime(scope_id="diagnostic-peer", trace_patch_cadence=60) as runtime:
            dispatcher.add_observer(broken)
            try:
                subscription = runtime.trace_patch_subscribe()
                snapshot = await subscription.get()
                failures = runtime.diagnostics[
                    "domain_dispatcher_observer_failures"
                ]
                # The health event fails once at the broken observer; updating
                # its health facet must not recursively emit another event.
                assert failures == 1
                facets = {
                    item.facet_id.rsplit(":", 1)[-1]: item.value
                    for item in runtime.projection.facets.snapshots()
                    if item.owner_entity_id == "tracing:diagnostic-peer"
                }
                assert facets["dispatcher_observer_failures"] == failures
                assert snapshot["data"]["diagnostics"][
                    "domain_dispatcher_observer_failures"
                ] == failures
                assert runtime.trace_patch_flush() == ()
            finally:
                dispatcher.remove_observer(broken)
                subscription.close()

    asyncio.run(scenario())


def test_domain_dispatcher_drop_is_exported_without_recursive_flush_churn():
    class RecursiveObserver:
        def __init__(self, dispatcher):
            self.dispatcher = dispatcher

        def on_domain_event(self, event):
            self.dispatcher.publish(event)

    async def scenario():
        dispatcher = get_domain_event_dispatcher()
        recursive = RecursiveObserver(dispatcher)
        old_capacity = dispatcher.capacity
        async with Runtime(trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe()
            await subscription.get()
            dispatcher.capacity = 2
            dispatcher.add_observer(recursive)
            try:
                assert dispatcher.publish(PeerStateChanged(
                    context=runtime.root_context,
                ))
            finally:
                dispatcher.remove_observer(recursive)
                dispatcher.capacity = old_capacity

            batch = runtime.trace_patch_flush()[0]
            diagnostic_event = next(
                event for event in batch["data"]["events"]
                if event["type"] == "diagnostics:patch"
            )
            assert diagnostic_event["values"]["domain_dispatcher_dropped"] == 1
            assert runtime.trace_patch_flush() == ()
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
            diagnostic_batch = runtime.trace_patch_flush()
            assert len(diagnostic_batch) == 1
            diagnostic_events = diagnostic_batch[0]["data"]["events"]
            assert [event["type"] for event in diagnostic_events] == [
                "diagnostics:patch"
            ]
            assert diagnostic_events[0]["values"]["trace_resync_required"] == 1
            assert runtime.trace_patch_flush() == ()
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


def test_all_machine_transitions_survive_source_coalescing_in_commit_order():
    async def scenario():
        async with Runtime(trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe()
            await subscription.get()
            spec = MachineSpec(
                "journal", "new", {
                    "new": frozenset({"starting"}),
                    "starting": frozenset({"active"}),
                    "active": frozenset({"closed"}),
                    "closed": frozenset(),
                }, frozenset(),
            )
            runtime.projection.machines.register("journal", spec)
            states = (("new", "starting"), ("starting", "active"), ("active", "closed"))
            for revision, (previous, current) in enumerate(states, 1):
                runtime.projection.machines.apply(MachineTransitionOp(
                    "journal", "journal", previous, current, 1, revision,
                    ProducerDot(runtime.runtime_epoch, 77, revision),
                    cause_id=f"cause-{revision}", monotonic_ns=100 + revision,
                ))

            batch = runtime.trace_patch_flush()[0]
            event = next(
                item for item in batch["data"]["events"]
                if item["type"] == "machine:transition"
            )
            assert [item["revision"] for item in event["records"]] == [1, 2, 3]
            assert [item["from_state"] for item in event["records"]] == [
                "new", "starting", "active"
            ]
            assert [item["to_state"] for item in event["records"]] == [
                "starting", "active", "closed"
            ]
            assert [item["order"] for item in event["records"]] == sorted(
                item["order"] for item in event["records"]
            )
            assert event["records"][1]["cause_id"] == "cause-2"
            subscription.close()

    asyncio.run(scenario())


def test_machine_transition_journal_is_bounded_and_patch_reset_is_truthful():
    async def scenario():
        async with Runtime(
            trace_patch_cadence=60, trace_transition_journal_limit=2,
        ) as runtime:
            subscription = runtime.trace_patch_subscribe(maxsize=4)
            initial = await subscription.get()
            assert initial["data"]["transition_journal_limit"] == 2
            spec = MachineSpec(
                "journal", "new", {
                    "new": frozenset({"one"}), "one": frozenset({"two"}),
                    "two": frozenset({"three"}), "three": frozenset(),
                }, frozenset(),
            )
            runtime.projection.machines.register("bounded", spec)
            for revision, (previous, current) in enumerate(
                (("new", "one"), ("one", "two"), ("two", "three")), 1,
            ):
                runtime.projection.machines.apply(MachineTransitionOp(
                    "bounded", "journal", previous, current, 1, revision,
                    ProducerDot(runtime.runtime_epoch, 88, revision),
                    monotonic_ns=revision,
                ))

            assert len(runtime.projection.machines.transition_snapshots()) == 2
            batch = runtime.trace_patch_flush()[0]
            machine = next(
                item for item in batch["data"]["events"]
                if item["type"] == "machine:upsert"
            )
            assert machine["records"][0]["state"] == "three"
            event = next(
                item for item in batch["data"]["events"]
                if item["type"] == "machine:transition"
            )
            assert event["reset"] is True
            assert [item["revision"] for item in event["records"]] == [2, 3]
            snapshot = runtime.trace_snapshot()["data"]
            assert [item["revision"] for item in snapshot["transitions"]] == [2, 3]
            assert runtime.diagnostics["machine_transition_journal_resets"] == 1
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
