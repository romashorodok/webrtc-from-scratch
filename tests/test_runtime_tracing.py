import asyncio
import threading

import pytest

from webrtc.performance import (
    MetricEvent,
    MetricGroupAggregator,
    ObservedComponent,
    worker,
)
from webrtc import Runtime
from webrtc.runtime_services import (
    Borrowed,
    TaskScheduler,
    current_execution_context,
)


def batch_events(message):
    return message.get("data", {}).get("events", [])


def test_scheduler_works_without_tracing_and_cleans_registry():
    async def scenario():
        scheduler = TaskScheduler()
        seen = {}

        async def work():
            seen["context"] = current_execution_context()

        await scheduler.run_factory(lambda: work(), trace_id="peer-trace")
        assert seen["context"].trace_id == "peer-trace"
        assert scheduler.registry.task_ids() == ()

    asyncio.run(scenario())


def test_runtime_tasks_share_trace_and_have_unique_parented_task_ids():
    async def scenario():
        seen = {}
        async with Runtime(scope_id="peer", max_workers=1) as execution:
            root = current_execution_context()

            async def child():
                seen["child"] = current_execution_context()

            await execution.start(lambda: child(), name="child")
            assert seen["child"].trace_id == root.trace_id
            assert seen["child"].task_id != root.task_id
            assert seen["child"].parent_task_id == root.task_id
            assert seen["child"].scope_id == "peer"

    asyncio.run(scenario())


def test_terminal_task_emits_snapshot_then_is_pruned():
    async def scenario():
        async with Runtime(trace_subscriber_batch_interval=0.01) as execution:
            sub = execution.observability.subscribe()
            assert await execution.start(
                lambda: asyncio.sleep(0, result=7), name="short"
            ) == 7
            message = await asyncio.wait_for(sub.get(), 1)
            events = batch_events(message)
            assert [item["event"] for item in events] == [
                "trace:init",
                "trace:complete",
                "trace:delete",
            ]
            task = events[0]["data"]["tasks"][0]
            assert task["trace_id"] and task["task_id"]
            assert events[1]["data"]["tasks"][0]["status"] == "completed"
            assert events[2]["data"]["task_ids"] == [task["task_id"]]
            assert [node["name"] for node in execution.observability.live_tree()] == [
                "execution.root"
            ]
            sub.close()

    asyncio.run(scenario())


def test_trace_groups_only_include_live_task_ids():
    async def scenario():
        async with Runtime() as execution:
            root = current_execution_context()
            execution.metric_sink.emit(MetricEvent(
                root.trace_id, root.task_id, "live.operation", "success", 1.0,
            ))
            execution.metric_sink.emit(MetricEvent(
                root.trace_id, "deleted-task", "stale.operation", "success", 1.0,
            ))

            groups = execution.trace_groups(root.trace_id)
            assert [group["task_id"] for group in groups] == [root.task_id]

    asyncio.run(scenario())


def test_live_duration_and_signature_are_task_centric():
    async def scenario():
        gate = asyncio.Event()
        async with Runtime() as execution:
            task = execution.start(lambda: gate.wait(), name="heartbeat")
            await asyncio.sleep(0)
            snapshot = next(
                item
                for item in execution.observability.live_running(include_duration=True)
                if item["name"] == "heartbeat"
            )
            assert snapshot["task_id"]
            assert snapshot["duration_ms"] >= 0
            assert (snapshot["task_id"], execution.root_context.task_id, "running") in (
                execution.observability.running_signature()
            )
            gate.set()
            await task

    asyncio.run(scenario())


def test_parent_completion_joins_managed_children():
    async def scenario():
        child_gate = asyncio.Event()
        child_started = asyncio.Event()
        async with Runtime() as execution:
            async def parent():
                async def child():
                    child_started.set()
                    await child_gate.wait()

                execution.start(lambda: child(), name="child")
                await child_started.wait()

            parent_task = execution.start(lambda: parent(), name="parent")
            await child_started.wait()
            await asyncio.sleep(0)
            assert not parent_task.done()
            live_names = {item["name"] for item in execution.observability.live_tree()}
            assert {"execution.root", "parent", "child"} <= live_names
            child_gate.set()
            await parent_task

    asyncio.run(scenario())


def test_cancel_uses_node_id_and_preserves_observer_owned_pruning():
    class Waiting(ObservedComponent):
        async def wait(self):
            await asyncio.sleep(10)

    async def scenario():
        async with Runtime() as execution:
            task = execution.start(lambda: Waiting().wait(), name="sleep")
            await asyncio.sleep(0)
            method = next(
                node
                for node in execution.observability.live_tree()
                if node["metadata"].get("node_type") == "async-call"
            )
            assert execution.observability.cancel(method["task_id"]) is False
            node_id = next(
                node["task_id"]
                for node in execution.observability.live_tree()
                if node["name"] == "sleep"
            )
            assert execution.observability.cancel(node_id)
            with pytest.raises(asyncio.CancelledError):
                await task
            assert [node["name"] for node in execution.observability.live_tree()] == [
                "execution.root"
            ]

    asyncio.run(scenario())


def test_worker_context_propagates_and_metric_group_is_not_a_task():
    class Worker(ObservedComponent):
        @worker
        def context(self):
            return current_execution_context()

    async def scenario():
        sink = MetricGroupAggregator()
        async with Runtime(metric_sink=Borrowed(sink)) as execution:
            seen = {}

            async def owner():
                seen["event_loop"] = current_execution_context()
                seen["worker"] = await Worker().context()
                for duration in (1.0, 3.0):
                    sink.emit(
                        MetricEvent(
                            seen["event_loop"].trace_id,
                            seen["event_loop"].task_id,
                            "packet",
                            "success",
                            duration,
                            group="rtp",
                        )
                    )

            await execution.start(lambda: owner(), name="owner")
            assert seen["worker"].trace_id == seen["event_loop"].trace_id
            assert seen["worker"].task_id == seen["event_loop"].task_id
            group = next(item for item in sink.snapshots() if item.operation == "packet")
            assert group.calls == 2 and group.average_duration_ms == 2.0
            assert execution.task_registry.task_ids() == (execution.root_context.task_id,)

    asyncio.run(scenario())


def test_observer_failure_cannot_change_task_outcome():
    class Broken:
        def task_started(self, event):
            raise RuntimeError("observer")

        task_completed = task_started
        task_failed = task_started
        task_cancelled = task_started

    async def scenario():
        async with Runtime(task_observers=[Broken()]) as execution:
            assert await execution.start(
                lambda: asyncio.sleep(0, result="ok"), name="observed"
            ) == "ok"
            assert execution.task_scheduler.diagnostics["observer_failures"] >= 1

    asyncio.run(scenario())


def test_metric_groups_are_bounded_under_packet_load():
    aggregator = MetricGroupAggregator(max_groups=2)
    for _ in range(10_000):
        aggregator.emit(
            MetricEvent("trace", "task", "packet", "success", 1.0, group="media")
        )
    assert aggregator.snapshots()[0].calls == 10_000
    aggregator.emit(MetricEvent("two", "task", "packet", "success", 1.0))
    aggregator.emit(MetricEvent("three", "task", "packet", "success", 1.0))
    assert len(aggregator.snapshots()) == 2
    assert aggregator.diagnostics["evicted_groups"] == 1


def test_worker_queue_is_cancelable_but_running_worker_is_not():
    release = threading.Event()
    entered = threading.Event()

    class Blocking(ObservedComponent):
        @worker
        def first(self):
            entered.set()
            release.wait(2)

        @worker
        def second(self):
            return None

    async def scenario():
        subject = Blocking()
        async with Runtime(max_workers=1, offload_capacity=1) as execution:
            first = execution.start(lambda: subject.first(), name="first")
            await asyncio.to_thread(entered.wait, 1)
            second = execution.start(lambda: subject.second(), name="second")
            await asyncio.sleep(0)
            worker_nodes = [
                item
                for item in execution.observability.live_tree()
                if item["metadata"].get("node_type") == "worker-call"
            ]
            running = next(item for item in worker_nodes if item["name"].endswith("first"))
            queued = next(item for item in worker_nodes if item["name"].endswith("second"))
            assert execution.observability.cancel(running["task_id"]) is False
            assert execution.observability.cancel(queued["task_id"]) is True
            release.set()
            await first
            with pytest.raises(asyncio.CancelledError):
                await second

    asyncio.run(scenario())


def test_trace_live_context_limit_rejects_admission_without_evicting_running_nodes():
    class Subject(ObservedComponent):
        async def wait(self, release):
            await release.wait()

    async def scenario():
        release = asyncio.Event()
        async with Runtime(trace_context_limit=1) as execution:
            task = asyncio.create_task(Subject().wait(release))
            await asyncio.sleep(0)
            live = execution.observability.live_tree()
            assert len(live) == 1
            assert live[0]["name"] == "execution.root"
            assert execution.trace_service.diagnostics["live_context_limit_rejections"] >= 1
            assert execution.diagnostics["live_context_limit_rejections"] >= 1
            release.set()
            await task

    asyncio.run(scenario())


def test_queued_node_cancellation_does_not_cancel_its_managed_owner_task():
    release = threading.Event()
    entered = threading.Event()

    class Blocking(ObservedComponent):
        @worker
        def first(self):
            entered.set()
            release.wait(2)

        @worker
        def queued(self):
            return "unexpected"

    async def scenario():
        survived = asyncio.Event()
        subject = Blocking()
        async with Runtime(max_workers=1) as execution:
            first = execution.start(lambda: subject.first(), name="first")
            await asyncio.to_thread(entered.wait, 1)

            async def owner():
                try:
                    await subject.queued()
                except asyncio.CancelledError:
                    survived.set()
                return "owner-survived"

            owner_task = execution.start(owner, name="queue-owner")
            await asyncio.sleep(0)
            node = next(
                item for item in execution.observability.live_tree()
                if item["name"].endswith("Blocking.queued")
            )
            assert execution.observability.cancel(node["task_id"])
            assert await owner_task == "owner-survived"
            assert survived.is_set()
            release.set()
            await first

    asyncio.run(scenario())
