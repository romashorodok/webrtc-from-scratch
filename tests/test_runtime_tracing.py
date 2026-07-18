import asyncio
import threading

import pytest

from webrtc.performance import (
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


def test_runtime_tasks_are_projected_only_through_schema2_snapshot():
    async def scenario():
        async with Runtime() as execution:
            sub = execution.trace_patch_subscribe()
            snapshot = await sub.get()
            assert snapshot["event"] == "trace:snapshot"
            assert snapshot["data"]["schema"] == 2
            assert await execution.start(
                lambda: asyncio.sleep(0, result=7), name="short"
            ) == 7
            sub.close()

    asyncio.run(scenario())


def test_trace_groups_only_include_live_task_ids():
    async def scenario():
        async with Runtime() as execution:
            root = current_execution_context()
            groups = execution.trace_groups(root.trace_id)
            assert groups == []

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
            node_id = next(
                node["task_id"]
                for node in execution.observability.live_tree()
                if node["name"] == "sleep"
            )
            assert execution.observability.cancel(node_id)
            with pytest.raises(asyncio.CancelledError):
                await task
            names = [node["name"] for node in execution.observability.live_tree()]
            assert "sleep" not in names
            assert "execution.root" in names

    asyncio.run(scenario())


def test_worker_context_propagates_and_metric_group_is_not_a_task():
    class Worker(ObservedComponent):
        @worker
        def context(self):
            return current_execution_context()

    async def scenario():
        async with Runtime() as execution:
            seen = {}

            async def owner():
                seen["event_loop"] = current_execution_context()
                seen["worker"] = await Worker().context()

            await execution.start(lambda: owner(), name="owner")
            assert seen["worker"].trace_id == seen["event_loop"].trace_id
            assert seen["worker"].task_id != seen["event_loop"].task_id
            group = next(item for item in execution.activity_groups.snapshots()
                         if item.operation.endswith("Worker.context"))
            assert group.calls == 1
            assert not any(
                item["name"] == "owner" for item in execution.observability.live_tree()
            )

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
            task_nodes = execution.observability.live_tree()
            running = next(item for item in task_nodes if item["name"] == "first")
            queued = next(item for item in task_nodes if item["name"] == "second")
            assert execution.observability.cancel(running["task_id"]) is False
            assert execution.observability.cancel(queued["task_id"]) is True
            release.set()
            await first
            with pytest.raises(asyncio.CancelledError):
                await second

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
            owner_task.cancel()
            assert await owner_task == "owner-survived"
            assert survived.is_set()
            release.set()
            await first

    asyncio.run(scenario())
