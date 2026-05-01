import asyncio

import pytest

from webrtc.peer_context import PeerContext
from webrtc.runtime import WebRTCRuntimeResources, get_current_task_context


def trace_batch_events(messages, event_name=None):
    events = []
    for message in messages:
        if message.get("event") != "trace:batch":
            continue
        data = message.get("data", {})
        batch_events = data.get("events") if isinstance(data, dict) else None
        for event in batch_events or []:
            if event_name is None or event.get("event") == event_name:
                events.append(event)
    return events


def test_peer_context_spawn_inherits_parent_task_context():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            async with PeerContext(object(), runtime=runtime, peer_id="peer-test") as peer:
                parent = get_current_task_context()
                assert parent is not None

                seen = {}

                async def child():
                    seen["context"] = get_current_task_context()

                await peer.spawn(child(), name="child-task")
                child_context = seen["context"]
                assert child_context.peer_id == "peer-test"
                assert child_context.parent_id == parent.trace_id
                assert child_context.name == "child-task"
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_terminal_traces_are_pruned_immediately_from_live_tree():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            async def ok():
                await asyncio.sleep(0)
                return 7

            assert await runtime.trace_awaitable(ok(), name="ok-task") == 7
            assert not [t for t in runtime.trace_snapshot() if t["name"] == "ok-task"]
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_subscriber_sees_complete_then_auto_prune_delete():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            sub = runtime.subscribe_traces()

            async def ok():
                return "done"

            assert await runtime.trace_awaitable(ok(), name="ordered-task") == "done"
            batch = await asyncio.wait_for(sub.get(), timeout=1)
            events = [e["event"] for e in batch["data"]["events"]]
            assert events == ["trace:init", "trace:update", "trace:complete", "trace:delete"]
            sub.close()
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_running_trace_heartbeat_snapshot_includes_transitions():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        context = runtime.create_task_context(name="heartbeat", peer_id="peer-heartbeat")
        runtime.start_task_context(context)
        traces = runtime.running_trace_heartbeat_snapshot(peer_id="peer-heartbeat")
        assert len(traces) == 1
        assert traces[0]["trace_id"] == context.trace_id
        assert traces[0]["status"] == "running"
        assert "transitions" in traces[0]
    finally:
        runtime.shutdown()


def test_completed_parent_is_pruned_and_children_are_promoted():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        root = runtime.create_task_context(name="root", kind="task", peer_id="peer-a")
        runtime.start_task_context(root)
        child = runtime.create_task_context(name="child", kind="task", peer_id="peer-a", parent=root)
        runtime.start_task_context(child)

        runtime.complete_task_context(root)
        live = {t["trace_id"]: t for t in runtime.trace_snapshot(peer_id="peer-a")}
        assert root.trace_id not in live
        assert live[child.trace_id]["parent_id"] is None
    finally:
        runtime.shutdown()


def test_delete_running_cancellable_trace_emits_success_and_removes_subtree():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            sub = runtime.subscribe_traces(peer_id="peer-delete")
            task = runtime.spawn_task(asyncio.sleep(10), name="sleep", peer_id="peer-delete")
            await asyncio.sleep(0.02)
            trace = next(t for t in runtime.trace_snapshot(peer_id="peer-delete") if t["name"] == "sleep")

            assert runtime.delete_trace(trace["trace_id"])
            assert not runtime.trace_snapshot(peer_id="peer-delete")

            messages = []
            for _ in range(6):
                messages.append(await asyncio.wait_for(sub.get(), timeout=1))
                results = [e for e in trace_batch_events(messages, "trace:delete_result")]
                if results:
                    break
            else:
                results = []
            assert results
            assert results[-1]["data"]["success"] is True
            sub.close()
            task.cancel()
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_delete_fails_for_running_non_cancelable_thread_trace():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        sub_events = []

        async def scenario():
            sub = runtime.subscribe_traces(peer_id="peer-thread")
            ctx = runtime.create_task_context(name="thread-loop", kind="thread", peer_id="peer-thread")
            runtime.start_task_context(ctx)
            assert runtime.delete_trace(ctx.trace_id) is False
            sub_events.append(await asyncio.wait_for(sub.get(), timeout=1))
            sub.close()

        asyncio.run(scenario())
        still_live = [t for t in runtime.trace_snapshot(peer_id="peer-thread") if t["trace_id"]]
        assert still_live
        results = trace_batch_events(sub_events, "trace:delete_result")
        assert results
        payload = results[-1]["data"]
        assert payload["success"] is False
        assert payload["reason"] == "non_cancelable_path"
        assert payload["failed_trace_ids"]
    finally:
        runtime.shutdown()


def test_delete_allows_running_trace_group_nodes():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        ctx = runtime.create_task_context(
            name="group-node",
            kind="thread",
            peer_id="peer-group",
            metadata={"trace_group": True},
        )
        runtime.start_task_context(ctx)
        assert runtime.delete_trace(ctx.trace_id) is True
        assert not runtime.trace_snapshot(peer_id="peer-group")
    finally:
        runtime.shutdown()


def test_trace_subscription_is_peer_scoped():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        sub_a = runtime.subscribe_traces(peer_id="peer-a")
        sub_b = runtime.subscribe_traces(peer_id="peer-b")

        try:
            runtime.create_task_context(name="a-task", peer_id="peer-a", kind="task")
            runtime.create_task_context(name="b-task", peer_id="peer-b", kind="task")
            batch_a = await asyncio.wait_for(sub_a.get(), timeout=1)
            batch_b = await asyncio.wait_for(sub_b.get(), timeout=1)
            names_a = [
                event["data"]["trace"]["name"]
                for event in batch_a["data"]["events"]
                if event["event"] == "trace:init"
            ]
            names_b = [
                event["data"]["trace"]["name"]
                for event in batch_b["data"]["events"]
                if event["event"] == "trace:init"
            ]
            assert names_a == ["a-task"]
            assert names_b == ["b-task"]
        finally:
            sub_a.close()
            sub_b.close()
            await runtime.aclose()

    asyncio.run(scenario())
