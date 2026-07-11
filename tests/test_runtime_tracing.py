import asyncio

import pytest

from webrtc.peer_context import PeerContext
from webrtc.runtime import WebRTCRuntimeResources, get_current_task_context
from webrtc.tracing import perf_mark


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
                assert not hasattr(child_context, "peer_id")
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
            assert not [t for t in runtime.trace_live_tree() if t["name"] == "ok-task"]
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_subscriber_sees_complete_then_auto_prune_delete():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            sub = runtime.trace_subscribe()

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


def test_runtime_aggregates_performance_events_onto_owning_trace():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, trace_subscriber_batch_interval=0.01)
        try:
            context = runtime.create_task_context(
                name="rtp-receive-loop", metadata={"peer_id": "peer-performance"}
            )
            runtime.start_task_context(context)
            runtime._tracing.performance_recorder.mark(
                "udp", "datagram", "rx",
                metadata={
                    "trace_id": context.trace_id,
                    "peer_id": "peer-performance",
                    "packet_kind": "rtp",
                    "size_bytes": 128,
                },
            )
            traces = runtime.trace_live_tree()
            metric_trace = next(trace for trace in traces if trace["trace_id"] == context.trace_id)
            metric = metric_trace["metadata"]["performance_metrics"]["udp.datagram.rx"]
            assert metric["count"] == 1
            assert metric["duration_count"] == 0
            assert metric["metadata"] == {"packet_kind": "rtp", "size_bytes": 128}
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_live_running_includes_transitions():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        context = runtime.create_task_context(name="heartbeat")
        runtime.start_task_context(context)
        traces = runtime.trace_live_running(include_duration=True)
        assert len(traces) == 1
        assert traces[0]["trace_id"] == context.trace_id
        assert traces[0]["status"] == "running"
        assert "transitions" in traces[0]
    finally:
        runtime.shutdown()


def test_running_trace_signature_avoids_snapshot_payloads():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        context = runtime.create_task_context(name="signature")
        runtime.start_task_context(context)

        assert runtime.trace_running_signature() == ((context.trace_id, None, "running"),)
    finally:
        runtime.shutdown()


def test_completed_parent_is_pruned_and_children_are_promoted():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        root = runtime.create_task_context(name="root", kind="task")
        runtime.start_task_context(root)
        child = runtime.create_task_context(name="child", kind="task", parent=root)
        runtime.start_task_context(child)

        runtime.complete_task_context(root)
        live = {t["trace_id"]: t for t in runtime.trace_live_tree()}
        assert root.trace_id not in live
        assert live[child.trace_id]["parent_id"] is None
    finally:
        runtime.shutdown()


def test_delete_running_cancellable_trace_emits_success_and_removes_subtree():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            sub = runtime.trace_subscribe()
            task = runtime.spawn_task(asyncio.sleep(10), name="sleep")
            await asyncio.sleep(0.02)
            trace = next(t for t in runtime.trace_live_tree() if t["name"] == "sleep")

            assert runtime.delete_trace(trace["trace_id"])
            assert not runtime.trace_live_tree()

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
            sub = runtime.trace_subscribe()
            ctx = runtime.create_task_context(name="thread-loop", kind="thread")
            runtime.start_task_context(ctx)
            assert runtime.delete_trace(ctx.trace_id) is False
            sub_events.append(await asyncio.wait_for(sub.get(), timeout=1))
            sub.close()

        asyncio.run(scenario())
        still_live = [t for t in runtime.trace_live_tree() if t["trace_id"]]
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
            metadata={"trace_group": True},
        )
        runtime.start_task_context(ctx)
        assert runtime.delete_trace(ctx.trace_id) is True
        assert not runtime.trace_live_tree()
    finally:
        runtime.shutdown()


def test_trace_subscription_is_runtime_stream_wide():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        sub_a = runtime.trace_subscribe()
        sub_b = runtime.trace_subscribe()

        try:
            runtime.create_task_context(name="a-task", kind="task")
            runtime.create_task_context(name="b-task", kind="task")
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
            assert names_a == ["a-task", "b-task"]
            assert names_b == ["a-task", "b-task"]
        finally:
            sub_a.close()
            sub_b.close()
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_subscriber_coalesces_pending_updates_per_trace():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, trace_subscriber_batch_interval=0.05)
        sub = runtime.trace_subscribe()
        try:
            context = runtime.create_task_context(name="coalesced", kind="task")
            for index in range(10):
                context.metadata["index"] = index
                runtime.start_task_context(context)

            batch = await asyncio.wait_for(sub.get(), timeout=1)
            updates = [
                event
                for event in batch["data"]["events"]
                if event["event"] == "trace:update" and event["data"]["trace"]["trace_id"] == context.trace_id
            ]
            assert len(updates) == 1
            assert updates[0]["data"]["trace"]["metadata"]["index"] == 9
        finally:
            sub.close()
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_subscriber_coalesces_updates_across_mixed_events_per_trace():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, trace_subscriber_batch_interval=0.05)
        sub = runtime.trace_subscribe()
        try:
            first = runtime.create_task_context(name="first", kind="task")
            runtime.start_task_context(first)

            other = runtime.create_task_context(name="other", kind="task")

            first.metadata["index"] = 1
            runtime.start_task_context(first)

            batch = await asyncio.wait_for(sub.get(), timeout=1)
            updates = [
                event
                for event in batch["data"]["events"]
                if event["event"] == "trace:update" and event["data"]["trace"]["trace_id"] == first.trace_id
            ]
            inits = [
                event
                for event in batch["data"]["events"]
                if event["event"] == "trace:init" and event["data"]["trace"]["trace_id"] == other.trace_id
            ]
            assert len(updates) == 1
            assert updates[0]["data"]["trace"]["metadata"]["index"] == 1
            assert len(inits) == 1
        finally:
            sub.close()
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_subscriber_filters_events_to_peer_id():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, trace_subscriber_batch_interval=0.01)
        sub = runtime.trace_subscribe(peer_id="peer-a")
        try:
            async with PeerContext(object(), runtime=runtime, peer_id="peer-a") as peer_a:
                runtime.create_task_context(
                    name="peer-a-task",
                    kind="task",
                    parent_id=peer_a.root_trace_id,
                    metadata={"peer_id": "peer-a"},
                )
                async with PeerContext(object(), runtime=runtime, peer_id="peer-b") as peer_b:
                    runtime.create_task_context(
                        name="peer-b-task",
                        kind="task",
                        parent_id=peer_b.root_trace_id,
                        metadata={"peer_id": "peer-b"},
                    )
                    batch = await asyncio.wait_for(sub.get(), timeout=1)

            events = batch["data"]["events"]
            assert events
            for event in events:
                data = event.get("data", {})
                if event["event"] in {"trace:init", "trace:update", "trace:complete"}:
                    traces = data.get("traces") if isinstance(data, dict) else None
                    trace = data.get("trace") if isinstance(data, dict) else None
                    payloads = list(traces or []) + ([trace] if isinstance(trace, dict) else [])
                    assert payloads
                    for payload in payloads:
                        assert payload["metadata"].get("peer_id") == "peer-a"
                elif event["event"] in {"trace:delete", "trace:delete_result"}:
                    assert data.get("peer_id") == "peer-a"
        finally:
            sub.close()
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_groups_are_recreated_after_close():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            first = runtime.get_or_create_trace_group(name="group", kind="thread", group_key="shared")
            runtime.record_trace_group_call(first, duration_ms=12.0, force=True)
            runtime.close_trace_groups()

            second = runtime.get_or_create_trace_group(name="group", kind="thread", group_key="shared")

            assert second.trace_id != first.trace_id
            assert second.metadata["call_count"] == 0
            assert runtime.trace_live_tree()
        finally:
            runtime.shutdown()

    asyncio.run(scenario())


def test_trace_group_updates_emit_after_throttle_window_without_new_calls():
    async def scenario():
        runtime = WebRTCRuntimeResources(
            max_workers=1,
            trace_group_update_interval=0.05,
            trace_subscriber_batch_interval=0.01,
        )
        sub = runtime.trace_subscribe()
        try:
            group = runtime.get_or_create_trace_group(name="group", kind="thread", group_key="shared")
            runtime.record_trace_group_call(group, duration_ms=10.0, force=True)
            await asyncio.wait_for(sub.get(), timeout=1)

            runtime.record_trace_group_call(group, duration_ms=20.0)

            batch = await asyncio.wait_for(sub.get(), timeout=1)
            updates = [
                event
                for event in batch["data"]["events"]
                if event["event"] == "trace:update" and event["data"]["trace"]["trace_id"] == group.trace_id
            ]
            assert updates
            payload = updates[-1]["data"]["trace"]
            assert payload["metadata"]["call_count"] == 2
            assert payload["metadata"]["last_duration_ms"] == 20.0
        finally:
            sub.close()
            await runtime.aclose()

    asyncio.run(scenario())
