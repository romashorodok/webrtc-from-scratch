import asyncio
import sys
from pathlib import Path

import pytest

from webrtc.peer_context import PeerContext
from webrtc.runtime import (
    WebRTCRuntimeResources,
    get_current_task_context,
)


def transition_events(trace):
    return [transition["event"] for transition in trace["transitions"]]


def assert_transition_shape(trace):
    assert trace["transitions"]
    for transition in trace["transitions"]:
        assert set(transition) >= {"at", "event", "status", "duration_ms"}


def test_peer_context_spawn_inherits_parent_task_context():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            async with PeerContext(object(), runtime=runtime, peer_id="peer-test") as peer:
                parent = get_current_task_context()
                assert parent is not None

                seen = {}

                async def child():
                    context = get_current_task_context()
                    seen["context"] = context

                await peer.spawn(child(), name="child-task")

                child_context = seen["context"]
                assert child_context.peer_id == "peer-test"
                assert child_context.parent_id == parent.trace_id
                assert child_context.name == "child-task"
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_awaitable_records_success_failure_and_cancellation():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            async def ok():
                await asyncio.sleep(0)
                return 7

            assert await runtime.trace_awaitable(ok(), name="ok-task") == 7
            ok_trace = next(trace for trace in runtime.trace_snapshot() if trace["name"] == "ok-task")
            assert ok_trace["status"] == "completed"
            assert ok_trace["started_at"] is not None
            assert ok_trace["ended_at"] is not None
            assert ok_trace["duration_ms"] is not None

            async def fail():
                raise ValueError("boom")

            with pytest.raises(ValueError):
                await runtime.trace_awaitable(fail(), name="fail-task")
            fail_trace = next(trace for trace in runtime.trace_snapshot() if trace["name"] == "fail-task")
            assert fail_trace["status"] == "failed"
            assert "ValueError: boom" == fail_trace["error"]

            async def never():
                await asyncio.Event().wait()

            task = runtime.spawn_task(never(), name="cancel-task")
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            cancel_trace = next(trace for trace in runtime.trace_snapshot() if trace["name"] == "cancel-task")
            assert cancel_trace["status"] == "cancelled"
            assert cancel_trace["ended_at"] is not None
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_offload_sync_inherits_task_context_in_worker_thread():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            async with PeerContext(object(), runtime=runtime, peer_id="peer-offload") as peer:
                parent = get_current_task_context()
                assert parent is not None

                def inspect_context():
                    context = get_current_task_context()
                    assert context is not None
                    return context.parent_id, context.peer_id, context.kind, context.name

                parent_id, peer_id, kind, name = await peer.offload_sync(
                    inspect_context,
                    name="inspect-context",
                )

                assert parent_id == parent.trace_id
                assert peer_id == "peer-offload"
                assert kind == "thread"
                assert name == "inspect-context"
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_subscriber_receives_ordered_lifecycle_events():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            subscription = runtime.subscribe_traces()

            async def ok():
                return "done"

            assert await runtime.trace_awaitable(ok(), name="ordered-task") == "done"

            events = [await asyncio.wait_for(subscription.get(), timeout=1) for _ in range(3)]
            assert [event["event"] for event in events] == [
                "trace:init",
                "trace:update",
                "trace:complete",
            ]
            assert [event["data"]["sequence"] for event in events] == sorted(
                event["data"]["sequence"] for event in events
            )
            assert all(event["data"]["trace"]["name"] == "ordered-task" for event in events)
            subscription.close()
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_completed_trace_records_ordered_lifecycle_transitions():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            async def ok():
                await asyncio.sleep(0)
                return "done"

            assert await runtime.trace_awaitable(ok(), name="transition-ok") == "done"
            trace = next(
                trace
                for trace in runtime.trace_snapshot()
                if trace["name"] == "transition-ok"
            )

            assert transition_events(trace) == ["created", "started", "completed"]
            assert [transition["at"] for transition in trace["transitions"]] == sorted(
                transition["at"] for transition in trace["transitions"]
            )
            assert trace["transitions"][-1]["status"] == "completed"
            assert trace["transitions"][-1]["duration_ms"] is not None
            assert_transition_shape(trace)
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_snapshot_reports_live_running_duration_without_completing():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            context = runtime.create_task_context(
                name="live-root",
                kind="peer",
                peer_id="peer-live",
            )
            runtime.start_task_context(context)

            first = next(
                trace
                for trace in runtime.trace_snapshot(peer_id="peer-live")
                if trace["trace_id"] == context.trace_id
            )
            await asyncio.sleep(0.02)
            second = next(
                trace
                for trace in runtime.trace_snapshot(peer_id="peer-live")
                if trace["trace_id"] == context.trace_id
            )

            assert first["status"] == "running"
            assert first["duration_ms"] is not None
            assert second["duration_ms"] > first["duration_ms"]
            assert second["ended_at"] is None
            assert context.ended_at is None
            assert context.duration_ms is None
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_running_trace_snapshot_filters_peer_and_terminal_statuses():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        created = runtime.create_task_context(name="created", peer_id="peer-a")
        running = runtime.create_task_context(name="running", peer_id="peer-a")
        runtime.start_task_context(running)
        other_peer = runtime.create_task_context(name="other-peer", peer_id="peer-b")
        runtime.start_task_context(other_peer)

        completed = runtime.create_task_context(name="completed", peer_id="peer-a")
        runtime.start_task_context(completed)
        runtime.complete_task_context(completed)
        failed = runtime.create_task_context(name="failed", peer_id="peer-a")
        runtime.complete_task_context(failed, status="failed", error="boom")
        cancelled = runtime.create_task_context(name="cancelled", peer_id="peer-a")
        runtime.complete_task_context(cancelled, status="cancelled")

        traces = runtime.running_trace_snapshot(peer_id="peer-a")

        assert {trace["trace_id"] for trace in traces} == {
            created.trace_id,
            running.trace_id,
        }
        assert {trace["status"] for trace in traces} == {"created", "running"}
        assert all(trace["peer_id"] == "peer-a" for trace in traces)
        assert all(trace["duration_ms"] is not None for trace in traces)
    finally:
        runtime.shutdown()


def test_running_trace_snapshot_does_not_record_heartbeat_transitions():
    runtime = WebRTCRuntimeResources(max_workers=1)
    try:
        context = runtime.create_task_context(name="heartbeat", peer_id="peer-heartbeat")
        runtime.start_task_context(context)
        before = list(context.transitions)

        traces = runtime.running_trace_snapshot(peer_id="peer-heartbeat")

        assert len(traces) == 1
        assert traces[0]["duration_ms"] is not None
        assert context.transitions == before
        assert context.ended_at is None
        assert context.duration_ms is None
    finally:
        runtime.shutdown()


def test_delete_running_trace_archives_live_duration():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1)
        try:
            context = runtime.create_task_context(
                name="delete-running",
                kind="peer",
                peer_id="peer-delete-running",
            )
            runtime.start_task_context(context)
            await asyncio.sleep(0.02)

            before_delete = runtime.running_trace_snapshot(peer_id="peer-delete-running")[0]
            assert runtime.delete_trace(context.trace_id) is True

            summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-delete-running")
                if summary["deleted_trace_id"] == context.trace_id
            )
            deleted_trace = summary["deleted_trace"]
            after_delete_running = runtime.running_trace_snapshot(peer_id="peer-delete-running")

            assert deleted_trace["duration_ms"] is not None
            assert deleted_trace["duration_ms"] >= before_delete["duration_ms"]
            assert summary["avg_duration_ms"] >= before_delete["duration_ms"]
            assert summary["archived_traces"][0]["duration_ms"] == deleted_trace["duration_ms"]
            assert not runtime.trace_snapshot(peer_id="peer-delete-running")
            assert [trace["trace_id"] for trace in after_delete_running] == [context.trace_id]
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_trace_pump_sends_heartbeat_updates_for_running_traces():
    async def scenario():
        examples_root = Path(__file__).resolve().parents[1] / "examples"
        if str(examples_root) not in sys.path:
            sys.path.insert(0, str(examples_root))
        from examples.trace_pump import pump_trace_updates

        runtime = WebRTCRuntimeResources(max_workers=1)
        messages = []

        async def send_json(message):
            messages.append(message)

        try:
            context = runtime.create_task_context(name="pump-running", peer_id="peer-pump")
            runtime.start_task_context(context)
            task = asyncio.create_task(
                pump_trace_updates(
                    runtime,
                    "peer-pump",
                    send_json,
                    heartbeat_interval=0.01,
                )
            )
            try:
                for _ in range(50):
                    heartbeat = next(
                        (
                            message
                            for message in messages
                            if message["event"] == "trace:update"
                            and message["data"]["trace"]["trace_id"] == context.trace_id
                            and message["data"]["trace"]["duration_ms"] is not None
                        ),
                        None,
                    )
                    if heartbeat is not None:
                        break
                    await asyncio.sleep(0.01)
                else:
                    raise AssertionError("trace heartbeat update was not sent")

                assert messages[0]["event"] == "trace:init"
                assert heartbeat["data"]["peer_id"] == "peer-pump"
                assert heartbeat["data"]["trace"]["status"] == "running"
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_failed_and_cancelled_traces_record_terminal_transitions():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            async def fail():
                raise ValueError("boom")

            with pytest.raises(ValueError):
                await runtime.trace_awaitable(fail(), name="transition-fail")

            failed_trace = next(
                trace
                for trace in runtime.trace_snapshot()
                if trace["name"] == "transition-fail"
            )
            assert transition_events(failed_trace)[-1] == "failed"
            assert failed_trace["transitions"][-1]["status"] == "failed"
            assert failed_trace["transitions"][-1]["error"] == "ValueError: boom"
            assert_transition_shape(failed_trace)

            async def never():
                await asyncio.Event().wait()

            task = runtime.spawn_task(never(), name="transition-cancel")
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            cancelled_trace = next(
                trace
                for trace in runtime.trace_snapshot()
                if trace["name"] == "transition-cancel"
            )
            assert transition_events(cancelled_trace)[-1] == "cancelled"
            assert cancelled_trace["transitions"][-1]["status"] == "cancelled"
            assert_transition_shape(cancelled_trace)
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_aggregate_offload_uses_one_group_and_deletes_success_on_close():
    async def scenario():
        runtime = WebRTCRuntimeResources(
            max_workers=1,
            trace_group_update_interval=0,
            success_trace_retention_seconds=0,
        )
        try:
            async with PeerContext(object(), runtime=runtime, peer_id="peer-group") as peer:
                for value in range(3):
                    result = await peer.offload_sync(
                        lambda item: item + 1,
                        value,
                        name="packet:encode",
                        aggregate=True,
                        group_name="packet:encode-group",
                        group_key="packet:encode",
                    )
                    assert result == value + 1

                groups = [
                    trace
                    for trace in runtime.trace_snapshot(peer_id="peer-group")
                    if trace["metadata"].get("trace_group")
                ]
                assert len(groups) == 1
                assert groups[0]["metadata"]["call_count"] == 3
                assert groups[0]["metadata"]["success_count"] == 3
                assert "grouped-call-updated" in transition_events(groups[0])

            assert not [
                trace
                for trace in runtime.trace_snapshot(peer_id="peer-group")
                if trace["metadata"].get("trace_group")
            ]
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_deleted_success_group_keeps_average_summary_and_delta():
    async def scenario():
        runtime = WebRTCRuntimeResources(
            max_workers=1,
            trace_group_update_interval=0,
            success_trace_retention_seconds=3600,
        )
        try:
            async with PeerContext(object(), runtime=runtime, peer_id="peer-summary") as peer:
                await peer.offload_sync(
                    lambda: "ok",
                    name="packet:encrypt",
                    aggregate=True,
                    group_name="packet:encrypt-group",
                    group_key="packet:encrypt",
                )

            kept = [
                trace
                for trace in runtime.trace_snapshot(peer_id="peer-summary")
                if trace["metadata"].get("trace_group")
            ]
            assert len(kept) == 1
            runtime.delete_traces(peer_id="peer-summary", statuses={"completed"})
            first_summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-summary")
                if summary["group_key"] == "packet:encrypt"
            )
            first_summary_id = first_summary["summary_id"]
            assert first_summary["avg_duration_ms"] >= 0
            assert first_summary["delta_avg_duration_ms"] is None

            async with PeerContext(object(), runtime=runtime, peer_id="peer-summary") as peer:
                await peer.offload_sync(
                    lambda: "ok",
                    name="packet:encrypt",
                    aggregate=True,
                    group_name="packet:encrypt-group",
                    group_key="packet:encrypt",
                )

            runtime.delete_traces(peer_id="peer-summary", statuses={"completed"})
            packet_summaries = [
                summary
                for summary in runtime.trace_summaries(peer_id="peer-summary")
                if summary["group_key"] == "packet:encrypt"
            ]
            assert len(packet_summaries) == 2
            old_aggregate_summary_id = (
                "peer-summary|packet:encrypt|packet:encrypt-group|thread"
            )
            assert all(
                summary["summary_id"] != old_aggregate_summary_id
                for summary in packet_summaries
            )
            assert any(summary["summary_id"] == first_summary_id for summary in packet_summaries)
            second_summary = packet_summaries[0]
            assert second_summary["summary_id"] != first_summary_id
            assert second_summary["previous_avg_duration_ms"] == first_summary["avg_duration_ms"]
            assert second_summary["delta_avg_duration_ms"] is not None
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_double_delete_keeps_one_deleted_archive():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            trace = runtime.create_task_context(
                name="double-delete",
                kind="task",
                peer_id="peer-double-delete",
            )
            runtime.start_task_context(trace)
            runtime.complete_task_context(trace)

            assert runtime.delete_trace(trace.trace_id)
            assert runtime.delete_trace(trace.trace_id)

            summaries = runtime.trace_summaries(peer_id="peer-double-delete")
            assert len(summaries) == 1
            assert summaries[0]["summary_id"] == trace.trace_id
            assert summaries[0]["deleted_trace_id"] == trace.trace_id
            assert [
                archived["trace_id"] for archived in summaries[0]["archived_traces"]
            ] == [trace.trace_id]
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_deleted_archive_preserves_lifecycle_and_records_delete_transition():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            trace = runtime.create_task_context(
                name="deleted-transition",
                kind="task",
                peer_id="peer-delete-transition",
            )
            runtime.start_task_context(trace)
            runtime.complete_task_context(trace)

            assert runtime.delete_trace(trace.trace_id)

            summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-delete-transition")
                if summary["deleted_trace_id"] == trace.trace_id
            )
            archived = summary["archived_traces"][0]
            assert transition_events(archived) == [
                "created",
                "started",
                "completed",
                "deleted",
            ]
            assert archived["transitions"][-1]["status"] == "completed"
            assert_transition_shape(archived)
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_deleted_sibling_subtrees_keep_separate_archives():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            root = runtime.create_task_context(
                name="sibling-root",
                kind="peer",
                peer_id="peer-siblings",
            )
            runtime.start_task_context(root)
            first = runtime.create_task_context(
                name="sibling-child-a",
                kind="task",
                peer_id="peer-siblings",
                parent=root,
            )
            second = runtime.create_task_context(
                name="sibling-child-b",
                kind="task",
                peer_id="peer-siblings",
                parent=root,
            )
            runtime.start_task_context(first)
            runtime.start_task_context(second)
            runtime.complete_task_context(first)
            runtime.complete_task_context(second)

            assert runtime.delete_trace(first.trace_id)
            assert runtime.delete_trace(second.trace_id)

            live_ids = {trace["trace_id"] for trace in runtime.trace_snapshot(peer_id="peer-siblings")}
            assert live_ids == {root.trace_id}

            summaries = runtime.trace_summaries(peer_id="peer-siblings")
            assert {summary["deleted_trace_id"] for summary in summaries} == {
                first.trace_id,
                second.trace_id,
            }
            for summary in summaries:
                archived_by_id = {
                    trace["trace_id"]: trace for trace in summary["archived_traces"]
                }
                deleted_trace_id = summary["deleted_trace_id"]
                sibling_id = second.trace_id if deleted_trace_id == first.trace_id else first.trace_id
                assert root.trace_id in archived_by_id
                assert deleted_trace_id in archived_by_id
                assert sibling_id not in archived_by_id
                assert archived_by_id[root.trace_id]["metadata"]["deleted_target"] is False
                assert archived_by_id[deleted_trace_id]["parent_id"] == root.trace_id
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_deleted_summary_keeps_archived_parent_structure():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            root = runtime.create_task_context(
                name="archive-root",
                kind="peer",
                peer_id="peer-archive",
            )
            runtime.start_task_context(root)
            child = runtime.create_task_context(
                name="archive-child",
                kind="task",
                peer_id="peer-archive",
                parent=root,
            )
            runtime.start_task_context(child)
            grandchild = runtime.create_task_context(
                name="archive-grandchild",
                kind="task",
                peer_id="peer-archive",
                parent=child,
            )
            runtime.start_task_context(grandchild)
            runtime.complete_task_context(grandchild)
            runtime.complete_task_context(child)
            runtime.complete_task_context(root)

            assert runtime.delete_trace(root.trace_id)
            assert not runtime.trace_snapshot(peer_id="peer-archive")

            root_summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-archive")
                if summary["name"] == "archive-root"
            )
            archived_by_id = {
                trace["trace_id"]: trace for trace in root_summary["archived_traces"]
            }
            assert root.trace_id in archived_by_id
            assert child.trace_id in archived_by_id
            assert grandchild.trace_id in archived_by_id
            assert archived_by_id[child.trace_id]["parent_id"] == root.trace_id
            assert archived_by_id[grandchild.trace_id]["parent_id"] == child.trace_id
            assert archived_by_id[root.trace_id]["metadata"]["deleted_target"] is True
            assert archived_by_id[child.trace_id]["metadata"]["deleted_target"] is True
            assert archived_by_id[grandchild.trace_id]["metadata"]["deleted_target"] is True

            assert [
                summary["name"]
                for summary in runtime.trace_summaries(peer_id="peer-archive")
            ] == ["archive-root"]
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_deleted_root_with_mixed_state_children_restores_full_subtree():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            root = runtime.create_task_context(
                name="mixed-root",
                kind="peer",
                peer_id="peer-mixed",
            )
            runtime.start_task_context(root)
            completed = runtime.create_task_context(
                name="mixed-completed",
                kind="task",
                peer_id="peer-mixed",
                parent=root,
            )
            failed = runtime.create_task_context(
                name="mixed-failed",
                kind="task",
                peer_id="peer-mixed",
                parent=root,
            )
            running = runtime.create_task_context(
                name="mixed-running",
                kind="task",
                peer_id="peer-mixed",
                parent=root,
            )
            runtime.start_task_context(completed)
            runtime.start_task_context(failed)
            runtime.start_task_context(running)
            runtime.complete_task_context(completed)
            runtime.complete_task_context(failed, status="failed", error="child failed")

            assert runtime.delete_trace(root.trace_id)
            assert not runtime.trace_snapshot(peer_id="peer-mixed")

            summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-mixed")
                if summary["deleted_trace_id"] == root.trace_id
            )
            archived_by_id = {
                trace["trace_id"]: trace for trace in summary["archived_traces"]
            }
            assert set(archived_by_id) == {
                root.trace_id,
                completed.trace_id,
                failed.trace_id,
                running.trace_id,
            }
            assert archived_by_id[completed.trace_id]["status"] == "completed"
            assert archived_by_id[failed.trace_id]["status"] == "failed"
            assert archived_by_id[running.trace_id]["status"] == "running"
            assert archived_by_id[completed.trace_id]["parent_id"] == root.trace_id
            assert archived_by_id[failed.trace_id]["parent_id"] == root.trace_id
            assert archived_by_id[running.trace_id]["parent_id"] == root.trace_id
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_deleted_running_root_is_archived_and_not_restored_on_completion():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            root = runtime.create_task_context(
                name="running-root",
                kind="task",
                peer_id="peer-running-delete",
            )
            runtime.start_task_context(root)

            assert runtime.delete_trace(root.trace_id)
            assert not runtime.trace_snapshot(peer_id="peer-running-delete")

            running_summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-running-delete")
                if summary["name"] == "running-root"
            )
            assert running_summary["status"] == "running"
            assert running_summary["archived_traces"][0]["trace_id"] == root.trace_id
            assert running_summary["archived_traces"][0]["parent_id"] is None

            runtime.complete_task_context(root, status="completed")
            assert not runtime.trace_snapshot(peer_id="peer-running-delete")

            completed_summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-running-delete")
                if summary["name"] == "running-root"
            )
            assert completed_summary["status"] == "completed"
            assert completed_summary["archived_traces"][0]["status"] == "completed"
            assert completed_summary["archived_traces"][0]["ended_at"] is not None
            assert transition_events(completed_summary["archived_traces"][0]) == [
                "created",
                "started",
                "deleted",
                "completed",
            ]
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_deleted_running_subtree_updates_archived_children_after_completion():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, success_trace_retention_seconds=3600)
        try:
            root = runtime.create_task_context(
                name="running-subtree-root",
                kind="task",
                peer_id="peer-running-subtree",
            )
            runtime.start_task_context(root)
            child = runtime.create_task_context(
                name="running-subtree-child",
                kind="task",
                peer_id="peer-running-subtree",
                parent=root,
            )
            runtime.start_task_context(child)

            assert runtime.delete_trace(root.trace_id)
            assert not runtime.trace_snapshot(peer_id="peer-running-subtree")

            runtime.complete_task_context(child, status="failed", error="late failure")
            runtime.complete_task_context(root, status="completed")
            assert not runtime.trace_snapshot(peer_id="peer-running-subtree")

            summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-running-subtree")
                if summary["deleted_trace_id"] == root.trace_id
            )
            archived_by_id = {
                trace["trace_id"]: trace for trace in summary["archived_traces"]
            }
            assert archived_by_id[root.trace_id]["status"] == "completed"
            assert archived_by_id[child.trace_id]["status"] == "failed"
            assert archived_by_id[child.trace_id]["error"] == "late failure"
            assert archived_by_id[child.trace_id]["parent_id"] == root.trace_id
        finally:
            await runtime.aclose()

    asyncio.run(scenario())


def test_failed_aggregate_group_persists_until_deleted():
    async def scenario():
        runtime = WebRTCRuntimeResources(max_workers=1, trace_group_update_interval=0)
        try:
            async with PeerContext(object(), runtime=runtime, peer_id="peer-fail") as peer:
                with pytest.raises(RuntimeError):
                    await peer.offload_sync(
                        lambda: (_ for _ in ()).throw(RuntimeError("packet failed")),
                        name="packet:send",
                        aggregate=True,
                        group_name="packet:send-group",
                        group_key="packet:send",
                    )

            failed = [
                trace
                for trace in runtime.trace_snapshot(peer_id="peer-fail")
                if trace["status"] == "failed"
            ]
            assert len(failed) == 1
            assert failed[0]["metadata"]["trace_group"] is True
            assert "packet failed" in failed[0]["error"]

            assert runtime.delete_trace(failed[0]["trace_id"])
            assert not [
                trace
                for trace in runtime.trace_snapshot(peer_id="peer-fail")
                if trace["status"] == "failed"
            ]
            failed_summary = next(
                summary
                for summary in runtime.trace_summaries(peer_id="peer-fail")
                if summary["group_key"] == "packet:send"
            )
            assert failed_summary["status"] == "failed"
            assert "packet failed" in failed_summary["error"]
            assert failed[0]["trace_id"] in {
                trace["trace_id"] for trace in failed_summary["archived_traces"]
            }
        finally:
            await runtime.aclose()

    asyncio.run(scenario())
