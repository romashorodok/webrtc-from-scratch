import asyncio
import threading
from types import SimpleNamespace

import pytest

from webrtc.runtime_services import (
    Borrowed,
    ExecutionContext,
    MissingExecutionScope,
    Owned,
    ScopeNotActive,
    ScopeShutdownTimeout,
    ScopeState,
    SerializedWorkerLane,
    SyncOffloader,
    TaskScheduler,
    current_execution_context,
    current_execution_scope,
    require_execution_scope,
    use_execution_scope,
)


def scope(state=ScopeState.ACTIVE):
    return SimpleNamespace(state=state)


def test_scope_activation_is_nested_and_resets_tokens():
    outer = scope()
    inner = scope()
    assert current_execution_scope() is None
    with use_execution_scope(outer):
        assert require_execution_scope() is outer
        with use_execution_scope(inner):
            assert require_execution_scope() is inner
        assert require_execution_scope() is outer
    assert current_execution_scope() is None


def test_scope_requirements_and_resource_declarations_are_generic():
    with pytest.raises(MissingExecutionScope):
        require_execution_scope()
    closing = scope(ScopeState.CLOSING)
    with use_execution_scope(closing):
        assert current_execution_scope() is closing
        with pytest.raises(ScopeNotActive):
            require_execution_scope()
    resource = object()
    assert Owned(resource).resource is resource
    assert Borrowed(resource).resource is resource


def test_concurrent_scope_activation_is_isolated():
    async def scenario():
        first = scope()
        second = scope()
        gate = asyncio.Event()

        async def inspect(selected):
            with use_execution_scope(selected):
                await gate.wait()
                await asyncio.sleep(0)
                return current_execution_scope()

        tasks = [asyncio.create_task(inspect(first)), asyncio.create_task(inspect(second))]
        gate.set()
        assert await asyncio.gather(*tasks) == [first, second]
        assert current_execution_scope() is None

    asyncio.run(scenario())


def test_scheduler_propagates_context_and_preserves_native_result_and_failure():
    async def scenario():
        failures = []
        scheduler = TaskScheduler(failure_observers=[failures.append])
        observed = {}

        async def child():
            observed["context"] = current_execution_context()
            return 42

        async def parent():
            child_task = scheduler.spawn_factory(child, name="child")
            return await child_task

        result = await scheduler.run_factory(
            parent, name="parent", trace_id="trace", scope_id="scope"
        )
        assert result == 42
        context = observed["context"]
        assert context.trace_id == "trace"
        assert context.scope_id == "scope"
        assert context.parent_task_id is not None

        error = ValueError("original")

        async def fail():
            raise error

        task = scheduler.spawn_factory(fail, name="failure")
        with pytest.raises(ValueError) as caught:
            await task
        assert caught.value is error
        assert task.exception() is error
        assert failures[-1].exception is error

    asyncio.run(scenario())


def test_factory_rejection_does_not_invoke_or_create_a_coroutine():
    async def scenario():
        scheduler = TaskScheduler()
        scheduler.closed = True
        calls = 0

        def factory():
            nonlocal calls
            calls += 1

            async def work():
                return None

            return work()

        with pytest.raises(ScopeNotActive):
            scheduler.spawn_factory(factory)
        assert calls == 0

    asyncio.run(scenario())


def test_task_cancelled_before_factory_start_is_removed_without_invoking_factory():
    async def scenario():
        scheduler = TaskScheduler()
        calls = 0

        def factory():
            nonlocal calls
            calls += 1

            async def work():
                return None

            return work()

        task = scheduler.spawn_factory(factory)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        assert calls == 0
        assert scheduler.registry.task_ids() == ()

    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", ["completed", "failed", "cancelled"])
def test_parent_terminal_state_reconciles_all_descendants(outcome):
    async def scenario():
        scheduler = TaskScheduler()
        child_started = asyncio.Event()
        child_finished = asyncio.Event()
        descendant_started = asyncio.Event()
        descendant_finished = asyncio.Event()

        async def descendant():
            descendant_started.set()
            try:
                if outcome == "completed":
                    await asyncio.sleep(0.02)
                else:
                    await asyncio.Event().wait()
            finally:
                descendant_finished.set()

        async def child():
            scheduler.spawn_factory(descendant, name="descendant")
            await descendant_started.wait()
            child_started.set()
            try:
                if outcome == "completed":
                    await asyncio.sleep(0.01)
                else:
                    await asyncio.Event().wait()
            finally:
                child_finished.set()

        async def parent():
            scheduler.spawn_factory(child, name="child")
            await child_started.wait()
            if outcome == "failed":
                raise LookupError("parent")
            if outcome == "cancelled":
                await asyncio.Event().wait()
            return "done"

        parent_task = scheduler.spawn_factory(parent, name="parent")
        await child_started.wait()
        if outcome == "cancelled":
            parent_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await parent_task
        elif outcome == "failed":
            with pytest.raises(LookupError):
                await parent_task
        else:
            assert await parent_task == "done"
        assert child_finished.is_set()
        assert descendant_finished.is_set()
        assert scheduler.registry.task_ids() == ()

    asyncio.run(scenario())


def test_repeated_cancel_cannot_publish_parent_before_worker_barrier_finishes():
    async def scenario():
        scheduler = TaskScheduler()
        started = asyncio.Event()
        barrier = asyncio.get_running_loop().create_future()
        parent_id = None

        async def parent():
            nonlocal parent_id
            context = current_execution_context()
            assert context is not None
            parent_id = context.task_id
            scheduler.registry.add_barrier(context.task_id, barrier)
            started.set()
            await asyncio.Event().wait()

        parent_task = scheduler.spawn_factory(parent, name="barrier-parent")
        await started.wait()
        parent_task.cancel()
        await asyncio.sleep(0)
        parent_task.cancel()
        await asyncio.sleep(0)
        parent_task.cancel()
        await asyncio.sleep(0)

        assert not parent_task.done()
        assert parent_id is not None
        assert scheduler.registry.get(parent_id) is not None

        barrier.set_result(None)
        with pytest.raises(asyncio.CancelledError):
            await parent_task
        assert scheduler.registry.get(parent_id) is None

    asyncio.run(scenario())


def test_serialized_lane_keeps_dispatch_context_and_cancels_queued_work():
    async def scenario():
        offloader = SyncOffloader(max_workers=2)
        lane = SerializedWorkerLane(offloader)
        release = threading.Event()
        first_started = threading.Event()
        second_started = threading.Event()

        def first():
            first_started.set()
            release.wait(2)
            return current_execution_context()

        def second():
            second_started.set()

        context = ExecutionContext("trace", "task", scope_id="scope")
        from webrtc.runtime_services import reset_execution_context, set_execution_context

        token = set_execution_context(context)
        try:
            first_waiter = asyncio.create_task(lane.run(first))
            await asyncio.to_thread(first_started.wait, 1)
            queued = asyncio.create_task(lane.run(second))
            await asyncio.sleep(0)
            queued.cancel()
            with pytest.raises(asyncio.CancelledError):
                await queued
            assert not second_started.is_set()
            release.set()
            assert await first_waiter == context
        finally:
            reset_execution_context(token)
            await lane.aclose(1)
            offloader.shutdown()

    asyncio.run(scenario())


def test_cancelled_offloader_waiter_retains_capacity_until_worker_finishes():
    async def scenario():
        offloader = SyncOffloader(capacity=1, max_workers=2)
        release = threading.Event()
        first_started = threading.Event()
        second_started = threading.Event()

        def first():
            first_started.set()
            release.wait(2)

        def second():
            second_started.set()

        first_waiter = asyncio.create_task(offloader.run(first))
        await asyncio.to_thread(first_started.wait, 1)
        first_waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_waiter
        second_waiter = asyncio.create_task(offloader.run(second))
        await asyncio.sleep(0.01)
        assert not second_started.is_set()
        release.set()
        await second_waiter
        assert second_started.is_set()
        offloader.shutdown()

    asyncio.run(scenario())


def test_cancelled_dispatched_call_holds_lane_and_shutdown_timeout_is_truthful():
    async def scenario():
        offloader = SyncOffloader(max_workers=2)
        lane = SerializedWorkerLane(offloader)
        release = threading.Event()
        first_started = threading.Event()
        second_started = threading.Event()

        def first():
            first_started.set()
            release.wait(2)

        def second():
            second_started.set()

        first_waiter = asyncio.create_task(lane.run(first))
        await asyncio.to_thread(first_started.wait, 1)
        first_waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_waiter
        second_waiter = asyncio.create_task(lane.run(second))
        await asyncio.sleep(0.01)
        assert not second_started.is_set()

        with pytest.raises(ScopeShutdownTimeout):
            await lane.aclose(0.01)
        assert lane.state is ScopeState.CLOSING
        assert offloader.dispatched_count == 1
        second_waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second_waiter

        release.set()
        for _ in range(100):
            if offloader.dispatched_count == 0:
                break
            await asyncio.sleep(0.01)
        await lane.aclose(1)
        assert lane.state is ScopeState.CLOSED
        offloader.shutdown()

    asyncio.run(scenario())
