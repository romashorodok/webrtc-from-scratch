import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from webrtc import Runtime
from webrtc.performance import ObservedComponent, worker
from webrtc.runtime_services import (
    Borrowed,
    ExecutionScope,
    Owned,
    ScopeNotActive,
    ScopeShutdownTimeout,
    ScopeState,
    current_execution_context,
    current_execution_scope,
)


def test_runtime_activation_creates_root_and_parents_dynamic_children():
    async def scenario():
        runtime = Runtime(scope_id="peer-a", trace_subscriber_batch_interval=0.01)
        assert isinstance(runtime, ExecutionScope)
        assert runtime.state is ScopeState.NEW
        child_context = None
        release = asyncio.Event()

        async def child():
            nonlocal child_context
            child_context = current_execution_context()
            await release.wait()

        async with runtime:
            root = current_execution_context()
            assert current_execution_scope() is runtime
            assert root is runtime.root_context
            assert root.scope_id == "peer-a"
            task = runtime.start(child, name="application.child")
            await asyncio.sleep(0)
            assert child_context.parent_task_id == root.task_id
            assert child_context.trace_id == root.trace_id
            live = runtime.trace_live_tree()
            assert {node["name"] for node in live} == {"execution.root", "application.child"}
            root_node = next(node for node in live if node["name"] == "execution.root")
            assert root_node["metadata"]["cancelable"] is False
            release.set()
            await task

        assert current_execution_scope() is None
        assert current_execution_context() is None
        assert runtime.state is ScopeState.CLOSED
        assert runtime.trace_live_tree() == []

    asyncio.run(scenario())


def test_runtime_start_rejects_racing_close_without_invoking_factory():
    async def scenario():
        runtime = Runtime()
        entered = asyncio.Event()

        async def managed():
            entered.set()
            await asyncio.Event().wait()

        calls = 0

        def rejected_factory():
            nonlocal calls
            calls += 1
            return managed()

        async with runtime:
            task = runtime.start(managed, name="managed")
            await entered.wait()
            closing = asyncio.create_task(runtime.aclose())
            await asyncio.sleep(0)
            assert runtime.state in (ScopeState.CLOSING, ScopeState.CLOSED)
            with pytest.raises(ScopeNotActive):
                runtime.start(rejected_factory, name="rejected")
            assert calls == 0
            await closing
            assert task.cancelled()

    asyncio.run(scenario())


def test_shared_borrowed_executor_keeps_per_runtime_lanes_independent():
    async def scenario():
        executor = ThreadPoolExecutor(max_workers=2)
        first_release = threading.Event()
        first_started = threading.Event()
        same_lane_second_started = threading.Event()
        other_runtime_started = threading.Event()

        def first():
            first_started.set()
            first_release.wait(2)

        def same_lane_second():
            same_lane_second_started.set()

        def other_runtime():
            other_runtime_started.set()

        left = Runtime(scope_id="left", executor=Borrowed(executor))
        right = Runtime(scope_id="right", executor=Borrowed(executor))
        async with left:
            async with right:
                first_waiter = asyncio.create_task(left.worker_lane.run(first))
                await asyncio.to_thread(first_started.wait, 1)
                same_waiter = asyncio.create_task(left.worker_lane.run(same_lane_second))
                other_waiter = asyncio.create_task(right.worker_lane.run(other_runtime))
                await asyncio.to_thread(other_runtime_started.wait, 1)
                assert other_runtime_started.is_set()
                assert not same_lane_second_started.is_set()
                first_release.set()
                await asyncio.gather(first_waiter, same_waiter, other_waiter)

        # Borrowing leaves the provider usable after both runtimes close.
        assert executor.submit(lambda: 7).result(timeout=1) == 7
        executor.shutdown()

    asyncio.run(scenario())


def test_runtime_closes_only_owned_injected_resources():
    class Sink:
        def __init__(self):
            self.closed = 0

        def emit(self, event):
            pass

        def close(self):
            self.closed += 1

    async def scenario():
        owned_sink = Sink()
        borrowed_sink = Sink()
        owned_executor = ThreadPoolExecutor(max_workers=1)
        borrowed_executor = ThreadPoolExecutor(max_workers=1)

        async with Runtime(
            executor=Owned(owned_executor), metric_sink=Owned(owned_sink)
        ):
            pass
        async with Runtime(
            executor=Borrowed(borrowed_executor), metric_sink=Borrowed(borrowed_sink)
        ):
            pass

        assert owned_sink.closed == 1
        assert borrowed_sink.closed == 0
        with pytest.raises(RuntimeError):
            owned_executor.submit(lambda: None)
        assert borrowed_executor.submit(lambda: 8).result(timeout=1) == 8
        borrowed_executor.shutdown()

    asyncio.run(scenario())


def test_runtime_rejects_undeclared_injected_resources():
    class Sink:
        def emit(self, event):
            pass

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        with pytest.raises(TypeError, match="Owned.*Borrowed"):
            Runtime(executor=executor)
        with pytest.raises(TypeError, match="Owned.*Borrowed"):
            Runtime(metric_sink=Sink())
    finally:
        executor.shutdown()


def test_aclose_can_retry_after_dispatched_worker_timeout():
    async def scenario():
        release = threading.Event()
        started = threading.Event()
        runtime = Runtime(shutdown_timeout=0.01)

        def blocking():
            started.set()
            release.wait(2)

        with pytest.raises(ScopeShutdownTimeout):
            async with runtime:
                waiter = asyncio.create_task(runtime.worker_lane.run(blocking))
                await asyncio.to_thread(started.wait, 1)
                waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiter

        assert runtime.state is ScopeState.CLOSING
        assert current_execution_scope() is None
        release.set()
        for _ in range(100):
            if runtime.sync_offloader.dispatched_count == 0:
                break
            await asyncio.sleep(0.01)
        await runtime.aclose()
        assert runtime.state is ScopeState.CLOSED

    asyncio.run(scenario())


def test_shared_shutdown_deadline_bounds_managed_worker_descendant_wait():
    async def scenario():
        release = threading.Event()
        started = threading.Event()
        runtime = Runtime(shutdown_timeout=0.02)

        class Blocking(ObservedComponent):
            @worker
            def call(self):
                started.set()
                release.wait(2)

        await runtime.__aenter__()
        owner = runtime.start(lambda: Blocking().call(), name="managed-blocker")
        await asyncio.to_thread(started.wait, 1)
        began = asyncio.get_running_loop().time()
        with pytest.raises(ScopeShutdownTimeout):
            await runtime.aclose()
        assert asyncio.get_running_loop().time() - began < 0.2
        assert runtime.state is ScopeState.CLOSING
        assert not owner.done()

        release.set()
        await owner
        await runtime.aclose()
        runtime._deactivate()
        assert runtime.state is ScopeState.CLOSED

    asyncio.run(scenario())
