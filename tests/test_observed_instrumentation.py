import asyncio
import inspect
import threading
import time

import pytest

from webrtc.performance import (
    ObservedComponent,
    event_loop,
    performance,
    task,
    unobserved,
    worker,
)
from webrtc import Runtime
from webrtc.runtime_services import (
    Borrowed,
    MissingExecutionScope,
    current_execution_context,
    use_execution_scope,
)


class Work(ObservedComponent):
    @worker
    @performance(name="work.sync", on_call=lambda call: {"value": call.args[1]},
                 on_success=lambda event: {"result": event.result})
    def sync(self, value):
        return value + 1

    @performance(name="work.async")
    async def async_work(self):
        await asyncio.sleep(0)
        return "ok"

    @worker
    @performance(name="work.worker", group="worker")
    def blocking(self):
        return current_execution_context()

    @event_loop
    def inline(self):
        return threading.get_ident()


async def run_owned(runtime, factory):
    with use_execution_scope(runtime):
        return await runtime.task_scheduler.run_factory(factory, trace_id="trace", scope_id="scope")


def test_automatic_sync_async_worker_and_inline_contracts():
    async def scenario():
        runtime = Runtime()
        work = Work()
        assert work.sync(1) == 2
        assert inspect.iscoroutinefunction(work.async_work)

        async def owner():
            assert await work.async_work() == "ok"
            parent = current_execution_context()
            worker_context = await work.blocking()
            assert worker_context.task_id == parent.task_id
            assert worker_context.node_id != parent.node_id
            assert work.inline() == threading.get_ident()

        await run_owned(runtime, owner)
        operations = {group.operation for group in runtime.metric_sink.snapshots()}
        assert {"work.async", "work.worker", "work.worker.queue", "work.worker.worker"} <= operations
        assert runtime.trace_live_tree() == []
        await runtime.aclose()

    asyncio.run(scenario())


def test_task_is_immediate_native_task_and_preserves_result_error_and_cancellation():
    class Tasks(ObservedComponent):
        @task(name="result")
        async def result(self):
            return 7

        @task(name="failure")
        async def failure(self, error):
            raise error

        @task(name="waiting")
        async def waiting(self, started):
            started.set()
            await asyncio.Event().wait()

    async def scenario():
        runtime = Runtime()
        subject = Tasks()
        with use_execution_scope(runtime):
            result = subject.result()
            assert isinstance(result, asyncio.Task)
            assert await result == 7

            error = ValueError("original")
            failed = subject.failure(error)
            with pytest.raises(ValueError) as caught:
                await failed
            assert caught.value is error
            assert failed.exception() is error

            started = asyncio.Event()
            waiting = subject.waiting(started)
            await started.wait()
            waiting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiting
            assert waiting.cancelled()
        await runtime.aclose()

    asyncio.run(scenario())


def test_task_rejects_missing_scope_before_factory_or_coroutine_creation():
    calls = 0

    class Subject(ObservedComponent):
        @task()
        async def call(self):
            nonlocal calls
            calls += 1

    with pytest.raises(MissingExecutionScope):
        Subject().call()
    assert calls == 0


def test_performance_and_all_ordinary_calls_work_without_scope_without_recording():
    class Subject(ObservedComponent):
        @worker
        @performance(name="outside")
        def call(self):
            return 3

        async def async_call(self):
            return 4

    runtime = Runtime()
    assert Subject().call() == 3
    assert asyncio.run(Subject().async_call()) == 4
    assert runtime.metric_sink.snapshots() == ()
    runtime.shutdown()


def test_nested_worker_calls_execute_inline_without_redispatch():
    class Nested(ObservedComponent):
        @worker
        def outer(self):
            inner = self.inner()
            assert not inspect.isawaitable(inner)
            return inner

        @worker
        def inner(self):
            return threading.get_ident()

    async def scenario():
        runtime = Runtime(max_workers=1)
        main_thread = threading.get_ident()

        async def owner():
            worker_thread = await Nested().outer()
            assert worker_thread != main_thread

        await asyncio.wait_for(run_owned(runtime, owner), timeout=1)
        assert runtime.sync_offloader.dispatched_count == 0
        await runtime.aclose()

    asyncio.run(scenario())


def test_async_calls_have_live_child_nodes_and_inherited_wrappers_remain_active():
    class Base(ObservedComponent):
        async def wait(self, entered, release):
            entered.set()
            await release.wait()

    class Child(Base):
        pass

    async def scenario():
        runtime = Runtime()
        entered = asyncio.Event()
        release = asyncio.Event()

        async def owner():
            call = asyncio.create_task(Child().wait(entered, release))
            await entered.wait()
            nodes = runtime.trace_live_tree()
            method = next(node for node in nodes
                          if node["metadata"].get("node_type") == "async-call")
            task = next(node for node in nodes
                        if node["metadata"].get("node_type") == "task")
            assert method["parent_task_id"] == task["task_id"]
            assert method["metadata"]["owner_task_id"] == task["task_id"]
            assert method["metadata"]["cancelable"] is False
            release.set()
            await call

        await run_owned(runtime, owner)
        assert runtime.trace_live_tree() == []
        await runtime.aclose()

    asyncio.run(scenario())


def test_dispatched_cancellation_holds_lane_and_live_node_until_physical_completion():
    release = threading.Event()
    started = threading.Event()
    second_started = threading.Event()

    class Blocking(ObservedComponent):
        @worker
        def first(self):
            started.set()
            release.wait(2)

        @worker
        def second(self):
            second_started.set()

    async def scenario():
        runtime = Runtime(max_workers=2)
        subject = Blocking()

        async def owner():
            first = asyncio.create_task(subject.first())
            await asyncio.to_thread(started.wait, 1)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            worker_nodes = [node for node in runtime.trace_live_tree()
                            if node["metadata"].get("node_type") == "worker-call"]
            assert len(worker_nodes) == 1
            assert worker_nodes[0]["metadata"]["cancelable"] is False

            second = asyncio.create_task(subject.second())
            await asyncio.sleep(0.03)
            assert not second_started.is_set()
            release.set()
            await second
            await asyncio.sleep(0)
            assert not [node for node in runtime.trace_live_tree()
                        if node["metadata"].get("node_type") == "worker-call"]

        await run_owned(runtime, owner)
        assert any(snapshot.operation.endswith("Blocking.first.worker")
                   for snapshot in runtime.metric_sink.snapshots())
        await runtime.aclose()

    asyncio.run(scenario())


def test_descriptors_properties_dunders_and_unobserved_are_preserved():
    class Descriptors(ObservedComponent):
        @staticmethod
        @event_loop
        def static(value):
            return value

        @classmethod
        @event_loop
        def class_method(cls):
            return cls

        @property
        def value(self):
            return 8

        def __str__(self):
            return "descriptor"

        @unobserved
        def raw(self):
            return 9

    runtime = Runtime()
    with use_execution_scope(runtime):
        assert Descriptors.static(3) == 3
        assert Descriptors.class_method() is Descriptors
        assert Descriptors().value == 8
        assert str(Descriptors()) == "descriptor"
        assert Descriptors().raw() == 9
    assert runtime.trace_live_tree() == []
    runtime.shutdown()


def test_marker_combinations_and_affinity_classification_are_validated_at_creation():
    with pytest.raises(TypeError, match="mutually exclusive"):
        class Both(ObservedComponent):
            @event_loop
            @worker
            def call(self):
                pass

    with pytest.raises(TypeError, match="affinity markers require"):
        class AsyncWorker(ObservedComponent):
            @worker
            async def call(self):
                pass

    with pytest.raises(TypeError, match="unobserved cannot"):
        class ExcludedPerformance(ObservedComponent):
            @unobserved
            @performance(name="bad")
            def call(self):
                pass

    with pytest.raises(TypeError, match="ambiguous synchronous affinity"):
        class Dynamic(ObservedComponent):
            def call(self):
                return getattr(self, "value", None)

    class Resolved(ObservedComponent):
        @worker
        def call(self):
            return getattr(self, "value", None)

    class DirectLoopHit(ObservedComponent):
        def call(self):
            return self._loop.call_soon(lambda: None)

    assert Resolved.call.__wrapped__ is not None
    runtime = Runtime()
    with use_execution_scope(runtime):
        direct = DirectLoopHit.__new__(DirectLoopHit)
        direct._loop = type("Loop", (), {"call_soon": lambda self, callback: callback()})()
        assert not inspect.isawaitable(direct.call())
    runtime.shutdown()


def test_extractor_and_sink_failures_do_not_change_results():
    class BrokenSink:
        def emit(self, event):
            raise RuntimeError("sink")

    class Broken(ObservedComponent):
        @performance(name="broken", on_success=lambda event: 1 / 0)
        async def call(self):
            return 7

    async def scenario():
        runtime = Runtime(metric_sink=Borrowed(BrokenSink()))

        async def owner():
            assert await Broken().call() == 7

        await run_owned(runtime, owner)
        assert runtime.diagnostics["sink_failures"] >= 1
        assert runtime.diagnostics["extractor_failures"] >= 1
        await runtime.aclose()

    asyncio.run(scenario())


def test_worker_barrier_delays_parent_terminal_and_restores_root_cancelability():
    entered = threading.Event()
    release = threading.Event()

    class Blocking(ObservedComponent):
        @worker
        def call(self):
            entered.set()
            release.wait(2)

    async def scenario():
        async with Runtime(shutdown_timeout=0.5) as runtime:
            root_id = runtime.root_context.task_id
            assert runtime.task_registry.get(root_id).cancelable is False
            owner = runtime.start(lambda: Blocking().call(), name="barrier-owner")
            await asyncio.to_thread(entered.wait, 1)
            owner.cancel()
            await asyncio.sleep(0)
            assert not owner.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await owner
            assert runtime.task_registry.get(root_id).cancelable is False

    asyncio.run(scenario())


def test_worker_failure_records_queue_worker_and_total_metrics():
    class Broken(ObservedComponent):
        @worker
        @performance(name="broken.worker")
        def call(self):
            time.sleep(0.01)
            raise LookupError("broken")

    async def scenario():
        async with Runtime() as runtime:
            with pytest.raises(LookupError):
                await Broken().call()
            snapshots = {item.operation: item for item in runtime.metric_sink.snapshots()}
            assert {"broken.worker", "broken.worker.queue", "broken.worker.worker"} <= snapshots.keys()
            assert snapshots["broken.worker.worker"].total_duration_ms > 0
            assert snapshots["broken.worker"].errors == 1

    asyncio.run(scenario())


def test_async_worker_method_exposes_awaitable_static_application_contract():
    from webrtc.performance import async_worker_method

    method = async_worker_method(Work().sync)
    assert hasattr(Work.sync, "__runtime_result_annotation__")

    async def scenario():
        async with Runtime():
            assert await method(2) == 3

    asyncio.run(scenario())
