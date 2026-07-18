import asyncio
import threading
import time

import pytest

from webrtc import Runtime
from webrtc.performance import (
    ObservedComponent,
    event_loop,
    observe,
    performance,
    task,
    worker,
)


def test_repeated_aggregate_calls_reuse_one_compact_group_without_trace_events():
    class Subject(ObservedComponent):
        @event_loop
        def call(self, value):
            return value + 1

    async def scenario():
        async with Runtime() as runtime:
            before = runtime.trace_snapshot()
            subject = Subject()
            for value in range(100):
                assert subject.call(value) == value + 1
            snapshots = runtime.activity_groups.snapshots()
            assert len(snapshots) == 1
            assert snapshots[0].calls == snapshots[0].successes == 100
            assert snapshots[0].in_flight == 0
            assert len({item.group_id for item in snapshots}) == 1
            assert (
                runtime.trace_snapshot()["data"]["schema"]
                == before["data"]["schema"]
                == 2
            )

    asyncio.run(scenario())


def test_runtime_registers_root_and_top_level_aggregate_owns_it():
    class Subject(ObservedComponent):
        @event_loop
        def call(self):
            return 1

    async def scenario():
        async with Runtime(scope_id="scope") as runtime:
            owner = runtime.projection.machines.get("runtime:scope")
            assert owner is not None
            assert owner.machine_type == "runtime"
            assert owner.state == "active"

            assert Subject().call() == 1
            group = next(
                item for item in runtime.activity_groups.snapshots()
                if item.operation.endswith("Subject.call")
            )
            assert group.owner_entity_id == owner.entity_id
            assert runtime.projection.machines.get(group.owner_entity_id) == owner

    asyncio.run(scenario())


def test_worker_aggregate_calls_are_owned_by_runtime_and_worker_lane_is_projected():
    class Subject(ObservedComponent):
        @event_loop
        def step(self):
            return 1

        @worker
        def serve(self):
            return self.step()

    async def scenario():
        async with Runtime(scope_id="scope") as runtime:
            assert await Subject().serve() == 1
            worker_machine = runtime.projection.machines.get(runtime._worker_entity_id)
            assert worker_machine is not None
            assert worker_machine.machine_type == "worker-lane"
            owned = {
                item.operation: item.owner_entity_id
                for item in runtime.activity_groups.snapshots()
                if item.operation.endswith("Subject.step")
            }
            assert len(owned) == 1
            assert set(owned.values()) == {runtime._runtime_entity_id}

    asyncio.run(scenario())


def test_nested_groups_have_stable_causal_parent_and_track_concurrency():
    class Subject(ObservedComponent):
        @event_loop
        def child(self):
            return 1

        async def parent(self, entered=None, release=None):
            self.child()
            if entered is not None:
                entered.set()
                await release.wait()

    async def scenario():
        async with Runtime() as runtime:
            subject = Subject()
            await subject.parent()
            await subject.parent()
            child = next(item for item in runtime.activity_groups.snapshots()
                         if item.operation.endswith("Subject.child"))
            parent = next(item for item in runtime.activity_groups.snapshots()
                          if item.operation.endswith("Subject.parent"))
            assert child.parent_ref_type == "group"
            assert child.parent_ref_id == parent.group_id
            assert child.calls == 2

            entered = asyncio.Event()
            release = asyncio.Event()
            running = asyncio.create_task(subject.parent(entered, release))
            await entered.wait()
            parent = next(
                item for item in runtime.activity_groups.snapshots()
                    if item.operation.endswith("Subject.parent")
            )
            assert parent.in_flight == 1
            release.set()
            await running
            assert next(
                item for item in runtime.activity_groups.snapshots()
                    if item.operation.endswith("Subject.parent")
            ).in_flight == 0

    asyncio.run(scenario())


def test_worker_delta_merges_nested_calls_once_on_loop_and_reuses_timings():
    class Subject(ObservedComponent):
        @worker
        def outer(self):
            return self.inner() + self.inner()

        @worker
        def inner(self):
            time.sleep(0.001)
            return 2

    async def scenario():
        async with Runtime(max_workers=1) as runtime:
            loop_thread = threading.get_ident()
            mutation_threads = []
            original = runtime.activity_groups.merge_worker_delta

            def checked(*args, **kwargs):
                mutation_threads.append(threading.get_ident())
                return original(*args, **kwargs)

            runtime.activity_groups.merge_worker_delta = checked
            assert await Subject().outer() == 4
            snapshots = runtime.activity_groups.snapshots()
            outer = next(item for item in snapshots if item.operation.endswith("Subject.outer"))
            inner = next(item for item in snapshots if item.operation.endswith("Subject.inner"))
            assert mutation_threads == [loop_thread]
            assert inner.calls == inner.successes == 2
            assert inner.parent_ref_id == outer.group_id
            assert outer.total_worker_ns > 0
            assert outer.total_queue_ns >= 0
            assert outer.total_duration_ns >= outer.total_worker_ns
            assert not any(item.operation.endswith((".queue", ".worker")) for item in snapshots)

    asyncio.run(scenario())


def test_failure_slow_exemplars_are_bounded_and_do_not_capture_messages():
    class Subject(ObservedComponent):
        @observe(detail="aggregate", slow_ms=0, capture_failures=True)
        async def call(self, fail=False):
            if fail:
                raise ValueError("secret-argument-value")

    async def scenario():
        async with Runtime(activity_exemplar_limit=1) as runtime:
            subject = Subject()
            await subject.call()
            with pytest.raises(ValueError):
                await subject.call(True)
            snapshot = runtime.activity_groups.snapshots()[0]
            assert snapshot.calls == 2
            assert snapshot.successes == 1
            assert snapshot.errors == 1
            assert snapshot.latest_failure_class == "ValueError"
            assert len(snapshot.exemplars) == 1
            assert snapshot.exemplars[0]["failure_class"] == "ValueError"
            assert "secret" not in repr(snapshot.exemplars)
            assert runtime.diagnostics["exemplar_overflow"] >= 1

    asyncio.run(scenario())


def test_group_cardinality_uses_bounded_overflow_without_evicting_active_group():
    class Subject(ObservedComponent):
        @event_loop
        @performance(name="one", group="component")
        def one(self):
            return 1

        @event_loop
        @performance(name="two", group="component")
        def two(self):
            return 2

    async def scenario():
        async with Runtime(activity_group_limit=1, activity_overflow_group_limit=1) as runtime:
            subject = Subject()
            assert subject.one() == 1
            assert subject.two() == 2
            assert subject.two() == 2
            snapshots = runtime.activity_groups.snapshots()
            normal = next(item for item in snapshots if not item.overflow)
            overflow = next(item for item in snapshots if item.overflow)
            assert normal.operation == "one"
            assert normal.calls == 1
            assert overflow.operation == "__overflow__"
            assert overflow.calls == 2
            assert runtime.diagnostics["group_cardinality_overflow"] == 2

    asyncio.run(scenario())


def test_aggregate_store_failure_never_changes_application_result():
    class Subject(ObservedComponent):
        async def call(self):
            return 7

    async def scenario():
        async with Runtime() as runtime:
            runtime.activity_groups.resolve = lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("observation failed")
            )
            assert await Subject().call() == 7
            assert runtime.diagnostics["activity_failures"] == 1

    asyncio.run(scenario())
