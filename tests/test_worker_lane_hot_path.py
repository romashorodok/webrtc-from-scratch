import asyncio

from webrtc import Runtime
from webrtc.runtime_services import ConcurrentWorkerLane, SyncOffloader


def test_worker_load_does_not_submit_lifecycle_commands():
    async def scenario():
        async with Runtime(scope_id="worker-hot-path") as runtime:
            submissions = 0
            original_submit = runtime._worker_runner.try_submit

            def record_submit(command):
                nonlocal submissions
                submissions += 1
                return original_submit(command)

            runtime._worker_runner.try_submit = record_submit
            try:
                assert await runtime.worker_lane.run(lambda: 42) == 42
                await asyncio.sleep(0)
                machine = runtime.projection.machines.get(runtime._worker_entity_id)
                assert machine is not None
                assert machine.state == "accepting"
                assert machine.revision == 0
                assert submissions == 0
            finally:
                # Runtime close still uses the admission lifecycle mailbox.
                runtime._worker_runner.try_submit = original_submit

    asyncio.run(scenario())


def test_worker_metric_publication_is_coalesced_per_event_loop_turn():
    async def scenario():
        async with Runtime(scope_id="worker-metrics") as runtime:
            publish_count = 0
            original_publish = runtime._publish_worker_facets

            def record_publish(revision):
                nonlocal publish_count
                publish_count += 1
                original_publish(revision)

            runtime._publish_worker_facets = record_publish
            runtime._worker_state_changed(queued=1, running=0, high_water=1)
            runtime._worker_state_changed(queued=0, running=1, high_water=1)
            runtime._worker_state_changed(queued=0, running=0, high_water=1)
            await asyncio.sleep(0)

            assert publish_count == 1
            facets = {
                item.facet_id.rsplit(":", 1)[-1]: item
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == runtime._worker_entity_id
            }
            assert facets["queued"].value == 0
            assert facets["running"].value == 0
            assert facets["high_water"].value == 0
            assert {item.observer_meta for item in facets.values()} == {"aggregate"}

    asyncio.run(scenario())


def test_worker_metric_callback_failure_cannot_fail_work():
    async def scenario():
        offloader = SyncOffloader(capacity=1, max_workers=1)
        lane = ConcurrentWorkerLane(offloader)

        def fail_metrics(**_values):
            raise RuntimeError("metrics unavailable")

        lane.set_state_publisher(fail_metrics)
        try:
            assert await lane.run(lambda: "completed") == "completed"
            assert lane.load_snapshot() == (0, 0, 1)
        finally:
            offloader.shutdown()

    asyncio.run(scenario())


def test_worker_projection_failure_does_not_escape_loop_callback():
    async def scenario():
        async with Runtime(scope_id="worker-projection-failure") as runtime:
            loop = asyncio.get_running_loop()
            loop_errors = []
            previous_handler = loop.get_exception_handler()
            original_merge = runtime.projection.merge_values

            def record_loop_error(_loop, context):
                loop_errors.append(context)

            def fail_projection(*_args, **_kwargs):
                raise RuntimeError("projection unavailable")

            loop.set_exception_handler(record_loop_error)
            runtime.projection.merge_values = fail_projection
            try:
                assert await runtime.worker_lane.run(lambda: "completed") == "completed"
                await asyncio.sleep(0)
                assert runtime.diagnostics["worker_facet_publish_failures"] >= 1
                assert loop_errors == []
            finally:
                runtime.projection.merge_values = original_merge
                loop.set_exception_handler(previous_handler)

    asyncio.run(scenario())
