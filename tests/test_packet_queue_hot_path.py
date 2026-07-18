import asyncio

from webrtc import Runtime
from webrtc.ice.net.types import Address, Packet
from webrtc.ice.net.udp_mux import Interceptor
from webrtc.queue_machine import RuntimeOwnedQueue
from webrtc.srtp.session import Stream
from webrtc.state_machine import AsyncStateMachineRunner


def _facets(runtime: Runtime, owner: str):
    return {
        item.facet_id.rsplit(":", 1)[-1]: item
        for item in runtime.projection.facets.snapshots()
        if item.owner_entity_id == owner
    }


def test_runtime_owned_queue_packet_facets_coalesce_per_loop_turn():
    async def scenario():
        async with Runtime(scope_id="queue-hot-path") as runtime:
            queue = RuntimeOwnedQueue[int](
                4, entity_id="queue:runtime-owned", queue_kind="packets"
            )
            calls = 0
            original_merge = runtime.projection.merge_values

            def count_merge(*args, **kwargs):
                nonlocal calls
                calls += 1
                return original_merge(*args, **kwargs)

            runtime.projection.merge_values = count_merge
            queue.put_nowait(1)
            await queue.put(2)
            assert queue.get_nowait() == 1
            assert await queue.get() == 2
            assert calls == 0

            await asyncio.sleep(0)
            assert calls == 1
            facets = _facets(runtime, runtime.telemetry_entity_id("queue", queue.entity_id))
            assert facets["depth"].value == 0
            assert facets["high_water"].value == 2
            assert facets["enqueued_packets"].value == 2
            assert facets["dequeued_packets"].value == 2
            assert {item.observer_meta for item in facets.values()} == {"aggregate"}
            runtime.projection.merge_values = original_merge
            await queue.close()

    asyncio.run(scenario())


def test_udp_interceptor_coalesces_admission_drop_and_dequeue_counters():
    async def scenario():
        async with Runtime(scope_id="udp-hot-path") as runtime:
            queue = Interceptor(maxsize=2, queue_id="udp-packets")
            packet = lambda value: Packet(Address("127.0.0.1", 9), value)
            calls = 0
            original_merge = runtime.projection.merge_values

            def count_merge(*args, **kwargs):
                nonlocal calls
                calls += 1
                return original_merge(*args, **kwargs)

            runtime.projection.merge_values = count_merge
            queue.put_nowait(packet(b"one"))
            queue.put_nowait(packet(b"two"))
            queue.put_nowait(packet(b"three"))
            assert (await queue.get()).data == b"two"
            assert calls == 0

            await asyncio.sleep(0)
            assert calls == 1
            facets = _facets(runtime, runtime.telemetry_entity_id("queue", queue.entity_id))
            assert facets["depth"].value == 1
            assert facets["high_water"].value == 2
            assert facets["admitted_packets"].value == 3
            assert facets["dequeued_packets"].value == 1
            assert facets["dropped_media_packets"].value == 1
            assert {item.observer_meta for item in facets.values()} == {"aggregate"}
            runtime.projection.merge_values = original_merge
            await queue.aclose()

    asyncio.run(scenario())


def test_srtp_stream_coalesces_delivery_drop_and_read_counters():
    async def scenario():
        async with Runtime(scope_id="srtp-hot-path") as runtime:
            stream = Stream(1234, True, observability_id="srtp-hot-stream")
            snapshot = stream._runner.snapshot()
            while snapshot.state != "active":
                snapshot = await stream._runner.wait_for_revision(snapshot.revision)
            stream._queue = asyncio.Queue(maxsize=2)
            calls = 0
            original_merge = runtime.projection.merge_values

            def count_merge(*args, **kwargs):
                nonlocal calls
                calls += 1
                return original_merge(*args, **kwargs)

            runtime.projection.merge_values = count_merge
            assert await stream.write(b"one")
            assert await stream.write(b"two")
            assert not await stream.write(b"three")
            assert await stream.read() == b"one"
            assert calls == 0

            await asyncio.sleep(0)
            assert calls == 1
            facets = _facets(
                runtime, runtime.telemetry_entity_id("queue", stream.observability_id)
            )
            assert facets["depth"].value == 1
            assert facets["high_water"].value == 2
            assert facets["delivered_packets"].value == 2
            assert facets["dequeued_packets"].value == 1
            assert facets["dropped_packets"].value == 1
            assert {item.observer_meta for item in facets.values()} == {"aggregate"}
            runtime.projection.merge_values = original_merge
            await stream.close()

    asyncio.run(scenario())


def test_packet_processing_survives_projection_failure():
    async def scenario():
        async with Runtime(scope_id="packet-projection-failure") as runtime:
            queue = RuntimeOwnedQueue[int](
                2, entity_id="queue:projection-failure", queue_kind="packets"
            )
            original_merge = runtime.projection.merge_values
            loop = asyncio.get_running_loop()
            loop_errors = []
            previous_handler = loop.get_exception_handler()
            loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))

            def fail_merge(*_args, **_kwargs):
                raise RuntimeError("projection unavailable")

            runtime.projection.merge_values = fail_merge
            try:
                queue.put_nowait(7)
                assert queue.get_nowait() == 7
                await asyncio.sleep(0)
                assert runtime.diagnostics["queue_facet_publish_failures"] == 1
                assert loop_errors == []
            finally:
                runtime.projection.merge_values = original_merge
                loop.set_exception_handler(previous_handler)
            await queue.close()

    asyncio.run(scenario())


def test_packet_queue_lifecycle_survives_projection_failure():
    async def scenario():
        async with Runtime(scope_id="packet-lifecycle-projection-failure") as runtime:
            owned = RuntimeOwnedQueue[int](
                2, entity_id="queue:lifecycle-projection-failure",
                queue_kind="packets",
            )
            udp = Interceptor(maxsize=2, queue_id="udp-projection-failure")
            original_merge = runtime.projection.merge_values

            def fail_merge(*_args, **_kwargs):
                raise RuntimeError("projection unavailable")

            runtime.projection.merge_values = fail_merge
            try:
                # Observability failure cannot prevent primitive-owned close.
                await owned.close()
                await udp.aclose()
                assert owned._state == "closed"
                assert "_runner" not in owned.__dict__
                assert udp._runner.snapshot().state == "closed"
                assert not isinstance(udp._runner, AsyncStateMachineRunner)
                assert runtime.diagnostics["queue_facet_publish_failures"] == 1
                assert runtime.diagnostics["udp_queue_projection_failures"] == 3
            finally:
                runtime.projection.merge_values = original_merge

    asyncio.run(scenario())


def test_runtime_owned_queue_close_rejects_and_wakes_blocked_admission():
    async def scenario():
        async with Runtime(scope_id="queue-close-race") as runtime:
            queue = RuntimeOwnedQueue[int](
                1, entity_id="queue:close-race", queue_kind="packets",
            )
            queue.put_nowait(1)
            blocked_put = asyncio.create_task(queue.put(2))
            await asyncio.sleep(0)

            await queue.close()

            result = await asyncio.gather(blocked_put, return_exceptions=True)
            assert isinstance(result[0], RuntimeError)
            assert queue.empty()
            assert queue._state == "closed"
            assert "_runner" not in queue.__dict__
            assert runtime.projection.machines.get(queue.entity_id) is None

    asyncio.run(scenario())
