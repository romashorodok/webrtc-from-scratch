import asyncio
import threading

import pytest

from webrtc.runtime import Runtime
from webrtc.runtime_services import StaleOwnerEpoch, WrongRuntimeLoop


def test_explicit_worker_execution_is_identical_with_tracing_on_and_off():
    async def run(tracing_enabled: bool):
        async with Runtime(tracing_enabled=tracing_enabled) as runtime:
            owner = f"worker-owner:{tracing_enabled}"
            runtime.register_owner(owner, epoch=1)
            execution = runtime.execution_port(owner, 1)
            loop_thread = threading.get_ident()

            value, worker_thread = await execution.run_worker(
                lambda left, right: (left + right, threading.get_ident()),
                20,
                22,
                name="worker:test-parity",
            )
            assert worker_thread != loop_thread
            runtime.remove_owner(owner, 1)
            return value

    assert asyncio.run(run(False)) == asyncio.run(run(True)) == 42


def test_owned_task_cancellation_and_stale_epoch_are_execution_concerns():
    async def scenario():
        async with Runtime(tracing_enabled=False) as runtime:
            owner = "task-owner"
            runtime.register_owner(owner, epoch=1)
            execution = runtime.execution_port(owner, 1)
            entered = asyncio.Event()

            async def waiting():
                entered.set()
                await asyncio.Event().wait()

            handle = execution.start_task(waiting, name="owned:waiting")
            await entered.wait()
            with pytest.raises(AssertionError, match="live children"):
                runtime.remove_owner(owner, 1)
            assert handle.cancel()
            with pytest.raises(asyncio.CancelledError):
                await handle.wait()
            await asyncio.sleep(0)
            runtime.remove_owner(owner, 1)

            with pytest.raises(StaleOwnerEpoch):
                await execution.run_worker(lambda: None)

    asyncio.run(scenario())


def test_cancelling_worker_waiter_does_not_cancel_physical_worker_or_ownership():
    async def scenario():
        async with Runtime(tracing_enabled=True) as runtime:
            owner = "worker-cancel-owner"
            runtime.register_owner(owner, epoch=1)
            execution = runtime.execution_port(owner, 1)
            started = threading.Event()
            release = threading.Event()
            completed = threading.Event()

            def blocking():
                started.set()
                release.wait(2)
                completed.set()
                return 7

            waiter = asyncio.create_task(execution.run_worker(blocking))
            await asyncio.to_thread(started.wait, 1)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            release.set()
            await runtime.join_owner_children(owner, 1)
            assert completed.is_set()
            runtime.remove_owner(owner, 1)

    asyncio.run(scenario())


def test_execution_port_preserves_runtime_loop_affinity_assertion():
    async def scenario():
        async with Runtime() as runtime:
            owner = "loop-owner"
            runtime.register_owner(owner, epoch=1)
            execution = runtime.execution_port(owner, 1)

            def wrong_loop():
                async def invoke():
                    execution.assert_event_loop()

                with pytest.raises(WrongRuntimeLoop):
                    asyncio.run(invoke())

            await asyncio.to_thread(wrong_loop)
            runtime.remove_owner(owner, 1)

    asyncio.run(scenario())
