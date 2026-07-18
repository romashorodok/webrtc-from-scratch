import asyncio
import unittest

from webrtc import Runtime
from webrtc.runtime_services import TaskRegistry
from webrtc.state_machine import (
    AsyncStateMachineRunner,
    MachineCommand,
    MachineSpec,
    PreparedTransition,
    ReplyPort,
    TransitionCommit,
)


_SPEC = MachineSpec(
    "notification-test",
    initial="new",
    transitions={"new": frozenset({"ready"}), "ready": frozenset({"closed"})},
    terminal=frozenset({"closed"}),
)


class _Runner(AsyncStateMachineRunner[str]):
    async def step(self, cause: str):
        if cause == "fail":
            raise RuntimeError("transition failed")
        proposed = {"ready": "ready", "close": "closed"}[cause]
        return PreparedTransition(self.state, proposed, None)


class _BlockingRunner(AsyncStateMachineRunner[str]):
    def __init__(self):
        super().__init__(_SPEC, entity_id="blocking")
        self.entered = asyncio.Event()

    async def step(self, cause: str):
        self.entered.set()
        await asyncio.Event().wait()


class _CommandRunner(
    AsyncStateMachineRunner[MachineCommand[None, TransitionCommit]]
):
    async def step(self, cause):
        return PreparedTransition(self.state, "ready", None)


class StateChangeNotificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_revision_and_terminal_waiters_wake_after_commits(self):
        runner = _Runner(_SPEC, entity_id="success")
        task = asyncio.create_task(runner.run())

        initial = runner.snapshot()
        await runner.submit("ready")
        ready = await asyncio.wait_for(runner.wait_for_revision(initial.revision), 1)
        self.assertEqual((ready.state, ready.revision), ("ready", 1))

        await runner.submit("close")
        terminal = await asyncio.wait_for(runner.wait_terminal(), 1)
        self.assertEqual(terminal.state, "closed")
        await task

    async def test_revision_waiter_wakes_and_propagates_runner_failure(self):
        runner = _Runner(_SPEC, entity_id="failure")
        waiter = asyncio.create_task(runner.wait_for_revision(0))
        task = asyncio.create_task(runner.run())
        await runner.submit("fail")

        with self.assertRaisesRegex(RuntimeError, "transition failed"):
            await asyncio.wait_for(waiter, 1)
        with self.assertRaisesRegex(RuntimeError, "transition failed"):
            await task

    async def test_revision_waiter_wakes_when_runner_is_cancelled(self):
        runner = _BlockingRunner()
        task = asyncio.create_task(runner.run())
        await runner.submit("block")
        await asyncio.wait_for(runner.entered.wait(), 1)
        waiter = asyncio.create_task(runner.wait_for_revision(0))

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(waiter, 1)

    async def test_runtime_machine_cancelled_before_first_timeslice_wakes_waiters(self):
        async with Runtime(scope_id="prestart-machine-cancel") as runtime:
            runner = _CommandRunner(_SPEC, entity_id="prestart")
            runtime.register_owner(runner.entity_id, epoch=runner.epoch)
            reply = ReplyPort[TransitionCommit]()
            runner.try_submit(MachineCommand(
                "ready", 1, runner.epoch, None, reply,
            ))
            handle = runtime.start_machine(
                runner, owner_entity_id=runner.entity_id,
                owner_epoch=runner.epoch,
            )
            handle.cancel()

            with self.assertRaises(asyncio.CancelledError):
                await handle.wait()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(reply.wait(), 1)
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(runner.wait_for_revision(0), 1)

    async def test_task_registry_change_wait_has_no_lost_wakeup(self):
        registry = TaskRegistry()
        revision = registry.revision
        barrier = asyncio.get_running_loop().create_future()
        registry.add_barrier("parent", barrier)

        changed = await asyncio.wait_for(registry.wait_for_change(revision), 1)
        self.assertGreater(changed, revision)

        removal_revision = registry.revision
        barrier.set_result(None)
        changed = await asyncio.wait_for(
            registry.wait_for_change(removal_revision), 1
        )
        self.assertGreater(changed, removal_revision)
