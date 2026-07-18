import asyncio
import threading

import pytest

from webrtc import Runtime
from webrtc.runtime_services import (
    FailurePolicy,
    ImmutableWorkerResult,
    ScopeShutdownTimeout,
    StaleOwnerEpoch,
    UntrackedRuntimeTask,
)
from webrtc.state_machine import (
    AsyncStateMachineRunner,
    BoundedMailbox,
    MachineCommand,
    MachineSpec,
    MailboxClosed,
    MailboxFull,
    PreparedTransition,
    ReplyPort,
    StaleMachineAccess,
    TransitionController,
    WrongEventLoop,
)


SPEC = MachineSpec(
    "synthetic", "idle",
    {"idle": {"running"}, "running": {"closed"}, "closed": set()},
    frozenset({"closed"}),
)


class SyntheticRunner(AsyncStateMachineRunner[MachineCommand[str, object]]):
    def __init__(self, *args, terminal_release=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.terminal_release = terminal_release
        self.reconciled = False

    async def step(self, command):
        await asyncio.sleep(0)
        return PreparedTransition(
            self.snapshot().state, command.payload, {"command": command.command_id},
            command.cause_id, command.expected_epoch, command.expected_revision,
        )

    async def reconcile_terminal(self, prepared):
        if self.terminal_release is not None:
            await self.terminal_release.wait()
        self.reconciled = True


class FailingTerminalRunner(SyntheticRunner):
    async def after_commit(self, commit, effects):
        if commit.to_state == "closed":
            raise RuntimeError("terminal publication failed")


def command(kind, sequence, state, *, revision, epoch=7, reply=None):
    return MachineCommand(
        kind, sequence, epoch, state, reply, revision, producer_id=11,
        producer_seq=sequence, cause_id=f"cause-{sequence}",
    )


def test_bounded_mailbox_overflow_close_and_blocked_submit_are_deterministic():
    async def scenario():
        mailbox = BoundedMailbox[str](1)
        mailbox.try_submit("first")
        with pytest.raises(MailboxFull):
            mailbox.try_submit("overflow")
        blocked = asyncio.create_task(mailbox.submit("blocked"))
        await asyncio.sleep(0)
        assert not blocked.done()
        assert mailbox.close() == ("first",)
        with pytest.raises(MailboxClosed):
            await blocked
        with pytest.raises(MailboxClosed):
            await mailbox.receive()

    asyncio.run(scenario())


def test_duplicate_reordered_wrong_epoch_and_idempotent_replies():
    async def scenario():
        commits = []
        runner = SyntheticRunner(
            SPEC, entity_id="machine", epoch=7, mailbox_capacity=8,
            transition_sink=commits.append,
        )
        handle = asyncio.create_task(runner.run())

        first = ReplyPort()
        duplicate = ReplyPort()
        future = ReplyPort()
        wrong_epoch = ReplyPort()
        terminal = ReplyPort()
        for item in (
            command("start", 1, "running", revision=0, reply=first),
            command("start", 1, "running", revision=0, reply=duplicate),
            command("close", 2, "closed", revision=9, reply=future),
            command("close", 3, "closed", revision=1, epoch=6, reply=wrong_epoch),
            command("close", 4, "closed", revision=1, reply=terminal),
        ):
            runner.try_submit(item)

        assert await first.wait() is await duplicate.wait()
        with pytest.raises(StaleMachineAccess):
            await future.wait()
        with pytest.raises(StaleMachineAccess):
            await wrong_epoch.wait()
        assert (await terminal.wait()).to_state == "closed"
        await handle
        assert [(item.revision, item.to_state) for item in commits] == [
            (1, "running"), (2, "closed")
        ]
        assert runner.snapshot(expected_epoch=7).terminal
        with pytest.raises(StaleMachineAccess):
            runner.snapshot(expected_epoch=6)

    asyncio.run(scenario())


def test_cancellation_resolves_active_and_queued_replies():
    async def scenario():
        controller = TransitionController(timeout=1)
        controller.pause_at("synthetic", to_state="running", phase="before_commit")
        runner = SyntheticRunner(SPEC, entity_id="machine", epoch=7, controller=controller)
        active, queued = ReplyPort(), ReplyPort()
        runner.try_submit(command("start", 1, "running", revision=0, reply=active))
        runner.try_submit(command("close", 2, "closed", revision=1, reply=queued))
        task = asyncio.create_task(runner.run())
        await controller.wait_until("synthetic", "running")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(asyncio.CancelledError):
            await active.wait()
        with pytest.raises(asyncio.CancelledError):
            await queued.wait()
        assert runner.snapshot().state == "idle"

    asyncio.run(scenario())


def test_terminal_commit_waits_for_child_reconciliation_and_checkpoint():
    async def scenario():
        release = asyncio.Event()
        controller = TransitionController(timeout=1)
        controller.pause_at("synthetic", to_state="closed", phase="terminal")
        runner = SyntheticRunner(
            SPEC, entity_id="machine", epoch=7, terminal_release=release,
            controller=controller,
        )
        runner.try_submit(command("start", 1, "running", revision=0))
        runner.try_submit(command("close", 2, "closed", revision=1))
        task = asyncio.create_task(runner.run())
        while runner.snapshot().state != "running":
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert runner.snapshot().state == "running"
        release.set()
        checkpoint = await controller.wait_until("synthetic", "closed", phase="terminal")
        assert runner.reconciled and runner.snapshot().state == "closed"
        controller.release(checkpoint.checkpoint_id)
        await task

    asyncio.run(scenario())


def test_runtime_machine_terminal_failure_closes_mailbox_and_resolves_replies():
    async def scenario():
        async with Runtime() as runtime:
            runtime.register_owner("machine", epoch=7)
            runner = FailingTerminalRunner(
                SPEC, entity_id="machine", epoch=7, dedupe_capacity=2
            )
            handle = runtime.start_machine(
                runner, owner_entity_id="machine", owner_epoch=7,
                failure=FailurePolicy.REPORT,
            )
            start, start_duplicate = ReplyPort(), ReplyPort()
            terminal, queued = ReplyPort(), ReplyPort()
            runner.try_submit(command("start", 0, "running", revision=0, reply=start))
            runner.try_submit(MachineCommand(
                "start", 99, 7, "running", start_duplicate, 0,
                producer_id=11, producer_seq=0, cause_id="retry-zero",
            ))
            runner.try_submit(command("close", 1, "closed", revision=1, reply=terminal))
            runner.try_submit(command("late", 2, "closed", revision=2, reply=queued))

            assert await start.wait() is await start_duplicate.wait()
            assert (await terminal.wait()).to_state == "closed"
            with pytest.raises(MailboxClosed):
                await queued.wait()
            with pytest.raises(RuntimeError, match="terminal publication failed"):
                await handle
            assert runner.snapshot().terminal and runner.commands.closed
            with pytest.raises(MailboxClosed):
                runner.try_submit(command("late", 3, "closed", revision=2))
            assert len(runner._seen) <= 2
            assert all(not isinstance(value, BaseException) for value in runner._seen.values())
            runtime.remove_owner("machine", 7)

    asyncio.run(scenario())


def test_runtime_machine_wrong_loop_epoch_and_owned_timer_contracts():
    async def scenario():
        async with Runtime() as runtime:
            runtime.register_owner("machine", epoch=7)
            runner = SyntheticRunner(SPEC, entity_id="machine", epoch=7)
            handle = runtime.start_machine(
                runner, owner_entity_id="machine", owner_epoch=7,
                failure=FailurePolicy.REPORT,
            )
            await asyncio.sleep(0)

            async def wrong_loop_probe():
                with pytest.raises(WrongEventLoop):
                    runner.snapshot()

            await asyncio.to_thread(asyncio.run, wrong_loop_probe())
            with pytest.raises(StaleOwnerEpoch):
                runtime.call_later_owned(
                    0, lambda: None, owner_entity_id="machine", owner_epoch=6
                )
            fired = []
            timer = runtime.call_later_owned(
                0, lambda: fired.append(True),
                owner_entity_id="machine", owner_epoch=7,
            )
            assert await timer.wait() and fired == [True]
            runner.try_submit(command("start", 1, "running", revision=0))
            runner.try_submit(command("close", 2, "closed", revision=1))
            await handle
            runtime.remove_owner("machine", 7)

    asyncio.run(scenario())


def test_runtime_failed_close_is_retryable_and_concurrent_retry_is_shared():
    async def scenario():
        runtime = await Runtime().__aenter__()
        original = runtime.task_scheduler.aclose
        calls = 0

        async def fail_once(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise ScopeShutdownTimeout("injected close timeout")
            await original(**kwargs)

        runtime.task_scheduler.aclose = fail_once
        try:
            with pytest.raises(ScopeShutdownTimeout):
                await runtime.aclose()
            assert runtime.shutdown_started
            await asyncio.gather(runtime.aclose(), runtime.aclose())
            assert calls == 2
            assert runtime.state.value == "closed"
        finally:
            await runtime.__aexit__(None, None, None)

    asyncio.run(scenario())


def test_runtime_owned_handles_late_worker_and_ownership_assertions():
    async def scenario():
        release = threading.Event()
        started = threading.Event()

        def work():
            started.set()
            release.wait(2)
            return {"immutable": True}

        async with Runtime(max_workers=1) as runtime:
            runtime.register_owner("child", epoch=3)
            worker = runtime.call_worker(
                work, owner_entity_id="child", owner_epoch=3, name="synthetic-worker"
            )
            await asyncio.to_thread(started.wait, 1)
            with pytest.raises(AssertionError, match="live children"):
                runtime.remove_owner("child", 3)
            assert worker.cancel()
            result = await worker
            assert isinstance(result, ImmutableWorkerResult)
            assert result.outcome == "cancelled"
            await asyncio.sleep(0)
            runtime.remove_owner("child", 3)
            with pytest.raises(StaleOwnerEpoch):
                runtime.assert_owner_epoch("child", 3)

            stray = asyncio.create_task(asyncio.sleep(0))
            with pytest.raises(UntrackedRuntimeTask):
                runtime.assert_task_tracked(stray)
            await stray

            release.set()
            while runtime.sync_offloader.dispatched_count:
                await asyncio.sleep(0.01)
            assert runtime.diagnostics["worker_completion_after_close"] == 1

    asyncio.run(scenario())
