import asyncio
from pathlib import Path

from webrtc import Runtime
from webrtc.srtp.session import Stream
from webrtc.state_machine import (
    AsyncStateMachineRunner,
    MachineCommand,
    MachineSpec,
    PreparedTransition,
    ReplyPort,
    TransitionCommit,
)


_SPEC = MachineSpec(
    "metadata-test",
    "new",
    {
        "new": frozenset({"active"}),
        "active": frozenset({"closed"}),
        "closed": frozenset(),
    },
    frozenset({"closed"}),
)


class _Runner(AsyncStateMachineRunner[MachineCommand[str, TransitionCommit]]):
    async def step(self, command):
        return PreparedTransition(
            self.state,
            command.payload,
            None,
            command.cause_id,
            command.expected_epoch,
            command.expected_revision,
        )


def test_local_commands_do_not_populate_retry_cache():
    async def scenario():
        runner = _Runner(_SPEC, entity_id="local")
        task = asyncio.create_task(runner.run())

        first = ReplyPort[TransitionCommit]()
        await runner.submit(MachineCommand("move", 1, 1, "active", first))
        assert (await first.wait()).revision == 1

        # Reusing a local diagnostic command id is not deduplication. Only an
        # explicit producer identity opts a caller into retry semantics.
        second = ReplyPort[TransitionCommit]()
        await runner.submit(MachineCommand("move", 1, 1, "closed", second))
        assert (await second.wait()).revision == 2
        await task
        assert runner._seen == {}

    asyncio.run(scenario())


def test_retry_identity_is_explicit_and_deduplicates_one_commit():
    async def scenario():
        runner = _Runner(_SPEC, entity_id="retry")
        task = asyncio.create_task(runner.run())

        first = ReplyPort[TransitionCommit]()
        retry = ReplyPort[TransitionCommit]()
        await runner.submit(MachineCommand(
            "move", 10, 1, "active", first, producer_id=7, producer_seq=3,
        ))
        await runner.submit(MachineCommand(
            "move", 999, 1, "active", retry, producer_id=7, producer_seq=3,
        ))
        committed = await first.wait()
        assert await retry.wait() == committed
        assert runner.revision == 1
        assert len(runner._seen) == 1

        terminal = ReplyPort[TransitionCommit]()
        await runner.submit(MachineCommand("move", 11, 1, "closed", terminal))
        await terminal.wait()
        await task

    asyncio.run(scenario())


def test_projection_failure_cannot_terminate_committed_owner():
    async def scenario():
        async with Runtime(scope_id="metadata-failure") as runtime:
            entity_id = "metadata-owner"
            runtime.register_owner(entity_id, epoch=1)
            runtime.projection.machines.register(entity_id, _SPEC)
            original = runtime.projection.transition
            runtime.projection.transition = lambda _operation: (_ for _ in ()).throw(
                RuntimeError("projection unavailable")
            )
            runner = _Runner(
                _SPEC, entity_id=entity_id,
                transition_sink=runtime.observe_transition,
            )
            task = asyncio.create_task(runner.run())

            active = ReplyPort[TransitionCommit]()
            await runner.submit(MachineCommand("move", 1, 1, "active", active))
            assert (await active.wait()).to_state == "active"
            assert not task.done()
            assert runtime.diagnostics["transition_observation_failures"] == 1

            runtime.projection.transition = original
            closed = ReplyPort[TransitionCommit]()
            await runner.submit(MachineCommand("move", 2, 1, "closed", closed))
            assert (await closed.wait()).to_state == "closed"
            await task

    asyncio.run(scenario())


def test_protocol_components_do_not_construct_projection_metadata():
    root = Path(__file__).parents[1]
    component_modules = (
        "webrtc/peer_components.py",
        "webrtc/queue_machine.py",
        "webrtc/peer_connection.py",
        "webrtc/transceiver.py",
        "webrtc/ice/agent.py",
        "webrtc/ice/net/udp_mux.py",
        "webrtc/dtls/dtlstransport.py",
        "webrtc/srtp/session.py",
    )
    forbidden = (
        "MachineTransitionOp",
        "new_producer_dot",
        "new_facet_source_order",
        ".merge_values(",
        "transition_sink=self._project_transition",
    )
    for relative_path in component_modules:
        source = (root / relative_path).read_text()
        for token in forbidden:
            assert token not in source, f"{relative_path} owns projection metadata: {token}"


def test_srtp_facet_failure_keeps_domain_path_and_diagnostic():
    async def scenario():
        async with Runtime(scope_id="srtp-facet-failure") as runtime:
            stream = Stream(7, True, observability_id="srtp-stream:failure")
            original = runtime.projection.merge_values
            runtime.projection.merge_values = lambda *_args, **_kwargs: (
                (_ for _ in ()).throw(RuntimeError("projection unavailable"))
            )
            try:
                assert await stream.write(b"packet")
                await asyncio.sleep(0)
                assert runtime.diagnostics["srtp_queue_facet_publish_failures"] == 1
            finally:
                runtime.projection.merge_values = original
            await stream.close()

    asyncio.run(scenario())
