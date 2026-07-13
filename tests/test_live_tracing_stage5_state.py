import asyncio

from webrtc import Runtime
from webrtc.dtls.fsm import FSM, FSMState, StartHandshake
from webrtc.observability import FacetOp, FacetStore, ProducerDot
from webrtc.runtime_services import Borrowed
from webrtc.state_machine import TransitionController
from webrtc.performance import ObservedComponent, task


class SelectedWorker(ObservedComponent):
    @task(state="worker")
    async def serve(self):
        await asyncio.sleep(0)


def _bare_fsm(controller=None):
    fsm = object.__new__(FSM)
    fsm.handshake_state = FSMState.Sending
    fsm.transition_revision = 0
    fsm.entity_id = "dtls:test"
    fsm._transition_controller = controller
    fsm._projection = None
    fsm.handshake_complete = asyncio.Event()
    fsm._complete_handshake = lambda: None
    return fsm


def test_dtls_before_commit_stops_then_release_commits_one_revision():
    async def scenario():
        controller = TransitionController(timeout=1)
        controller.pause_at("dtls", to_state="Finished", phase="before_commit")
        fsm = _bare_fsm(controller)
        task = asyncio.create_task(
            fsm._transition(FSMState.Finished, StartHandshake())
        )
        reached = await controller.wait_until("dtls", "Finished")
        assert fsm.handshake_state is FSMState.Sending
        assert fsm.transition_revision == 0
        assert not fsm.handshake_complete.is_set()
        controller.release(reached.checkpoint_id)
        await task
        assert fsm.handshake_state is FSMState.Finished
        assert fsm.transition_revision == 1
        assert fsm.handshake_complete.is_set()

    asyncio.run(scenario())


def test_dtls_terminal_checkpoint_observes_completion_and_revision():
    async def scenario():
        controller = TransitionController(timeout=1)
        controller.pause_at("dtls", to_state="Finished", phase="terminal")
        fsm = _bare_fsm(controller)
        task = asyncio.create_task(
            fsm._transition(FSMState.Finished, StartHandshake())
        )
        reached = await controller.wait_until("dtls", "Finished", phase="terminal")
        assert fsm.handshake_state is FSMState.Finished
        assert fsm.transition_revision == reached.revision == 1
        assert fsm.handshake_complete.is_set()
        assert not task.done()
        controller.release(reached.checkpoint_id)
        await task

    asyncio.run(scenario())


def test_facet_values_are_bounded_redacted_and_cardinality_limited():
    diagnostics = __import__("collections").Counter()
    store = FacetStore(
        runtime_epoch=1, diagnostics=diagnostics, limit=2, max_string_length=4
    )
    dot = lambda sequence: ProducerDot(1, 1, sequence)
    assert store.apply(FacetOp("peer:name", "peer", 1, "abcdefgh", 1, dot(1)))
    assert store.snapshots()[0].value == "abcd"
    assert not store.apply(FacetOp("peer:certificate", "peer", 1, "secret", 1, dot(2)))
    assert store.apply(FacetOp("peer:depth", "peer", 1, 3, 1, dot(3)))
    assert not store.apply(FacetOp("peer:third", "peer", 1, True, 1, dot(4)))
    assert diagnostics["facet_redactions"] == 1
    assert diagnostics["facet_cardinality_overflow"] == 1


def test_srtp_readiness_boolean_is_not_mistaken_for_key_material():
    diagnostics = __import__("collections").Counter()
    store = FacetStore(runtime_epoch=1, diagnostics=diagnostics)

    assert store.apply(FacetOp(
        "dtls:peer:srtp_keys_ready", "dtls:peer", 1, True, 1,
        ProducerDot(1, 1, 1),
    ))
    assert store.snapshots()[0].value is True
    assert diagnostics["facet_redactions"] == 0


def test_runtime_shutdown_releases_transition_checkpoint():
    async def scenario():
        controller = TransitionController(timeout=30)
        controller.pause_at("dtls", to_state="Finished")
        async with Runtime(transition_controller=Borrowed(controller)) as runtime:
            fsm = _bare_fsm(controller)
            transition = runtime.start(
                lambda: fsm._transition(FSMState.Finished, StartHandshake()),
                name="paused-transition",
            )
            await controller.wait_until("dtls", "Finished")
            await runtime.aclose()
            assert transition.done()

    asyncio.run(scenario())


def test_selected_task_projects_machine_transitions_without_exact_node():
    async def scenario():
        async with Runtime(scope_id="scope") as runtime:
            await SelectedWorker().serve()
            machine = runtime.projection.machines.get("worker:scope")
            assert machine is not None
            assert machine.state == "idle"
            assert machine.revision == 3
            assert not any(
                item["name"].endswith("serve") for item in runtime.trace_live_tree()
            )

    asyncio.run(scenario())
