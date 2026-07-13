import asyncio
import inspect
from types import MappingProxyType

import pytest

from webrtc import Runtime
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.performance import (
    ObservedComponent,
    TraceDetail,
    compiled_operation_strings,
    event_loop,
    observe,
    performance,
    task,
    unobserved,
    worker,
)
from webrtc.runtime_services import Borrowed
from webrtc.state_machine import (
    AsyncStateMachineRunner,
    InvalidTransition,
    MachineSpec,
    TransitionController,
)


def test_policy_is_compiled_for_every_eligible_method_at_class_creation():
    class Subject(ObservedComponent):
        @event_loop
        def inline(self):
            return 1

        async def async_call(self):
            return 2

        @worker
        @performance(name="named", group="legacy-group")
        def worker_call(self):
            return 3

        @task(name="helper")
        async def helper(self):
            return None

        @task(name="ice-controller", state="ice")
        async def controller(self):
            return None

        @observe(detail="exact", group="debug", slow_ms=12.5, capture_failures=False)
        async def diagnostic(self):
            return None

        @unobserved
        def raw(self):
            return None

        @property
        def value(self):
            return 4

    policies = Subject.__observations__
    assert isinstance(policies, MappingProxyType)
    assert set(policies) == {
        "inline", "async_call", "worker_call", "helper", "controller", "diagnostic"
    }
    assert policies["inline"].detail is TraceDetail.AGGREGATE
    assert policies["async_call"].detail is TraceDetail.AGGREGATE
    assert policies["worker_call"].operation == "named"
    assert policies["worker_call"].group == "legacy-group"
    assert policies["helper"].detail is TraceDetail.OFF
    assert policies["controller"].detail is TraceDetail.STATE
    assert policies["diagnostic"].detail is TraceDetail.EXACT
    assert policies["diagnostic"].slow_ms == 12.5
    assert policies["diagnostic"].capture_failures is False
    assert Subject.diagnostic.__compiled_observation__ is policies["diagnostic"]
    assert len({policy.operation_id for policy in policies.values()}) == len(policies)


def test_inherited_policy_is_reused_and_override_gets_a_new_interned_id():
    class Base(ObservedComponent):
        async def inherited(self):
            return None

    class Child(Base):
        @observe(detail=TraceDetail.OFF)
        async def local(self):
            return None

    assert Child.__observations__["inherited"] is Base.__observations__["inherited"]
    assert (Child.__observations__["local"].operation_id
            != Base.__observations__["inherited"].operation_id)
    assert compiled_operation_strings()[Child.__observations__["local"].operation_id] == (
        Child.__observations__["local"].operation
    )

    class SameNamedOperation(ObservedComponent):
        @performance(name=Child.__observations__["local"].operation)
        async def call(self):
            return None

    assert (SameNamedOperation.__observations__["call"].operation_id
            == Child.__observations__["local"].operation_id)


def test_marker_validation_includes_observe_and_bounded_task_owner_mapping():
    with pytest.raises(TypeError, match="unobserved cannot"):
        class Invalid(ObservedComponent):
            @unobserved
            @observe(detail="aggregate")
            def call(self):
                pass

    with pytest.raises(ValueError, match="unknown observable task state owner"):
        task(state="per-packet")


def test_machine_specs_are_bounded_and_cover_required_owners():
    assert set(MACHINE_SPECS) == {
        "peer", "ice", "dtls", "transport", "worker", "transceiver", "media"
    }
    for name, spec in MACHINE_SPECS.items():
        assert spec.machine_type == name
        assert spec.initial in spec.states
        assert spec.terminal <= spec.states
        assert len(spec.states) <= 8


class _Runner(AsyncStateMachineRunner[str]):
    async def step(self, cause: str) -> str:
        return cause


def test_runner_commits_once_and_test_controller_pauses_only_at_safe_points():
    async def scenario():
        spec = MachineSpec(
            "test", "idle", {"idle": {"running"}, "running": {"done"}, "done": set()},
            frozenset({"done"}),
        )
        controller = TransitionController(timeout=1)
        controller.pause_at("test", to_state="running", phase="before_commit")
        commits = []
        runner = _Runner(spec, entity_id="owner", controller=controller, projector=commits.append)
        await runner.commands.put("running")
        await runner.commands.put("done")
        running = asyncio.create_task(runner.run())
        reached = await controller.wait_until("test", "running")
        assert runner.state == "idle"
        assert runner.revision == 0
        assert commits == []
        controller.release(reached.checkpoint_id)
        await running
        assert runner.state == "done"
        assert [commit.to_state for commit in commits] == ["running", "done"]
        assert [commit.revision for commit in commits] == [1, 2]

    asyncio.run(scenario())


def test_runner_rejects_invalid_edge_before_checkpoint_or_projection():
    async def scenario():
        spec = MachineSpec(
            "test", "idle", {"idle": {"done"}, "done": set()}, frozenset({"done"})
        )
        commits = []
        runner = _Runner(spec, entity_id="owner", projector=commits.append)
        await runner.commands.put("missing")
        with pytest.raises(InvalidTransition):
            await runner.run()
        assert runner.state == "idle"
        assert commits == []

    asyncio.run(scenario())


def test_runtime_uses_null_controller_and_shutdown_releases_borrowed_test_controller():
    runtime = Runtime()
    assert type(runtime.transition_controller).__name__ == "NullTransitionController"
    runtime.shutdown()

    async def scenario():
        controller = TransitionController(timeout=1)
        async with Runtime(transition_controller=Borrowed(controller)) as runtime:
            assert runtime.transition_controller is controller
            # release_all is idempotent and is also called before shutdown awaits children.
            controller.release_all()

    asyncio.run(scenario())
