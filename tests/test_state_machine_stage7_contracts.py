import asyncio
import ast
import inspect
import threading
from pathlib import Path

import pytest

from webrtc import Runtime
from webrtc.performance import ObservedComponent, worker
from webrtc.runtime_services import MissingExecutionScope, OwnedTaskHandle
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.observability import MachineStore, MachineTransitionOp, ProducerDot


ROOT = Path(__file__).resolve().parents[1]
WEBRTC = ROOT / "webrtc"


def _sources() -> dict[Path, str]:
    return {
        path: path.read_text(encoding="utf-8")
        for path in WEBRTC.rglob("*.py")
    }


def test_stage7_has_no_project_lock_or_removed_compatibility_authority():
    sources = _sources()
    combined = "\n".join(sources.values())
    forbidden = (
        "asyncio.Lock(", "asyncio.Semaphore(", "threading.Lock(",
        "threading.RLock(", "from threading import Lock",
        "from threading import RLock", "EventEmitter", "TraceEventBus",
        "TraceService", "TASK_STATE_MACHINE_MAP", "projector=",
        "SerializedWorkerLane", "async_worker_method",
        "DomainEventDispatcher", "emit_domain_event",
        "_lifecycle_revision", "stream_active", "_state_task_projection",
    )
    for spelling in forbidden:
        assert spelling not in combined

    raw_task_sites = {
        path.relative_to(ROOT)
        for path, source in sources.items()
        if "create_task(" in source or "ensure_future(" in source
    }
    assert raw_task_sites <= {Path("webrtc/runtime_services.py")}


def test_only_dtls_handshake_uses_async_runner_and_permanent_machine_task():
    sources = _sources()
    async_runner_classes = []
    start_machine_calls = []
    for path, source in sources.items():
        relative = path.relative_to(ROOT)
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                (
                    isinstance(base, ast.Name)
                    and base.id == "AsyncStateMachineRunner"
                ) or (
                    isinstance(base, ast.Subscript)
                    and isinstance(base.value, ast.Name)
                    and base.value.id == "AsyncStateMachineRunner"
                )
                for base in node.bases
            ):
                async_runner_classes.append((relative, node.name))
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "start_machine"
            ):
                start_machine_calls.append(relative)

    assert async_runner_classes == [
        (Path("webrtc/dtls/fsm.py"), "_HandshakePhaseRunner")
    ]
    assert start_machine_calls == [Path("webrtc/dtls/fsm.py")]

    raw_timer_sites = {
        path.relative_to(ROOT) for path, source in sources.items()
        if ".call_later(" in source
    }
    assert raw_timer_sites == {Path("webrtc/runtime.py")}

    example_ws = (ROOT / "examples" / "examples" / "ws.py").read_text(encoding="utf-8")
    assert "asyncio.Lock(" not in example_ws
    assert ".add_done_callback(" not in example_ws


def test_stage7_events_are_only_generic_notification_and_test_checkpoint_edges():
    sites = {
        path.relative_to(ROOT)
        for path, source in _sources().items()
        if "asyncio.Event(" in source
    }
    assert sites == {Path("webrtc/state_machine.py")}


def test_stage7_worker_calls_are_always_async_and_runtime_start_is_opaque():
    class Subject(ObservedComponent):
        @worker
        def calculate(self, value: int) -> int:
            return value + 1

    async def scenario() -> None:
        with pytest.raises(MissingExecutionScope):
            Subject().calculate(1)

        async with Runtime(scope_id="stage7-contract") as runtime:
            observed = Subject().calculate(2)
            assert inspect.isawaitable(observed)
            assert await observed == 3
            handle = runtime.start(
                lambda: asyncio.sleep(0, result=4), name="stage7-owned"
            )
            assert isinstance(handle, OwnedTaskHandle)
            assert not isinstance(handle, asyncio.Task)
            assert await handle == 4

    asyncio.run(scenario())


def test_stage7_owned_coalescing_timer_cannot_publish_after_runtime_close():
    async def scenario() -> None:
        runtime = Runtime(
            scope_id="stage7-timer", srtp_delivery_facet_cadence=60,
        )
        async with runtime:
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="stream", delivered=True,
            )
            timer = runtime._aggregate_facet_adapter._srtp_flush_handle
            assert timer is not None and not timer.done()
        assert timer.done()
        revisions = tuple(
            (facet.facet_id, facet.revision)
            for facet in runtime.projection.facets.snapshots()
        )
        await asyncio.sleep(0)
        assert revisions == tuple(
            (facet.facet_id, facet.revision)
            for facet in runtime.projection.facets.snapshots()
        )

    asyncio.run(scenario())


def test_component_close_joins_its_worker_descendant_while_runtime_stays_active():
    class Component(ObservedComponent):
        @worker
        def block(self, started: threading.Event, release: threading.Event):
            started.set()
            release.wait(2)

        async def aclose(self, runtime):
            await runtime.join_owner_children("component", 1)
            runtime.remove_owner("component", 1)

    async def scenario():
        started, release = threading.Event(), threading.Event()
        async with Runtime(scope_id="component-worker-owner") as runtime:
            runtime.register_owner("component", epoch=1)
            component = Component()
            component.__bind_worker_owner__(runtime, "component", 1)
            caller = runtime.start(
                lambda: component.block(started, release), name="invoke-component"
            )
            await asyncio.to_thread(started.wait, 1)
            closing = asyncio.create_task(component.aclose(runtime))
            await asyncio.sleep(0)
            assert not closing.done()
            assert runtime.state.value == "active"
            release.set()
            await caller
            await closing
            assert runtime.state.value == "active"
            assert "component" not in runtime._owner_epochs

    asyncio.run(scenario())


def test_machine_observed_remove_rejects_stale_and_allows_new_epoch_reuse():
    store = MachineStore(runtime_epoch=7)
    store.register("queue", MACHINE_SPECS["queue"], epoch=1)
    assert store.remove_owner("queue", 1)
    assert store.get("queue") is None
    assert not store.apply(MachineTransitionOp(
        "queue", "queue", "open", "closing", 1, 1,
        ProducerDot(7, 1, 1),
    ))
    reused = store.register("queue", MACHINE_SPECS["queue"], epoch=2)
    assert reused.machine_epoch == 2 and reused.state == "open"
