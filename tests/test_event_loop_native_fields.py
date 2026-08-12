"""Stage-2 acceptance tests for native event-loop instance storage."""

from __future__ import annotations

import asyncio
import gc
import os
import subprocess
import sys
import textwrap
import weakref
from pathlib import Path
import inspect

import pytest

from webrtc.compiler import event_loop as reference_event_loop
from webrtc.compiler.module_compiler import compile_module
from webrtc.compiler.native_artifact import (
    NativeClassRequirement,
    NativeModuleRequirements,
    load_native_artifact,
)


@pytest.fixture(scope="module")
def native_artifact(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("event-loop-native-fields")
    return compile_module(
        Path(reference_event_loop.__file__), output
    ).artifact_path.resolve()


@pytest.fixture(scope="module")
def native_module(native_artifact: Path) -> object:
    requirements = NativeModuleRequirements(
        module_name="event_loop_native",
        source_path=Path(reference_event_loop.__file__),
        functions=("new_event_loop",),
        classes={
            "WebRTCSelectorEventLoop": NativeClassRequirement(
                asyncio.SelectorEventLoop, ("_run_once",)
            )
        },
    )
    return load_native_artifact(native_artifact, requirements)


_NATIVE_ATTRIBUTES = (
    "_ready",
    "_scheduled",
    "_selector",
    "_timer_cancelled_count",
    "_clock_resolution",
    "_debug",
    "_stopping",
    "_current_handle",
    "slow_callback_duration",
)


def test_base_initializer_populates_native_member_descriptors(native_module: object) -> None:
    loop_type = native_module.WebRTCSelectorEventLoop  # type: ignore[attr-defined]
    loop = loop_type()
    try:
        for name in _NATIVE_ATTRIBUTES:
            assert inspect.isdatadescriptor(vars(loop_type)[name])
            assert hasattr(loop, name)
            assert name not in vars(loop)

        assert loop._timer_cancelled_count == 0
        assert loop._clock_resolution > 0.0
        assert loop._debug is False
        assert loop._stopping is False
        assert loop._current_handle is None
        assert loop.slow_callback_duration == 0.1
        assert "_closed" in vars(loop)
    finally:
        loop.close()


def test_native_members_preserve_assignment_identity_and_readback(
    native_module: object,
) -> None:
    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    originals = {name: getattr(loop, name) for name in _NATIVE_ATTRIBUTES}
    values = {
        "_ready": object(),
        "_scheduled": object(),
        "_selector": object(),
        "_timer_cancelled_count": object(),
        "_clock_resolution": object(),
        "_debug": object(),
        "_stopping": object(),
        "_current_handle": object(),
        "slow_callback_duration": object(),
    }
    try:
        for name, value in values.items():
            setattr(loop, name, value)
            assert getattr(loop, name) is value
            assert name not in vars(loop)
    finally:
        for name, value in originals.items():
            setattr(loop, name, value)
        loop.close()


def test_deleted_native_member_matches_object_slot_errors(native_module: object) -> None:
    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    original = loop._ready
    try:
        del loop._ready
        with pytest.raises(AttributeError, match="_ready"):
            _ = loop._ready
        with pytest.raises(AttributeError, match="_ready"):
            del loop._ready
        with pytest.raises(AttributeError, match="_ready"):
            loop._run_once()

        loop._ready = original
        loop.call_soon(loop.stop)
        loop.run_forever()
    finally:
        loop.close()


def test_native_run_once_reads_tail_fields_without_instance_attribute_lookup(
    native_module: object,
) -> None:
    loop_type = native_module.WebRTCSelectorEventLoop  # type: ignore[attr-defined]
    loop = loop_type()
    trace: list[str] = []
    ready_descriptor = vars(loop_type)["_ready"]

    def forbidden(_self: object) -> object:
        raise AssertionError("native turn looked up _ready")

    try:
        loop.call_soon(trace.append, "ready")
        loop_type._ready = property(forbidden)
        loop._run_once()
        assert trace == ["ready"]
    finally:
        loop_type._ready = ready_descriptor
        loop.close()


def test_boxed_numeric_and_flag_fallback_matches_reference(native_module: object) -> None:
    def exercise(factory: object) -> tuple[list[str], object, object, object]:
        loop = factory()  # type: ignore[operator]
        trace: list[str] = []
        try:
            loop._debug = []
            loop._stopping = []
            loop._clock_resolution = 1
            loop.slow_callback_duration = 1
            loop._timer_cancelled_count = True
            loop.call_soon(trace.append, "ready")
            loop._run_once()
            return (
                trace,
                loop._debug,
                loop._clock_resolution,
                loop._timer_cancelled_count,
            )
        finally:
            loop.close()

    assert exercise(native_module.new_event_loop) == exercise(  # type: ignore[attr-defined]
        reference_event_loop.new_event_loop
    )


def test_python_subclass_and_native_member_cycle_are_collectable(
    native_module: object,
) -> None:
    loop_type = native_module.WebRTCSelectorEventLoop  # type: ignore[attr-defined]

    class DerivedLoop(loop_type):
        pass

    loop = DerivedLoop()
    reference = weakref.ref(loop)
    loop._current_handle = loop
    loop.close()
    del loop
    gc.collect()
    assert reference() is None


def test_deallocation_stress_is_subprocess_isolated(native_artifact: Path) -> None:
    script = textwrap.dedent(
        """
        import asyncio
        import gc
        import os
        import weakref
        from pathlib import Path
        from webrtc.compiler import event_loop as source
        from webrtc.compiler.native_artifact import (
            NativeClassRequirement, NativeModuleRequirements, load_native_artifact,
        )

        requirements = NativeModuleRequirements(
            "event_loop_native", Path(source.__file__), ("new_event_loop",),
            {"WebRTCSelectorEventLoop": NativeClassRequirement(
                asyncio.SelectorEventLoop, ("_run_once",)
            )},
        )
        module = load_native_artifact(Path(os.environ["STAGE2_ARTIFACT"]), requirements)
        class Derived(module.WebRTCSelectorEventLoop):
            pass
        class Marker:
            pass

        for loop_type in (module.WebRTCSelectorEventLoop, Derived):
            loop_refs = []
            marker_refs = []
            for _ in range(250):
                loop = loop_type()
                marker = Marker()
                loop._current_handle = marker
                loop_refs.append(weakref.ref(loop))
                marker_refs.append(weakref.ref(marker))
                loop.close()
                del loop, marker
            gc.collect()
            assert all(item() is None for item in loop_refs)
            assert all(item() is None for item in marker_refs)

            loop = loop_type()
            loop._current_handle = loop
            loop_ref = weakref.ref(loop)
            loop.close()
            del loop
            gc.collect()
            assert loop_ref() is None
        """
    )
    environment = os.environ.copy()
    environment["STAGE2_ARTIFACT"] = str(native_artifact)
    completed = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr


def test_native_worker_teardown_and_python_fallback_are_subprocess_safe(
    native_artifact: Path,
) -> None:
    script = textwrap.dedent(
        """
        import asyncio
        import gc
        import importlib.util
        import os
        import sys
        import threading
        import time
        from webrtc.event_loop.datagrams import OwnedPacket
        from webrtc.event_loop.workers import PacketResult

        failures = []
        sys.unraisablehook = lambda arg: failures.append(
            ("unraisable", repr(arg.exc_value)))
        threading.excepthook = lambda arg: failures.append(
            ("thread", repr(arg.exc_value)))
        spec = importlib.util.spec_from_file_location(
            "event_loop_native", os.environ["WORKER_ARTIFACT"])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for count in (1, 3):
            loop = asyncio.new_event_loop()
            workers = [module.PacketWorker(
                index, 1, None, loop, lambda result: None)
                for index in range(count)]
            for worker in workers:
                worker.start()
            # Exercise teardown after the loop has already cleared its reader
            # state.  tp_clear/dealloc must neither re-enter nor report an
            # unraisable cleanup exception.
            loop.close()
            del workers, loop
            for _ in range(5):
                gc.collect()

        loop = asyncio.new_event_loop()
        results = []
        worker = module.PacketWorker(
            0, 2, lambda packet: PacketResult(packet.peer_id, 7),
            loop, results.append)
        assert type(worker._thread) is threading.Thread
        assert worker._input.closed is False
        assert worker._output.closed is False
        worker.start()
        assert worker.submit(OwnedPacket(41, b"x"))
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not results:
            loop.run_until_complete(asyncio.sleep(0.001))
        assert [(item.peer_id, item.value) for item in results] == [(41, 7)]
        worker.stop()
        assert worker._input.closed is True
        worker.join()
        worker.join()
        worker.close_channels()
        assert worker._output.closed is True
        loop.close()
        del worker, loop
        for _ in range(5):
            gc.collect()
        assert failures == [], failures
        """
    )
    environment = os.environ.copy()
    environment["WORKER_ARTIFACT"] = str(native_artifact)
    completed = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""


def test_native_worker_prestart_queue_matches_reference_semantics(
    native_artifact: Path,
) -> None:
    script = textwrap.dedent(
        """
        import asyncio
        import gc
        import importlib.util
        import os
        import sys
        import threading
        import time
        from webrtc.event_loop.datagrams import OwnedPacket

        failures = []
        sys.unraisablehook = lambda arg: failures.append(
            ("unraisable", repr(arg.exc_value)))
        threading.excepthook = lambda arg: failures.append(
            ("thread", repr(arg.exc_value)))

        spec = importlib.util.spec_from_file_location(
            "event_loop_native", os.environ["WORKER_ARTIFACT"])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        loop = asyncio.new_event_loop()
        results = []
        worker = module.PacketWorker(0, 2, None, loop, results.append)
        accepted = [worker.submit(OwnedPacket(index, b"x")) for index in range(3)]
        assert accepted == [True, True, False]
        assert worker.dropped == 1
        assert worker._input.qsize() == 2
        worker.start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and len(results) < 2:
            loop.run_until_complete(asyncio.sleep(0.001))
        assert [item.peer_id for item in results] == [0, 1]
        try:
            worker.start()
        except RuntimeError as error:
            assert "only be started once" in str(error)
        else:
            raise AssertionError("native worker accepted a repeated start")
        worker.stop()
        worker.join()
        worker.close_channels()
        loop.close()

        loop = asyncio.new_event_loop()
        results = []
        worker = module.PacketWorker(0, 2, None, loop, results.append)
        assert worker.submit(OwnedPacket(7, b"x"))
        worker.stop()
        try:
            worker.join()
        except RuntimeError:
            pass
        else:
            raise AssertionError("native worker accepted join before start")
        worker.start()
        worker.join()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and len(results) < 1:
            loop.run_until_complete(asyncio.sleep(0.001))
        assert [item.peer_id for item in results] == [7]
        worker.close_channels()
        loop.close()

        # A callback failure must be reported through asyncio while the
        # already-completed FIFO tail is still delivered by the same drain.
        loop = asyncio.new_event_loop()
        attempted = []
        loop_errors = []
        loop.set_exception_handler(lambda unused_loop, context: loop_errors.append(context))
        def callback(result):
            attempted.append(result.peer_id)
            if result.peer_id == 10:
                raise LookupError("expected callback failure")
        worker = module.PacketWorker(0, 3, None, loop, callback)
        assert worker.submit(OwnedPacket(10, b"x"))
        assert worker.submit(OwnedPacket(11, b"x"))
        worker.stop()
        worker.start()
        worker.join()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and (
                len(attempted) < 2 or not loop_errors):
            loop.run_until_complete(asyncio.sleep(0.001))
        assert attempted == [10, 11]
        assert len(loop_errors) == 1
        assert isinstance(loop_errors[0].get("exception"), LookupError)
        worker.close_channels()
        loop.close()

        # Registration and FIFO delivery are independent per shard/worker.
        loop = asyncio.new_event_loop()
        per_worker = [[], []]
        workers = [module.PacketWorker(
            index, 2, None, loop,
            lambda result, index=index: per_worker[index].append(result.peer_id))
            for index in range(2)]
        for index, worker in enumerate(workers):
            assert worker.submit(OwnedPacket(index * 10, b"x"))
            assert worker.submit(OwnedPacket(index * 10 + 1, b"x"))
            worker.stop()
            worker.start()
            worker.join()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and any(
                len(results) < 2 for results in per_worker):
            loop.run_until_complete(asyncio.sleep(0.001))
        assert per_worker == [[0, 1], [10, 11]]
        for worker in workers:
            worker.close_channels()
        loop.close()

        loop = asyncio.new_event_loop()
        worker = module.PacketWorker(0, 2, None, loop, lambda result: None)
        assert worker.submit(OwnedPacket(9, b"x"))
        worker.close_channels()
        assert worker._input.closed and worker._input.empty()
        worker.start()
        worker.join()
        loop.close()
        del worker, loop
        for _ in range(5):
            gc.collect()
        assert failures == [], failures
        """
    )
    environment = os.environ.copy()
    environment["WORKER_ARTIFACT"] = str(native_artifact)
    completed = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""
