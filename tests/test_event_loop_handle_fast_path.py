"""Stage-4 acceptance tests for the guarded native Handle._run path."""

from __future__ import annotations

import asyncio
import contextvars
import gc
import os
import subprocess
import sys
import textwrap
import weakref
from pathlib import Path
from types import FrameType
from typing import Callable

import pytest

from webrtc.compiler import event_loop as reference_event_loop
from webrtc.compiler.module_compiler import compile_module
from webrtc.compiler.native_artifact import (
    NativeClassRequirement,
    NativeModuleRequirements,
    load_native_artifact,
)
from webrtc.event_loop.commands import PublishedHandle


@pytest.fixture(scope="module")
def native_artifact(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return compile_module(
        Path(reference_event_loop.__file__),
        tmp_path_factory.mktemp("event-loop-stage4"),
    ).artifact_path.resolve()


@pytest.fixture(scope="module")
def native_module(native_artifact: Path) -> object:
    source = Path(reference_event_loop.__file__)
    return load_native_artifact(
        native_artifact,
        NativeModuleRequirements(
            "event_loop_native",
            source,
            ("new_event_loop",),
            {
                "WebRTCSelectorEventLoop": NativeClassRequirement(
                    asyncio.SelectorEventLoop, ("_run_once",)
                )
            },
        ),
    )


def _profile_handle_run(callback: Callable[[], None]) -> int:
    calls = 0
    code = asyncio.Handle._run.__code__

    def profile(frame: FrameType, event: str, arg: object) -> None:
        del arg
        nonlocal calls
        if event == "call" and frame.f_code is code:
            calls += 1

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        callback()
    finally:
        sys.setprofile(previous)
    return calls


def test_exact_handle_and_timer_avoid_python_run_frame(native_module: object) -> None:
    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    trace: list[object] = []
    marker = contextvars.ContextVar("stage4-marker", default="outer")
    context = contextvars.copy_context()
    context.run(marker.set, "captured")
    try:
        loop.call_soon(
            lambda *values: trace.append((*values, marker.get())),
            1,
            "two",
            context=context,
        )
        loop.call_at(loop.time(), trace.append, "timer")
        calls = _profile_handle_run(loop._run_once)
        assert calls == 0
        assert trace == [(1, "two", "captured"), "timer"]
    finally:
        loop.close()


def test_cancelled_exact_handle_is_not_invoked(native_module: object) -> None:
    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    trace: list[str] = []
    try:
        handle = loop.call_soon(trace.append, "forbidden")
        handle.cancel()
        calls = _profile_handle_run(loop._run_once)
        assert calls == 0
        assert trace == []
    finally:
        loop.close()


def test_nonexact_args_and_handle_subclass_fall_back(native_module: object) -> None:
    class Args(tuple[object, ...]):
        pass

    class DerivedHandle(asyncio.Handle):
        runs = 0

        def _run(self) -> None:
            type(self).runs += 1
            super()._run()

    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    trace: list[str] = []
    try:
        nonexact = asyncio.Handle(trace.append, Args(("args",)), loop)
        derived = DerivedHandle(trace.append, ("derived",), loop)
        loop._ready.extend((nonexact, derived))
        calls = _profile_handle_run(loop._run_once)
        assert calls == 2
        assert DerivedHandle.runs == 1
        assert trace == ["args", "derived"]
    finally:
        loop.close()


def test_threadsafe_handle_uses_dynamic_run(native_module: object) -> None:
    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    trace: list[str] = []
    try:
        handle = loop.call_soon_threadsafe(trace.append, "threadsafe")
        calls = _profile_handle_run(loop._run_once)
        # The custom loop publishes through its cancellation/claim wrapper;
        # command dispatch later enqueues the wrapper's exact asyncio Handle.
        assert type(handle).__name__ == PublishedHandle.__name__
        assert isinstance(handle, (PublishedHandle, native_module.PublishedHandle))  # type: ignore[attr-defined]
        # The wrapper dynamically executes its claim/state transition; only
        # exact asyncio Handle/TimerHandle objects use the C fast path.
        assert calls == 1
        assert trace == ["threadsafe"]
    finally:
        loop.close()


def test_monkeypatched_handle_run_forces_fallback(
    native_module: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    trace: list[str] = []
    original = asyncio.Handle._run
    patched_calls = 0

    def patched(self: asyncio.Handle) -> None:
        nonlocal patched_calls
        patched_calls += 1
        original(self)

    try:
        loop.call_soon(trace.append, "patched")
        monkeypatch.setattr(asyncio.Handle, "_run", patched)
        loop._run_once()
        assert patched_calls == 1
        assert trace == ["patched"]
    finally:
        loop.close()


def test_monkeypatched_handle_member_descriptor_forces_fallback(
    native_module: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = native_module.new_event_loop()  # type: ignore[attr-defined]
    trace: list[str] = []
    descriptor = vars(asyncio.Handle)["_callback"]
    try:
        loop.call_soon(trace.append, "descriptor")
        monkeypatch.setattr(
            asyncio.Handle,
            "_callback",
            property(lambda handle: descriptor.__get__(handle, type(handle))),
        )
        calls = _profile_handle_run(loop._run_once)
        assert calls == 1
        assert trace == ["descriptor"]
    finally:
        monkeypatch.setattr(asyncio.Handle, "_callback", descriptor)
        loop.close()


def _exception_trace(factory: Callable[[], asyncio.AbstractEventLoop]) -> dict[str, object]:
    loop = factory()
    captured: list[dict[str, object]] = []
    try:
        loop.set_debug(True)
        loop.set_exception_handler(lambda _loop, context: captured.append(dict(context)))

        def fail(value: str) -> None:
            raise LookupError(value)

        handle = loop.call_soon(fail, "callback failure")
        loop._run_once()  # type: ignore[attr-defined]
        context = captured[0]
        return {
            "message": context["message"],
            "exception": (
                type(context["exception"]).__name__,
                str(context["exception"]),
            ),
            "same_handle": context["handle"] is handle,
            "has_source": bool(context.get("source_traceback")),
            "current": getattr(loop, "_current_handle"),
        }
    finally:
        loop.close()


def test_callback_exception_context_matches_reference(native_module: object) -> None:
    expected = _exception_trace(reference_event_loop.new_event_loop)
    actual = _exception_trace(native_module.new_event_loop)  # type: ignore[attr-defined]
    assert actual == expected
    assert actual["message"].startswith("Exception in callback ")  # type: ignore[union-attr]
    assert ".fail('callback failure')" in actual["message"]  # type: ignore[operator]


@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit))
def test_control_flow_baseexceptions_propagate_and_clear_debug_handle(
    native_module: object, exception_type: type[BaseException]
) -> None:
    for factory in (
        reference_event_loop.new_event_loop,
        native_module.new_event_loop,  # type: ignore[attr-defined]
    ):
        loop = factory()
        loop.set_debug(True)

        def stop() -> None:
            raise exception_type("stop")

        try:
            loop.call_soon(stop)
            with pytest.raises(exception_type, match="stop"):
                loop._run_once()  # type: ignore[attr-defined]
            assert getattr(loop, "_current_handle") is None
        finally:
            loop.close()


def test_call_exception_handler_failure_propagates(native_module: object) -> None:
    for factory in (
        reference_event_loop.new_event_loop,
        native_module.new_event_loop,  # type: ignore[attr-defined]
    ):
        loop = factory()

        def fail_callback() -> None:
            raise ValueError("callback")

        def fail_handler(_context: dict[str, object]) -> None:
            raise RuntimeError("handler")

        try:
            loop.call_exception_handler = fail_handler
            loop.call_soon(fail_callback)
            with pytest.raises(RuntimeError, match="handler"):
                loop._run_once()  # type: ignore[attr-defined]
        finally:
            loop.close()


def test_callback_refcount_and_context_gc_stress_isolated(
    native_artifact: Path,
) -> None:
    script = textwrap.dedent(
        """
        import asyncio
        import contextvars
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
        module = load_native_artifact(Path(os.environ["STAGE4_ARTIFACT"]), requirements)
        class Callback:
            def __init__(self, output):
                self.output = output
            def __call__(self, value):
                self.output.append(value)

        loop = module.new_event_loop()
        output = []
        references = []
        marker = contextvars.ContextVar("marker")
        for value in range(5000):
            callback = Callback(output)
            references.append(weakref.ref(callback))
            context = contextvars.copy_context()
            context.run(marker.set, value)
            loop.call_soon(callback, value, context=context)
            del callback, context
        while loop._ready:
            loop._run_once()
        gc.collect()
        assert output == list(range(5000))
        assert all(reference() is None for reference in references)
        loop.close()
        """
    )
    environment = os.environ.copy()
    environment["STAGE4_ARTIFACT"] = str(native_artifact)
    completed = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
