"""End-to-end acceptance for the bounded native event-loop compiler profile."""

from __future__ import annotations

import asyncio
import contextvars
import inspect
from pathlib import Path

import pytest

from webrtc import event_loop
from webrtc.compiler import event_loop as reference_event_loop
from webrtc.compiler.module_compiler import ModuleCompileError, compile_module


@pytest.fixture(scope="module")
def native_event_loop_artifact(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    output = tmp_path_factory.mktemp("native-event-loop")
    return compile_module(Path(reference_event_loop.__file__), output).artifact_path


def test_compiler_emits_native_selector_heap_type(
    native_event_loop_artifact: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBRTC_EVENT_LOOP_NATIVE", str(native_event_loop_artifact))
    event_loop._reset_native_selection_for_tests()
    loop = event_loop.new_event_loop()
    try:
        loop_type = type(loop)
        assert event_loop.event_loop_mode() == "native"
        assert issubclass(loop_type, asyncio.SelectorEventLoop)
        assert loop_type.__module__ == "event_loop_native"
        assert inspect.ismethoddescriptor(vars(loop_type)["_run_once"])
    finally:
        loop.close()
        event_loop._reset_native_selection_for_tests()


def test_compiled_loop_preserves_ready_snapshot_and_timer_cancellation(
    native_event_loop_artifact: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBRTC_EVENT_LOOP_NATIVE", str(native_event_loop_artifact))
    event_loop._reset_native_selection_for_tests()
    loop = event_loop.new_event_loop()
    trace: list[str] = []
    captured: list[str] = []
    failures: list[tuple[str, str]] = []
    marker = contextvars.ContextVar("compiled-loop-marker", default="outer")
    try:
        def first() -> None:
            trace.append("first")
            loop.call_soon(trace.append, "next-turn")

        loop.call_soon(first)
        loop.call_soon(trace.append, "second")
        loop._run_once()  # type: ignore[attr-defined]
        assert trace == ["first", "second"]
        loop._run_once()  # type: ignore[attr-defined]

        deadline = loop.time()
        cancelled = loop.call_at(deadline, trace.append, "cancelled")
        cancelled.cancel()
        loop.call_at(deadline, trace.append, "timer")
        loop._run_once()  # type: ignore[attr-defined]
        assert trace == ["first", "second", "next-turn", "timer"]

        callback_context = contextvars.copy_context()
        callback_context.run(marker.set, "captured")
        loop.call_soon(lambda: captured.append(marker.get()), context=callback_context)
        marker.set("changed")
        loop._run_once()  # type: ignore[attr-defined]
        assert captured == ["captured"]

        def exception_handler(
            _loop: asyncio.AbstractEventLoop, context: dict[str, object]
        ) -> None:
            exception = context["exception"]
            assert isinstance(exception, BaseException)
            failures.append((type(exception).__name__, str(exception)))

        def fail() -> None:
            raise LookupError("native callback failure")

        loop.set_debug(True)
        loop.set_exception_handler(exception_handler)
        loop.call_soon(fail)
        loop._run_once()  # type: ignore[attr-defined]
        assert failures == [("LookupError", "native callback failure")]
        assert getattr(loop, "_current_handle") is None
    finally:
        loop.close()
        event_loop._reset_native_selection_for_tests()


def test_unresolvable_copied_event_loop_fails_closed_without_artifact(
    tmp_path: Path,
) -> None:
    changed = tmp_path / "event_loop.py"
    source = Path(reference_event_loop.__file__).read_text(encoding="utf-8")
    changed.write_text(source, encoding="utf-8")
    output = tmp_path / "artifact"

    with pytest.raises(ModuleCompileError, match="unsafe import is not supported"):
        compile_module(changed, output)

    assert not list(output.glob("*.so"))
