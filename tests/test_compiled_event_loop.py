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
from webrtc.event_loop import compile_policy


@pytest.fixture(scope="module")
def native_event_loop_artifact(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    if (reason := compile_policy.host_compatibility_error()) is not None:
        pytest.skip(reason)
    output = tmp_path_factory.mktemp("native-event-loop")
    return compile_module(
        compile_policy.SOURCE_PATH,
        output,
        source_paths=compile_policy.SOURCE_PATHS,
        artifact_metadata=compile_policy.ARTIFACT_POLICY_METADATA,
    ).artifact_path


def test_compiler_emits_native_selector_heap_type(
    native_event_loop_artifact: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if (reason := compile_policy.host_compatibility_error()) is not None:
        pytest.skip(reason)
    monkeypatch.setenv("WEBRTC_EVENT_LOOP_NATIVE", str(native_event_loop_artifact))
    event_loop._reset_native_selection_for_tests()
    assert event_loop.event_loop_mode() == "asyncio"
    assert "diagnostic-only" in event_loop.event_loop_selection_reason()
    loop = event_loop.new_event_loop(require_native=True)
    try:
        loop_type = type(loop)
        assert issubclass(loop_type, asyncio.SelectorEventLoop)
        assert loop_type.__module__ == "event_loop_native"
        assert inspect.ismethoddescriptor(vars(loop_type)["_run_once"])
    finally:
        loop.close()
        event_loop._reset_native_selection_for_tests()


def test_scheduler_ingress_uses_guarded_direct_storage_graph(
    native_event_loop_artifact: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBRTC_EVENT_LOOP_NATIVE", str(native_event_loop_artifact))
    event_loop._reset_native_selection_for_tests()
    loop = event_loop.new_event_loop(require_native=True)
    factory = event_loop._diagnostic_factories[native_event_loop_artifact]
    module = factory.__self__
    loop_type = type(loop)
    installed_call_soon = vars(loop_type)["_call_soon"]

    backends = set(module.__pymeta_native_region_backends__)
    assert module.__pymeta_pyobject_region_backend__ == "aot_direct_graph"
    for method in (
        "_run_once", "call_soon", "_call_soon", "call_at", "call_later",
        "call_soon_threadsafe",
    ):
        assert (
            f"WebRTCSelectorEventLoop.{method}=aot_direct_graph" in backends
        )
    assert (
        "WebRTCSelectorEventLoop._call_soon=aot_direct_graph" in backends
    )
    assert "WebRTCSelectorEventLoop._call_at=aot_direct_graph" in backends
    assert (
        "WebRTCSelectorEventLoop._run_once->ReactorScheduler.run_once"
        in module.__pymeta_native_call_graph__
    )
    assert module.__pymeta_native_operation_abi__ == (
        "typed_results;ownership;nullability;exception_edges"
    )
    assert "pre_mutation" in module.__pymeta_native_guard_policy__
    assert "unbound_descriptors" in module.__pymeta_native_cache_policy__
    graph = set(module.__pymeta_native_call_graph__)
    required_sources = {
        edge.split("->", 1)[0]
        for edge in graph
        if edge.split("->", 1)[0] in dict(
            entry.rsplit("=", 1) for entry in backends
        )
    }
    region_backends = dict(entry.rsplit("=", 1) for entry in backends)
    pending = [
        f"WebRTCSelectorEventLoop.{method}"
        for method in (
            "_run_once", "call_soon", "_call_soon", "call_at",
            "call_later", "call_soon_threadsafe",
        )
    ]
    visited: set[str] = set()
    while pending:
        source = pending.pop()
        if source in visited:
            continue
        visited.add(source)
        assert region_backends[source] == "aot_direct_graph"
        for edge in graph:
            owner, target = edge.split("->", 1)
            if owner == source and target in region_backends:
                pending.append(target)
    assert required_sources

    try:
        module.__pymeta_reset_native_allocation_counters__()
        loop._call_soon(lambda: None, (), None)
        timer = loop._call_at(loop.time() + 60.0, lambda: None, (), None)
        counters = module.__pymeta_native_allocation_counters__()
        assert counters["native_materialization.allocations"] == 0
        timer.cancel()

        def replacement(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("cached original fallback was not used")

        loop_type._call_soon = replacement
        assert vars(loop_type)["_call_soon"] is replacement
        module.__pymeta_reset_native_allocation_counters__()
        handle = installed_call_soon.__get__(loop, loop_type)(
            lambda: None, (), None
        )
        counters = module.__pymeta_native_allocation_counters__()
        assert isinstance(handle, asyncio.Handle)
        assert counters["fallback_deoptimization.allocations"] == 1
    finally:
        loop_type._call_soon = installed_call_soon
        loop.close()
        event_loop._reset_native_selection_for_tests()


def test_compiled_loop_preserves_ready_snapshot_and_timer_cancellation(
    native_event_loop_artifact: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if (reason := compile_policy.host_compatibility_error()) is not None:
        pytest.skip(reason)
    monkeypatch.setenv("WEBRTC_EVENT_LOOP_NATIVE", str(native_event_loop_artifact))
    event_loop._reset_native_selection_for_tests()
    loop = event_loop.new_event_loop(require_native=True)
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

        bulk_deadline = loop.time() + 60.0
        handles = [
            loop.call_at(bulk_deadline + index, lambda: None)
            for index in range(120)
        ]
        for handle in handles[:80]:
            handle.cancel()
        loop.call_soon(lambda: None)
        loop._run_once()  # type: ignore[attr-defined]
        assert len(loop._scheduled) == 40  # type: ignore[attr-defined]
        assert loop._timer_cancelled_count == 0  # type: ignore[attr-defined]
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
