"""Production selection must fail directly to stock asyncio."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest

from webrtc import event_loop
from webrtc.compiler import event_loop as reference_event_loop


@pytest.fixture(autouse=True)
def reset_selection() -> None:
    event_loop._reset_native_selection_for_tests()
    yield
    event_loop._reset_native_selection_for_tests()


def test_missing_artifact_falls_back_to_stock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: ())

    loop = event_loop.new_event_loop()
    try:
        assert event_loop.event_loop_mode() == "asyncio"
        assert not isinstance(loop, reference_event_loop.WebRTCSelectorEventLoop)
    finally:
        loop.close()


def test_missing_artifact_reports_reason_and_strict_mode_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: ())

    assert event_loop.event_loop_mode() == "asyncio"
    assert event_loop.event_loop_selection_reason() == (
        "no native event-loop artifact candidate was found"
    )
    with pytest.raises(
        event_loop.NativeArtifactCompatibilityError,
        match="compatible native event loop is required",
    ):
        event_loop.new_event_loop(require_native=True)


def test_force_asyncio_bypasses_compatible_native_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = tmp_path / "event_loop_native.so"
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))

    def forbidden(_artifact: Path) -> object:
        raise AssertionError("force-asyncio attempted native artifact validation")

    monkeypatch.setattr(event_loop, "_validated_native_factory", forbidden)
    loop = event_loop.new_event_loop(force_asyncio=True)
    try:
        assert event_loop.event_loop_mode() == "asyncio"
        assert event_loop.event_loop_selection_reason() == (
            "stock asyncio explicitly requested"
        )
        assert type(loop).__module__ != "webrtc.event_loop.loop"
    finally:
        loop.close()


def test_native_required_and_force_asyncio_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        event_loop.new_event_loop(require_native=True, force_asyncio=True)


def test_explicit_absent_artifact_falls_back_to_stock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "event_loop_native.so"
    monkeypatch.setenv("WEBRTC_EVENT_LOOP_NATIVE", str(missing))

    loop = event_loop.new_event_loop()
    try:
        assert event_loop.event_loop_mode() == "asyncio"
        assert isinstance(loop, asyncio.SelectorEventLoop)
        assert not isinstance(loop, reference_event_loop.WebRTCSelectorEventLoop)
    finally:
        loop.close()


def test_failed_extension_import_falls_back_to_stock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    invalid = tmp_path / "event_loop_native.so"
    invalid.write_bytes(b"not a CPython extension")
    monkeypatch.setenv("WEBRTC_EVENT_LOOP_NATIVE", str(invalid))

    loop = event_loop.new_event_loop()
    try:
        assert event_loop.event_loop_mode() == "asyncio"
        assert not isinstance(loop, reference_event_loop.WebRTCSelectorEventLoop)
    finally:
        loop.close()


@pytest.mark.parametrize(
    "metadata",
    (
        "source_sha256",
        "semantic_sha256",
        "compiler_version",
        "cpython_revision",
        "cpython_source_revision",
        "target",
        "architecture",
        "cache_tag",
        "abi_flags",
        "extension_suffix",
        "optimization",
    ),
)
def test_each_metadata_mismatch_falls_back_to_stock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, metadata: str
) -> None:
    candidate = tmp_path / "event_loop_native.so"
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))

    def incompatible(_artifact: Path) -> object:
        raise event_loop.NativeArtifactCompatibilityError(
            f"native artifact compatibility mismatch: {metadata}='stale'"
        )

    monkeypatch.setattr(event_loop, "_validated_native_factory", incompatible)
    loop = event_loop.new_event_loop()
    try:
        assert event_loop.event_loop_mode() == "asyncio"
        assert not isinstance(loop, reference_event_loop.WebRTCSelectorEventLoop)
    finally:
        loop.close()


def test_incompatible_artifact_reason_is_exposed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = tmp_path / "event_loop_native.so"
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))
    monkeypatch.setattr(
        event_loop,
        "_validated_native_factory",
        lambda _: (_ for _ in ()).throw(
            event_loop.NativeArtifactCompatibilityError("stale semantic hash")
        ),
    )

    assert event_loop.event_loop_mode() == "asyncio"
    assert str(candidate) in event_loop.event_loop_selection_reason()
    assert "stale semantic hash" in event_loop.event_loop_selection_reason()


def test_native_factory_receives_nondefault_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = tmp_path / "event_loop_native.so"
    received: dict[str, int] = {}

    def native_factory(**kwargs: int) -> asyncio.AbstractEventLoop:
        received.update(kwargs)
        return asyncio.new_event_loop()

    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))
    monkeypatch.setattr(
        event_loop, "_validated_native_factory", lambda _: native_factory
    )

    loop = event_loop.new_event_loop(
        packet_workers=2,
        packet_queue_capacity=64,
        receive_packet_budget=9,
        receive_time_budget_us=75,
    )
    try:
        assert event_loop.event_loop_mode() == "native"
        assert received == {
            "packet_workers": 2,
            "packet_queue_capacity": 64,
            "receive_packet_budget": 9,
            "receive_time_budget_us": 75,
        }
        assert "compatible native artifact" in event_loop.event_loop_selection_reason()
    finally:
        loop.close()


def test_factory_failure_after_validation_permanently_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = tmp_path / "event_loop_native.so"
    calls = 0

    def fail() -> asyncio.AbstractEventLoop:
        nonlocal calls
        calls += 1
        raise RuntimeError("native startup failure")

    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))
    monkeypatch.setattr(event_loop, "_validated_native_factory", lambda _: fail)

    first = event_loop.new_event_loop()
    second = event_loop.new_event_loop()
    try:
        assert calls == 1
        assert event_loop.event_loop_mode() == "asyncio"
        assert not isinstance(first, reference_event_loop.WebRTCSelectorEventLoop)
        assert not isinstance(second, reference_event_loop.WebRTCSelectorEventLoop)
    finally:
        first.close()
        second.close()


def test_auto_mode_never_calls_interpreted_reference_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: ())

    def forbidden() -> asyncio.AbstractEventLoop:
        raise AssertionError("production called interpreted custom-loop source")

    monkeypatch.setattr(reference_event_loop, "new_event_loop", forbidden)
    loop = event_loop.new_event_loop()
    try:
        assert event_loop.event_loop_mode() == "asyncio"
    finally:
        loop.close()


def test_selected_native_override_is_not_interpreted_python() -> None:
    loop = event_loop.new_event_loop()
    try:
        if event_loop.event_loop_mode() != "native":
            pytest.skip("no compatible native event-loop artifact installed")
        assert isinstance(loop, asyncio.SelectorEventLoop)
        assert not inspect.isfunction(type(loop)._run_once)
    finally:
        loop.close()
