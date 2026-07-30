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
