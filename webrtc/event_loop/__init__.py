"""Automatic native-or-stock selection and explicit reference-loop exports."""

from __future__ import annotations

import asyncio

from collections.abc import Callable
from pathlib import Path
from threading import RLock
from typing import Literal, cast

from webrtc.compiler.native_artifact import (
    NativeArtifactCompatibilityError,
    load_native_artifact,
)

from .compile_policy import (
    NATIVE_CLASS,
    NATIVE_FACTORY,
    NATIVE_REQUIREMENTS,
    artifact_candidates,
    require_compatible_host,
)

__all__ = [
    "LoopConfig",
    "WebRTCSelectorEventLoop",
    "automatic_loop_factory",
    "event_loop_mode",
    "new_event_loop",
    "reference_loop_factory",
]

_selection_lock = RLock()
_selected_factory: Callable[..., asyncio.AbstractEventLoop] | None = None
_selected_mode: Literal["native", "asyncio"] | None = None


def _artifact_candidates() -> tuple[Path, ...]:
    return artifact_candidates()


def _validated_native_factory(artifact: Path) -> Callable[..., asyncio.AbstractEventLoop]:
    require_compatible_host()
    native = load_native_artifact(artifact, NATIVE_REQUIREMENTS)
    loop_type = getattr(native, NATIVE_CLASS, None)
    factory = getattr(native, NATIVE_FACTORY)
    try:
        probe = factory()
    except Exception as exc:
        raise NativeArtifactCompatibilityError(
            f"native event-loop factory failed validation: {exc}"
        ) from exc
    if type(probe) is not loop_type:
        if isinstance(probe, asyncio.AbstractEventLoop):
            probe.close()
        raise NativeArtifactCompatibilityError(
            "native event-loop factory did not return its exported loop class"
        )
    probe.close()
    return cast(Callable[..., asyncio.AbstractEventLoop], factory)


def _select_factory() -> Callable[..., asyncio.AbstractEventLoop]:
    global _selected_factory, _selected_mode
    with _selection_lock:
        if _selected_factory is not None:
            return _selected_factory
        for artifact in _artifact_candidates():
            try:
                factory = _validated_native_factory(artifact)
            except Exception:
                continue
            _selected_factory = factory
            _selected_mode = "native"
            return factory
        _selected_factory = asyncio.new_event_loop
        _selected_mode = "asyncio"
        return _selected_factory


def automatic_loop_factory(config: "LoopConfig") -> asyncio.AbstractEventLoop:
    global _selected_factory, _selected_mode
    factory = _select_factory()
    if _selected_mode == "native":
        try:
            if config == LoopConfig():
                loop = factory()
            else:
                loop = factory(**config.factory_arguments())
        except Exception:
            with _selection_lock:
                _selected_factory = asyncio.new_event_loop
                _selected_mode = "asyncio"
            return asyncio.new_event_loop()
        if isinstance(loop, asyncio.AbstractEventLoop):
            return loop
        with _selection_lock:
            _selected_factory = asyncio.new_event_loop
            _selected_mode = "asyncio"
        return asyncio.new_event_loop()
    return asyncio.new_event_loop()


def new_event_loop(
    *,
    packet_workers: int = 0,
    packet_queue_capacity: int = 2048,
    receive_packet_budget: int = 32,
    receive_time_budget_us: int = 100,
) -> asyncio.AbstractEventLoop:
    return automatic_loop_factory(
        LoopConfig(
            packet_workers=packet_workers,
            packet_queue_capacity=packet_queue_capacity,
            receive_packet_budget=receive_packet_budget,
            receive_time_budget_us=receive_time_budget_us,
        )
    )


def reference_loop_factory(**kwargs: int) -> asyncio.AbstractEventLoop:
    from .loop import new_event_loop as reference_factory

    return reference_factory(**kwargs)


def event_loop_mode() -> Literal["native", "asyncio"]:
    _select_factory()
    return cast(Literal["native", "asyncio"], _selected_mode)


def _reset_native_selection_for_tests() -> None:
    global _selected_factory, _selected_mode
    with _selection_lock:
        _selected_factory = None
        _selected_mode = None


from .loop import LoopConfig, WebRTCSelectorEventLoop
