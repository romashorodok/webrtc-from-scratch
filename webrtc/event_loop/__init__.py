"""Automatic native-or-stock selection and explicit reference-loop exports."""

from __future__ import annotations

import asyncio

from collections.abc import Callable
from pathlib import Path
from threading import RLock
from typing import Any, Literal, cast

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
from .config import LoopConfig

__all__ = [
    "LoopConfig",
    "WebRTCSelectorEventLoop",
    "automatic_loop_factory",
    "event_loop_mode",
    "event_loop_selection_reason",
    "new_event_loop",
    "reference_loop_factory",
]

_selection_lock = RLock()
_selected_factory: Callable[..., asyncio.AbstractEventLoop] | None = None
_selected_mode: Literal["native", "asyncio"] | None = None
_selection_reason: str | None = None
_diagnostic_factories: dict[Path, Callable[..., asyncio.AbstractEventLoop]] = {}


def _artifact_candidates() -> tuple[Path, ...]:
    return artifact_candidates()


def _validated_native_factory(
    artifact: Path, *, allow_diagnostic: bool = False
) -> Callable[..., asyncio.AbstractEventLoop]:
    require_compatible_host()
    cached = _diagnostic_factories.get(artifact)
    if cached is not None:
        if allow_diagnostic:
            return cached
        raise NativeArtifactCompatibilityError(
            "native event-loop artifact is diagnostic-only: performance gates "
            "have not been adopted"
        )
    native = load_native_artifact(artifact, NATIVE_REQUIREMENTS)
    adopted = getattr(native, "__pymeta_performance_adopted__", None) == "true"
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
    validated = cast(Callable[..., asyncio.AbstractEventLoop], factory)
    if not adopted:
        _diagnostic_factories[artifact] = validated
        if not allow_diagnostic:
            raise NativeArtifactCompatibilityError(
                "native event-loop artifact is diagnostic-only: performance "
                "gates have not been adopted"
            )
    return validated


def _select_factory() -> Callable[..., asyncio.AbstractEventLoop]:
    global _selected_factory, _selected_mode, _selection_reason
    with _selection_lock:
        if _selected_factory is not None:
            return _selected_factory
        candidates = _artifact_candidates()
        last_rejection: str | None = None
        for artifact in candidates:
            try:
                factory = _validated_native_factory(artifact)
            except Exception as exc:
                last_rejection = f"{artifact}: {exc}"
                continue
            _selected_factory = factory
            _selected_mode = "native"
            _selection_reason = f"compatible native artifact: {artifact}"
            return factory
        _selected_factory = asyncio.new_event_loop
        _selected_mode = "asyncio"
        _selection_reason = (
            last_rejection
            if last_rejection is not None
            else "no native event-loop artifact candidate was found"
        )
        return _selected_factory


def automatic_loop_factory(
    config: LoopConfig,
    *,
    require_native: bool = False,
    force_asyncio: bool = False,
) -> asyncio.AbstractEventLoop:
    global _selected_factory, _selected_mode, _selection_reason
    if require_native and force_asyncio:
        raise ValueError("require_native and force_asyncio are mutually exclusive")
    if force_asyncio:
        with _selection_lock:
            _selected_factory = asyncio.new_event_loop
            _selected_mode = "asyncio"
            _selection_reason = "stock asyncio explicitly requested"
        return asyncio.new_event_loop()
    if require_native:
        last_rejection: str | None = None
        for artifact in _artifact_candidates():
            try:
                factory = _validated_native_factory(
                    artifact, allow_diagnostic=True
                )
                return factory() if config == LoopConfig() else factory(
                    **config.factory_arguments()
                )
            except Exception as exc:
                last_rejection = f"{artifact}: {exc}"
        raise NativeArtifactCompatibilityError(
            "compatible native event loop is required: "
            f"{last_rejection or 'no artifact candidate was found'}"
        )
    factory = _select_factory()
    if _selected_mode == "native":
        try:
            if config == LoopConfig():
                loop = factory()
            else:
                loop = factory(**config.factory_arguments())
        except Exception as exc:
            with _selection_lock:
                _selected_factory = asyncio.new_event_loop
                _selected_mode = "asyncio"
                _selection_reason = f"native event-loop factory failed: {exc}"
            if require_native:
                raise NativeArtifactCompatibilityError(
                    f"compatible native event-loop factory failed: {exc}"
                ) from exc
            return asyncio.new_event_loop()
        if isinstance(loop, asyncio.AbstractEventLoop):
            return loop
        with _selection_lock:
            _selected_factory = asyncio.new_event_loop
            _selected_mode = "asyncio"
            _selection_reason = "native factory returned a non-event-loop object"
        if require_native:
            raise NativeArtifactCompatibilityError(_selection_reason)
        return asyncio.new_event_loop()
    return asyncio.new_event_loop()


def new_event_loop(
    *,
    packet_workers: int = 0,
    packet_queue_capacity: int = 2048,
    receive_packet_budget: int = 32,
    receive_time_budget_us: int = 100,
    require_native: bool = False,
    force_asyncio: bool = False,
) -> asyncio.AbstractEventLoop:
    return automatic_loop_factory(
        LoopConfig(
            packet_workers=packet_workers,
            packet_queue_capacity=packet_queue_capacity,
            receive_packet_budget=receive_packet_budget,
            receive_time_budget_us=receive_time_budget_us,
        ),
        require_native=require_native,
        force_asyncio=force_asyncio,
    )


def reference_loop_factory(**kwargs: int) -> asyncio.AbstractEventLoop:
    from .loop import new_event_loop as reference_factory

    return reference_factory(**kwargs)


def event_loop_mode() -> Literal["native", "asyncio"]:
    _select_factory()
    return cast(Literal["native", "asyncio"], _selected_mode)


def event_loop_selection_reason() -> str:
    _select_factory()
    return _selection_reason or "event-loop selection has no detail"


def _reset_native_selection_for_tests() -> None:
    global _selected_factory, _selected_mode, _selection_reason
    with _selection_lock:
        _selected_factory = None
        _selected_mode = None
        _selection_reason = None


def __getattr__(name: str) -> Any:
    if name == "WebRTCSelectorEventLoop":
        from .loop import WebRTCSelectorEventLoop

        return WebRTCSelectorEventLoop
    raise AttributeError(name)
