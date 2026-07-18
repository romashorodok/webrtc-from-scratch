"""Atomic module-level dispatch for compiled PyMeta extension modules."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import inspect
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from types import MappingProxyType, ModuleType
from typing import Literal

from . import kernel_e as _python
from .module_contract import (
    FUNCTION_REGISTRY_ATTRIBUTE,
    METADATA_ATTRIBUTES,
    runtime_compatibility,
    semantic_sha256,
)

class NativeArtifactError(RuntimeError):
    """A native-required module is absent or incompatible."""


@dataclass(frozen=True, slots=True)
class ModuleDispatcher:
    """One immutable dispatch unit retaining its complete implementation module."""

    module: ModuleType
    functions: Mapping[str, Callable[..., object]]
    mode: Literal["python", "native-required"]

    def function(self, name: str) -> Callable[..., object]:
        try:
            return self.functions[name]
        except KeyError as exc:
            raise NativeArtifactError(
                f"dispatcher does not contain required function {name!r}"
            ) from exc


def _python_dispatcher() -> ModuleDispatcher:
    names = _required_public_functions(_python)
    functions = MappingProxyType({name: getattr(_python, name) for name in names})
    return ModuleDispatcher(_python, functions, "python")


_lock = RLock()
_dispatcher: ModuleDispatcher


def configure_kernel_e(
    *, mode: Literal["python", "native-required"], library_path: str | Path | None = None
) -> None:
    """Atomically select Python execution or one validated native module.

    ``library_path`` keeps its historical name for API compatibility, but must
    now identify an importable CPython extension rather than a plain C library.
    Validation and registry construction finish before global dispatch changes.
    """
    global _dispatcher
    with _lock:
        if mode == "python":
            if library_path is not None:
                raise ValueError("library_path is not accepted in python mode")
            candidate = _python_dispatcher()
        elif mode == "native-required":
            if library_path is None:
                raise NativeArtifactError("native-required mode needs library_path")
            candidate = load_native_module(Path(library_path), _python)
        else:
            raise ValueError("mode must be 'python' or 'native-required'")

        candidate.function("packetize_av1_frame")
        _dispatcher = candidate


def kernel_e_mode() -> str:
    return _dispatcher.mode


def loaded_kernel_e_module() -> ModuleType:
    """Return the retained module backing the current immutable dispatcher."""
    return _dispatcher.module


def packetize_av1_frame(
    frame: bytes,
    fragmentation_limit: int,
    timestamp: int,
    ssrc: int,
    current_rtp_sequence: int,
    current_twcc_sequence: int,
) -> tuple[tuple[bytes, ...], int, int]:
    function = _dispatcher.function("packetize_av1_frame")
    return function(
        frame,
        fragmentation_limit,
        timestamp,
        ssrc,
        current_rtp_sequence,
        current_twcc_sequence,
    )  # type: ignore[return-value]


def load_native_module(path: str | Path, source_module: ModuleType) -> ModuleDispatcher:
    """Import and validate one compiled source module as an immutable unit."""
    path = Path(path)
    path = path.expanduser().resolve()
    if not path.is_file():
        raise NativeArtifactError(f"native artifact does not exist: {path}")
    module_name = _extension_module_name(path)
    source_path = Path(source_module.__file__).resolve()
    expected_module_name = f"{source_path.stem}_native"
    if module_name != expected_module_name:
        raise NativeArtifactError(
            "native artifact module name mismatch: "
            f"expected {expected_module_name!r}, got {module_name!r}"
        )
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or not isinstance(
            spec.loader, importlib.machinery.ExtensionFileLoader
        ):
            raise NativeArtifactError(
                f"native artifact is not a CPython extension: {path}"
            )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except NativeArtifactError:
        raise
    except (ImportError, OSError, SystemError) as exc:
        raise NativeArtifactError(f"cannot import native artifact {path}: {exc}") from exc

    required = _required_public_functions(source_module)
    _validate_metadata(module, source_module)
    registry = _validate_registry(module, required)
    _validate_public_functions(module, source_module, required, registry)
    return ModuleDispatcher(module, registry, "native-required")


def _extension_module_name(path: Path) -> str:
    for suffix in importlib.machinery.EXTENSION_SUFFIXES:
        if path.name.endswith(suffix):
            return path.name[: -len(suffix)]
    raise NativeArtifactError(
        "native artifact filename does not use this CPython's extension suffix"
    )


def _required_public_functions(module: ModuleType) -> tuple[str, ...]:
    exported = getattr(module, "__all__", None)
    if exported is not None:
        if not isinstance(exported, (tuple, list)) or not all(
            isinstance(name, str) for name in exported
        ):
            raise NativeArtifactError("source module __all__ must be a string sequence")
        public_names = tuple(exported)
        names = tuple(
            name
            for name in public_names
            if callable(getattr(module, name, None))
        )
    else:
        names = tuple(
            name
            for name, value in vars(module).items()
            if not name.startswith("_") and _is_module_function(module, value)
        )
    if len(names) != len(set(names)):
        raise NativeArtifactError("source module __all__ contains duplicate names")
    return names


def _is_module_function(module: ModuleType, value: object) -> bool:
    return inspect.isfunction(value) and value.__module__ == module.__name__


def _validate_metadata(native: ModuleType, source: ModuleType) -> None:
    source_path = Path(source.__file__).resolve()
    source_bytes = source_path.read_bytes()
    expected = {
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "semantic_sha256": semantic_sha256(source_bytes, filename=str(source_path)),
        **runtime_compatibility(),
    }
    mismatches: list[str] = []
    for key, attribute in METADATA_ATTRIBUTES.items():
        actual = getattr(native, attribute, None)
        if not isinstance(actual, str):
            mismatches.append(f"{key}=missing")
        elif actual != expected[key]:
            mismatches.append(f"{key}={actual!r}")
    if mismatches:
        raise NativeArtifactError(
            "native artifact compatibility mismatch: " + ", ".join(mismatches)
        )


def _validate_registry(
    native: ModuleType, required: tuple[str, ...]
) -> Mapping[str, Callable[..., object]]:
    registry = getattr(native, FUNCTION_REGISTRY_ATTRIBUTE, None)
    if not isinstance(registry, MappingProxyType):
        raise NativeArtifactError(
            f"native artifact {FUNCTION_REGISTRY_ATTRIBUTE} must be read-only"
        )
    if not all(isinstance(name, str) and callable(value) for name, value in registry.items()):
        raise NativeArtifactError("native artifact function registry is malformed")
    if set(registry) != set(required):
        missing = sorted(set(required) - set(registry))
        extra = sorted(set(registry) - set(required))
        raise NativeArtifactError(
            f"native artifact function registry mismatch: missing={missing}, extra={extra}"
        )
    return registry


def _validate_public_functions(
    native: ModuleType,
    source: ModuleType,
    required: tuple[str, ...],
    registry: Mapping[str, Callable[..., object]],
) -> None:
    source_all = getattr(source, "__all__", required)
    native_all = getattr(native, "__all__", None)
    if not isinstance(native_all, (tuple, list)) or tuple(native_all) != tuple(source_all):
        raise NativeArtifactError("native artifact __all__ does not match source module")
    for name in required:
        function = getattr(native, name, None)
        if function is None or function is not registry[name]:
            raise NativeArtifactError(
                f"native artifact public function {name!r} is absent from its registry"
            )


_dispatcher = _python_dispatcher()
