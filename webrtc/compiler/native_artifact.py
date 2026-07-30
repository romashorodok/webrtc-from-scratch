"""Generic compatibility and native-surface validation for compiled modules."""

from __future__ import annotations

import ast
import hashlib
import importlib.machinery
import importlib.util
import inspect
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from .module_contract import (
    METADATA_ATTRIBUTES,
    normalize_artifact_metadata,
    runtime_compatibility,
    semantic_sha256,
    source_manifest_sha256,
)


class NativeArtifactCompatibilityError(RuntimeError):
    """A compiled module is absent, stale, or does not expose its native contract."""


@dataclass(frozen=True, slots=True)
class NativeClassRequirement:
    """One generated heap type and the approved CPython base it must derive from."""

    base: type
    required_methods: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NativeModuleRequirements:
    """Required import identity and callable/type surface for a generated artifact."""

    module_name: str
    source_path: Path
    functions: tuple[str, ...] = ()
    classes: Mapping[str, NativeClassRequirement] = field(default_factory=dict)
    metadata: Mapping[str, str] = field(default_factory=dict)
    source_paths: tuple[Path, ...] = ()

    def expected_metadata(self) -> tuple[tuple[str, str], ...]:
        """Return normalized open metadata, including the discovered source set."""
        expected = dict(self.metadata)
        if self.source_paths:
            manifest_hash = source_manifest_sha256(self.source_paths)
            configured = expected.setdefault(
                "source_manifest_sha256", manifest_hash
            )
            if configured != manifest_hash:
                raise ValueError(
                    "configured source_manifest_sha256 does not match source_paths"
                )
        return normalize_artifact_metadata(expected)


def load_native_artifact(
    path: str | Path, requirements: NativeModuleRequirements
) -> ModuleType:
    """Import an extension by absolute path and validate it before returning it."""
    artifact = Path(path).expanduser().resolve()
    if not artifact.is_file():
        raise NativeArtifactCompatibilityError(
            f"native artifact does not exist: {artifact}"
        )
    actual_name = _extension_module_name(artifact)
    if actual_name != requirements.module_name:
        raise NativeArtifactCompatibilityError(
            "native artifact module name mismatch: "
            f"expected {requirements.module_name!r}, got {actual_name!r}"
        )
    try:
        spec = importlib.util.spec_from_file_location(actual_name, artifact)
        if spec is None or not isinstance(
            spec.loader, importlib.machinery.ExtensionFileLoader
        ):
            raise NativeArtifactCompatibilityError(
                f"native artifact is not a CPython extension: {artifact}"
            )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except NativeArtifactCompatibilityError:
        raise
    except (ImportError, OSError, SystemError) as exc:
        raise NativeArtifactCompatibilityError(
            f"cannot import native artifact {artifact}: {exc}"
        ) from exc
    validate_native_artifact(module, requirements)
    return module


def validate_native_artifact(
    module: ModuleType, requirements: NativeModuleRequirements
) -> None:
    """Validate compatibility metadata and prove the required surface is native."""
    source_path = Path(requirements.source_path).expanduser().resolve()
    try:
        source = source_path.read_bytes()
    except OSError as exc:
        raise NativeArtifactCompatibilityError(
            f"cannot read native artifact source authority {source_path}: {exc}"
        ) from exc
    expected = {
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "semantic_sha256": semantic_sha256(source, filename=str(source_path)),
        **runtime_compatibility(),
    }
    mismatches: list[str] = []
    for key, attribute in METADATA_ATTRIBUTES.items():
        actual = getattr(module, attribute, None)
        if not isinstance(actual, str):
            mismatches.append(f"{key}=missing")
        elif actual != expected[key]:
            mismatches.append(f"{key}={actual!r}")
    if mismatches:
        raise NativeArtifactCompatibilityError(
            "native artifact compatibility mismatch: " + ", ".join(mismatches)
        )

    policy_mismatches: list[str] = []
    try:
        expected_metadata = requirements.expected_metadata()
    except (OSError, TypeError, ValueError) as exc:
        raise NativeArtifactCompatibilityError(
            f"cannot resolve native artifact source manifest: {exc}"
        ) from exc
    for key, expected_value in expected_metadata:
        attribute = f"__pymeta_{key}__"
        actual_value = getattr(module, attribute, None)
        if not isinstance(actual_value, str):
            policy_mismatches.append(f"{key}=missing")
        elif actual_value != expected_value:
            policy_mismatches.append(f"{key}={actual_value!r}")
    if policy_mismatches:
        raise NativeArtifactCompatibilityError(
            "native artifact policy mismatch: " + ", ".join(policy_mismatches)
        )

    for name in requirements.functions:
        value = getattr(module, name, None)
        if not inspect.isbuiltin(value) or getattr(value, "__module__", None) != module.__name__:
            raise NativeArtifactCompatibilityError(
                f"required factory {name!r} is not a native function of "
                f"{module.__name__!r}"
            )

    for name, requirement in requirements.classes.items():
        value = getattr(module, name, None)
        if not isinstance(value, type):
            raise NativeArtifactCompatibilityError(
                f"required native class {name!r} is absent"
            )
        if value.__module__ != module.__name__:
            raise NativeArtifactCompatibilityError(
                f"required class {name!r} is not defined by {module.__name__!r}"
            )
        if not value.__flags__ & (1 << 9):  # Py_TPFLAGS_HEAPTYPE
            raise NativeArtifactCompatibilityError(
                f"required class {name!r} is not a generated heap type"
            )
        if not issubclass(value, requirement.base):
            raise NativeArtifactCompatibilityError(
                f"required class {name!r} does not derive from approved base "
                f"{requirement.base.__module__}.{requirement.base.__qualname__}"
            )
        for method_name in requirement.required_methods:
            method = vars(value).get(method_name)
            if method is None or inspect.isfunction(method):
                raise NativeArtifactCompatibilityError(
                    f"required method {name}.{method_name} is not installed natively"
                )


def _extension_module_name(path: Path) -> str:
    for suffix in importlib.machinery.EXTENSION_SUFFIXES:
        if path.name.endswith(suffix):
            return path.name[: -len(suffix)]
    raise NativeArtifactCompatibilityError(
        "native artifact filename does not use this CPython's extension suffix"
    )


def validate_native_class_profile(source: bytes, *, filename: str) -> None:
    """Reject class sources outside the deliberately bounded native profile.

    This is a source-only guard used before lowering.  It does not claim that
    the general 0.3 backend can generate classes; it makes the inheritance and
    method surface explicit for specialized class compilation paths.
    """
    tree = ast.parse(source, filename=filename)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    for node in classes:
        bases = tuple(_dotted_name(base) for base in node.bases)
        if bases != ("asyncio.SelectorEventLoop",):
            raise NativeArtifactCompatibilityError(
                f"{filename}:{node.lineno}: native class {node.name!r} must derive "
                "directly from asyncio.SelectorEventLoop"
            )
        if node.keywords:
            raise NativeArtifactCompatibilityError(
                f"{filename}:{node.lineno}: native class keywords are unsupported"
            )
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AnnAssign, ast.Expr, ast.Pass)):
                continue
            raise NativeArtifactCompatibilityError(
                f"{filename}:{member.lineno}: unsupported native class member "
                f"{type(member).__name__}"
            )


def _dotted_name(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))
