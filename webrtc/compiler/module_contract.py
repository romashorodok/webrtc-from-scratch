"""Shared metadata contract for generated PyMeta extension modules."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import platform
import re
import sys
import sysconfig
from collections.abc import Iterable, Mapping
from pathlib import Path

COMPILER_VERSION = "wrtc-pymeta-compiler/0.4"
OPTIMIZATION_MODE = "release"
CPYTHON_SOURCE_REVISION = "070700ed4d95c16855603cecab3f41f3b587f973"

METADATA_ATTRIBUTES = {
    "source_sha256": "__pymeta_source_sha256__",
    "semantic_sha256": "__pymeta_semantic_sha256__",
    "compiler_version": "__pymeta_compiler_version__",
    "cpython_revision": "__pymeta_cpython_revision__",
    "cpython_source_revision": "__pymeta_cpython_source_revision__",
    "target": "__pymeta_target__",
    "architecture": "__pymeta_architecture__",
    "cache_tag": "__pymeta_cache_tag__",
    "abi_flags": "__pymeta_abi_flags__",
    "extension_suffix": "__pymeta_extension_suffix__",
    "optimization": "__pymeta_optimization__",
}
FUNCTION_REGISTRY_ATTRIBUTE = "__pymeta_functions__"
_METADATA_KEY = re.compile(r"[a-z][a-z0-9_]*\Z")


def semantic_sha256(source: bytes, *, filename: str = "<module>") -> str:
    """Hash the location-independent CPython AST used as semantic input."""
    tree = ast.parse(source, filename=filename)
    normalized = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def source_manifest_sha256(
    source_paths: Iterable[str | Path],
    *,
    root: str | Path | None = None,
) -> str:
    """Hash a normalized, order-independent set of source names and bytes."""
    paths = tuple(Path(path).expanduser().resolve() for path in source_paths)
    if not paths:
        raise ValueError("source manifest must contain at least one path")
    if root is None:
        common = Path(os.path.commonpath(tuple(str(path.parent) for path in paths)))
    else:
        common = Path(root).expanduser().resolve()

    entries: list[tuple[str, bytes]] = []
    names: set[str] = set()
    for path in paths:
        try:
            name = path.relative_to(common).as_posix()
        except ValueError as exc:
            raise ValueError(f"source path is outside manifest root: {path}") from exc
        if name in names:
            raise ValueError(f"duplicate source manifest name: {name}")
        names.add(name)
        entries.append((name, path.read_bytes()))

    digest = hashlib.sha256()
    for name, source in sorted(entries):
        encoded_name = name.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(source).to_bytes(8, "big"))
        digest.update(source)
    return digest.hexdigest()


def policy_sha256(document: Mapping[str, object]) -> str:
    """Hash a normalized JSON policy document."""
    encoded = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_artifact_metadata(
    metadata: Mapping[str, str] | None,
) -> tuple[tuple[str, str], ...]:
    """Validate and sort open artifact metadata for build and inspection."""
    normalized: list[tuple[str, str]] = []
    for key, value in (metadata or {}).items():
        if not isinstance(key, str) or _METADATA_KEY.fullmatch(key) is None:
            raise ValueError(f"invalid artifact metadata key: {key!r}")
        if key in METADATA_ATTRIBUTES:
            raise ValueError(f"artifact metadata key is reserved: {key}")
        if not isinstance(value, str):
            raise TypeError(f"artifact metadata value for {key!r} must be str")
        normalized.append((key, value))
    return tuple(sorted(normalized))


def runtime_compatibility() -> dict[str, str]:
    """Return the exact host facts embedded into a compatible artifact."""
    return {
        "compiler_version": COMPILER_VERSION,
        "cpython_revision": sys.version,
        "cpython_source_revision": CPYTHON_SOURCE_REVISION,
        "target": sysconfig.get_platform(),
        "architecture": platform.machine(),
        "cache_tag": sys.implementation.cache_tag or "",
        "abi_flags": getattr(sys, "abiflags", ""),
        "extension_suffix": sysconfig.get_config_var("EXT_SUFFIX") or "",
        "optimization": OPTIMIZATION_MODE,
    }
