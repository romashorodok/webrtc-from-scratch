"""Shared metadata contract for generated PyMeta extension modules."""

from __future__ import annotations

import ast
import hashlib
import platform
import sys
import sysconfig

COMPILER_VERSION = "wrtc-pymeta-compiler/0.3"
OPTIMIZATION_MODE = "release"

METADATA_ATTRIBUTES = {
    "source_sha256": "__pymeta_source_sha256__",
    "semantic_sha256": "__pymeta_semantic_sha256__",
    "compiler_version": "__pymeta_compiler_version__",
    "cpython_revision": "__pymeta_cpython_revision__",
    "target": "__pymeta_target__",
    "architecture": "__pymeta_architecture__",
    "optimization": "__pymeta_optimization__",
}
FUNCTION_REGISTRY_ATTRIBUTE = "__pymeta_functions__"


def semantic_sha256(source: bytes, *, filename: str = "<module>") -> str:
    """Hash the location-independent CPython AST used as semantic input."""
    tree = ast.parse(source, filename=filename)
    normalized = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def runtime_compatibility() -> dict[str, str]:
    """Return the exact host facts embedded into a compatible artifact."""
    return {
        "compiler_version": COMPILER_VERSION,
        "cpython_revision": sys.version,
        "target": sysconfig.get_platform(),
        "architecture": platform.machine(),
        "optimization": OPTIMIZATION_MODE,
    }
