"""CPython-specific semantic descriptors.

This module contains no CPython layout constants or native implementation.
"""

from __future__ import annotations

from typing import Any

from . import Descriptor, compact_object, native_class, tracked

__all__ = [
    "compact_object", "cpython_exact", "native_class", "pinned_semantics",
    "tracked",
]


cpython_exact = Descriptor("cpython_exact", category="cpython_semantics")


def pinned_semantics(name: str, **facts: Any) -> Descriptor:
    if not name:
        raise ValueError("pinned semantic name must not be empty")
    return Descriptor(
        "pinned_semantics",
        (("name", name), *facts.items()),
        "cpython_semantics",
    )
