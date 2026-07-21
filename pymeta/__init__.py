"""Executable, behavior-neutral metadata for the bounded PyMeta compiler.

Descriptors are ordinary immutable Python values.  Decorators only attach a
frozen :class:`Metadata` value to their target, so annotated programs retain
their normal CPython calling and exception behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping, TypeVar

__all__ = [
    "Access", "Bounds", "Buffer", "Effect", "Integer", "Lifetime",
    "Metadata", "Overflow", "buffer", "effects", "integer", "metadata", "record",
    "region", "required", "i8", "i16", "i32", "i64", "u8", "u16",
    "u32", "u64",
]


class Overflow(str, Enum):
    CHECKED = "checked"
    WRAP = "wrap"
    SATURATE = "saturate"


class Access(str, Enum):
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


class Lifetime(str, Enum):
    BORROWED = "borrowed"
    OWNED = "owned"


class Effect(str, Enum):
    ALLOCATE = "allocate"
    RAISE = "raise"
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True, slots=True)
class Bounds:
    minimum: int = 0
    maximum: int | None = None

    def __post_init__(self) -> None:
        if self.minimum < 0 or (self.maximum is not None and self.maximum < self.minimum):
            raise ValueError("invalid bounds")


@dataclass(frozen=True, slots=True)
class Integer:
    bits: int
    signed: bool = False
    overflow: Overflow = Overflow.CHECKED

    def __post_init__(self) -> None:
        if self.bits not in (8, 16, 32, 64):
            raise ValueError("integer width must be 8, 16, 32, or 64")
        object.__setattr__(self, "overflow", Overflow(self.overflow))


@dataclass(frozen=True, slots=True)
class Buffer:
    element: Integer = field(default_factory=lambda: Integer(8))
    bounds: Bounds = field(default_factory=Bounds)
    access: Access = Access.READ
    lifetime: Lifetime = Lifetime.BORROWED

    def __post_init__(self) -> None:
        object.__setattr__(self, "access", Access(self.access))
        object.__setattr__(self, "lifetime", Lifetime(self.lifetime))


@dataclass(frozen=True, slots=True)
class Metadata:
    required: bool = False
    region: str | None = None
    effects: frozenset[Effect] = frozenset()
    records: tuple[tuple[str, object], ...] = ()
    values: tuple[tuple[str, object], ...] = ()

    @property
    def mapping(self) -> Mapping[str, object]:
        return MappingProxyType(dict(self.values))


T = TypeVar("T")


def integer(bits: int, *, signed: bool = False, overflow: Overflow = Overflow.CHECKED) -> Integer:
    return Integer(bits, signed, overflow)


def buffer(
    element: Integer | None = None,
    *,
    minimum: int = 0,
    maximum: int | None = None,
    access: Access = Access.READ,
    lifetime: Lifetime = Lifetime.BORROWED,
) -> Buffer:
    return Buffer(element or Integer(8), Bounds(minimum, maximum), access, lifetime)


def _metadata(target: object) -> Metadata:
    value = getattr(target, "__pymeta__", None)
    return value if isinstance(value, Metadata) else Metadata()


def metadata(target: object) -> Metadata:
    """Return a target's immutable metadata, or an empty metadata value."""
    return _metadata(target)


def _attach(target: T, **changes: object) -> T:
    current = _metadata(target)
    setattr(target, "__pymeta__", replace(current, **changes))
    return target


def required(target: T | None = None) -> T | Callable[[T], T]:
    def decorate(value: T) -> T:
        return _attach(value, required=True)
    return decorate if target is None else decorate(target)


def region(name: str, **values: object) -> Callable[[T], T]:
    if not name:
        raise ValueError("region name must not be empty")
    frozen_values = tuple(sorted(values.items()))
    return lambda target: _attach(target, region=name, values=frozen_values)


def effects(*items: Effect | str) -> Callable[[T], T]:
    frozen = frozenset(Effect(item) for item in items)
    return lambda target: _attach(target, effects=_metadata(target).effects | frozen)


def record(target: T | None = None, **fields: object) -> T | Callable[[T], T]:
    frozen = tuple(fields.items())
    def decorate(value: T) -> T:
        return _attach(value, records=_metadata(value).records + frozen)
    return decorate if target is None else decorate(target)


i8 = Integer(8, True)
i16 = Integer(16, True)
i32 = Integer(32, True)
i64 = Integer(64, True)
u8 = Integer(8)
u16 = Integer(16)
u32 = Integer(32)
u64 = Integer(64)
