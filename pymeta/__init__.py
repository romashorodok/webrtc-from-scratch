"""Executable, immutable metadata for the PyMeta source language.

The objects in this module are ordinary Python values.  They describe facts to
the compiler without changing the values in ``Annotated`` or the callables
decorated with :func:`region`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, is_dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping, TypeVar

__all__ = [
    "Access", "Bounds", "Buffer", "Descriptor", "DescriptorSet", "Effect",
    "EffectSpec", "Float", "Integer", "Lifetime", "Metadata", "Overflow",
    "allocate", "block", "bounded", "buffer", "checked", "compact_object",
    "contiguous", "diagnostics", "effects", "exact_type", "float_", "i8",
    "i16", "i32", "i64", "integer", "io", "lifetime", "metadata",
    "native_class", "never", "normalize", "owned_by", "preferred", "read",
    "readwrite", "record", "region", "required", "serialize", "stable_hash", "sint",
    "specialize", "storage", "suspend", "synchronize", "tracked", "u8",
    "u16", "u32", "u64", "uint", "wrap", "write",
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


def _qualified_name(value: type[object]) -> str:
    return f"{value.__module__}.{value.__qualname__}"


def _freeze(value: Any) -> Any:
    descriptor_factory = globals().get("_DescriptorFactory")
    if descriptor_factory is not None and isinstance(value, descriptor_factory):
        return value.descriptor
    if isinstance(value, dict):
        return tuple(sorted((str(key), _freeze(item)) for key, item in value.items()))
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, type):
        return ("python_type", _qualified_name(value))
    try:
        hash(value)
    except TypeError as error:
        raise TypeError(f"PyMeta value must be immutable: {value!r}") from error
    return value


class _Composable:
    def __or__(self, other: object) -> "DescriptorSet":
        return _compose(self, other)


@dataclass(frozen=True, slots=True)
class Descriptor(_Composable):
    """A closed, hashable semantic fact with normalized named arguments."""

    name: str
    arguments: tuple[tuple[str, Any], ...] = ()
    category: str | None = None

    def __post_init__(self) -> None:
        if not self.name or self.name.lower() != self.name:
            raise ValueError("descriptor names must be lower-case")
        object.__setattr__(
            self,
            "arguments",
            tuple(sorted((name, _freeze(value)) for name, value in self.arguments)),
        )

    def __repr__(self) -> str:
        if not self.arguments:
            return self.name
        arguments = ", ".join(f"{name}={value!r}" for name, value in self.arguments)
        return f"{self.name}({arguments})"


@dataclass(frozen=True, slots=True)
class DescriptorSet(_Composable):
    """A deterministically ordered conjunction of non-contradictory facts."""

    items: tuple[Any, ...]

    def __post_init__(self) -> None:
        flattened: list[Any] = []
        for item in self.items:
            flattened.extend(item.items if isinstance(item, DescriptorSet) else (item,))

        by_category: dict[str, Any] = {}
        unique: dict[str, Any] = {}
        for item in flattened:
            if not isinstance(item, (Descriptor, Integer, Float, Buffer)):
                raise TypeError(f"cannot compose PyMeta descriptor with {item!r}")
            category = _category(item)
            previous = by_category.get(category)
            if previous is not None and previous != item:
                access = {previous, item}
                if access == {read, write}:
                    by_category[category] = readwrite
                    unique.pop(repr(previous), None)
                    unique[repr(readwrite)] = readwrite
                    continue
                raise ValueError(
                    f"contradictory descriptors for {category}: "
                    f"{previous!r} and {item!r}"
                )
            by_category[category] = item
            unique[repr(item)] = item
        representation = by_category.get("representation")
        overflow = by_category.get("overflow")
        if isinstance(representation, Integer) and overflow in (checked, wrap):
            normalized_integer = replace(
                representation,
                overflow=(
                    Overflow.CHECKED if overflow is checked else Overflow.WRAP
                ),
            )
            unique.pop(repr(representation), None)
            unique.pop(repr(overflow), None)
            unique[repr(normalized_integer)] = normalized_integer
        object.__setattr__(
            self, "items", tuple(sorted(unique.values(), key=lambda item: (_order(item), repr(item))))
        )

    def __repr__(self) -> str:
        return " | ".join(repr(item) for item in self.items)


def _category(value: Any) -> str:
    if isinstance(value, Integer):
        return "representation"
    if isinstance(value, Float):
        return "representation"
    if isinstance(value, Buffer):
        return "representation"
    assert isinstance(value, Descriptor)
    return value.category or value.name


_CATEGORY_ORDER = {
    "representation": 0,
    "access": 10,
    "lifetime": 20,
    "storage": 30,
    "ownership": 40,
    "bounds": 50,
    "execution": 60,
}


def _order(value: Any) -> int:
    return _CATEGORY_ORDER.get(_category(value), 100)


def _compose(left: object, right: object) -> DescriptorSet:
    return DescriptorSet((left, right))


@dataclass(frozen=True, slots=True)
class Bounds(_Composable):
    minimum: int | float | None = 0
    maximum: int | float | None = None
    minimum_inclusive: bool = True
    maximum_inclusive: bool = True

    def __post_init__(self) -> None:
        if self.minimum is not None and self.maximum is not None:
            if self.maximum < self.minimum:
                raise ValueError("invalid bounds")
            if self.maximum == self.minimum and not (
                self.minimum_inclusive and self.maximum_inclusive
            ):
                raise ValueError("invalid bounds")
        if isinstance(self.minimum, (int, float)) and self.minimum < 0:
            # Kept for compatibility with the original bounded buffer API.
            raise ValueError("invalid bounds")

    @property
    def category(self) -> str:
        return "bounds"


@dataclass(frozen=True, slots=True)
class Integer(_Composable):
    bits: int
    signed: bool = False
    overflow: Overflow = Overflow.CHECKED

    def __post_init__(self) -> None:
        if self.bits not in (8, 16, 32, 64):
            raise ValueError("integer width must be 8, 16, 32, or 64")
        object.__setattr__(self, "overflow", Overflow(self.overflow))

    def __repr__(self) -> str:
        prefix = "sint" if self.signed else "uint"
        base = f"{prefix}[{self.bits}]"
        return base if self.overflow is Overflow.CHECKED else f"{base}({self.overflow.value})"


@dataclass(frozen=True, slots=True)
class Float(_Composable):
    bits: int

    def __post_init__(self) -> None:
        if self.bits not in (32, 64):
            raise ValueError("float width must be 32 or 64")

    def __repr__(self) -> str:
        return f"float_[{self.bits}]"


@dataclass(frozen=True, slots=True)
class Buffer(_Composable):
    element: Any = field(default_factory=lambda: Integer(8))
    bounds: Bounds = field(default_factory=Bounds)
    access: Access = Access.READ
    lifetime: Lifetime = Lifetime.BORROWED

    def __post_init__(self) -> None:
        object.__setattr__(self, "element", _freeze(self.element))
        object.__setattr__(self, "access", Access(self.access))
        object.__setattr__(self, "lifetime", Lifetime(self.lifetime))


class _RepresentationFactory:
    def __init__(self, kind: str) -> None:
        self.kind = kind

    def __getitem__(self, value: Any) -> Any:
        if self.kind == "sint":
            return Integer(value, signed=True)
        if self.kind == "uint":
            return Integer(value)
        if self.kind == "float_":
            return Float(value)
        if self.kind == "buffer":
            return Buffer(value)
        raise AssertionError(self.kind)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self.kind == "buffer":
            element = args[0] if args else kwargs.pop("element", None)
            minimum = kwargs.pop("minimum", 0)
            maximum = kwargs.pop("maximum", None)
            access = kwargs.pop("access", Access.READ)
            value_lifetime = kwargs.pop("lifetime", Lifetime.BORROWED)
            if kwargs:
                raise TypeError(f"unknown buffer arguments: {sorted(kwargs)}")
            return Buffer(
                element or Integer(8),
                Bounds(minimum, maximum),
                access,
                value_lifetime,
            )
        if len(args) != 1 or kwargs:
            raise TypeError(f"{self.kind} expects one width")
        return self[args[0]]

    def __repr__(self) -> str:
        return self.kind


sint = _RepresentationFactory("sint")
uint = _RepresentationFactory("uint")
float_ = _RepresentationFactory("float_")
buffer = _RepresentationFactory("buffer")


def integer(
    bits: int, *, signed: bool = False, overflow: Overflow = Overflow.CHECKED
) -> Integer:
    return Integer(bits, signed, overflow)


class _Policy(Descriptor):
    def __call__(self, target: Any = None) -> Any:
        if target is None:
            return lambda value: _attach(value, required=self is required)
        if not callable(target):
            raise TypeError(f"{self.name} decorates a callable or class")
        return _attach(target, required=self is required)


required = _Policy("required", category="region_policy")
preferred = _Policy("preferred", category="region_policy")
never = Descriptor("never", category="effect_policy")

checked = Descriptor("checked", category="overflow")
wrap = Descriptor("wrap", category="overflow")
read = Descriptor("read", category="access")
write = Descriptor("write", category="access")
readwrite = Descriptor("readwrite", category="access")
contiguous = Descriptor("contiguous", category="contiguity")
compact_object = Descriptor("compact_object", category="native_layout")
tracked = Descriptor("tracked", category="gc")

allocate = Descriptor("allocate", category="effect_kind")
suspend = Descriptor("suspend", category="effect_kind")
block = Descriptor("block", category="effect_kind")
io = Descriptor("io", category="effect_kind")
synchronize = Descriptor("synchronize", category="effect_kind")


class _LifetimeNamespace:
    call = Descriptor("lifetime.call", category="lifetime")
    owned = Descriptor("lifetime.owned", category="lifetime")


lifetime = _LifetimeNamespace()


class _DescriptorFactory(_Composable):
    def __init__(self, name: str, category: str, **defaults: Any) -> None:
        self.name = name
        self.category = category
        self.defaults = tuple(defaults.items())

    @property
    def descriptor(self) -> Descriptor:
        return Descriptor(self.name, self.defaults, self.category)

    def __call__(self, **kwargs: Any) -> Descriptor:
        values = dict(self.defaults)
        overlap = values.keys() & kwargs.keys()
        if overlap:
            raise TypeError(f"duplicate descriptor arguments: {sorted(overlap)}")
        values.update(kwargs)
        return Descriptor(self.name, tuple(values.items()), self.category)

    def __or__(self, other: object) -> DescriptorSet:
        return self.descriptor | other

    def __ror__(self, other: object) -> DescriptorSet:
        return _compose(other, self.descriptor)

    def __repr__(self) -> str:
        return self.name


class _StorageNamespace:
    native_field = Descriptor("storage.native_field", category="storage")
    fifo = Descriptor("storage.fifo", category="storage")
    min_heap = _DescriptorFactory("storage.min_heap", "storage")
    slab = _DescriptorFactory("storage.slab", "storage")
    inline_record = Descriptor("storage.inline_record", category="storage")


storage = _StorageNamespace()


def bounded(
    *, min: int | float | None = 0, max: int | float | None = None
) -> Descriptor:
    checked_bounds = Bounds(min, max)
    return Descriptor(
        "bounded",
        (
            ("minimum", checked_bounds.minimum),
            ("maximum", checked_bounds.maximum),
            ("minimum_inclusive", checked_bounds.minimum_inclusive),
            ("maximum_inclusive", checked_bounds.maximum_inclusive),
        ),
        "bounds",
    )


def owned_by(owner: str) -> Descriptor:
    if not owner:
        raise ValueError("owner must not be empty")
    return Descriptor("owned_by", (("owner", owner),), "ownership")


def exact_type(*types: type[object]) -> Descriptor:
    if not types or not all(isinstance(value, type) for value in types):
        raise TypeError("exact_type requires one or more Python types")
    return Descriptor(
        "exact_type",
        (("types", tuple(_qualified_name(value) for value in types)),),
        "exact_type",
    )


def specialize(**values: Any) -> Descriptor:
    if not values:
        raise ValueError("specialize requires at least one fact")
    return Descriptor("specialize", tuple(values.items()), "specialization")


@dataclass(frozen=True, slots=True)
class EffectSpec:
    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()
    noescape: frozenset[str] = frozenset()
    owner: str | None = None
    allocate: Any = None
    suspend: Any = None
    block: Any = None
    io: Any = None
    synchronize: Any = None
    disjoint_by: str | None = None
    legacy: frozenset[Effect] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reads", frozenset(self.reads))
        object.__setattr__(self, "writes", frozenset(self.writes))
        object.__setattr__(self, "noescape", frozenset(self.noescape))
        object.__setattr__(
            self, "legacy", frozenset(Effect(value) for value in self.legacy)
        )
        if self.owner == "":
            raise ValueError("effect owner must not be empty")

    @property
    def items(self) -> frozenset[Effect]:
        return self.legacy

    def __call__(self, target: Any) -> Any:
        current = _metadata(target)
        return _attach(target, effects=current.effects | self.legacy)


def effects(*items: Effect | str, **values: Any) -> EffectSpec:
    allowed = {
        "reads", "writes", "noescape", "owner", "allocate", "suspend",
        "block", "io", "synchronize", "disjoint_by",
    }
    unknown = values.keys() - allowed
    if unknown:
        raise TypeError(f"unknown effect arguments: {sorted(unknown)}")
    return EffectSpec(
        reads=frozenset(values.get("reads", ())),
        writes=frozenset(values.get("writes", ())),
        noescape=frozenset(values.get("noescape", ())),
        owner=values.get("owner"),
        allocate=values.get("allocate"),
        suspend=values.get("suspend"),
        block=values.get("block"),
        io=values.get("io"),
        synchronize=values.get("synchronize"),
        disjoint_by=values.get("disjoint_by"),
        legacy=frozenset(Effect(item) for item in items),
    )


@dataclass(frozen=True, slots=True)
class Metadata:
    required: bool = False
    region: object | None = None
    effects: frozenset[Effect] = frozenset()
    records: tuple[tuple[str, object], ...] = ()
    values: tuple[tuple[str, object], ...] = ()
    native_layout: object | None = None
    gc: object | None = None
    weakrefs: bool | None = None

    @property
    def mapping(self) -> Mapping[str, object]:
        return MappingProxyType(dict(self.values))


T = TypeVar("T")


def _metadata(target: object) -> Metadata:
    value = getattr(target, "__pymeta__", None)
    return value if isinstance(value, Metadata) else Metadata()


def metadata(target: object) -> Metadata:
    return _metadata(target)


def _attach(target: T, **changes: object) -> T:
    current = _metadata(target)
    setattr(target, "__pymeta__", replace(current, **changes))
    return target


def region(policy: object, **values: object) -> Callable[[T], T]:
    if policy is None or policy == "":
        raise ValueError("region name must not be empty")
    if not isinstance(policy, (str, _Policy)):
        raise TypeError("region policy must be required, preferred, or a region name")
    frozen_values = tuple(sorted((name, _freeze(value)) for name, value in values.items()))

    def decorate(target: T) -> T:
        return _attach(
            target,
            required=policy is required or _metadata(target).required,
            region=policy,
            values=frozen_values,
        )

    return decorate


def native_class(
    layout: object, *, gc: object, weakrefs: bool
) -> Callable[[T], T]:
    if layout != compact_object:
        raise ValueError("only compact_object native classes are supported")
    if gc != tracked:
        raise ValueError("only tracked native classes are supported")
    if not isinstance(weakrefs, bool):
        raise TypeError("weakrefs must be bool")
    return lambda target: _attach(
        target, native_layout=layout, gc=gc, weakrefs=weakrefs
    )


def record(target: T | None = None, **record_fields: object) -> T | Callable[[T], T]:
    frozen = tuple((name, _freeze(value)) for name, value in record_fields.items())

    def decorate(value: T) -> T:
        return _attach(value, records=_metadata(value).records + frozen)

    return decorate if target is None else decorate(target)


def _to_data(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, type):
        return {"python_type": _qualified_name(value)}
    if isinstance(value, Mapping):
        return {str(key): _to_data(item) for key, item in sorted(value.items())}
    if isinstance(value, (set, frozenset)):
        return sorted((_to_data(item) for item in value), key=repr)
    if isinstance(value, tuple):
        return [_to_data(item) for item in value]
    if isinstance(value, DescriptorSet):
        return {"descriptor_set": [_to_data(item) for item in value.items]}
    if isinstance(value, Descriptor):
        return {
            "descriptor": value.name,
            "arguments": {name: _to_data(item) for name, item in value.arguments},
        }
    if is_dataclass(value):
        return {
            value.__class__.__name__: {
                item.name: _to_data(getattr(value, item.name)) for item in fields(value)
            }
        }
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"cannot serialize PyMeta value {value!r}")


def normalize(value: Any) -> Any:
    """Return the public, deterministic normalized data graph for *value*."""
    return _to_data(value)


def serialize(value: Any) -> str:
    """Serialize metadata with stable ordering and no process-specific values."""
    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"))


def stable_hash(value: Any) -> str:
    """Return a cross-process SHA-256 hash of normalized metadata."""
    from hashlib import sha256

    return sha256(serialize(value).encode("utf-8")).hexdigest()


def diagnostics(value: Any) -> tuple[str, ...]:
    """Return deterministic human-readable diagnostics for valid metadata."""
    normalize(value)
    return ()


i8 = Integer(8, True)
i16 = Integer(16, True)
i32 = Integer(32, True)
i64 = Integer(64, True)
u8 = Integer(8)
u16 = Integer(16)
u32 = Integer(32)
u64 = Integer(64)
