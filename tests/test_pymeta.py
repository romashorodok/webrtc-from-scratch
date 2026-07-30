"""Executable contract tests for the public PyMeta annotation API."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from inspect import signature
from types import MappingProxyType

import pytest

import pymeta


def test_descriptors_are_immutable_composable_and_inspectable() -> None:
    descriptor = pymeta.buffer(
        pymeta.u16,
        minimum=2,
        maximum=8,
        access=pymeta.Access.READ_WRITE,
        lifetime=pymeta.Lifetime.OWNED,
    )

    assert descriptor.element is pymeta.u16
    assert descriptor.bounds == pymeta.Bounds(2, 8)
    assert descriptor.access is pymeta.Access.READ_WRITE
    assert descriptor.lifetime is pymeta.Lifetime.OWNED
    with pytest.raises(FrozenInstanceError):
        descriptor.access = pymeta.Access.READ  # type: ignore[misc]


def test_decorators_compose_without_changing_python_behavior() -> None:
    @pymeta.required
    @pymeta.effects(pymeta.Effect.READ, "raise")
    @pymeta.effects(pymeta.Effect.ALLOCATE)
    @pymeta.region("packet", payload=pymeta.buffer(maximum=16), count=pymeta.u8)
    def parse(payload: bytes, count: int = 1) -> tuple[bytes, int]:
        """Return its inputs unchanged."""
        if count < 0:
            raise ValueError("count must be non-negative")
        return payload, count

    description = pymeta.metadata(parse)
    assert description.required is True
    assert description.region == "packet"
    assert description.effects == frozenset(
        {pymeta.Effect.ALLOCATE, pymeta.Effect.RAISE, pymeta.Effect.READ}
    )
    assert isinstance(description.mapping, MappingProxyType)
    assert description.mapping == {"count": pymeta.u8, "payload": pymeta.buffer(maximum=16)}
    assert parse(b"data", 2) == (b"data", 2)
    assert parse.__name__ == "parse"
    assert parse.__doc__ == "Return its inputs unchanged."
    assert str(signature(parse)) == "(payload: 'bytes', count: 'int' = 1) -> 'tuple[bytes, int]'"
    with pytest.raises(ValueError, match="count must be non-negative"):
        parse(b"data", -1)


def test_record_metadata_preserves_class_construction_and_field_order() -> None:
    @pymeta.record(first=pymeta.u8)
    @pymeta.record(second=pymeta.u16)
    class Header:
        def __init__(self, first: int, second: int) -> None:
            self.first = first
            self.second = second

    value = Header(1, 258)
    assert (value.first, value.second) == (1, 258)
    assert pymeta.metadata(Header).records == (
        ("second", pymeta.u16),
        ("first", pymeta.u8),
    )


def test_native_class_and_preferred_region_metadata_are_behavior_neutral() -> None:
    declared_effects = pymeta.effects(
        pymeta.Effect.ALLOCATE,
        pymeta.Effect.RAISE,
        pymeta.Effect.READ,
        pymeta.Effect.WRITE,
    )

    @pymeta.native_class(
        pymeta.compact_object, gc=pymeta.tracked, weakrefs=False
    )
    class Loop:
        @pymeta.region(pymeta.preferred, effects=declared_effects)
        def _run_once(self) -> int:
            return 7

    class_metadata = pymeta.metadata(Loop)
    method_metadata = pymeta.metadata(Loop._run_once)
    assert class_metadata.native_layout == pymeta.compact_object
    assert class_metadata.gc == pymeta.tracked
    assert class_metadata.weakrefs is False
    assert method_metadata.region == pymeta.preferred
    assert method_metadata.mapping == {"effects": declared_effects}
    assert Loop()._run_once() == 7


@pytest.mark.parametrize(
    ("factory", "message"),
    (
        (lambda: pymeta.Integer(7), "integer width must be 8, 16, 32, or 64"),
        (lambda: pymeta.Bounds(-1), "invalid bounds"),
        (lambda: pymeta.Bounds(4, 3), "invalid bounds"),
        (lambda: pymeta.region(""), "region name must not be empty"),
    ),
)
def test_invalid_metadata_is_rejected_early(factory: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        factory()  # type: ignore[operator]


def test_metadata_for_unannotated_target_is_empty() -> None:
    def plain() -> None:
        pass

    assert pymeta.metadata(plain) == pymeta.Metadata()
